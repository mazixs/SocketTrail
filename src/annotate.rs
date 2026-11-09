//! Переписывание дампа после записи: подпись пакетов процессом и доменом (opt_comment,
//! в Wireshark - поле frame.comment), отбор трафика процесса, сокращение и разбиение на
//! части. Отбор идет по владельцу соединения, а не по адресам на момент старта, поэтому
//! серверы, к которым игра подключилась позже, не теряются.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::pcap::{self, Flow};
use crate::state::{ConnKey, classify};

pub struct Owner {
    pub label: Option<String>,
    pub keep: bool,
}

/// Сокращение дампа: заголовки и исходные длины остаются у всех кадров, а содержимое -
/// только там, где оно обычно нужно для разбора.
#[derive(Clone, Copy, Debug)]
pub struct Compact {
    /// Сколько байт кадров потока хранится целиком: рукопожатие и начало обмена.
    pub flow_bytes: u64,
    /// Сколько байт нагрузки остается после заголовков в остальных кадрах.
    pub tail: usize,
    /// Предел для кадров без TCP и UDP.
    pub other_frame: usize,
}

impl Default for Compact {
    fn default() -> Self {
        Self {
            flow_bytes: 64 * 1024,
            tail: 16,
            other_frame: 128,
        }
    }
}

pub struct Plan {
    pub owners: HashMap<ConnKey, Owner>,
    /// false - весь трафик, true - только соединения процесса.
    pub only_group: bool,
    pub compact: Option<Compact>,
    pub comment: String,
    /// Адреса компьютера: с их стороны строится ключ потока, которого нет в карте.
    pub local_ips: HashSet<IpAddr>,
}

/// Сводка по потоку, посчитанная по самому файлу.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowStats {
    pub packets: u64,
    /// Исходный объем кадров.
    pub bytes: u64,
    /// Объем кадров в файле после сокращения.
    pub stored: u64,
    pub first_us: u64,
    pub last_us: u64,
}

impl FlowStats {
    fn add(&mut self, bytes: u64, stored: u64, at_us: u64) {
        if self.packets == 0 || at_us < self.first_us {
            self.first_us = at_us;
        }
        self.last_us = self.last_us.max(at_us);
        self.packets += 1;
        self.bytes += bytes;
        self.stored += stored;
    }
}

#[derive(Default, Debug)]
pub struct Stats {
    /// Кадров прочитано.
    pub packets: u64,
    /// Кадров записано.
    pub kept: u64,
    pub labeled: u64,
    pub trimmed: u64,
    /// Записанные кадры всего, по файлу.
    pub total: FlowStats,
    /// Кадры без TCP и UDP, а также сверх предела числа потоков.
    pub loose: FlowStats,
    pub flows: HashMap<ConnKey, FlowStats>,
}

/// Предел таблицы потоков: при сканировании портов их число растет вместе с пакетами.
const MAX_FLOWS: usize = 2_000_000;
const MAX_BLOCK: usize = 1 << 26;

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 1;
/// Устаревший Packet Block и Simple Packet Block: тоже содержат кадры.
const OBSOLETE_PACKET: u32 = 2;
const SPB: u32 = 3;
const EPB: u32 = 6;
const MAGIC: u32 = 0x1A2B_3C4D;

const OPT_COMMENT: u16 = 1;
const IF_TSRESOL: u16 = 9;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn push_comment(out: &mut Vec<u8>, text: &str) {
    let t = text.as_bytes();
    let t = &t[..t.len().min(u16::MAX as usize - 3)];
    out.extend_from_slice(&OPT_COMMENT.to_le_bytes());
    out.extend_from_slice(&(t.len() as u16).to_le_bytes());
    out.extend_from_slice(t);
    out.resize(out.len().div_ceil(4) * 4, 0);
}

/// Список опций блока с новым комментарием: прежние комментарии заменяются, поэтому
/// повторная обработка файла не копит подписи. Без нового комментария список не меняется.
fn write_options(out: &mut Vec<u8>, old: &[u8], comment: Option<&str>) {
    let Some(comment) = comment else {
        out.extend_from_slice(old);
        return;
    };
    push_comment(out, comment);
    let mut at = 0;
    while let Some(head) = old.get(at..at + 4) {
        let (code, len) = (le16(head, 0), le16(head, 2) as usize);
        if code == 0 {
            break;
        }
        let end = at + 4 + len.div_ceil(4) * 4;
        let Some(raw) = old.get(at..end) else {
            break;
        };
        if code != OPT_COMMENT {
            out.extend_from_slice(raw);
        }
        at = end;
    }
    out.extend_from_slice(&[0u8; 4]);
}

fn write_block(out: &mut impl Write, ty: u32, body: &[u8]) -> std::io::Result<()> {
    let len = (12 + body.len()) as u32;
    out.write_all(&ty.to_le_bytes())?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&len.to_le_bytes())
}

/// Чтение блоков pcapng в общий буфер: на файле в сотни мегабайт выделять память на
/// каждый пакет незачем.
struct Blocks<'p, R> {
    r: BufReader<R>,
    body: Vec<u8>,
    progress: Option<&'p AtomicU64>,
}

impl<'p, R: Read> Blocks<'p, R> {
    fn new(src: R, progress: Option<&'p AtomicU64>) -> Self {
        Self {
            r: BufReader::with_capacity(1 << 20, src),
            body: Vec::with_capacity(64 * 1024),
            progress,
        }
    }

    /// Тип следующего блока, его тело без заголовка и хвоста - в `body`.
    fn next(&mut self) -> std::io::Result<Option<u32>> {
        if self.r.fill_buf()?.is_empty() {
            return Ok(None);
        }
        let mut head = [0u8; 8];
        self.r.read_exact(&mut head)?;
        let ty = le32(&head, 0);
        let len = le32(&head, 4) as usize;
        if !(12..=MAX_BLOCK).contains(&len) || !len.is_multiple_of(4) {
            return Err(std::io::Error::other(t!(
                "corrupted pcapng block",
                "поврежденный блок pcapng"
            )));
        }
        self.body.resize(len - 8, 0);
        self.r.read_exact(&mut self.body)?;
        if le32(&self.body, self.body.len() - 4) as usize != len {
            return Err(std::io::Error::other(t!(
                "pcapng block lengths disagree",
                "Длины блока pcapng не совпадают"
            )));
        }
        self.body.truncate(len - 12);
        if let Some(p) = self.progress {
            p.fetch_add(len as u64, Ordering::Relaxed);
        }
        Ok(Some(ty))
    }
}

#[derive(Clone, Copy)]
struct Iface {
    linktype: u16,
    /// Единиц времени в секунде.
    units: u64,
}

const DEFAULT_IFACE: Iface = Iface {
    linktype: 1,
    units: 1_000_000,
};

fn iface_of(body: &[u8]) -> Iface {
    let mut units = DEFAULT_IFACE.units;
    let mut at = 8;
    while let Some(head) = body.get(at..at + 4) {
        let (code, len) = (le16(head, 0), le16(head, 2) as usize);
        if code == 0 {
            break;
        }
        // Старший бит if_tsresol выбирает основание: 10^-n или 2^-n.
        if code == IF_TSRESOL
            && len >= 1
            && let Some(&res) = body.get(at + 4)
        {
            let n = u32::from(res & 0x7f);
            let base: u64 = if res & 0x80 == 0 { 10 } else { 2 };
            units = base.checked_pow(n).unwrap_or(units).max(1);
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    Iface {
        linktype: le16(body, 0),
        units,
    }
}

fn micros(body: &[u8], iface: Iface) -> u64 {
    let ticks = (u64::from(le32(body, 4)) << 32) | u64::from(le32(body, 8));
    match iface.units {
        1_000_000 => ticks,
        u if u.is_multiple_of(1_000_000) => ticks / (u / 1_000_000),
        u => (u128::from(ticks) * 1_000_000 / u128::from(u)) as u64,
    }
}

/// Поля кадра из тела Enhanced Packet Block.
struct Epb<'a> {
    body: &'a [u8],
    caplen: usize,
    fixed: usize,
    iface: Iface,
}

impl<'a> Epb<'a> {
    fn parse(body: &'a [u8], ifaces: &[Iface]) -> std::io::Result<Self> {
        let caplen = le32(body, 12) as usize;
        let fixed = 20 + caplen.div_ceil(4) * 4;
        if body.len() < fixed {
            return Err(std::io::Error::other(t!(
                "corrupted pcapng packet",
                "поврежденный пакет pcapng"
            )));
        }
        Ok(Self {
            body,
            caplen,
            fixed,
            iface: ifaces
                .get(le32(body, 0) as usize)
                .copied()
                .unwrap_or(DEFAULT_IFACE),
        })
    }

    fn frame(&self) -> &'a [u8] {
        &self.body[20..20 + self.caplen]
    }

    fn origlen(&self) -> u64 {
        u64::from(le32(self.body, 16)).max(self.caplen as u64)
    }

    fn flow(&self) -> Option<Flow> {
        pcap::parse_flow(self.iface.linktype, self.frame())
    }

    /// Тело блока с новой длиной кадра и подписью. Исходная длина сохраняется.
    fn rebuild(&self, out: &mut Vec<u8>, store: usize, label: Option<&str>) {
        out.clear();
        out.extend_from_slice(&self.body[..12]);
        out.extend_from_slice(&(store as u32).to_le_bytes());
        out.extend_from_slice(&self.body[16..20]);
        out.extend_from_slice(&self.frame()[..store]);
        out.resize(out.len().div_ceil(4) * 4, 0);
        write_options(out, &self.body[self.fixed..], label);
    }
}

fn no_header() -> std::io::Error {
    std::io::Error::other(t!(
        "pcapng section header is missing",
        "В pcapng отсутствует заголовок секции"
    ))
}

fn check_section(body: &[u8]) -> std::io::Result<()> {
    if body.len() < 16 || le32(body, 0) != MAGIC {
        return Err(std::io::Error::other(t!(
            "big-endian pcapng",
            "pcapng с обратным порядком байт"
        )));
    }
    Ok(())
}

impl Plan {
    /// Ключ потока и его владелец. Поток вне карты получает ключ со стороны компьютера,
    /// одинаковый для обоих направлений.
    pub fn key_of(&self, f: &Flow) -> (ConnKey, Option<&Owner>) {
        let fwd = ConnKey {
            proto: f.proto,
            local: f.src,
            lport: f.sport,
            remote: f.dst,
            rport: f.dport,
        };
        let back = ConnKey {
            proto: f.proto,
            local: f.dst,
            lport: f.dport,
            remote: f.src,
            rport: f.sport,
        };
        if let Some(o) = self.owners.get(&fwd) {
            return (fwd, Some(o));
        }
        if let Some(o) = self.owners.get(&back) {
            return (back, Some(o));
        }
        let mine = |k: &ConnKey| self.local_ips.contains(&k.local);
        let near = |k: &ConnKey| classify(&k.local) != "public";
        let forward = match (mine(&fwd), mine(&back)) {
            (true, false) => true,
            (false, true) => false,
            _ => match (near(&fwd), near(&back)) {
                (true, false) => true,
                (false, true) => false,
                _ => (fwd.local, fwd.lport) <= (back.local, back.lport),
            },
        };
        (if forward { fwd } else { back }, None)
    }

    pub fn apply(
        &self,
        src: impl Read,
        dst: impl Write,
        progress: Option<&AtomicU64>,
    ) -> std::io::Result<Stats> {
        let mut blocks = Blocks::new(src, progress);
        let mut w = BufWriter::with_capacity(1 << 20, dst);
        let mut st = Stats::default();
        let mut ifaces: Vec<Iface> = Vec::new();
        let mut saw_header = false;
        let mut out = Vec::with_capacity(64 * 1024);
        while let Some(ty) = blocks.next()? {
            let body = &blocks.body;
            match ty {
                SHB => {
                    check_section(body)?;
                    saw_header = true;
                    ifaces.clear();
                    out.clear();
                    out.extend_from_slice(&body[..16]);
                    write_options(&mut out, &body[16..], Some(&self.comment));
                    write_block(&mut w, ty, &out)?;
                }
                IDB => {
                    if body.len() >= 2 {
                        ifaces.push(iface_of(body));
                    }
                    write_block(&mut w, ty, body)?;
                }
                EPB if body.len() >= 20 => {
                    self.frame(&Epb::parse(body, &ifaces)?, &mut st, &mut out, &mut w)?;
                }
                OBSOLETE_PACKET | SPB if self.only_group => {}
                _ => write_block(&mut w, ty, body)?,
            }
        }
        if !saw_header {
            return Err(no_header());
        }
        w.flush()?;
        Ok(st)
    }

    fn frame(
        &self,
        e: &Epb,
        st: &mut Stats,
        out: &mut Vec<u8>,
        w: &mut impl Write,
    ) -> std::io::Result<()> {
        st.packets += 1;
        let orig = e.origlen();
        let at = micros(e.body, e.iface);
        let (store, label) = match e.flow() {
            Some(f) => {
                let (key, owner) = self.key_of(&f);
                if self.only_group && !owner.is_some_and(|o| o.keep) {
                    return Ok(());
                }
                let slot = if st.flows.len() < MAX_FLOWS || st.flows.contains_key(&key) {
                    st.flows.entry(key).or_default()
                } else {
                    &mut st.loose
                };
                let store = self.compact.map_or(e.caplen, |c| {
                    if f.is_dns() || slot.stored + e.caplen as u64 <= c.flow_bytes {
                        e.caplen
                    } else {
                        e.caplen.min(f.payload.start + c.tail.min(f.payload.len()))
                    }
                });
                slot.add(orig, store as u64, at);
                (store, owner.and_then(|o| o.label.as_deref()))
            }
            None => {
                if self.only_group {
                    return Ok(());
                }
                let store = self
                    .compact
                    .map_or(e.caplen, |c| e.caplen.min(c.other_frame));
                st.loose.add(orig, store as u64, at);
                (store, None)
            }
        };
        st.kept += 1;
        st.total.add(orig, store as u64, at);
        if label.is_some() {
            st.labeled += 1;
        }
        if store < e.caplen {
            st.trimmed += 1;
        }
        if store == e.caplen && label.is_none() {
            return write_block(w, EPB, e.body);
        }
        e.rebuild(out, store, label);
        write_block(w, EPB, out)
    }

    /// Переписать файл на месте. При ошибке исходный дамп остается как был. Запись, в
    /// которой процессу не досталось ни одного пакета, не заменяет исходные данные:
    /// пустой файл нельзя отличить от сбоя привязки, а восстановить пакеты уже нечем.
    pub fn rewrite(&self, path: &Path, progress: Option<&AtomicU64>) -> std::io::Result<Stats> {
        let tmp = crate::paths::with_suffix(path, ".part");
        let src = File::open(path)?;
        let permissions = src.metadata()?.permissions();
        let dst = crate::paths::new_private_file(&tmp)?;
        let res = (|| {
            dst.set_permissions(permissions)?;
            let stats = self.apply(src, dst, progress)?;
            if self.only_group && stats.kept == 0 && stats.packets > 0 {
                return Err(std::io::Error::other(t!(
                    "no packet belongs to the process",
                    "ни один пакет не принадлежит процессу"
                )));
            }
            crate::paths::rename_retry(&tmp, path)?;
            Ok(stats)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res
    }
}

/// Куда попадают кадры при разбиении на части.
pub struct Split<'a> {
    pub plan: &'a Plan,
    /// Поток -> номер части в `names`.
    pub assign: HashMap<ConnKey, usize>,
    /// Имена файлов без расширения. Последнее - часть для всего остального.
    pub names: Vec<String>,
    /// После этого размера часть продолжается в следующем файле.
    pub max_file: u64,
}

/// Записанный файл части.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartFile {
    /// Номер части в `Split::names`.
    pub part: usize,
    pub file: String,
    pub packets: u64,
    pub stored: u64,
}

/// Открытый файл части. Заголовки секции дописываются перед первым кадром: файл должен
/// читаться сам по себе, а номера интерфейсов в кадрах относятся к текущей секции.
#[derive(Default)]
struct PartWriter {
    out: Option<BufWriter<File>>,
    volume: u32,
    section: u64,
    written_headers: usize,
    size: u64,
    index: usize,
}

impl Split<'_> {
    pub fn run(
        &self,
        src: impl Read,
        dir: &Path,
        progress: Option<&AtomicU64>,
    ) -> std::io::Result<Vec<PartFile>> {
        let mut blocks = Blocks::new(src, progress);
        let mut writers: Vec<PartWriter> = Vec::new();
        writers.resize_with(self.names.len(), PartWriter::default);
        let mut files: Vec<PartFile> = Vec::new();
        let mut ifaces: Vec<Iface> = Vec::new();
        let mut headers: Vec<Vec<u8>> = Vec::new();
        let mut section = 0u64;
        let other = self.names.len().saturating_sub(1);
        while let Some(ty) = blocks.next()? {
            let body = &blocks.body;
            match ty {
                SHB => {
                    check_section(body)?;
                    section += 1;
                    ifaces.clear();
                    headers.clear();
                    let mut raw = Vec::with_capacity(body.len() + 12);
                    write_block(&mut raw, ty, body)?;
                    headers.push(raw);
                }
                IDB => {
                    if body.len() >= 2 {
                        ifaces.push(iface_of(body));
                    }
                    let mut raw = Vec::with_capacity(body.len() + 12);
                    write_block(&mut raw, ty, body)?;
                    headers.push(raw);
                }
                EPB if body.len() >= 20 => {
                    if section == 0 {
                        return Err(no_header());
                    }
                    let e = Epb::parse(body, &ifaces)?;
                    let part = e
                        .flow()
                        .and_then(|f| self.assign.get(&self.plan.key_of(&f).0).copied())
                        .unwrap_or(other);
                    let size = 12 + body.len() as u64;
                    let w = &mut writers[part];
                    if w.out.is_none() || w.size >= self.max_file {
                        self.next_volume(w, part, dir, &mut files)?;
                    }
                    w.write_headers(section, &headers)?;
                    let out = w.out.as_mut().ok_or_else(no_header)?;
                    write_block(out, ty, body)?;
                    w.size += size;
                    let f = &mut files[w.index];
                    f.packets += 1;
                    f.stored += e.caplen as u64;
                }
                _ => {}
            }
        }
        for w in &mut writers {
            if let Some(out) = w.out.as_mut() {
                out.flush()?;
            }
        }
        Ok(files)
    }

    fn next_volume(
        &self,
        w: &mut PartWriter,
        part: usize,
        dir: &Path,
        files: &mut Vec<PartFile>,
    ) -> std::io::Result<()> {
        if let Some(out) = w.out.as_mut() {
            out.flush()?;
        }
        w.volume += 1;
        let name = match w.volume {
            1 => format!("{}.pcapng", self.names[part]),
            n => format!("{}-{n}.pcapng", self.names[part]),
        };
        let file = crate::paths::new_private_file(&dir.join(&name))?;
        w.out = Some(BufWriter::with_capacity(128 * 1024, file));
        w.section = 0;
        w.written_headers = 0;
        w.size = 0;
        w.index = files.len();
        files.push(PartFile {
            part,
            file: name,
            ..PartFile::default()
        });
        Ok(())
    }
}

impl PartWriter {
    fn write_headers(&mut self, section: u64, headers: &[Vec<u8>]) -> std::io::Result<()> {
        if self.section != section {
            self.section = section;
            self.written_headers = 0;
        }
        let out = self.out.as_mut().ok_or_else(no_header)?;
        for raw in &headers[self.written_headers..] {
            out.write_all(raw)?;
            self.size += raw.len() as u64;
        }
        self.written_headers = headers.len();
        Ok(())
    }
}

/// Подпись пакета: "cs2.exe [1234] -> api.steampowered.com".
pub fn label(pname: Option<&str>, pid: Option<i32>, domain: Option<&str>) -> Option<String> {
    let who = match (pname, pid) {
        (Some(n), Some(p)) => Some(format!("{n} [{p}]")),
        (Some(n), None) => Some(n.to_string()),
        (None, Some(p)) => Some(format!("[{p}]")),
        (None, None) => None,
    };
    match (who, domain) {
        (Some(w), Some(d)) => Some(format!("{w} -> {d}")),
        (Some(w), None) => Some(w),
        (None, Some(d)) => Some(format!("-> {d}")),
        (None, None) => None,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::sockets::Proto;
    use std::net::Ipv4Addr;

    pub fn udp_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        sized_udp_frame(src, sport, dst, dport, 0)
    }

    fn sized_udp_frame(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: usize,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&(28 + payload as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&(8 + payload as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.resize(f.len() + payload, 0xAB);
        f
    }

    fn epb_at(iface: u32, ticks: u64, f: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&iface.to_le_bytes());
        b.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        b.extend_from_slice(&(ticks as u32).to_le_bytes());
        b.extend_from_slice(&(f.len() as u32).to_le_bytes());
        b.extend_from_slice(&(f.len() as u32).to_le_bytes());
        b.extend_from_slice(f);
        b.resize(b.len().div_ceil(4) * 4, 0);
        b
    }

    fn section_header(out: &mut Vec<u8>) {
        let mut shb = Vec::new();
        shb.extend_from_slice(&MAGIC.to_le_bytes());
        shb.extend_from_slice(&[1, 0, 0, 0]);
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        write_block(out, SHB, &shb).unwrap();
    }

    pub fn file(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        section_header(&mut out);
        write_block(&mut out, IDB, &[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        for (i, f) in frames.iter().enumerate() {
            write_block(&mut out, EPB, &epb_at(0, 1_000_000 + i as u64, f)).unwrap();
        }
        out
    }

    /// Кадры файла: (длина в файле, исходная длина, комментарии).
    fn frames_of(data: &[u8]) -> Vec<(usize, u32, Vec<String>)> {
        let mut blocks = Blocks::new(data, None);
        let mut out = Vec::new();
        while let Some(ty) = blocks.next().unwrap() {
            if ty != EPB {
                continue;
            }
            let b = &blocks.body;
            let caplen = le32(b, 12) as usize;
            let mut at = 20 + caplen.div_ceil(4) * 4;
            let mut comments = Vec::new();
            while let Some(h) = b.get(at..at + 4) {
                let (code, len) = (le16(h, 0), le16(h, 2) as usize);
                if code == 0 {
                    break;
                }
                if code == OPT_COMMENT {
                    comments.push(String::from_utf8_lossy(&b[at + 4..at + 4 + len]).into_owned());
                }
                at += 4 + len.div_ceil(4) * 4;
            }
            out.push((caplen, le32(b, 16), comments));
        }
        out
    }

    fn key(lport: u16, rport: u16) -> ConnKey {
        ConnKey {
            proto: Proto::Udp,
            local: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            lport,
            remote: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            rport,
        }
    }

    fn plan(owners: HashMap<ConnKey, Owner>, only_group: bool) -> Plan {
        Plan {
            owners,
            only_group,
            compact: None,
            comment: "SocketTrail".into(),
            local_ips: HashSet::new(),
        }
    }

    #[test]
    fn labels_and_filters() {
        let me = [10, 0, 0, 2];
        let game = udp_frame(me, 40000, [1, 2, 3, 4], 27015);
        let reply = udp_frame([1, 2, 3, 4], 27015, me, 40000);
        let other = udp_frame(me, 40001, [5, 6, 7, 8], 443);
        // Общий сервер/CDN не дает неизвестному соединению владельца игры.
        let same_host = udp_frame(me, 40002, [1, 2, 3, 4], 27015);
        let src = file(&[game, reply, other, same_host]);

        let mut plan = plan(
            HashMap::from([(
                key(40000, 27015),
                Owner {
                    label: label(Some("cs2.exe"), Some(1234), Some("valve.net")),
                    keep: true,
                },
            )]),
            true,
        );

        let mut out = Vec::new();
        let st = plan.apply(&src[..], &mut out, None).unwrap();
        assert_eq!((st.packets, st.kept, st.labeled), (4, 2, 2));
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("cs2.exe [1234] -> valve.net"));

        let mut pk = Vec::new();
        pcap::PcapngReader::new().push(&out, &mut pk);
        assert_eq!(pk.len(), 2);

        plan.only_group = false;
        let mut all = Vec::new();
        let st = plan.apply(&src[..], &mut all, None).unwrap();
        assert_eq!((st.kept, st.labeled), (4, 2));
    }

    #[test]
    fn processing_twice_keeps_one_comment_and_the_same_frames() {
        let me = [10, 0, 0, 2];
        let src = file(&[udp_frame(me, 40000, [1, 2, 3, 4], 27015)]);
        let mut plan = plan(
            HashMap::from([(
                key(40000, 27015),
                Owner {
                    label: Some("first".into()),
                    keep: true,
                },
            )]),
            false,
        );
        let mut once = Vec::new();
        plan.apply(&src[..], &mut once, None).unwrap();
        plan.owners.get_mut(&key(40000, 27015)).unwrap().label = Some("second".into());
        let mut twice = Vec::new();
        plan.apply(&once[..], &mut twice, None).unwrap();
        let frames = frames_of(&twice);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].2, ["second"]);
        // Без новой подписи прежняя остается: карты соединений могло не сохраниться.
        plan.owners.clear();
        let mut kept = Vec::new();
        plan.apply(&twice[..], &mut kept, None).unwrap();
        assert_eq!(frames_of(&kept)[0].2, ["second"]);
        assert_eq!(
            String::from_utf8_lossy(&twice)
                .matches("SocketTrail")
                .count(),
            1
        );
    }

    #[test]
    fn compact_keeps_flow_start_headers_and_original_lengths() {
        let me = [10, 0, 0, 2];
        let far = [1, 2, 3, 4];
        let big = sized_udp_frame(me, 40000, far, 27015, 1000);
        let dns = sized_udp_frame(me, 40001, far, 53, 1000);
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.resize(400, 7);
        let frames: Vec<Vec<u8>> = vec![
            big.clone(),
            big.clone(),
            big.clone(),
            dns.clone(),
            dns.clone(),
            arp,
        ];
        let src = file(&frames);
        let mut plan = plan(HashMap::new(), false);
        plan.compact = Some(Compact {
            flow_bytes: 2 * big.len() as u64,
            tail: 16,
            other_frame: 128,
        });
        let mut out = Vec::new();
        let st = plan.apply(&src[..], &mut out, None).unwrap();
        assert_eq!((st.packets, st.kept), (6, 6));
        // 2 кадра в пределах бюджета, третий урезан до 14+20+8 заголовков и 16 байт.
        assert_eq!(st.trimmed, 2);
        let got = frames_of(&out);
        assert_eq!(got[0].0, big.len());
        assert_eq!(got[1].0, big.len());
        assert_eq!(got[2].0, 14 + 20 + 8 + 16);
        assert_eq!(got[2].1 as usize, big.len());
        // DNS хранится целиком, у прочих кадров срезается все после предела.
        assert_eq!(got[3].0, dns.len());
        assert_eq!(got[4].0, dns.len());
        assert_eq!(got[5].0, 128);
        assert_eq!(got[5].1, 400);
        assert_eq!(
            st.total.bytes,
            3 * big.len() as u64 + 2 * dns.len() as u64 + 400
        );

        // Урезанный файл по-прежнему разбирается и обрабатывается повторно без потерь.
        let mut packets = Vec::new();
        pcap::PcapngReader::new().push(&out, &mut packets);
        assert_eq!(packets.len(), 5);
        let mut again = Vec::new();
        let second = plan.apply(&out[..], &mut again, None).unwrap();
        assert_eq!(second.kept, 6);
        assert_eq!(second.total.bytes, st.total.bytes);
        assert_eq!(frames_of(&again), got);
    }

    #[test]
    fn flow_stats_count_both_directions_as_one_flow() {
        let me = [10, 0, 0, 2];
        let far = [1, 2, 3, 4];
        let src = file(&[
            udp_frame(me, 40000, far, 27015),
            udp_frame(far, 27015, me, 40000),
            udp_frame(me, 40001, far, 443),
        ]);
        let mut p = plan(HashMap::new(), false);
        p.local_ips.insert(IpAddr::V4(Ipv4Addr::from(me)));
        let st = p.apply(&src[..], Vec::new(), None).unwrap();
        assert_eq!(st.flows.len(), 2);
        let f = st.flows[&key(40000, 27015)];
        assert_eq!(f.packets, 2);
        assert_eq!((f.first_us, f.last_us), (1_000_000, 1_000_001));
    }

    #[test]
    fn timestamp_resolution_of_the_interface_is_respected() {
        for (res, units) in [
            (9u8, 1_000_000_000u64),
            (6, 1_000_000),
            (0x80 | 20, 1 << 20),
        ] {
            let mut idb = vec![1, 0, 0, 0, 0, 0, 0, 0];
            idb.extend_from_slice(&IF_TSRESOL.to_le_bytes());
            idb.extend_from_slice(&1u16.to_le_bytes());
            idb.extend_from_slice(&[res, 0, 0, 0]);
            idb.extend_from_slice(&[0u8; 4]);
            let iface = iface_of(&idb);
            assert_eq!(iface.units, units);
            let frame = udp_frame([10, 0, 0, 2], 40000, [1, 2, 3, 4], 27015);
            let body = epb_at(0, units * 5, &frame);
            assert_eq!(micros(&body, iface), 5_000_000);
        }
    }

    fn split_of<'a>(
        p: &'a Plan,
        assign: &[(ConnKey, usize)],
        names: &[&str],
        max_file: u64,
    ) -> Split<'a> {
        Split {
            plan: p,
            assign: assign.iter().copied().collect(),
            names: names.iter().map(|s| s.to_string()).collect(),
            max_file,
        }
    }

    #[test]
    fn split_writes_readable_parts_and_rotates_large_ones() {
        let dir = crate::paths::TestDir::new("split");
        let me = [10, 0, 0, 2];
        let far = [1, 2, 3, 4];
        let mut frames = Vec::new();
        for _ in 0..5 {
            frames.push(sized_udp_frame(me, 40000, far, 27015, 200));
            frames.push(sized_udp_frame(far, 27015, me, 40000, 200));
        }
        frames.push(udp_frame(me, 40001, [5, 6, 7, 8], 443));
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.resize(60, 0);
        frames.push(arp);
        let src = file(&frames);

        let mut p = plan(HashMap::new(), false);
        p.local_ips.insert(IpAddr::V4(Ipv4Addr::from(me)));
        // Первая часть переходит в новый файл после каждых 1000 байт.
        let split = split_of(
            &p,
            &[(key(40000, 27015), 0)],
            &["domain-example.com", "other"],
            1000,
        );
        let files = split.run(&src[..], &dir.0, None).unwrap();

        let names: Vec<&str> = files.iter().map(|f| f.file.as_str()).collect();
        assert!(names.contains(&"domain-example.com.pcapng"), "{names:?}");
        assert!(names.contains(&"domain-example.com-2.pcapng"), "{names:?}");
        assert!(names.contains(&"other.pcapng"), "{names:?}");
        assert_eq!(files.iter().map(|f| f.packets).sum::<u64>(), 12);
        let mut own = 0;
        for f in &files {
            let data = std::fs::read(dir.0.join(&f.file)).unwrap();
            let got = frames_of(&data);
            assert_eq!(got.len() as u64, f.packets, "{}", f.file);
            // Каждый файл читается сам по себе: у него есть свои заголовки.
            let mut pk = Vec::new();
            pcap::PcapngReader::new().push(&data, &mut pk);
            if f.part == 0 {
                own += pk.len();
                assert!(pk.iter().all(|p| p.sport == 40000 || p.dport == 40000));
            }
        }
        assert_eq!(own, 10);
    }

    #[test]
    fn empty_capture_is_not_a_successful_rewrite() {
        let dir = crate::paths::TestDir::new("empty-capture");
        let path = dir.0.join("demo.pcapng");
        std::fs::write(&path, []).unwrap();
        assert!(plan(HashMap::new(), true).rewrite(&path, None).is_err());
        assert_eq!(std::fs::read(path).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn filter_that_keeps_nothing_leaves_the_original_capture() {
        let dir = crate::paths::TestDir::new("nothing-kept");
        let path = dir.0.join("demo.pcapng");
        let data = file(&[udp_frame([10, 0, 0, 2], 40000, [1, 2, 3, 4], 27015)]);
        std::fs::write(&path, &data).unwrap();
        assert!(plan(HashMap::new(), true).rewrite(&path, None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(!dir.0.join("demo.pcapng.part").exists());
    }

    #[test]
    fn existing_temporary_file_is_never_overwritten_or_deleted() {
        let dir = crate::paths::TestDir::new("existing-part");
        let path = dir.0.join("demo.pcapng");
        let part = dir.0.join("demo.pcapng.part");
        let data = file(&[]);
        std::fs::write(&path, &data).unwrap();
        std::fs::write(&part, b"previous attempt").unwrap();
        assert!(plan(HashMap::new(), false).rewrite(&path, None).is_err());
        assert_eq!(std::fs::read(path).unwrap(), data);
        assert_eq!(std::fs::read(part).unwrap(), b"previous attempt");
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_keeps_private_capture_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::paths::TestDir::new("capture-permissions");
        let path = dir.0.join("demo.pcapng");
        std::fs::write(&path, file(&[])).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        plan(HashMap::new(), false).rewrite(&path, None).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn truncated_block_and_mismatched_trailer_preserve_original() {
        let dir = crate::paths::TestDir::new("truncated-capture");
        let path = dir.0.join("demo.pcapng");
        let header = file(&[]);
        let frame = udp_frame([192, 0, 2, 1], 40000, [198, 51, 100, 1], 443);
        let complete = file(&[frame]);
        let plan = plan(HashMap::new(), false);
        for n in header.len() + 1..complete.len() {
            let original = &complete[..n];
            std::fs::write(&path, original).unwrap();
            assert!(plan.rewrite(&path, None).is_err(), "prefix {n}");
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert!(!path.with_extension("pcapng.part").exists());
        }
        let mut bad = complete;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        assert!(plan.rewrite(&path, None).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bad);
    }

    #[test]
    fn filtered_output_does_not_leak_packets_in_obsolete_blocks() {
        let mut src = file(&[]);
        write_block(&mut src, SPB, &[60, 0, 0, 0, 1, 2, 3, 4]).unwrap();
        let mut out = Vec::new();
        plan(HashMap::new(), true)
            .apply(&src[..], &mut out, None)
            .unwrap();
        assert_eq!(out.len(), {
            let mut only_headers = Vec::new();
            plan(HashMap::new(), true)
                .apply(&file(&[])[..], &mut only_headers, None)
                .unwrap();
            only_headers.len()
        });
    }
}
