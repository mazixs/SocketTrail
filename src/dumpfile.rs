//! Файлы записи: постобработка дампа, сводка, старый формат и список для окна.
//!
//! - `<stem>.pcapng` - сам дамп;
//! - `<stem>.json` - сводка: что записано, какие домены и подсети, где части;
//! - `<stem>.connections.jsonl` - соединения, по строке на каждое;
//! - `<stem>.parts/` - части большого дампа: домены, подсети и все остальное.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::annotate::{self, Compact, FlowStats, Owner, PartFile, Plan, Split, Stats};
use crate::paths;
use crate::query::{base_domain, subnet_of};
use crate::sockets::Proto;
use crate::state::{Conn, ConnKey};

const FORMAT: u32 = 2;
/// Больше этого размера файл неудобно открывать целиком, режем на части.
const SPLIT_ABOVE: u64 = 64 << 20;
/// Отдельный файл получают самые объемные группы, остальное идет в other.
const MAX_PARTS: usize = 64;
const MAX_PART_FILE: u64 = 256 << 20;
/// Предел строк в сводке: она должна открываться обычным редактором.
const TOP: usize = 200;
const TOP_CHILDREN: usize = 100;
const LIST_LIMIT: usize = 50;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    /// Только если файл получился большим.
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    pub compact: bool,
    pub split: SplitMode,
}

/// Строка карты соединений: и в новом формате, и в `conns` прежнего.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnRecord {
    pub proto: String,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub pid: Option<i32>,
    #[serde(default)]
    pub pname: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub ptr: Option<String>,
    #[serde(default)]
    pub asn: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub first_seen: u64,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_pkts: u64,
    #[serde(default)]
    pub rx_pkts: u64,
    #[serde(default)]
    pub from_packets_only: bool,
    #[serde(default)]
    pub closed: bool,
    #[serde(default)]
    pub scope: String,
    /// Соединение принадлежит записанному процессу. В прежнем формате в карту попадали
    /// только такие, если запись шла по процессу.
    #[serde(default = "yes")]
    pub owned: bool,
    /// Посчитано по самому файлу.
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub stored: u64,
    #[serde(default)]
    pub first_us: u64,
    #[serde(default)]
    pub last_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
}

fn yes() -> bool {
    true
}

impl ConnRecord {
    pub fn new(c: &Conn, owned: bool) -> Self {
        Self {
            proto: c.proto.to_string(),
            local: c.local,
            lport: c.lport,
            remote: c.remote,
            rport: c.rport,
            state: c.state.to_string(),
            pid: c.pid,
            pname: c.pname.clone(),
            domain: c.domain.clone(),
            sni: c.sni.clone(),
            ptr: c.ptr.clone(),
            asn: c.asn.clone(),
            owner: c.owner.clone(),
            first_seen: c.first_seen,
            last_seen: c.last_seen,
            tx_bytes: c.tx_bytes,
            rx_bytes: c.rx_bytes,
            tx_pkts: c.tx_pkts,
            rx_pkts: c.rx_pkts,
            from_packets_only: c.from_packets_only,
            closed: c.closed,
            scope: c.scope.to_string(),
            owned,
            packets: 0,
            bytes: 0,
            stored: 0,
            first_us: 0,
            last_us: 0,
            part: None,
        }
    }

    /// Поток из файла, которого не было в карте: опрос сокетов его не застал.
    fn from_flow(k: &ConnKey, f: &FlowStats) -> Self {
        Self {
            proto: k.proto.as_str().to_string(),
            local: k.local,
            lport: k.lport,
            remote: k.remote,
            rport: k.rport,
            state: String::new(),
            pid: None,
            pname: None,
            domain: None,
            sni: None,
            ptr: None,
            asn: None,
            owner: None,
            first_seen: f.first_us / 1000,
            last_seen: f.last_us / 1000,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_pkts: 0,
            rx_pkts: 0,
            from_packets_only: true,
            closed: true,
            scope: crate::state::classify(&k.remote).to_string(),
            owned: false,
            packets: f.packets,
            bytes: f.bytes,
            stored: f.stored,
            first_us: f.first_us,
            last_us: f.last_us,
            part: None,
        }
    }

    fn key(&self) -> Option<ConnKey> {
        let proto = match self.proto.as_str() {
            "TCP" => Proto::Tcp,
            "UDP" => Proto::Udp,
            _ => return None,
        };
        Some(ConnKey {
            proto,
            local: self.local,
            lport: self.lport,
            remote: self.remote,
            rport: self.rport,
        })
    }

    /// Объем для сводки: по файлу, а если файл не обработан - по живому учету.
    fn weight(&self) -> u64 {
        if self.bytes > 0 {
            self.bytes
        } else {
            self.tx_bytes + self.rx_bytes
        }
    }

    fn packet_count(&self) -> u64 {
        if self.packets > 0 {
            self.packets
        } else {
            self.tx_pkts + self.rx_pkts
        }
    }

    fn apply_flow(&mut self, f: &FlowStats) {
        self.packets = f.packets;
        self.bytes = f.bytes;
        self.stored = f.stored;
        self.first_us = f.first_us;
        self.last_us = f.last_us;
    }
}

/// Все, что известно о записи к моменту обработки файла.
pub struct Recording {
    pub process: Value,
    pub group_pids: Vec<i32>,
    pub captured_from: Value,
    pub captured_until: Value,
    /// Оставить в файле только трафик процесса.
    pub only_process: bool,
    /// Запись задумана как дамп процесса. Признак сохраняется и у неотфильтрованного
    /// файла, чтобы его можно было отфильтровать позже.
    pub requested: bool,
    pub comment: String,
    /// Карта соединений: то, что описывается рядом с файлом.
    pub conns: Vec<ConnRecord>,
    /// Подписи и отбор. Шире карты: сюда входят и собственные соединения SocketTrail.
    pub owners: HashMap<ConnKey, Owner>,
    pub local_ips: HashSet<IpAddr>,
    pub warnings: Vec<String>,
    pub capture_complete: bool,
    pub capture: Value,
    /// Обработка уже записанного файла: при сбое прежняя сводка остается.
    pub reprocess: bool,
    pub previous_packets: Value,
    /// Файл уже сокращен: вырезанные данные не возвращаются, признак сохраняется.
    pub already_compact: bool,
}

/// Подпись секции файла: она видна в свойствах захвата в Wireshark.
pub fn section_comment(who: Option<&str>, only: bool) -> String {
    match (who, only) {
        (Some(w), true) => t!(
            "SocketTrail: only traffic of {w} and its child processes",
            "SocketTrail: только трафик {w} и его дочерних процессов"
        ),
        (Some(w), false) => t!(
            "SocketTrail: all traffic of the computer, selected {w}",
            "SocketTrail: весь трафик компьютера, выбран {w}"
        ),
        (None, _) => t!(
            "SocketTrail: all traffic of the computer",
            "SocketTrail: весь трафик компьютера"
        ),
    }
}

/// Сколько уже обработано: большой файл переписывается десятки секунд.
#[derive(Debug, Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
}

impl Progress {
    fn begin(&self, total: u64) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    pub fn percent(&self) -> Option<u8> {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }
        let done = self.done.load(Ordering::Relaxed).min(total);
        Some((done * 100 / total) as u8)
    }
}

#[derive(Debug, Default)]
pub struct Processed {
    pub sidecar: Option<String>,
    pub unfiltered: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub parts: usize,
}

pub fn sidecar_path(path: &Path) -> PathBuf {
    path.with_extension("json")
}

fn connections_path(path: &Path) -> PathBuf {
    path.with_extension("connections.jsonl")
}

fn parts_dir(path: &Path) -> PathBuf {
    path.with_extension("parts")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Группа разбиения: домен, а если имени нет - подсеть.
fn group_of(r: &ConnRecord) -> (&'static str, String) {
    match r.domain.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => ("domain", base_domain(d)),
        None => ("subnet", subnet_of(&r.remote).to_string()),
    }
}

/// Имя файла части. Домен приходит из сети: кроме букв и цифр ничего не остается,
/// поэтому выйти за пределы каталога частей он не может.
fn part_stem(kind: &str, label: &str) -> String {
    let mut safe = String::new();
    for c in label.chars() {
        let c = if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
            c
        } else {
            '-'
        };
        if safe.len() + c.len_utf8() > 96 {
            break;
        }
        safe.push(c);
    }
    format!("{kind}-{}", safe.trim_matches(['.', '-']))
}

#[derive(Default)]
struct Tally {
    connections: u64,
    packets: u64,
    bytes: u64,
    children: BTreeMap<String, u64>,
}

fn tally_json(map: BTreeMap<String, Tally>, key: &str, kids: &str) -> Value {
    let mut rows: Vec<(String, Tally)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| a.0.cmp(&b.0)));
    let rows: Vec<Value> = rows
        .into_iter()
        .take(TOP)
        .map(|(name, t)| {
            let mut children: Vec<(String, u64)> = t.children.into_iter().collect();
            children.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            children.truncate(TOP_CHILDREN);
            let children: Vec<String> = children.into_iter().map(|(n, _)| n).collect();
            json!({
                key: name,
                "connections": t.connections,
                "packets": t.packets,
                "bytes": t.bytes,
                kids: children,
            })
        })
        .collect();
    Value::Array(rows)
}

/// Домены с поддоменами и подсети с адресами, самые объемные сверху.
fn summarize(rows: &[ConnRecord]) -> (Value, Value) {
    let mut domains: BTreeMap<String, Tally> = BTreeMap::new();
    let mut subnets: BTreeMap<String, Tally> = BTreeMap::new();
    for r in rows {
        let (bytes, packets) = (r.weight(), r.packet_count());
        if let Some(name) = r.domain.as_deref().filter(|d| !d.is_empty()) {
            let t = domains.entry(base_domain(name)).or_default();
            t.connections += 1;
            t.packets += packets;
            t.bytes += bytes;
            *t.children.entry(name.to_ascii_lowercase()).or_default() += bytes;
        }
        let t = subnets.entry(subnet_of(&r.remote).to_string()).or_default();
        t.connections += 1;
        t.packets += packets;
        t.bytes += bytes;
        *t.children.entry(r.remote.to_string()).or_default() += bytes;
    }
    (
        tally_json(domains, "domain", "names"),
        tally_json(subnets, "subnet", "addresses"),
    )
}

/// Самые объемные группы получают свой файл, остальное идет в часть other. Строкам карты
/// проставляется имя части.
fn plan_parts<'a>(plan: &'a Plan, rows: &mut [ConnRecord]) -> Split<'a> {
    let mut totals: HashMap<(&'static str, String), u64> = HashMap::new();
    for r in rows.iter().filter(|r| r.stored > 0) {
        *totals.entry(group_of(r)).or_default() += r.stored;
    }
    let mut ranked: Vec<((&'static str, String), u64)> = totals.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut names: Vec<String> = Vec::new();
    let mut used: HashSet<String> = HashSet::from(["other".to_string()]);
    let mut index: HashMap<(&'static str, String), usize> = HashMap::new();
    for (group, _) in ranked.into_iter().take(MAX_PARTS) {
        let stem = part_stem(group.0, &group.1);
        let mut name = stem.clone();
        let mut n = 1;
        while !used.insert(name.to_lowercase()) {
            n += 1;
            name = format!("{stem}_{n}");
        }
        index.insert(group, names.len());
        names.push(name);
    }
    names.push("other".to_string());

    let mut assign = HashMap::new();
    for r in rows.iter_mut() {
        if r.packets == 0 {
            continue;
        }
        match (r.key(), index.get(&group_of(r))) {
            (Some(key), Some(&part)) => {
                assign.insert(key, part);
                r.part = Some(names[part].clone());
            }
            _ => r.part = Some("other".to_string()),
        }
    }
    Split {
        plan,
        assign,
        names,
        max_file: MAX_PART_FILE,
    }
}

/// Прежние части удаляются только как файлы дампов: посторонние файлы остаются на месте,
/// а каталог с ними не удалится и обработка сообщит об этом.
fn remove_parts(dir: &Path) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "pcapng") {
            std::fs::remove_file(path)?;
        }
    }
    std::fs::remove_dir(dir)
}

fn write_parts(
    path: &Path,
    split: &Split,
    progress: &Progress,
) -> std::io::Result<(PathBuf, Vec<PartFile>)> {
    let dir = parts_dir(path);
    let tmp = paths::with_suffix(&dir, ".tmp");
    remove_parts(&tmp)?;
    std::fs::create_dir(&tmp)?;
    let done = split.run(File::open(path)?, &tmp, Some(&progress.done));
    let finished = done.and_then(|files| {
        remove_parts(&dir)?;
        paths::rename_retry(&tmp, &dir)?;
        Ok(files)
    });
    match finished {
        Ok(files) => Ok((dir, files)),
        Err(e) => {
            let _ = remove_parts(&tmp);
            Err(e)
        }
    }
}

fn write_connections(path: &Path, rows: &[ConnRecord]) -> std::io::Result<()> {
    let tmp = paths::with_suffix(path, ".tmp");
    let _ = std::fs::remove_file(&tmp);
    let written = (|| {
        let mut w = BufWriter::new(paths::new_private_file(&tmp)?);
        for r in rows {
            serde_json::to_writer(&mut w, r)?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        drop(w);
        paths::rename_retry(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

fn merge_flows(conns: Vec<ConnRecord>, plan: &Plan, st: &Stats) -> Vec<ConnRecord> {
    let mut rows = conns;
    for r in &mut rows {
        if let Some(f) = r.key().and_then(|k| st.flows.get(&k)) {
            r.apply_flow(f);
        }
    }
    rows.extend(
        st.flows
            .iter()
            .filter(|(k, _)| !plan.owners.contains_key(k))
            .map(|(k, f)| ConnRecord::from_flow(k, f)),
    );
    rows
}

/// Постобработка файла. Отбор выполняется всегда, в том числе при потерях во время
/// записи: неизвестное соединение и так исключается, поэтому потери могут сделать файл
/// только неполным, но не перемешают в него чужой трафик. Они становятся предупреждением.
/// Ошибка - только когда файл не удалось переписать или сохранить сводку.
pub fn process(path: &Path, mut rec: Recording, opts: Options, progress: &Progress) -> Processed {
    let plan = Plan {
        owners: std::mem::take(&mut rec.owners),
        only_group: rec.only_process,
        compact: opts.compact.then(Compact::default),
        comment: rec.comment.clone(),
        local_ips: std::mem::take(&mut rec.local_ips),
    };
    let mut out = Processed::default();
    let mut warnings = std::mem::take(&mut rec.warnings);

    let input = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    progress.begin(input);
    let stats = match plan.rewrite(path, Some(&progress.done)) {
        Ok(st) => Some(st),
        Err(e) => {
            out.errors.push(if rec.only_process {
                t!(
                    "Filtering failed; the file contains unfiltered traffic: {e}",
                    "Фильтрация не выполнена; файл содержит нефильтрованный трафик: {e}"
                )
            } else {
                t!(
                    "Dump processing failed: {e}",
                    "Обработка дампа не выполнена: {e}"
                )
            });
            None
        }
    };
    let filtered = stats.is_some();
    out.unfiltered = rec.only_process && !filtered;
    if rec.reprocess && !filtered {
        out.warnings = warnings;
        return out;
    }

    let mut rows = match &stats {
        Some(st) => merge_flows(std::mem::take(&mut rec.conns), &plan, st),
        None => std::mem::take(&mut rec.conns),
    };

    let mut parts_info = Value::Null;
    if let Some(st) = &stats {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let wanted = match opts.split {
            SplitMode::Always => true,
            SplitMode::Auto => size > SPLIT_ABOVE,
            SplitMode::Never => false,
        };
        if wanted && st.kept > 0 {
            progress.total.fetch_add(size, Ordering::Relaxed);
            let split = plan_parts(&plan, &mut rows);
            match write_parts(path, &split, progress) {
                Ok((dir, files)) => {
                    out.parts = files.len();
                    let groups: Vec<Value> = files
                        .iter()
                        .map(|f| json!({"file": f.file, "packets": f.packets, "stored": f.stored}))
                        .collect();
                    parts_info = json!({"dir": dir.display().to_string(), "files": groups});
                }
                Err(e) => {
                    for r in &mut rows {
                        r.part = None;
                    }
                    warnings.push(t!(
                        "The dump was not split into parts: {e}",
                        "Дамп не разбит на части: {e}"
                    ));
                }
            }
        } else if let Err(e) = remove_parts(&parts_dir(path)) {
            warnings.push(t!(
                "Old parts of the dump remain: {e}",
                "Остались прежние части дампа: {e}"
            ));
        }
    }

    rows.sort_by(|a, b| {
        b.weight()
            .cmp(&a.weight())
            .then_with(|| b.first_seen.cmp(&a.first_seen))
            .then_with(|| (a.remote, a.rport, a.lport).cmp(&(b.remote, b.rport, b.lport)))
    });
    let map_path = connections_path(path);
    let mut connections = json!({
        "file": file_name(&map_path),
        "total": rows.len(),
        "owned": rows.iter().filter(|r| r.owned).count(),
    });
    if let Err(e) = write_connections(&map_path, &rows) {
        connections = Value::Null;
        out.errors.push(t!(
            "Connection map was not saved: {e}",
            "Карта соединений не сохранена: {e}"
        ));
    }

    let (domains, subnets) = summarize(&rows);
    let mut info = json!({
        "format": FORMAT,
        "dump": path.display().to_string(),
        "captured_from": rec.captured_from,
        "captured_until": rec.captured_until,
        "only_process": rec.only_process && filtered,
        "requested_only_process": rec.requested || rec.only_process,
        "process": rec.process,
        "group_pids": rec.group_pids,
        "capture": rec.capture,
        "processing": {
            "ok": filtered,
            "capture_complete": rec.capture_complete,
            "compact": opts.compact || rec.already_compact,
            "warnings": warnings,
            "errors": out.errors,
        },
        "connections": connections,
        "domains": domains,
        "subnets": subnets,
        "parts": parts_info,
    });
    if let Some(st) = &stats {
        let total = st
            .packets
            .max(rec.previous_packets["total"].as_u64().unwrap_or(0));
        info["packets"] = json!({
            "total": total,
            "kept": st.kept,
            "labeled": st.labeled,
            "trimmed": st.trimmed,
            "bytes": st.total.bytes,
            "stored": st.total.stored,
            "first_us": st.total.first_us,
            "last_us": st.total.last_us,
        });
    }
    let sidecar = sidecar_path(path);
    match serde_json::to_vec_pretty(&info)
        .map_err(std::io::Error::other)
        .and_then(|bytes| paths::write_replace(&sidecar, &bytes))
    {
        Ok(()) => out.sidecar = Some(sidecar.display().to_string()),
        Err(e) => out
            .errors
            .push(t!("Summary was not saved: {e}", "Сводка не сохранена: {e}")),
    }
    out.warnings = warnings;
    out
}

fn read_sidecar(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(sidecar_path(path)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn read_connections(path: &Path) -> Option<Vec<ConnRecord>> {
    let file = File::open(connections_path(path)).ok()?;
    let mut rows = Vec::new();
    for line in BufReader::new(file).lines() {
        if let Ok(r) = serde_json::from_str(&line.ok()?) {
            rows.push(r);
        }
    }
    Some(rows)
}

/// Карта из `conns` прежнего формата: испорченная строка не мешает остальным.
fn old_conns(info: &Value) -> Vec<ConnRecord> {
    info["conns"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Сведения об уже записанном файле для повторной обработки. Без `filter` состав файла
/// не меняется: сокращение и разбиение сами по себе трафик не отбирают. Без карты
/// соединений отбирать не по чему, такой запрос отклоняется.
pub fn load(path: &Path, filter: Option<bool>) -> std::io::Result<Recording> {
    let info = read_sidecar(path).unwrap_or(Value::Null);
    let conns = read_connections(path).unwrap_or_else(|| old_conns(&info));
    let filtered = info["only_process"].as_bool().unwrap_or(false);
    let requested = info["requested_only_process"].as_bool().unwrap_or(filtered);
    let only_process = filter.unwrap_or(filtered);
    let owned = conns.iter().filter(|r| r.owned).count();
    if only_process && owned == 0 {
        return Err(std::io::Error::other(t!(
            "There is no connection map of the process, nothing to filter by",
            "Нет карты соединений процесса, отбирать не по чему"
        )));
    }
    let process = info["process"].clone();
    let who = process["name"]
        .as_str()
        .map(|n| format!("{n} [{}]", process["pid"]));
    // Адреса компьютера известны из таблицы соединений: они нужны потокам, которых в ней нет.
    // Строки, восстановленные из самого файла, состояния не имеют и адрес не доказывают.
    let local_ips = conns
        .iter()
        .filter(|r| !r.state.is_empty())
        .map(|r| r.local)
        .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
        .collect();
    let mut owners = HashMap::with_capacity(conns.len());
    for r in &conns {
        if let Some(key) = r.key() {
            owners.insert(
                key,
                Owner {
                    label: annotate::label(r.pname.as_deref(), r.pid, r.domain.as_deref()),
                    keep: r.owned,
                },
            );
        }
    }
    Ok(Recording {
        comment: section_comment(who.as_deref(), only_process),
        group_pids: info["group_pids"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|p| p.as_i64())
                    .map(|p| p as i32)
                    .collect()
            })
            .unwrap_or_default(),
        captured_from: info["captured_from"].clone(),
        captured_until: info["captured_until"].clone(),
        capture_complete: info["processing"]["capture_complete"]
            .as_bool()
            .unwrap_or(true),
        capture: info["capture"].clone(),
        warnings: info["processing"]["warnings"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|w| w.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        previous_packets: info["packets"].clone(),
        already_compact: info["processing"]["compact"].as_bool().unwrap_or(false),
        process,
        only_process,
        requested,
        conns,
        owners,
        local_ips,
        reprocess: true,
    })
}

/// Файл дампа по имени из запроса: только сам файл в каталоге дампов, без путей и ссылок.
pub fn resolve(dir: &Path, name: &str) -> std::io::Result<PathBuf> {
    let bad = name.is_empty()
        || name.starts_with('.')
        || !name.ends_with(".pcapng")
        || name.contains(['/', '\\', ':', '\0']);
    if bad {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            t!("Invalid dump name", "Недопустимое имя дампа"),
        ));
    }
    let path = dir.join(name);
    if !std::fs::symlink_metadata(&path)?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            t!("Not a dump file", "Это не файл дампа"),
        ));
    }
    Ok(path)
}

/// Состояние файла для списка в окне.
fn status_of(info: &Value) -> &'static str {
    if info.is_null() {
        "unknown"
    } else if info["only_process"].as_bool().unwrap_or(false) {
        "filtered"
    } else if info["requested_only_process"].as_bool().unwrap_or(false) {
        "unfiltered"
    } else {
        "host"
    }
}

pub fn list(dir: &Path) -> Vec<Value> {
    let mut files: Vec<(PathBuf, u64, u64)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let path = e.path();
            if !path.extension().is_some_and(|x| x == "pcapng") {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            files.push((path, meta.len(), mtime));
        }
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.2));
    files.truncate(LIST_LIMIT);
    files
        .into_iter()
        .map(|(path, size, mtime)| {
            let info = read_sidecar(&path).unwrap_or(Value::Null);
            let warnings = info["processing"]["warnings"]
                .as_array()
                .map_or(0, Vec::len);
            let failed = info["processing"]["ok"].as_bool() == Some(false);
            json!({
                "name": file_name(&path),
                "size": size,
                "mtime": mtime,
                "status": status_of(&info),
                "format": info["format"].as_u64().unwrap_or(1),
                "process": info["process"]["name"],
                "compact": info["processing"]["compact"].as_bool().unwrap_or(false),
                "parts": info["parts"]["files"].as_array().map_or(0, Vec::len),
                "packets": info["packets"],
                "warnings": warnings,
                "failed": failed,
                "summary": !info.is_null(),
                "can_filter": info["requested_only_process"].as_bool().unwrap_or(false)
                    && !info["only_process"].as_bool().unwrap_or(false),
            })
        })
        .collect()
}

/// Сводка для окна. У прежнего формата она считается из его карты соединений.
pub fn summary(path: &Path) -> std::io::Result<Value> {
    let bytes = std::fs::read(sidecar_path(path))?;
    let mut info: Value = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    if info.get("format").is_none() {
        let rows = old_conns(&info);
        let (domains, subnets) = summarize(&rows);
        info["domains"] = domains;
        info["subnets"] = subnets;
        info["connections"] = json!({"total": rows.len(), "owned": rows.len()});
        if let Some(o) = info.as_object_mut() {
            o.remove("conns");
        }
    }
    Ok(info)
}

/// Каталог для кнопки "открыть": части, если они есть, иначе сама папка дампов.
pub fn reveal_target(path: &Path) -> Option<PathBuf> {
    let dir = parts_dir(path);
    dir.is_dir().then_some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annotate::tests::{file, udp_frame};
    use crate::paths::TestDir;
    use std::net::Ipv4Addr;

    fn key(lport: u16, remote: [u8; 4], rport: u16) -> ConnKey {
        ConnKey {
            proto: Proto::Udp,
            local: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            lport,
            remote: IpAddr::V4(Ipv4Addr::from(remote)),
            rport,
        }
    }

    fn record(k: &ConnKey, domain: Option<&str>, owned: bool) -> ConnRecord {
        ConnRecord {
            proto: "UDP".into(),
            local: k.local,
            lport: k.lport,
            remote: k.remote,
            rport: k.rport,
            state: "ACTIVE".into(),
            pid: Some(100),
            pname: Some("DemoGame.exe".into()),
            domain: domain.map(str::to_string),
            sni: None,
            ptr: None,
            asn: None,
            owner: None,
            first_seen: 1,
            last_seen: 2,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_pkts: 0,
            rx_pkts: 0,
            from_packets_only: false,
            closed: false,
            scope: "public".into(),
            owned,
            packets: 0,
            bytes: 0,
            stored: 0,
            first_us: 0,
            last_us: 0,
            part: None,
        }
    }

    fn recording(conns: Vec<ConnRecord>, only: bool) -> Recording {
        let owners = conns
            .iter()
            .map(|r| {
                (
                    r.key().unwrap(),
                    Owner {
                        label: annotate::label(r.pname.as_deref(), r.pid, r.domain.as_deref()),
                        keep: r.owned,
                    },
                )
            })
            .collect();
        Recording {
            process: json!({"pid": 100, "name": "DemoGame.exe", "cmdline": "DemoGame.exe"}),
            group_pids: vec![100],
            captured_from: json!("2026-01-01 10:00:00"),
            captured_until: json!("2026-01-01 10:30:00"),
            only_process: only,
            requested: only,
            comment: "demo".into(),
            conns,
            owners,
            local_ips: HashSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
            warnings: Vec::new(),
            capture_complete: true,
            capture: Value::Null,
            reprocess: false,
            previous_packets: Value::Null,
            already_compact: false,
        }
    }

    fn sidecar(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(sidecar_path(path)).unwrap()).unwrap()
    }

    fn sample(dir: &TestDir) -> (PathBuf, Vec<ConnRecord>) {
        let path = dir.0.join("demo.pcapng");
        let me = [192, 0, 2, 10];
        let game = key(40000, [198, 51, 100, 20], 27015);
        let other = key(40001, [203, 0, 113, 5], 443);
        std::fs::write(
            &path,
            file(&[
                udp_frame(me, 40000, [198, 51, 100, 20], 27015),
                udp_frame([198, 51, 100, 20], 27015, me, 40000),
                udp_frame(me, 40001, [203, 0, 113, 5], 443),
            ]),
        )
        .unwrap();
        (
            path,
            vec![
                record(&game, Some("api.example.com"), true),
                record(&other, None, false),
            ],
        )
    }

    #[test]
    fn losses_during_recording_only_warn_and_the_file_is_still_filtered() {
        let dir = TestDir::new("losses");
        let (path, conns) = sample(&dir);
        let mut rec = recording(conns, true);
        rec.capture_complete = false;
        rec.warnings.push("packets were lost".into());
        let done = process(&path, rec, Options::default(), &Progress::default());
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert!(!done.unfiltered);
        assert_eq!(done.warnings, ["packets were lost"]);
        let info = sidecar(&path);
        assert_eq!(info["only_process"], true);
        assert_eq!(info["processing"]["ok"], true);
        assert_eq!(info["processing"]["capture_complete"], false);
        assert_eq!(info["packets"]["total"], 3);
        assert_eq!(info["packets"]["kept"], 2);
    }

    #[test]
    fn summary_groups_domains_and_subnets_and_the_map_counts_the_file() {
        let dir = TestDir::new("summary");
        let (path, conns) = sample(&dir);
        process(
            &path,
            recording(conns, false),
            Options::default(),
            &Progress::default(),
        );
        let info = sidecar(&path);
        assert_eq!(info["format"], FORMAT);
        assert_eq!(info["only_process"], false);
        assert_eq!(info["domains"][0]["domain"], "example.com");
        assert_eq!(info["domains"][0]["names"][0], "api.example.com");
        let subnets: Vec<&str> = info["subnets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["subnet"].as_str().unwrap())
            .collect();
        assert!(subnets.contains(&"198.51.100.0/24"));
        assert!(subnets.contains(&"203.0.113.0/24"));
        assert_eq!(info["connections"]["total"], 2);

        let rows = read_connections(&path).unwrap();
        let game = rows.iter().find(|r| r.rport == 27015).unwrap();
        assert_eq!(game.packets, 2);
        assert!(game.owned);
        assert!(game.bytes > 0 && game.stored == game.bytes);
    }

    #[test]
    fn flows_missing_from_the_map_are_still_listed_as_not_owned() {
        let dir = TestDir::new("unknown-flow");
        let (path, conns) = sample(&dir);
        let first = conns[0].clone();
        process(
            &path,
            recording(vec![first], false),
            Options::default(),
            &Progress::default(),
        );
        let rows = read_connections(&path).unwrap();
        assert_eq!(rows.len(), 2);
        let unknown = rows.iter().find(|r| r.rport == 443).unwrap();
        assert!(!unknown.owned);
        assert_eq!(unknown.local, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(unknown.packets, 1);
    }

    #[test]
    fn filter_failure_keeps_the_capture_and_reports_its_actual_scope() {
        let dir = TestDir::new("filter-failure");
        let (path, conns) = sample(&dir);
        let data = std::fs::read(&path).unwrap();
        std::fs::create_dir(paths::with_suffix(&path, ".part")).unwrap();
        let done = process(
            &path,
            recording(conns, true),
            Options::default(),
            &Progress::default(),
        );
        assert!(done.unfiltered);
        assert!(!done.errors.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let info = sidecar(&path);
        assert_eq!(info["only_process"], false);
        assert_eq!(info["requested_only_process"], true);
        assert_eq!(info["processing"]["ok"], false);
        assert!(info.get("packets").is_none());
    }

    #[test]
    fn sidecar_write_failure_is_not_reported_as_success() {
        let dir = TestDir::new("sidecar-failure");
        let (path, conns) = sample(&dir);
        std::fs::create_dir(sidecar_path(&path)).unwrap();
        let done = process(
            &path,
            recording(conns, false),
            Options::default(),
            &Progress::default(),
        );
        assert!(done.sidecar.is_none());
        assert!(!done.unfiltered);
        assert!(!done.errors.is_empty());
    }

    #[test]
    fn forced_split_creates_parts_and_the_map_names_them() {
        let dir = TestDir::new("parts");
        let (path, conns) = sample(&dir);
        let opts = Options {
            compact: false,
            split: SplitMode::Always,
        };
        let done = process(&path, recording(conns, false), opts, &Progress::default());
        assert_eq!(done.parts, 2);
        let parts = parts_dir(&path);
        assert!(parts.join("domain-example.com.pcapng").is_file());
        assert!(parts.join("subnet-203.0.113.0-24.pcapng").is_file());
        let info = sidecar(&path);
        assert_eq!(info["parts"]["files"].as_array().unwrap().len(), 2);
        let rows = read_connections(&path).unwrap();
        let game = rows.iter().find(|r| r.rport == 27015).unwrap();
        assert_eq!(game.part.as_deref(), Some("domain-example.com"));

        // Следующая обработка без разбиения не оставляет устаревших частей.
        let never = Options {
            compact: false,
            split: SplitMode::Never,
        };
        let again = load(&path, None).unwrap();
        process(&path, again, never, &Progress::default());
        assert!(!parts.exists());
        assert!(sidecar(&path)["parts"].is_null());
    }

    #[test]
    fn groups_beyond_the_limit_go_to_the_other_part() {
        let mut rows: Vec<ConnRecord> = (0..MAX_PARTS + 3)
            .map(|i| {
                let k = key(40000 + i as u16, [198, 51, i as u8, 1], 443);
                let mut r = record(&k, None, true);
                r.packets = 1;
                r.stored = 1000 + i as u64;
                r
            })
            .collect();
        let plan = recording(Vec::new(), false);
        let plan = Plan {
            owners: plan.owners,
            only_group: false,
            compact: None,
            comment: String::new(),
            local_ips: plan.local_ips,
        };
        let split = plan_parts(&plan, &mut rows);
        assert_eq!(split.names.len(), MAX_PARTS + 1);
        assert_eq!(split.names.last().unwrap(), "other");
        let other = rows
            .iter()
            .filter(|r| r.part.as_deref() == Some("other"))
            .count();
        assert_eq!(other, 3);
        // В отдельные файлы попали самые объемные.
        assert_eq!(
            rows.last().unwrap().part.as_deref(),
            Some("subnet-198.51.66.0-24")
        );
        assert_eq!(rows.first().unwrap().part.as_deref(), Some("other"));
    }

    #[test]
    fn part_names_are_safe_file_names() {
        assert_eq!(part_stem("domain", "example.com"), "domain-example.com");
        assert_eq!(
            part_stem("subnet", "2001:db8:1::/48"),
            "subnet-2001-db8-1---48"
        );
        assert_eq!(part_stem("domain", "../../evil"), "domain-evil");
        assert!(part_stem("domain", &"a".repeat(500)).len() < 120);
        assert_eq!(part_stem("domain", "a b/c\\d:e"), "domain-a-b-c-d-e");
    }

    /// Сводка прежнего формата: запись процесса, отбор которой не выполнился.
    fn old_unfiltered_sidecar(path: &Path) {
        let old = json!({
            "dump": path.display().to_string(),
            "captured_from": "2026-01-01 10:00:00",
            "only_process": false,
            "requested_only_process": true,
            "processing": {"ok": false, "capture_complete": false, "errors": ["demo"]},
            "process": {"pid": 100, "name": "DemoGame.exe", "cmdline": "DemoGame.exe"},
            "group_pids": [100],
            "conns": [{
                "id": "UDP|192.0.2.10|40000|198.51.100.20|27015",
                "proto": "UDP",
                "local": "192.0.2.10",
                "lport": 40000,
                "remote": "198.51.100.20",
                "rport": 27015,
                "state": "CLOSED",
                "pid": 100,
                "pname": "DemoGame.exe",
                "domain": "api.example.com",
                "first_seen": 1,
                "last_seen": 2
            }, {"broken": true}],
        });
        std::fs::write(sidecar_path(path), old.to_string()).unwrap();
    }

    #[test]
    fn old_format_sidecar_is_filtered_and_upgraded() {
        let dir = TestDir::new("old-format");
        let (path, conns) = sample(&dir);
        drop(conns);
        old_unfiltered_sidecar(&path);

        let rows = list(&dir.0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], "unfiltered");
        assert_eq!(rows[0]["can_filter"], true);
        let old_summary = summary(&path).unwrap();
        assert_eq!(old_summary["domains"][0]["domain"], "example.com");
        assert!(old_summary.get("conns").is_none());

        let rec = load(&path, Some(true)).unwrap();
        assert!(rec.only_process && rec.reprocess);
        let done = process(&path, rec, Options::default(), &Progress::default());
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        let info = sidecar(&path);
        assert_eq!(info["format"], FORMAT);
        assert_eq!(info["only_process"], true);
        assert_eq!(info["packets"]["kept"], 2);
        assert_eq!(info["captured_from"], "2026-01-01 10:00:00");
        assert!(info.get("conns").is_none());
        assert_eq!(list(&dir.0)[0]["status"], "filtered");

        // Повторная обработка уже нового формата дает тот же результат и помнит итог.
        let again = load(&path, None).unwrap();
        process(&path, again, Options::default(), &Progress::default());
        let info = sidecar(&path);
        assert_eq!(info["packets"]["kept"], 2);
        assert_eq!(info["packets"]["total"], 3);
        assert_eq!(read_connections(&path).unwrap().len(), 1);
    }

    #[test]
    fn compacting_an_unfiltered_dump_keeps_its_traffic_and_the_filter_button() {
        let dir = TestDir::new("old-compact");
        let (path, conns) = sample(&dir);
        drop(conns);
        old_unfiltered_sidecar(&path);

        // Кнопки "Сократить" и "Разбить" не передают filter: отбор не выполняется.
        let rec = load(&path, None).unwrap();
        assert!(!rec.only_process && rec.requested);
        let opts = Options {
            compact: true,
            split: SplitMode::Never,
        };
        let done = process(&path, rec, opts, &Progress::default());
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        let info = sidecar(&path);
        assert_eq!(info["packets"]["kept"], 3);
        assert_eq!(info["only_process"], false);
        assert_eq!(info["requested_only_process"], true);
        let row = &list(&dir.0)[0];
        assert_eq!(row["status"], "unfiltered");
        assert_eq!(row["can_filter"], true);
        assert_eq!(row["compact"], true);

        // Отбор остается доступен и после сокращения.
        process(
            &path,
            load(&path, Some(true)).unwrap(),
            Options::default(),
            &Progress::default(),
        );
        assert_eq!(sidecar(&path)["packets"]["kept"], 2);
        assert_eq!(list(&dir.0)[0]["status"], "filtered");
    }

    #[test]
    fn reprocessing_compacts_a_file_without_changing_its_scope() {
        let dir = TestDir::new("reprocess-compact");
        let (path, conns) = sample(&dir);
        process(
            &path,
            recording(conns, false),
            Options::default(),
            &Progress::default(),
        );
        let opts = Options {
            compact: true,
            split: SplitMode::Never,
        };
        let done = process(
            &path,
            load(&path, None).unwrap(),
            opts,
            &Progress::default(),
        );
        assert!(done.errors.is_empty());
        let info = sidecar(&path);
        assert_eq!(info["processing"]["compact"], true);
        assert_eq!(info["only_process"], false);
        assert_eq!(info["packets"]["kept"], 3);
    }

    #[test]
    fn compact_flag_stays_after_processing_without_compaction() {
        let dir = TestDir::new("compact-sticky");
        let (path, conns) = sample(&dir);
        let opts = Options {
            compact: true,
            split: SplitMode::Never,
        };
        process(&path, recording(conns, false), opts, &Progress::default());
        assert_eq!(sidecar(&path)["processing"]["compact"], true);
        process(
            &path,
            load(&path, None).unwrap(),
            Options::default(),
            &Progress::default(),
        );
        assert_eq!(sidecar(&path)["processing"]["compact"], true);
    }

    #[test]
    fn reprocessing_knows_local_addresses_from_the_connection_table() {
        let dir = TestDir::new("reprocess-local");
        let path = dir.0.join("demo.pcapng");
        // Оба адреса публичные: только таблица соединений подскажет, какой из них свой.
        let me = [198, 51, 100, 7];
        let far = [203, 0, 113, 9];
        std::fs::write(&path, file(&[udp_frame(far, 443, me, 50000)])).unwrap();
        let mut known = record(&key(40000, [198, 51, 100, 20], 27015), None, true);
        known.local = IpAddr::V4(Ipv4Addr::from(me));
        process(
            &path,
            recording(vec![known], false),
            Options::default(),
            &Progress::default(),
        );
        let rec = load(&path, None).unwrap();
        assert!(rec.local_ips.contains(&IpAddr::V4(Ipv4Addr::from(me))));
        process(&path, rec, Options::default(), &Progress::default());
        let rows = read_connections(&path).unwrap();
        let flow = rows.iter().find(|r| r.packets == 1).unwrap();
        assert_eq!(flow.local, IpAddr::V4(Ipv4Addr::from(me)));
        assert_eq!(flow.remote, IpAddr::V4(Ipv4Addr::from(far)));
        // Адрес из строки, восстановленной по файлу, своим не считается.
        let again = load(&path, None).unwrap();
        assert!(!again.local_ips.contains(&IpAddr::V4(Ipv4Addr::from(far))));
        assert_eq!(again.local_ips.len(), 1);
    }

    #[test]
    fn failed_reprocessing_leaves_the_previous_summary() {
        let dir = TestDir::new("reprocess-failure");
        let (path, conns) = sample(&dir);
        process(
            &path,
            recording(conns, false),
            Options::default(),
            &Progress::default(),
        );
        let before = sidecar(&path);
        std::fs::create_dir(paths::with_suffix(&path, ".part")).unwrap();
        let done = process(
            &path,
            load(&path, None).unwrap(),
            Options::default(),
            &Progress::default(),
        );
        assert!(!done.errors.is_empty());
        assert_eq!(sidecar(&path), before);
    }

    #[test]
    fn filtering_without_a_process_map_is_refused() {
        let dir = TestDir::new("no-map");
        let (path, _) = sample(&dir);
        let data = std::fs::read(&path).unwrap();
        assert!(load(&path, Some(true)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let rec = load(&path, None).unwrap();
        assert!(!rec.only_process);
    }

    #[test]
    fn dump_names_cannot_leave_the_folder() {
        let dir = TestDir::new("names");
        std::fs::write(dir.0.join("demo.pcapng"), b"x").unwrap();
        std::fs::write(dir.0.join("demo.json"), b"{}").unwrap();
        std::fs::create_dir(dir.0.join("folder.pcapng")).unwrap();
        assert!(resolve(&dir.0, "demo.pcapng").is_ok());
        for name in [
            "",
            ".pcapng",
            "demo.json",
            "../demo.pcapng",
            "..\\demo.pcapng",
            "sub/demo.pcapng",
            "C:demo.pcapng",
            "demo.pcapng:stream",
            "folder.pcapng",
            "missing.pcapng",
        ] {
            assert!(resolve(&dir.0, name).is_err(), "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_a_dump_is_not_followed() {
        let dir = TestDir::new("symlink");
        let outside = TestDir::new("symlink-target");
        let target = outside.0.join("secret.pcapng");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.0.join("link.pcapng")).unwrap();
        assert!(resolve(&dir.0, "link.pcapng").is_err());
    }

    #[test]
    fn progress_is_reported_in_percent() {
        let p = Progress::default();
        assert_eq!(p.percent(), None);
        p.begin(200);
        p.done.store(50, Ordering::Relaxed);
        assert_eq!(p.percent(), Some(25));
        p.done.store(500, Ordering::Relaxed);
        assert_eq!(p.percent(), Some(100));
    }
}
