//! Доработка дампа после остановки записи: подпись каждого пакета процессом и
//! доменом (opt_comment, в Wireshark - поле frame.comment) и отбор трафика
//! выбранного процесса. Отбор идет по владельцу соединения, а не по адресам на
//! момент старта, поэтому серверы, к которым игра подключилась позже, не теряются.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::IpAddr;

use crate::pcap;
use crate::state::ConnKey;

pub struct Owner {
    pub label: Option<String>,
    pub keep: bool,
}

pub struct Plan {
    pub owners: HashMap<ConnKey, Owner>,
    /// Адреса процесса: для пакетов, чьих соединений нет в истории.
    pub hosts: HashSet<IpAddr>,
    /// false - весь трафик, true - только соединения процесса.
    pub only_group: bool,
    pub comment: String,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub packets: u64,
    pub kept: u64,
    pub labeled: u64,
}

const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 1;
const EPB: u32 = 6;
const MAGIC: u32 = 0x1A2B_3C4D;

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn opt_comment(text: &str) -> Vec<u8> {
    let t = text.as_bytes();
    let t = &t[..t.len().min(u16::MAX as usize - 3)];
    let mut o = Vec::with_capacity(8 + t.len());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&(t.len() as u16).to_le_bytes());
    o.extend_from_slice(t);
    o.resize(o.len().div_ceil(4) * 4, 0);
    o
}

/// Тело блока с опцией-комментарием в начале списка опций. fixed - длина полей
/// до опций. Если опций не было, дописывается opt_endofopt.
fn with_comment(body: &[u8], fixed: usize, text: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(body.len() + text.len() + 12);
    b.extend_from_slice(&body[..fixed]);
    b.extend_from_slice(&opt_comment(text));
    if body.len() > fixed {
        b.extend_from_slice(&body[fixed..]);
    } else {
        b.extend_from_slice(&[0u8; 4]);
    }
    b
}

fn write_block(out: &mut impl Write, ty: u32, body: &[u8]) -> std::io::Result<()> {
    let len = (12 + body.len()) as u32;
    out.write_all(&ty.to_le_bytes())?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&len.to_le_bytes())
}

impl Plan {
    fn lookup(&self, p: &pcap::Packet) -> Option<&Owner> {
        let fwd = ConnKey {
            proto: p.proto,
            local: p.src,
            lport: p.sport,
            remote: p.dst,
            rport: p.dport,
        };
        let back = ConnKey {
            proto: p.proto,
            local: p.dst,
            lport: p.dport,
            remote: p.src,
            rport: p.sport,
        };
        self.owners.get(&fwd).or_else(|| self.owners.get(&back))
    }

    /// (оставить пакет, подпись)
    fn judge(&self, linktype: u16, frame: &[u8]) -> (bool, Option<&str>) {
        let Some(p) = pcap::parse_link(linktype, frame) else {
            return (!self.only_group, None);
        };
        match self.lookup(&p) {
            Some(o) => (!self.only_group || o.keep, o.label.as_deref()),
            None => (
                !self.only_group || self.hosts.contains(&p.src) || self.hosts.contains(&p.dst),
                None,
            ),
        }
    }

    pub fn apply(&self, src: impl Read, dst: impl Write) -> std::io::Result<Stats> {
        let mut r = BufReader::with_capacity(1 << 20, src);
        let mut w = BufWriter::with_capacity(1 << 20, dst);
        let mut st = Stats::default();
        let mut linktypes: Vec<u16> = Vec::new();
        let mut head = [0u8; 8];
        let mut body = Vec::new();
        loop {
            match r.read_exact(&mut head) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let ty = le32(&head, 0);
            let len = le32(&head, 4) as usize;
            if !(12..=(1 << 26)).contains(&len) || !len.is_multiple_of(4) {
                return Err(std::io::Error::other(t!(
                    "corrupted pcapng block",
                    "поврежденный блок pcapng"
                )));
            }
            body.resize(len - 8, 0);
            match r.read_exact(&mut body) {
                Ok(()) => {}
                // обрубленный последний блок: запись прервали принудительно
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            body.truncate(len - 12);
            match ty {
                SHB => {
                    if body.len() < 16 || le32(&body, 0) != MAGIC {
                        return Err(std::io::Error::other(t!(
                            "big-endian pcapng",
                            "pcapng с обратным порядком байт"
                        )));
                    }
                    linktypes.clear();
                    write_block(&mut w, ty, &with_comment(&body, 16, &self.comment))?;
                }
                IDB => {
                    if body.len() >= 2 {
                        linktypes.push(u16::from_le_bytes([body[0], body[1]]));
                    }
                    write_block(&mut w, ty, &body)?;
                }
                EPB if body.len() >= 20 => {
                    st.packets += 1;
                    let caplen = le32(&body, 12) as usize;
                    let fixed = 20 + caplen.div_ceil(4) * 4;
                    if body.len() < fixed {
                        return Err(std::io::Error::other(t!(
                            "corrupted pcapng packet",
                            "поврежденный пакет pcapng"
                        )));
                    }
                    let lt = linktypes.get(le32(&body, 0) as usize).copied().unwrap_or(1);
                    let (keep, label) = self.judge(lt, &body[20..20 + caplen]);
                    if !keep {
                        continue;
                    }
                    st.kept += 1;
                    match label {
                        Some(l) => {
                            st.labeled += 1;
                            write_block(&mut w, ty, &with_comment(&body, fixed, l))?;
                        }
                        None => write_block(&mut w, ty, &body)?,
                    }
                }
                _ => write_block(&mut w, ty, &body)?,
            }
        }
        w.flush()?;
        Ok(st)
    }

    /// Переписать файл на месте. При ошибке исходный дамп остается как был.
    pub fn rewrite(&self, path: &str) -> std::io::Result<Stats> {
        let tmp = format!("{path}.part");
        let res = File::open(path)
            .and_then(|src| Ok((src, File::create(&tmp)?)))
            .and_then(|(src, dst)| self.apply(src, dst));
        match res {
            Ok(st) => {
                // в дампе полный трафик: права исходного файла (у dumpcap 0600) сохраняем
                if let Ok(meta) = std::fs::metadata(path) {
                    let _ = std::fs::set_permissions(&tmp, meta.permissions());
                }
                std::fs::rename(&tmp, path)?;
                Ok(st)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
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
mod tests {
    use super::*;
    use crate::sockets::Proto;
    use std::net::Ipv4Addr;

    fn udp_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0, 8, 0, 0]);
        f
    }

    fn file(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut shb = Vec::new();
        shb.extend_from_slice(&MAGIC.to_le_bytes());
        shb.extend_from_slice(&[1, 0, 0, 0]);
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        write_block(&mut out, SHB, &shb).unwrap();
        write_block(&mut out, IDB, &[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        for f in frames {
            let mut b = vec![0u8; 12];
            b.extend_from_slice(&(f.len() as u32).to_le_bytes());
            b.extend_from_slice(&(f.len() as u32).to_le_bytes());
            b.extend_from_slice(f);
            b.resize(b.len().div_ceil(4) * 4, 0);
            write_block(&mut out, EPB, &b).unwrap();
        }
        out
    }

    #[test]
    fn labels_and_filters() {
        let me = [10, 0, 0, 2];
        let game = udp_frame(me, 40000, [1, 2, 3, 4], 27015);
        let reply = udp_frame([1, 2, 3, 4], 27015, me, 40000);
        let other = udp_frame(me, 40001, [5, 6, 7, 8], 443);
        let src = file(&[game, reply, other]);

        let key = ConnKey {
            proto: Proto::Udp,
            local: IpAddr::V4(Ipv4Addr::from(me)),
            lport: 40000,
            remote: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            rport: 27015,
        };
        let mut plan = Plan {
            owners: HashMap::from([(
                key,
                Owner {
                    label: label(Some("cs2.exe"), Some(1234), Some("valve.net")),
                    keep: true,
                },
            )]),
            hosts: HashSet::new(),
            only_group: true,
            comment: "SocketTrail".into(),
        };

        let mut out = Vec::new();
        let st = plan.apply(&src[..], &mut out).unwrap();
        assert_eq!((st.packets, st.kept, st.labeled), (3, 2, 2));
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("cs2.exe [1234] -> valve.net"));

        let mut pk = Vec::new();
        pcap::PcapngReader::new().push(&out, &mut pk);
        assert_eq!(pk.len(), 2);

        plan.only_group = false;
        let mut all = Vec::new();
        let st = plan.apply(&src[..], &mut all).unwrap();
        assert_eq!((st.kept, st.labeled), (3, 2));
    }
}
