//! Разбор потока pcapng от dumpcap и извлечение из пакетов того, что
//! опрос сокетов увидеть не может: имен из DNS-ответов и SNI из TLS ClientHello.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sockets::Proto;

#[derive(Debug, Clone)]
pub struct Packet {
    pub proto: Proto,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub bytes: u32,
    /// Имя хоста из TLS ClientHello.
    pub sni: Option<String>,
    /// Разобранный DNS-ответ: (имя, адрес) и цепочки CNAME.
    pub dns_addrs: Vec<(String, IpAddr)>,
    pub dns_cnames: Vec<(String, String)>,
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

/// Инкрементальный разборщик: кормим байтами, получаем готовые пакеты.
pub struct PcapngReader {
    buf: Vec<u8>,
    /// linktype по индексу интерфейса, в порядке появления IDB
    linktypes: Vec<u16>,
}

impl PcapngReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1 << 20),
            linktypes: Vec::new(),
        }
    }

    pub fn push(&mut self, data: &[u8], out: &mut Vec<Packet>) {
        self.buf.extend_from_slice(data);
        let mut pos = 0usize;
        loop {
            if self.buf.len() - pos < 12 {
                break;
            }
            let btype = match le32(&self.buf[pos..], 0) {
                Some(v) => v,
                None => break,
            };
            let blen = match le32(&self.buf[pos..], 4) {
                Some(v) => v as usize,
                None => break,
            };
            if !(12..=(1 << 26)).contains(&blen) {
                // рассинхронизация потока - дальше разбирать бессмысленно
                self.buf.clear();
                return;
            }
            if self.buf.len() - pos < blen {
                break;
            }
            let body = &self.buf[pos + 8..pos + blen - 4];
            match btype {
                0x0000_0001 => {
                    // Interface Description Block
                    if let Some(lt) = body.first().zip(body.get(1)) {
                        self.linktypes.push(u16::from_le_bytes([*lt.0, *lt.1]));
                    }
                }
                0x0000_0006
                    // Enhanced Packet Block
                    if body.len() >= 20 => {
                        let iface = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
                        let caplen =
                            u32::from_le_bytes([body[12], body[13], body[14], body[15]]) as usize;
                        let lt = self.linktypes.get(iface).copied().unwrap_or(1);
                        if body.len() >= 20 + caplen
                            && let Some(p) = parse_link(lt, &body[20..20 + caplen]) {
                                out.push(p);
                            }
                    }
                _ => {}
            }
            pos += blen;
        }
        if pos > 0 {
            self.buf.drain(..pos);
        }
    }
}

/// Снятие канального заголовка. dumpcap -i any отдает LINUX_SLL или SLL2.
pub fn parse_link(linktype: u16, d: &[u8]) -> Option<Packet> {
    let (ethertype, off) = match linktype {
        1 => (be16(d, 12)?, 14),   // Ethernet
        113 => (be16(d, 14)?, 16), // LINUX_SLL
        276 => (be16(d, 0)?, 20),  // LINUX_SLL2
        101 | 12 | 14 => {
            // RAW IP: версию берем из первого нибла
            let v = d.first()? >> 4;
            (if v == 6 { 0x86DDu16 } else { 0x0800 }, 0)
        }
        _ => return None,
    };
    match ethertype {
        0x0800 => parse_ipv4(d.get(off..)?),
        0x86DD => parse_ipv6(d.get(off..)?),
        _ => None,
    }
}

fn parse_ipv4(d: &[u8]) -> Option<Packet> {
    let ihl = (d.first()? & 0x0F) as usize * 4;
    if ihl < 20 || d.len() < ihl {
        return None;
    }
    let total = be16(d, 2)? as u32;
    let proto = *d.get(9)?;
    let src = IpAddr::V4(Ipv4Addr::new(d[12], d[13], d[14], d[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(d[16], d[17], d[18], d[19]));
    parse_l4(proto, src, dst, total, d.get(ihl..)?)
}

fn parse_ipv6(d: &[u8]) -> Option<Packet> {
    if d.len() < 40 {
        return None;
    }
    let payload_len = be16(d, 4)? as u32;
    let next = *d.get(6)?;
    let mut s = [0u8; 16];
    let mut t = [0u8; 16];
    s.copy_from_slice(&d[8..24]);
    t.copy_from_slice(&d[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(s));
    let dst = IpAddr::V6(Ipv6Addr::from(t));
    parse_l4(next, src, dst, payload_len + 40, d.get(40..)?)
}

fn parse_l4(proto: u8, src: IpAddr, dst: IpAddr, bytes: u32, d: &[u8]) -> Option<Packet> {
    let (p, sport, dport, payload) = match proto {
        6 => {
            let off = ((*d.get(12)? >> 4) as usize) * 4;
            (
                Proto::Tcp,
                be16(d, 0)?,
                be16(d, 2)?,
                d.get(off..).unwrap_or(&[]),
            )
        }
        17 => (
            Proto::Udp,
            be16(d, 0)?,
            be16(d, 2)?,
            d.get(8..).unwrap_or(&[]),
        ),
        _ => return None,
    };

    let mut pkt = Packet {
        proto: p,
        src,
        sport,
        dst,
        dport,
        bytes,
        sni: None,
        dns_addrs: Vec::new(),
        dns_cnames: Vec::new(),
    };

    if p == Proto::Tcp && !payload.is_empty() {
        pkt.sni = parse_sni(payload);
    }
    if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353) && !payload.is_empty() {
        parse_dns(payload, &mut pkt);
    }
    Some(pkt)
}

/// SNI из TLS ClientHello. Единственный источник имени, когда у адреса нет ни PTR,
/// ни DNS-записи - так был опознан шард lime-frankfurt-p4-api.plaync.com.
fn parse_sni(d: &[u8]) -> Option<String> {
    if *d.first()? != 0x16 || *d.get(1)? != 0x03 {
        return None;
    }
    let rec = d.get(5..)?;
    if *rec.first()? != 0x01 {
        return None; // не ClientHello
    }
    let mut p = 4 + 2 + 32; // handshake header, version, random
    let sid_len = *rec.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = be16(rec, p)? as usize;
    p += 2 + cs_len;
    let comp_len = *rec.get(p)? as usize;
    p += 1 + comp_len;
    let ext_total = be16(rec, p)? as usize;
    p += 2;
    let end = (p + ext_total).min(rec.len());
    while p + 4 <= end {
        let etype = be16(rec, p)?;
        let elen = be16(rec, p + 2)? as usize;
        let ebody = rec.get(p + 4..p + 4 + elen)?;
        if etype == 0 {
            // server_name: list_len(2) type(1) name_len(2) name
            let name_len = be16(ebody, 3)? as usize;
            let name = ebody.get(5..5 + name_len)?;
            return String::from_utf8(name.to_vec()).ok();
        }
        p += 4 + elen;
    }
    None
}

fn dns_name(d: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut jumped = false;
    let mut after = p;
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 128 {
            return None;
        }
        let len = *d.get(p)? as usize;
        if len == 0 {
            if !jumped {
                after = p + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *d.get(p + 1)? as usize;
            if !jumped {
                after = p + 2;
            }
            jumped = true;
            p = ptr;
            continue;
        }
        let label = d.get(p + 1..p + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        p += 1 + len;
    }
    Some((out, after))
}

/// Разбор DNS-ответа: A, AAAA и цепочки CNAME - именно они связывают
/// вежливое имя вроде assets.playnccdn.com с реальным узлом CDN.
fn parse_dns(d: &[u8], pkt: &mut Packet) {
    if d.len() < 12 {
        return;
    }
    let flags = match be16(d, 2) {
        Some(f) => f,
        None => return,
    };
    if flags & 0x8000 == 0 {
        return; // запрос, адресов в нем нет
    }
    let qd = be16(d, 4).unwrap_or(0) as usize;
    let an = be16(d, 6).unwrap_or(0) as usize;
    let mut p = 12;
    for _ in 0..qd {
        match dns_name(d, p) {
            Some((_, np)) => p = np + 4,
            None => return,
        }
    }
    for _ in 0..an {
        let (name, np) = match dns_name(d, p) {
            Some(v) => v,
            None => return,
        };
        p = np;
        let rtype = match be16(d, p) {
            Some(v) => v,
            None => return,
        };
        let rdlen = match be16(d, p + 8) {
            Some(v) => v as usize,
            None => return,
        };
        let rdata = match d.get(p + 10..p + 10 + rdlen) {
            Some(v) => v,
            None => return,
        };
        match rtype {
            1 if rdlen == 4 => pkt.dns_addrs.push((
                name,
                IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            )),
            28 if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                pkt.dns_addrs.push((name, IpAddr::V6(Ipv6Addr::from(b))));
            }
            5 => {
                if let Some((cname, _)) = dns_name(d, p + 10) {
                    pkt.dns_cnames.push((name, cname));
                }
            }
            _ => {}
        }
        p += 10 + rdlen;
    }
}
