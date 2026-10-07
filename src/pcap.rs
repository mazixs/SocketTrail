//! Разбор потока pcapng от dumpcap и извлечение из пакетов того, что
//! опрос сокетов увидеть не может: имен из DNS-ответов и SNI из ClientHello
//! TLS и QUIC.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{quic, tls};

pub struct Parsers {
    quic: quic::Assembler,
    tcp: tls::Assembler,
}
impl Default for Parsers {
    fn default() -> Self {
        Self {
            quic: quic::Assembler::new(),
            tcp: tls::Assembler::default(),
        }
    }
}
use crate::sockets::Proto;

#[derive(Debug, Clone)]
pub struct Packet {
    pub proto: Proto,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub bytes: u32,
    /// Имя хоста из ClientHello: TLS поверх TCP или QUIC.
    pub sni: Option<String>,
    /// Разобранный DNS-ответ: (имя, адрес).
    pub dns_addrs: Vec<(String, IpAddr, u32)>,
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
#[cfg(any(not(windows), test))]
fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

/// Инкрементальный разборщик: кормим байтами, получаем готовые пакеты.
#[cfg(any(not(windows), test))]
pub struct PcapngReader {
    buf: Vec<u8>,
    /// linktype по индексу интерфейса, в порядке появления IDB
    linktypes: Vec<u16>,
    parsers: Parsers,
}

#[cfg(any(not(windows), test))]
impl PcapngReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1 << 20),
            linktypes: Vec::new(),
            parsers: Parsers::default(),
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
                            && let Some(p) = parse_link_live(lt, &body[20..20 + caplen], &mut self.parsers) {
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

/// Разбор одного кадра без состояния: SNI из QUIC тут не собрать.
pub fn parse_link(linktype: u16, d: &[u8]) -> Option<Packet> {
    parse_link_with(linktype, d, None)
}

/// Снятие канального заголовка. dumpcap -i any отдает LINUX_SLL или SLL2.
pub fn parse_link_with(
    linktype: u16,
    d: &[u8],
    quic: Option<&mut quic::Assembler>,
) -> Option<Packet> {
    parse_link_state(linktype, d, quic, None)
}

pub fn parse_link_live(linktype: u16, d: &[u8], parsers: &mut Parsers) -> Option<Packet> {
    parse_link_state(linktype, d, Some(&mut parsers.quic), Some(&mut parsers.tcp))
}

fn parse_link_state(
    linktype: u16,
    d: &[u8],
    quic: Option<&mut quic::Assembler>,
    tcp: Option<&mut tls::Assembler>,
) -> Option<Packet> {
    let (mut ethertype, mut off) = match linktype {
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
    for _ in 0..2 {
        if !matches!(ethertype, 0x8100 | 0x88a8) {
            break;
        }
        ethertype = be16(d, off + 2)?;
        off += 4;
    }
    match ethertype {
        0x0800 => parse_ipv4(d.get(off..)?, quic, tcp),
        0x86DD => parse_ipv6(d.get(off..)?, quic, tcp),
        _ => None,
    }
}

fn parse_ipv4(
    d: &[u8],
    quic: Option<&mut quic::Assembler>,
    tcp: Option<&mut tls::Assembler>,
) -> Option<Packet> {
    if d.first()? >> 4 != 4 || be16(d, 6)? & 0x1fff != 0 {
        return None;
    }
    let ihl = (d.first()? & 0x0F) as usize * 4;
    if ihl < 20 || d.len() < ihl {
        return None;
    }
    let total = be16(d, 2)? as u32;
    if total < ihl as u32 {
        return None;
    }
    let d = &d[..d.len().min(total as usize)];
    let proto = *d.get(9)?;
    let src = IpAddr::V4(Ipv4Addr::new(d[12], d[13], d[14], d[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(d[16], d[17], d[18], d[19]));
    parse_l4(proto, src, dst, total, d.get(ihl..)?, quic, tcp)
}

fn parse_ipv6(
    d: &[u8],
    quic: Option<&mut quic::Assembler>,
    tcp: Option<&mut tls::Assembler>,
) -> Option<Packet> {
    if d.len() < 40 || d[0] >> 4 != 6 {
        return None;
    }
    let payload_len = be16(d, 4)? as u32;
    let mut next = *d.get(6)?;
    let d = &d[..d.len().min(40 + payload_len as usize)];
    let mut s = [0u8; 16];
    let mut t = [0u8; 16];
    s.copy_from_slice(&d[8..24]);
    t.copy_from_slice(&d[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(s));
    let dst = IpAddr::V6(Ipv6Addr::from(t));
    let mut off = 40;
    for _ in 0..8 {
        let size = match next {
            0 | 43 | 60 => (*d.get(off + 1)? as usize + 1) * 8,
            51 => (*d.get(off + 1)? as usize + 2) * 4,
            44 => {
                if be16(d, off + 2)? & 0xfff8 != 0 {
                    return None;
                }
                8
            }
            6 | 17 => return parse_l4(next, src, dst, payload_len + 40, d.get(off..)?, quic, tcp),
            _ => return None,
        };
        next = *d.get(off)?;
        off = off.checked_add(size)?;
        if off > d.len() {
            return None;
        }
    }
    None
}

fn parse_l4(
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    bytes: u32,
    d: &[u8],
    quic: Option<&mut quic::Assembler>,
    tcp: Option<&mut tls::Assembler>,
) -> Option<Packet> {
    let (p, sport, dport, payload) = match proto {
        6 => {
            let off = ((*d.get(12)? >> 4) as usize) * 4;
            if off < 20 || d.len() < off {
                return None;
            }
            (
                Proto::Tcp,
                be16(d, 0)?,
                be16(d, 2)?,
                d.get(off..).unwrap_or(&[]),
            )
        }
        17 => {
            if be16(d, 4)? < 8 || d.len() < 8 {
                return None;
            }
            (
                Proto::Udp,
                be16(d, 0)?,
                be16(d, 2)?,
                &d[8..(be16(d, 4)? as usize).min(d.len())],
            )
        }
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
    };

    if p == Proto::Tcp {
        pkt.sni = if let Some(tcp) = tcp {
            let seq = u32::from_be_bytes(d.get(4..8)?.try_into().ok()?);
            tcp.feed((src, sport, dst, dport), seq, *d.get(13)?, payload)
        } else {
            parse_sni(payload)
        };
    }
    if p == Proto::Udp
        && payload.first().is_some_and(|b| b & 0x80 != 0)
        && let Some(q) = quic
    {
        pkt.sni = q.feed(src, sport, payload);
    }
    if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 {
        // По TCP перед сообщением идут 2 байта его длины (RFC 1035 4.2.2).
        // Сообщение, разбитое на несколько сегментов, не собираем: без
        // сборки потока продолжение разобралось бы со сдвигом.
        let msg = if p == Proto::Tcp {
            payload
                .get(2..)
                .filter(|m| be16(payload, 0).is_some_and(|n| n as usize == m.len()))
        } else {
            Some(payload)
        };
        if let Some(msg) = msg.filter(|m| !m.is_empty()) {
            parse_dns(msg, &mut pkt);
        }
    }
    Some(pkt)
}

/// SNI из TLS ClientHello позволяет узнать имя соединения без PTR и DNS-ответа.
fn parse_sni(d: &[u8]) -> Option<String> {
    if *d.first()? != 0x16 || *d.get(1)? != 0x03 {
        return None;
    }
    client_hello_sni(d.get(5..5 + be16(d, 3)? as usize)?)
}

/// SNI из сообщения ClientHello: TLS кладет его в запись, QUIC - в кадры CRYPTO.
pub fn client_hello_sni(rec: &[u8]) -> Option<String> {
    if *rec.first()? != 0x01 {
        return None; // не ClientHello
    }
    let length = u32::from_be_bytes([0, *rec.get(1)?, *rec.get(2)?, *rec.get(3)?]) as usize;
    let rec = rec.get(..4 + length)?;
    let mut p = 4 + 2 + 32; // handshake header, version, random
    let sid_len = *rec.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = be16(rec, p)? as usize;
    p += 2 + cs_len;
    let comp_len = *rec.get(p)? as usize;
    p += 1 + comp_len;
    let ext_total = be16(rec, p)? as usize;
    p += 2;
    let end = p.checked_add(ext_total)?;
    if end > rec.len() {
        return None;
    }
    while p + 4 <= end {
        let etype = be16(rec, p)?;
        let elen = be16(rec, p + 2)? as usize;
        if p + 4 + elen > end {
            return None;
        }
        let ebody = rec.get(p + 4..p + 4 + elen)?;
        if etype == 0 {
            // server_name: list_len(2) type(1) name_len(2) name
            let list_len = be16(ebody, 0)? as usize;
            if list_len + 2 != ebody.len() || *ebody.get(2)? != 0 {
                return None;
            }
            let name_len = be16(ebody, 3)? as usize;
            if name_len == 0 || name_len > 253 || name_len + 3 != list_len {
                return None;
            }
            let name = ebody.get(5..5 + name_len)?;
            if !name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
            {
                return None;
            }
            return String::from_utf8(name.to_vec())
                .ok()
                .map(|n| n.to_ascii_lowercase());
        }
        p += 4 + elen;
    }
    None
}

fn dns_name(d: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut wire = 1;
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
        if len > 63 {
            if len & 0xC0 != 0xC0 {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | *d.get(p + 1)? as usize;
            if !jumped {
                after = p + 2;
            }
            jumped = true;
            p = ptr;
            continue;
        }
        let label = d.get(p + 1..p + 1 + len)?;
        wire += 1 + len;
        if wire > MAX_DNS_NAME {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        p += 1 + len;
    }
    Some((out, after))
}

/// Предел имени по RFC 1035 и число адресов из одного ответа: ответ mDNS
/// от любого соседа в сети не должен раздувать карту имен.
const MAX_DNS_NAME: usize = 255;
const MAX_DNS_ADDRS: usize = 64;

/// Разбор DNS-ответа: записи A и AAAA связывают имя с адресом узла.
fn parse_dns(d: &[u8], pkt: &mut Packet) {
    if d.len() < 12 {
        return;
    }
    let flags = match be16(d, 2) {
        Some(f) => f,
        None => return,
    };
    if flags & 0x8000 == 0 || flags & 0x020f != 0 {
        return; // запрос, адресов в нем нет
    }
    let qd = be16(d, 4).unwrap_or(0) as usize;
    let an = be16(d, 6).unwrap_or(0) as usize;
    let mut p = 12;
    let mut qname = None;
    for _ in 0..qd {
        match dns_name(d, p) {
            Some((n, np)) => {
                qname.get_or_insert(n);
                p = np + 4;
            }
            None => return,
        }
    }
    // Адрес подписывается запрошенным именем, а не последним звеном цепочки
    // CNAME: пользователю нужен www.example.com, а не узел CDN за ним.
    let mut chain_ttl = u32::MAX;
    let mut chain: Vec<String> = qname.iter().cloned().collect();
    let shown = |owner: String, chain: &[String]| match &qname {
        Some(q) if chain.iter().any(|c| c.eq_ignore_ascii_case(&owner)) => q.clone(),
        _ => owner,
    };
    for _ in 0..an {
        if pkt.dns_addrs.len() >= MAX_DNS_ADDRS {
            return;
        }
        let (name, np) = match dns_name(d, p) {
            Some(v) => v,
            None => return,
        };
        p = np;
        let rtype = match be16(d, p) {
            Some(v) => v,
            None => return,
        };
        let ttl = d
            .get(p + 4..p + 8)
            .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
            .unwrap_or(0);
        let ttl = if chain.iter().any(|c| c.eq_ignore_ascii_case(&name)) {
            ttl.min(chain_ttl)
        } else {
            ttl
        };
        if be16(d, p + 2) != Some(1) {
            return;
        }
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
                shown(name, &chain),
                IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                ttl,
            )),
            28 if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                pkt.dns_addrs
                    .push((shown(name, &chain), IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            5 if chain.len() < 16 && chain.iter().any(|c| c.eq_ignore_ascii_case(&name)) => {
                if let Some((target, _)) = dns_name(d, p + 10) {
                    chain.push(target);
                    chain_ttl = chain_ttl.min(ttl);
                }
            }
            _ => {}
        }
        p += 10 + rdlen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_fragment(offset: u16) -> Vec<u8> {
        let mut f = vec![0u8; 28];
        f[0] = 0x45;
        f[2..4].copy_from_slice(&28u16.to_be_bytes());
        f[6..8].copy_from_slice(&offset.to_be_bytes());
        f[9] = 17;
        f[12..16].copy_from_slice(&[192, 0, 2, 10]);
        f[16..20].copy_from_slice(&[198, 51, 100, 20]);
        f[20..28].copy_from_slice(&[0x9c, 0x40, 0x01, 0xbb, 0, 16, 0, 0]);
        f
    }

    fn dns_name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// DNS-ответ: вопрос и `answers` записей A со ссылкой на имя вопроса.
    fn dns_response(qname: &[u8], answers: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
        m.extend_from_slice(&answers.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(qname);
        m.extend_from_slice(&[0, 1, 0, 1]);
        for i in 0..answers {
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100]);
            m.push(i as u8);
        }
        m
    }

    fn ipv4_from_dns(proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 20];
        f[0] = 0x45;
        f[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        f[9] = proto;
        f[12..16].copy_from_slice(&[192, 0, 2, 53]);
        f[16..20].copy_from_slice(&[192, 0, 2, 10]);
        f.extend_from_slice(l4);
        f
    }

    fn udp_dns(msg: &[u8]) -> Vec<u8> {
        let mut u = vec![0, 53, 0x9c, 0x40];
        u.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(msg);
        ipv4_from_dns(17, &u)
    }

    #[test]
    fn dns_response_over_udp_maps_name_to_address() {
        let msg = dns_response(&dns_name_bytes("www.example.com"), 1);
        let p = parse_link(101, &udp_dns(&msg)).unwrap();
        assert_eq!(
            p.dns_addrs,
            [(
                "www.example.com".to_string(),
                "198.51.100.0".parse().unwrap(),
                60
            )]
        );
    }

    fn tcp_dns(prefix: u16, data: &[u8]) -> Vec<u8> {
        let mut t = vec![
            0, 53, 0x9c, 0x40, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0, 0, 0, 0, 0, 0,
        ];
        t.extend_from_slice(&prefix.to_be_bytes());
        t.extend_from_slice(data);
        ipv4_from_dns(6, &t)
    }

    #[test]
    fn dns_response_over_tcp_skips_the_length_prefix() {
        let msg = dns_response(&dns_name_bytes("example.com"), 1);
        let p = parse_link(101, &tcp_dns(msg.len() as u16, &msg)).unwrap();
        assert_eq!(p.dns_addrs.len(), 1);
        assert_eq!(p.dns_addrs[0].0, "example.com");
    }

    #[test]
    fn dns_over_tcp_split_across_segments_is_ignored() {
        let msg = dns_response(&dns_name_bytes("example.com"), 2);
        let head = &msg[..msg.len() - 10];
        let p = parse_link(101, &tcp_dns(msg.len() as u16, head)).unwrap();
        assert!(p.dns_addrs.is_empty());

        // Продолжение сообщения без префикса длины: первые 2 байта - это ID.
        let p = parse_link(101, &tcp_dns(0x1234, &msg[2..])).unwrap();
        assert!(p.dns_addrs.is_empty());
    }

    #[test]
    fn dns_name_limit_counts_wire_bytes_not_text() {
        let mut qname = Vec::new();
        for len in [63u8, 63, 63, 61] {
            qname.push(len);
            qname.extend(std::iter::repeat_n(0xff, len.into()));
        }
        qname.push(0);
        assert_eq!(qname.len(), MAX_DNS_NAME);
        let p = parse_link(101, &udp_dns(&dns_response(&qname, 1))).unwrap();
        assert_eq!(p.dns_addrs.len(), 1);
    }

    #[test]
    fn dns_rejects_reserved_label_types_and_overlong_names() {
        let mut reserved = dns_name_bytes("example.com");
        reserved[0] = 0x45;
        let p = parse_link(101, &udp_dns(&dns_response(&reserved, 1))).unwrap();
        assert!(p.dns_addrs.is_empty());

        let long = vec!["a".repeat(63); 5].join(".");
        let p = parse_link(101, &udp_dns(&dns_response(&dns_name_bytes(&long), 1))).unwrap();
        assert!(p.dns_addrs.is_empty());
    }

    #[test]
    fn address_behind_a_cname_chain_gets_the_queried_name() {
        let qname = dns_name_bytes("www.example.com");
        let target = dns_name_bytes("edge.example.net");
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(&qname);
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, target.len() as u8]);
        let target_at = m.len();
        m.extend_from_slice(&target);
        m.extend_from_slice(&[
            0xc0,
            target_at as u8,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            60,
            0,
            4,
            203,
            0,
            113,
            7,
        ]);
        let p = parse_link(101, &udp_dns(&m)).unwrap();
        assert_eq!(
            p.dns_addrs,
            [(
                "www.example.com".to_string(),
                "203.0.113.7".parse().unwrap(),
                60
            )]
        );
    }

    #[test]
    fn dns_answer_count_is_capped() {
        let msg = dns_response(&dns_name_bytes("example.com"), 90);
        let p = parse_link(101, &udp_dns(&msg)).unwrap();
        assert_eq!(p.dns_addrs.len(), MAX_DNS_ADDRS);
    }

    #[test]
    fn truncated_dns_responses_do_not_panic() {
        let msg = dns_response(&dns_name_bytes("www.example.com"), 3);
        for n in 0..msg.len() {
            let _ = parse_link(101, &udp_dns(&msg[..n]));
        }
    }

    #[test]
    fn noninitial_ipv4_fragments_do_not_invent_ports() {
        for offset in [1, 0x2001, 0x1fff] {
            assert!(parse_link(101, &udp_fragment(offset)).is_none());
        }
    }

    #[test]
    fn first_ipv4_fragment_still_has_transport_ports() {
        for offset in [0, 0x2000, 0x4000] {
            let p = parse_link(101, &udp_fragment(offset)).unwrap();
            assert_eq!((p.sport, p.dport, p.bytes), (40000, 443, 28));
        }
    }

    #[test]
    fn ipv4_padding_cannot_supply_a_missing_transport_header() {
        let mut f = udp_fragment(0);
        f[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(parse_link(101, &f).is_none());
    }

    #[test]
    fn malformed_and_truncated_ipv4_headers_are_rejected() {
        let f = udp_fragment(0);
        for n in 0..28 {
            assert!(parse_link(101, &f[..n]).is_none());
        }
        let mut short = f.clone();
        short[2..4].copy_from_slice(&16u16.to_be_bytes());
        assert!(parse_link(101, &short).is_none());
        let mut other = f;
        other[0] = 0x65;
        assert!(parse_link(101, &other).is_none());
    }
    #[test]
    fn ipv6_extensions_and_vlan_preserve_transport_tuple() {
        let udp = [0x9c, 0x40, 0x01, 0xbb, 0, 8, 0, 0];
        for extension in [0u8, 43, 60, 44, 51] {
            let mut ip = vec![0u8; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&16u16.to_be_bytes());
            ip[6] = extension;
            ip[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            ip[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
            ip.extend([17, 0, 0, 0, 0, 0, 0, 0]);
            ip.extend(udp);
            let p = parse_link(101, &ip).unwrap();
            assert_eq!((p.sport, p.dport), (40000, 443));
            let mut tagged = vec![0u8; 12];
            tagged.extend([0x88, 0xa8, 0, 1, 0x81, 0, 0, 2, 0x86, 0xdd]);
            tagged.extend(&ip);
            assert_eq!(parse_link(1, &tagged).unwrap().sport, 40000);
            if extension == 44 {
                ip[42..44].copy_from_slice(&8u16.to_be_bytes());
                assert!(parse_link(101, &ip).is_none());
            }
            ip[4..6].copy_from_slice(&8u16.to_be_bytes());
            assert!(
                parse_link(101, &ip).is_none(),
                "padding cannot provide transport data"
            );
        }
    }
    #[test]
    fn live_parser_reassembles_tls_over_packets() {
        let hex: Vec<u8> = include_str!("testdata/rfc9001-client-hello-crypto.hex")
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .collect();
        let h: Vec<u8> = hex
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        let mut tls = vec![22, 3, 3];
        tls.extend(((h.len() - 4) as u16).to_be_bytes());
        tls.extend(&h[4..]);
        let mut parsers = Parsers::default();
        for (offset, part) in [(100, &tls[100..]), (0, &tls[..100])] {
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
            tcp[4..8].copy_from_slice(&(1000u32 + offset).to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = 0x18;
            tcp.extend(part);
            let frame = ipv4_from_dns(6, &tcp);
            let p = parse_link_live(101, &frame, &mut parsers).unwrap();
            assert_eq!(
                p.sni.as_deref(),
                if offset == 0 {
                    Some("example.com")
                } else {
                    None
                }
            );
        }
    }
}
