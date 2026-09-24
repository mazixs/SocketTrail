//! SNI из QUIC Initial. Ключи Initial выводятся из Destination Connection ID,
//! который идет открытым текстом (RFC 9001, раздел 5.2), поэтому ClientHello
//! читается без ключей сессии. Chrome раскладывает ClientHello с постквантовым
//! key share на несколько пакетов и перемешивает кадры, поэтому куски CRYPTO
//! собираются по смещению для каждого соединения.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Nonce, Tag};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::{Block, BlockCipherEncrypt};
use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::pcap::client_hello_sni;

struct Version {
    id: u32,
    salt: [u8; 20],
    key: &'static str,
    iv: &'static str,
    hp: &'static str,
    initial: u8,
    retry: u8,
}

const VERSIONS: [Version; 2] = [
    Version {
        id: 1,
        salt: *b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",
        key: "quic key",
        iv: "quic iv",
        hp: "quic hp",
        initial: 0,
        retry: 3,
    },
    // RFC 9369
    Version {
        id: 0x6b33_43cf,
        salt: *b"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9",
        key: "quicv2 key",
        iv: "quicv2 iv",
        hp: "quicv2 hp",
        initial: 1,
        retry: 0,
    },
];

/// Обычный ClientHello с постквантовым key share занимает около 2 КБ.
const MAX_HELLO: usize = 16 * 1024;
const MAX_FLOWS: usize = 256;
const TTL: Duration = Duration::from_secs(10);

fn expand_label(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) -> Option<()> {
    let len = (out.len() as u16).to_be_bytes();
    let full = [(6 + label.len()) as u8];
    hk.expand_multi_info(&[&len, &full, b"tls13 ", label.as_bytes(), &[0]], out)
        .ok()
}

/// key, iv и hp клиента.
fn secrets(v: &Version, dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let initial = Hkdf::<Sha256>::new(Some(&v.salt), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, "client in", &mut secret)?;
    let client = Hkdf::<Sha256>::from_prk(&secret).ok()?;
    let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand_label(&client, v.key, &mut key)?;
    expand_label(&client, v.iv, &mut iv)?;
    expand_label(&client, v.hp, &mut hp)?;
    Some((key, iv, hp))
}

struct Keys {
    aead: Aes128Gcm,
    iv: [u8; 12],
    hp: Aes128,
}

impl Keys {
    fn new(v: &Version, dcid: &[u8]) -> Option<Self> {
        let (key, iv, hp) = secrets(v, dcid)?;
        Some(Self {
            aead: Aes128Gcm::new_from_slice(&key).ok()?,
            iv,
            hp: Aes128::new_from_slice(&hp).ok()?,
        })
    }

    fn nonce(&self, pn: u64) -> Nonce<Aes128Gcm> {
        let mut n = self.iv;
        for (a, b) in n[4..].iter_mut().zip(pn.to_be_bytes()) {
            *a ^= b;
        }
        n.into()
    }

    fn mask(&self, sample: &[u8]) -> Option<[u8; 16]> {
        let mut block = Block::<Aes128>::try_from(sample).ok()?;
        self.hp.encrypt_block(&mut block);
        Some(block.into())
    }
}

fn varint(d: &[u8], p: usize) -> Option<(u64, usize)> {
    let first = *d.get(p)?;
    let n = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as u64;
    for b in d.get(p + 1..p + n)? {
        v = (v << 8) | *b as u64;
    }
    Some((v, n))
}

struct Header<'a> {
    version: &'static Version,
    initial: bool,
    dcid: &'a [u8],
    pn_off: usize,
    end: usize,
}

/// Пакет с длинным заголовком в начале `d`. None - короткий заголовок, чужая
/// версия, Retry или обрезанный пакет: дальше в датаграмме разбирать нечего.
fn header(d: &[u8]) -> Option<Header<'_>> {
    let first = *d.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let id = u32::from_be_bytes(d.get(1..5)?.try_into().ok()?);
    let version = VERSIONS.iter().find(|v| v.id == id)?;
    let ptype = (first >> 4) & 3;
    if ptype == version.retry {
        return None;
    }
    let dcid_len = *d.get(5)? as usize;
    if dcid_len > 20 {
        return None;
    }
    let dcid = d.get(6..6 + dcid_len)?;
    let mut p = 6 + dcid_len;
    p += 1 + *d.get(p)? as usize;
    let initial = ptype == version.initial;
    if initial {
        let (token, n) = varint(d, p)?;
        p += n + usize::try_from(token).ok()?;
    }
    let (len, n) = varint(d, p)?;
    p += n;
    let end = p.checked_add(usize::try_from(len).ok()?)?;
    (end <= d.len()).then_some(Header {
        version,
        initial,
        dcid,
        pn_off: p,
        end,
    })
}

/// Снятие защиты заголовка и расшифровка. Проверка тега отсекает Initial
/// сервера (у него другие ключи) и все, что только похоже на QUIC.
fn open(keys: &Keys, d: &[u8], h: &Header) -> Option<Vec<u8>> {
    let mut pkt = d[..h.end].to_vec();
    let mask = keys.mask(pkt.get(h.pn_off + 4..h.pn_off + 20)?)?;
    pkt[0] ^= mask[0] & 0x0f;
    let pn_len = (pkt[0] & 3) as usize + 1;
    let mut pn = 0u64;
    for i in 0..pn_len {
        pkt[h.pn_off + i] ^= mask[1 + i];
        pn = (pn << 8) | pkt[h.pn_off + i] as u64;
    }
    let body = h.pn_off + pn_len;
    let tag_at = h.end.checked_sub(16).filter(|&t| t >= body)?;
    let tag = Tag::<Aes128Gcm>::try_from(&pkt[tag_at..]).ok()?;
    let (aad, rest) = pkt.split_at_mut(body);
    keys.aead
        .decrypt_inout_detached(
            &keys.nonce(pn),
            aad,
            (&mut rest[..tag_at - body]).into(),
            &tag,
        )
        .ok()?;
    pkt.truncate(tag_at);
    pkt.drain(..body);
    Some(pkt)
}

/// Куски CRYPTO из открытого Initial. Кроме них в Initial бывают только
/// PADDING, PING, ACK и CONNECTION_CLOSE, на остальном разбор прекращается.
fn crypto_frames(d: &[u8]) -> Vec<(usize, &[u8])> {
    let mut out = Vec::new();
    let mut p = 0;
    let skip = |p: &mut usize, count: usize| -> Option<()> {
        for _ in 0..count {
            *p += varint(d, *p)?.1;
        }
        Some(())
    };
    while let Some(&t) = d.get(p) {
        p += 1;
        let ok = match t {
            0x00 | 0x01 => Some(()),
            0x02 | 0x03 => (|| {
                skip(&mut p, 2)?;
                let (ranges, n) = varint(d, p)?;
                p += n;
                skip(&mut p, 1 + 2 * usize::try_from(ranges).ok()?)?;
                if t == 0x03 {
                    skip(&mut p, 3)?;
                }
                Some(())
            })(),
            0x06 => (|| {
                let (off, n) = varint(d, p)?;
                p += n;
                let (len, n) = varint(d, p)?;
                p += n;
                let len = usize::try_from(len).ok()?;
                out.push((usize::try_from(off).ok()?, d.get(p..p + len)?));
                p += len;
                Some(())
            })(),
            0x1c => (|| {
                skip(&mut p, 2)?;
                let (len, n) = varint(d, p)?;
                p += n + usize::try_from(len).ok()?;
                Some(())
            })(),
            _ => None,
        };
        if ok.is_none() {
            break;
        }
    }
    out
}

struct Flow {
    buf: Vec<u8>,
    filled: Vec<bool>,
    ready: usize,
    seen: Instant,
    done: bool,
}

impl Flow {
    /// Кладет кусок на место и отдает SNI, когда ClientHello собран целиком.
    fn add(&mut self, off: usize, data: &[u8]) -> Option<String> {
        let end = off.saturating_add(data.len()).min(MAX_HELLO);
        if off < end {
            if self.buf.len() < end {
                self.buf.resize(end, 0);
                self.filled.resize(end, false);
            }
            self.buf[off..end].copy_from_slice(&data[..end - off]);
            self.filled[off..end].fill(true);
        }
        while self.filled.get(self.ready) == Some(&true) {
            self.ready += 1;
        }
        let head = self.buf.get(..4).filter(|_| self.ready >= 4)?;
        let total = 4 + (u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize);
        if head[0] != 0x01 || total > MAX_HELLO {
            self.finish();
            return None;
        }
        if self.ready < total {
            return None;
        }
        let sni = client_hello_sni(&self.buf[..total]);
        self.finish();
        sni
    }

    fn finish(&mut self) {
        self.done = true;
        self.buf = Vec::new();
        self.filled = Vec::new();
    }
}

type Key = (IpAddr, u16, Vec<u8>);

/// Сборщик ClientHello по соединениям: клиент, его порт и исходный DCID.
pub struct Assembler {
    flows: HashMap<Key, Flow>,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Датаграмма UDP. SNI возвращается один раз, на пакете, который
    /// дособрал ClientHello.
    pub fn feed(&mut self, src: IpAddr, sport: u16, mut d: &[u8]) -> Option<String> {
        let mut sni = None;
        while let Some(h) = header(d) {
            if h.initial
                && let Some(keys) = Keys::new(h.version, h.dcid)
                && let Some(plain) = open(&keys, d, &h)
                && let Some(flow) = self.flow((src, sport, h.dcid.to_vec()))
            {
                for (off, data) in crypto_frames(&plain) {
                    if flow.done {
                        break;
                    }
                    sni = flow.add(off, data).or(sni);
                }
            }
            d = &d[h.end..];
        }
        sni
    }

    fn flow(&mut self, key: Key) -> Option<&mut Flow> {
        let now = Instant::now();
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            self.flows.retain(|_, f| now.duration_since(f.seen) < TTL);
            if self.flows.len() >= MAX_FLOWS
                && let Some(old) = self
                    .flows
                    .iter()
                    .min_by_key(|(_, f)| f.seen)
                    .map(|(k, _)| k.clone())
            {
                self.flows.remove(&old);
            }
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            buf: Vec::new(),
            filled: Vec::new(),
            ready: 0,
            seen: now,
            done: false,
        });
        flow.seen = now;
        (!flow.done).then_some(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        s.chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    const DCID: &str = "8394c8f03e515708";
    const V1_PACKET: &str = include_str!("testdata/rfc9001-client-initial.hex");
    const V2_PACKET: &str = include_str!("testdata/rfc9369-client-initial.hex");

    /// Кадр CRYPTO с ClientHello из RFC 9001, A.2: SNI example.com.
    const CRYPTO: &str = include_str!("testdata/rfc9001-client-hello-crypto.hex");

    fn hello() -> Vec<u8> {
        unhex(CRYPTO)[4..].to_vec()
    }

    fn crypto(off: usize, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06, 0x40 | (off >> 8) as u8, off as u8];
        f.extend([0x40 | (data.len() >> 8) as u8, data.len() as u8]);
        f.extend(data);
        f
    }

    /// Initial клиента, как его собирает отправитель: тот же путь в обратную сторону.
    fn seal(v: &Version, dcid: &[u8], pn: u32, pn_len: usize, mut frames: Vec<u8>) -> Vec<u8> {
        frames.resize(frames.len().max(1162), 0);
        let keys = Keys::new(v, dcid).unwrap();
        let mut pkt = vec![0xc0 | (v.initial << 4) | (pn_len as u8 - 1)];
        pkt.extend(v.id.to_be_bytes());
        pkt.push(dcid.len() as u8);
        pkt.extend(dcid);
        pkt.extend([0, 0]);
        let len = pn_len + frames.len() + 16;
        pkt.extend([0x40 | (len >> 8) as u8, len as u8]);
        let pn_off = pkt.len();
        pkt.extend(&pn.to_be_bytes()[4 - pn_len..]);
        let tag = keys
            .aead
            .encrypt_inout_detached(&keys.nonce(pn as u64), &pkt, frames.as_mut_slice().into())
            .unwrap();
        pkt.extend(frames);
        pkt.extend(tag.as_slice());
        let mask = keys.mask(&pkt[pn_off + 4..pn_off + 20]).unwrap();
        pkt[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            pkt[pn_off + i] ^= mask[1 + i];
        }
        pkt
    }

    #[test]
    fn keys_match_rfc() {
        let (key, iv, hp) = secrets(&VERSIONS[0], &unhex(DCID)).unwrap();
        assert_eq!(key.to_vec(), unhex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv.to_vec(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp.to_vec(), unhex("9f50449e04a0e810283a1e9933adedd2"));
        let (key, iv, hp) = secrets(&VERSIONS[1], &unhex(DCID)).unwrap();
        assert_eq!(key.to_vec(), unhex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(iv.to_vec(), unhex("91f73e2351d8fa91660e909f"));
        assert_eq!(hp.to_vec(), unhex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    #[test]
    fn rfc_client_initial() {
        for packet in [V1_PACKET, V2_PACKET] {
            let mut a = Assembler::new();
            let d = unhex(packet);
            assert_eq!(d.len(), 1200);
            let src = "192.0.2.1".parse().unwrap();
            assert_eq!(a.feed(src, 50000, &d).as_deref(), Some("example.com"));
            assert_eq!(a.feed(src, 50000, &d), None, "SNI отдается один раз");
        }
    }

    #[test]
    fn seal_matches_rfc() {
        for (v, packet) in VERSIONS.iter().zip([V1_PACKET, V2_PACKET]) {
            assert_eq!(seal(v, &unhex(DCID), 2, 4, unhex(CRYPTO)), unhex(packet));
        }
    }

    #[test]
    fn split_hello_out_of_order() {
        let dcid = unhex("0011223344556677");
        let h = hello();
        let mut first = vec![0x01];
        first.extend(crypto(150, &h[150..]));
        first.extend([0, 0, 0x01]);
        let mut second = crypto(60, &h[60..150]);
        second.extend([0x01, 0, 0]);
        second.extend(crypto(0, &h[..60]));

        let src: IpAddr = "2001:db8::1".parse().unwrap();
        let p1 = seal(&VERSIONS[0], &dcid, 0, 1, first);
        let p2 = seal(&VERSIONS[0], &dcid, 1, 1, second);
        let mut a = Assembler::new();
        assert_eq!(a.feed(src, 443, &p1), None);
        assert_eq!(a.feed(src, 443, &p2).as_deref(), Some("example.com"));

        let mut coalesced = p2.clone();
        coalesced.extend(&p1);
        assert_eq!(
            Assembler::new().feed(src, 443, &coalesced).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn foreign_packets_leave_no_state() {
        let src = "192.0.2.1".parse().unwrap();
        let mut a = Assembler::new();
        let mut d = unhex(V1_PACKET);
        d[100] ^= 1;
        assert_eq!(a.feed(src, 1, &d), None);
        d[..5].copy_from_slice(&[0x40, 1, 2, 3, 4]);
        assert_eq!(a.feed(src, 1, &d), None);
        assert!(a.flows.is_empty());
    }

    #[test]
    fn limits() {
        let dcid = unhex("0102030405060708");
        let src = "192.0.2.1".parse().unwrap();
        let mut a = Assembler::new();
        let huge = crypto(0, &[0x01, 0x01, 0, 0]);
        assert_eq!(a.feed(src, 1, &seal(&VERSIONS[0], &dcid, 0, 1, huge)), None);
        let flow = a.flows.values().next().unwrap();
        assert!(flow.done && flow.buf.is_empty());

        let mut f = Flow {
            buf: Vec::new(),
            filled: Vec::new(),
            ready: 0,
            seen: Instant::now(),
            done: false,
        };
        assert_eq!(f.add(usize::MAX - 1, &[1, 2, 3]), None);
        assert!(f.buf.is_empty());
    }

    #[test]
    fn udp_frame_gets_sni() {
        let quic = unhex(V1_PACKET);
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7,
        ];
        let total = 20 + 8 + quic.len();
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip.extend(50000u16.to_be_bytes());
        ip.extend(443u16.to_be_bytes());
        ip.extend(((8 + quic.len()) as u16).to_be_bytes());
        ip.extend([0, 0]);
        ip.extend(&quic);

        let mut a = Assembler::new();
        let p = crate::pcap::parse_link_with(101, &ip, Some(&mut a)).unwrap();
        assert_eq!(p.sni.as_deref(), Some("example.com"));
        assert_eq!(crate::pcap::parse_link(101, &ip).unwrap().sni, None);
    }
}
