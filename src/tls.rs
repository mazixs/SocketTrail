//! Ограниченная сборка начала TCP-потока для TLS ClientHello.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_STREAM: usize = 32 * 1024;
const MAX_HELLO: usize = 16 * 1024;
const MAX_FLOWS: usize = 256;
const TTL: Duration = Duration::from_secs(10);
type Key = (IpAddr, u16, IpAddr, u16);

struct Flow {
    base: Option<u32>,
    pending: Vec<(u32, Vec<u8>)>,
    buf: Vec<u8>,
    filled: Vec<bool>,
    ready: usize,
    seen: Instant,
    done: bool,
}

impl Flow {
    fn finish(&mut self) {
        self.done = true;
        self.pending.clear();
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.filled.clear();
        self.filled.shrink_to_fit();
    }

    fn place(&mut self, sequence: u32, data: &[u8]) {
        let Some(base) = self.base else {
            return;
        };
        let offset = sequence.wrapping_sub(base) as usize;
        if offset >= MAX_STREAM || data.len() > MAX_STREAM - offset {
            return;
        }
        let end = offset + data.len();
        self.buf.resize(self.buf.len().max(end), 0);
        self.filled.resize(self.filled.len().max(end), false);
        // Противоречивые retransmit не дают достоверного имени.
        for (i, &byte) in data.iter().enumerate() {
            let at = offset + i;
            if self.filled[at] && self.buf[at] != byte {
                self.finish();
                return;
            }
            self.buf[at] = byte;
            self.filled[at] = true;
        }
        while self.filled.get(self.ready) == Some(&true) {
            self.ready += 1;
        }
    }

    fn add(&mut self, sequence: u32, data: &[u8]) -> Option<String> {
        if self.done || data.is_empty() || data.len() > MAX_STREAM {
            return None;
        }
        if self.base.is_none() {
            if data.first() == Some(&0x16) {
                self.base = Some(sequence);
                for (seq, bytes) in std::mem::take(&mut self.pending) {
                    self.place(seq, &bytes);
                }
            } else {
                let held: usize = self.pending.iter().map(|(_, d)| d.len()).sum();
                if self.pending.len() < 16 && held + data.len() <= MAX_STREAM {
                    self.pending.push((sequence, data.to_vec()));
                }
                return None;
            }
        }
        self.place(sequence, data);
        if self.done {
            return None;
        }
        let mut hello = Vec::new();
        let mut offset = 0;
        while self.ready.saturating_sub(offset) >= 5 {
            if self.buf[offset] != 0x16 || self.buf[offset + 1] != 3 {
                self.finish();
                return None;
            }
            let size = u16::from_be_bytes([self.buf[offset + 3], self.buf[offset + 4]]) as usize;
            if size == 0 || size > MAX_HELLO || hello.len() + size > MAX_HELLO {
                self.finish();
                return None;
            }
            if offset + 5 + size > self.ready {
                return None;
            }
            hello.extend_from_slice(&self.buf[offset + 5..offset + 5 + size]);
            offset += 5 + size;
            if hello.len() >= 4 {
                let total = 4 + u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
                if hello[0] != 1 || total > MAX_HELLO {
                    self.finish();
                    return None;
                }
                if hello.len() >= total {
                    let sni = crate::pcap::client_hello_sni(&hello[..total]);
                    self.finish();
                    return sni;
                }
            }
        }
        None
    }
}

#[derive(Default)]
pub struct Assembler {
    flows: HashMap<Key, Flow>,
}

impl Assembler {
    pub fn feed(&mut self, key: Key, sequence: u32, flags: u8, data: &[u8]) -> Option<String> {
        let syn = flags & 2 != 0;
        if flags & 4 != 0 {
            self.flows.remove(&key);
            return None;
        }
        if self
            .flows
            .get(&key)
            .is_some_and(|f| f.seen.elapsed() >= TTL)
        {
            self.flows.remove(&key);
        }
        if syn {
            self.flows.remove(&key);
        }
        if !syn && data.is_empty() {
            return None;
        }
        if !self.flows.contains_key(&key)
            && self.flows.len() >= MAX_FLOWS
            && let Some(old) = self
                .flows
                .iter()
                .min_by_key(|(_, f)| f.seen)
                .map(|(k, _)| *k)
        {
            self.flows.remove(&old);
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            base: syn.then_some(sequence.wrapping_add(1)),
            pending: Vec::new(),
            buf: Vec::new(),
            filled: Vec::new(),
            ready: 0,
            seen: Instant::now(),
            done: false,
        });
        flow.seen = Instant::now();
        let result = flow.add(sequence.wrapping_add(u32::from(syn)), data);
        if flags & 1 != 0 {
            self.flows.remove(&key);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello() -> Vec<u8> {
        let hex: Vec<u8> = include_str!("testdata/rfc9001-client-hello-crypto.hex")
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .collect();
        let data: Vec<u8> = hex
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        data[4..].to_vec()
    }
    fn record(data: &[u8]) -> Vec<u8> {
        let mut r = vec![22, 3, 3];
        r.extend((data.len() as u16).to_be_bytes());
        r.extend(data);
        r
    }
    fn key() -> Key {
        (
            "192.0.2.1".parse().unwrap(),
            40000,
            "198.51.100.1".parse().unwrap(),
            443,
        )
    }
    #[test]
    fn segments_reorder_retransmit_and_sequence_wrap() {
        let data = record(&hello());
        for base in [100u32, u32::MAX - 50] {
            let mut a = Assembler::default();
            assert!(a.feed(key(), base, 2, &[]).is_none());
            let first = base.wrapping_add(1);
            assert!(
                a.feed(key(), first.wrapping_add(100), 0x18, &data[100..])
                    .is_none()
            );
            assert!(
                a.feed(key(), first.wrapping_add(100), 0x18, &data[100..])
                    .is_none()
            );
            assert_eq!(
                a.feed(key(), first, 0x18, &data[..100]).as_deref(),
                Some("example.com")
            );
        }
    }
    #[test]
    fn multiple_records_and_capture_without_syn() {
        let h = hello();
        let mut data = record(&h[..100]);
        data.extend(record(&h[100..]));
        let mut a = Assembler::default();
        assert!(a.feed(key(), 200, 0x18, &data[100..]).is_none());
        assert_eq!(
            a.feed(key(), 100, 0x18, &data[..100]).as_deref(),
            Some("example.com")
        );
    }
    #[test]
    fn conflicting_retransmit_and_resource_limits() {
        let data = record(&hello());
        let mut a = Assembler::default();
        a.feed(key(), 100, 2, &[]);
        a.feed(key(), 101, 0x18, &data[..100]);
        let mut conflict = data[..100].to_vec();
        conflict[50] ^= 1;
        a.feed(key(), 101, 0x18, &conflict);
        assert!(a.feed(key(), 201, 0x18, &data[100..]).is_none());
        for port in 0..1000 {
            let mut k = key();
            k.1 = port;
            a.feed(k, 1, 0x18, &[42; 100]);
        }
        assert!(a.flows.len() <= MAX_FLOWS);
    }
    #[test]
    fn single_byte_header_without_syn_and_fin_payload() {
        let data = record(&hello());
        let mut a = Assembler::default();
        assert_eq!(a.feed(key(), 100, 0x18, &data[..1]), None);
        assert_eq!(
            a.feed(key(), 101, 0x19, &data[1..]).as_deref(),
            Some("example.com")
        );
        assert!(a.flows.is_empty());
    }
    #[test]
    fn large_client_hello_waits_for_all_segments() {
        let mut h = hello();
        let mut at = 38;
        at += 1 + h[at] as usize;
        at += 2 + u16::from_be_bytes([h[at], h[at + 1]]) as usize;
        at += 1 + h[at] as usize;
        let ext = u16::from_be_bytes([h[at], h[at + 1]]) as usize;
        h[at..at + 2].copy_from_slice(&((ext + 3004) as u16).to_be_bytes());
        h.extend([0, 21]);
        h.extend(3000u16.to_be_bytes());
        h.resize(h.len() + 3000, 0);
        let size = (h.len() - 4) as u32;
        h[1..4].copy_from_slice(&size.to_be_bytes()[1..]);
        let data = record(&h);
        assert!(data.len() > 2048);
        let mut a = Assembler::default();
        a.feed(key(), 100, 2, &[]);
        assert!(a.feed(key(), 101, 0x18, &data[..2048]).is_none());
        assert_eq!(
            a.feed(key(), 2149, 0x18, &data[2048..]).as_deref(),
            Some("example.com")
        );
        assert!(crate::pcap::client_hello_sni(&h[..h.len() - 1]).is_none());
    }
}
