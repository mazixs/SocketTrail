//! Ядро состояния: история соединений, привязка к процессам, имена и счетчики.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pcap::Packet;
use crate::procs::ProcInfo;
use crate::sockets::{Proto, SockEntry};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnKey {
    pub proto: Proto,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
}

/// Куда ведет соединение. Различать важно: к 127.0.0.53 домена не будет никогда,
/// это сам системный резолвер, а не удаленный узел.
pub fn classify(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                "loopback"
            } else if v4.is_broadcast() || o == [255, 255, 255, 255] {
                "broadcast"
            } else if v4.is_multicast() {
                "multicast"
            } else if v4.is_private() || v4.is_link_local() {
                "private"
            } else {
                "public"
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                "loopback"
            } else if v6.is_multicast() {
                "multicast"
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
            {
                "private"
            } else {
                "public"
            }
        }
    }
}

/// Понятная подпись вместо пустого места там, где доменного имени не существует.
pub fn well_known_label(ip: &IpAddr, port: u16) -> Option<&'static str> {
    match (ip.to_string().as_str(), port) {
        ("127.0.0.53", 53) => Some("systemd-resolved, локальный DNS"),
        ("127.0.0.54", _) => Some("systemd-resolved, делегирование"),
        ("127.0.0.1", _) | ("::1", _) => Some("localhost"),
        ("224.0.0.251", _) => Some("mDNS, многоадресная рассылка"),
        ("239.255.255.250", _) => Some("SSDP, обнаружение устройств"),
        ("255.255.255.255", _) => Some("широковещательная рассылка"),
        _ => None,
    }
}

#[derive(Clone, Serialize)]
pub struct Conn {
    pub id: String,
    pub proto: &'static str,
    pub local: String,
    pub lport: u16,
    pub remote: String,
    pub rport: u16,
    pub state: String,
    pub pid: Option<i32>,
    pub pname: Option<String>,
    /// Лучшее известное имя: SNI приоритетнее DNS, DNS приоритетнее PTR.
    pub domain: Option<String>,
    pub sni: Option<String>,
    pub ptr: Option<String>,
    pub asn: Option<String>,
    pub owner: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    /// Соединение видели только в пакетах, в таблице сокетов оно не поймано
    /// (типично для сессий короче интервала опроса).
    pub from_packets_only: bool,
    pub closed: bool,
    /// public, private, loopback, multicast, broadcast
    pub scope: &'static str,
}

/// Потолок истории. Каждое TIME_WAIT с новым локальным портом - отдельная запись,
/// за часы работы их набираются десятки тысяч; без потолка растет и память, и время
/// каждого прохода по таблице.
pub const MAX_CONNS: usize = 20_000;

#[derive(Default)]
pub struct Store {
    pub conns: HashMap<ConnKey, Conn>,
    /// IP -> имя из DNS-ответов
    pub dns: HashMap<IpAddr, String>,
    /// имя -> каноническое имя
    pub cnames: HashMap<String, String>,
    /// локальные адреса хоста, чтобы понимать направление пакета
    pub local_ips: HashSet<IpAddr>,
    pub packets_seen: u64,
}

fn key_id(k: &ConnKey) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        k.proto.as_str(),
        k.local,
        k.lport,
        k.remote,
        k.rport
    )
}

impl Store {
    /// Освобождение места: первыми уходят самые давние закрытые соединения,
    /// живые не трогаем ни при каких условиях.
    fn evict(&mut self) {
        if self.conns.len() < MAX_CONNS {
            return;
        }
        let target = MAX_CONNS * 9 / 10;
        let mut closed: Vec<(u64, ConnKey)> = self
            .conns
            .iter()
            .filter(|(_, c)| c.closed)
            .map(|(k, c)| (c.last_seen, *k))
            .collect();
        closed.sort_unstable_by_key(|(t, _)| *t);
        for (_, k) in closed
            .into_iter()
            .take(self.conns.len().saturating_sub(target))
        {
            self.conns.remove(&k);
        }
        // Если живых столько, что потолок все равно превышен - подрезаем самые старые из них.
        if self.conns.len() > MAX_CONNS {
            let mut all: Vec<(u64, ConnKey)> =
                self.conns.iter().map(|(k, c)| (c.last_seen, *k)).collect();
            all.sort_unstable_by_key(|(t, _)| *t);
            for (_, k) in all.into_iter().take(self.conns.len() - target) {
                self.conns.remove(&k);
            }
        }
    }

    fn entry(&mut self, k: ConnKey, from_packets: bool) -> &mut Conn {
        let t = now_ms();
        if !self.conns.contains_key(&k) {
            self.evict();
        }
        self.conns.entry(k).or_insert_with(|| Conn {
            id: key_id(&k),
            proto: k.proto.as_str(),
            local: k.local.to_string(),
            lport: k.lport,
            remote: k.remote.to_string(),
            rport: k.rport,
            state: "NEW".into(),
            pid: None,
            pname: None,
            domain: None,
            sni: None,
            ptr: None,
            asn: None,
            owner: None,
            first_seen: t,
            last_seen: t,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_pkts: 0,
            rx_pkts: 0,
            from_packets_only: from_packets,
            closed: false,
            scope: classify(&k.remote),
        })
    }

    /// Применение снимка сокетов: обновляет состояние и владельца.
    pub fn apply_sockets(&mut self, socks: &[SockEntry], procs: &HashMap<i32, ProcInfo>) {
        let t = now_ms();
        let mut alive: HashSet<ConnKey> = HashSet::with_capacity(socks.len());
        let mut udp_owner: HashMap<u16, i32> = HashMap::new();
        for s in socks {
            if s.rport == 0 {
                // слушающие сокеты в историю не идут, но UDP-порт дает владельца пакетам
                if s.proto == Proto::Udp
                    && let Some(pid) = s.pid
                {
                    udp_owner.insert(s.lport, pid);
                }
                continue;
            }
            let k = ConnKey {
                proto: s.proto,
                local: s.local,
                lport: s.lport,
                remote: s.remote,
                rport: s.rport,
            };
            // TIME_WAIT без истории - ничей сокет (ни inode, ни PID): локальные сервисы
            // оставляют их десятками тысяч, и они вытесняли бы живые соединения из истории.
            if s.state == "TIME_WAIT" && !self.conns.contains_key(&k) {
                continue;
            }
            alive.insert(k);
            let pid = s.pid;
            let pname = pid.and_then(|p| procs.get(&p)).map(|p| p.name.clone());
            let c = self.entry(k, false);
            c.state = s.state.to_string();
            c.last_seen = t;
            c.from_packets_only = false;
            c.closed = false;
            if pid.is_some() {
                c.pid = pid;
                c.pname = pname;
            }
            self.local_ips.insert(s.local);
        }
        for (k, c) in self.conns.iter_mut() {
            if c.pid.is_none()
                && k.proto == Proto::Udp
                && let Some(&pid) = udp_owner.get(&k.lport)
            {
                c.pid = Some(pid);
                c.pname = procs.get(&pid).map(|p| p.name.clone());
            }
            if !c.closed && c.state != "NEW" && !alive.contains(k) {
                c.closed = true;
                if c.state != "TIME_WAIT" {
                    c.state = "CLOSED".into();
                }
            }
        }
    }

    /// Применение пакета: счетчики, SNI, DNS.
    pub fn apply_packet(&mut self, p: &Packet) {
        self.packets_seen += 1;

        for (name, ip) in &p.dns_addrs {
            self.dns.insert(*ip, name.clone());
        }
        for (name, cname) in &p.dns_cnames {
            self.cnames.insert(name.clone(), cname.clone());
        }

        let outgoing = self.local_ips.contains(&p.src);
        let incoming = self.local_ips.contains(&p.dst);
        let k = if outgoing || !incoming {
            ConnKey {
                proto: p.proto,
                local: p.src,
                lport: p.sport,
                remote: p.dst,
                rport: p.dport,
            }
        } else {
            ConnKey {
                proto: p.proto,
                local: p.dst,
                lport: p.dport,
                remote: p.src,
                rport: p.sport,
            }
        };
        let known = self.conns.contains_key(&k);
        let c = self.entry(k, !known);
        c.last_seen = now_ms();
        if outgoing || !incoming {
            c.tx_bytes += p.bytes as u64;
            c.tx_pkts += 1;
        } else {
            c.rx_bytes += p.bytes as u64;
            c.rx_pkts += 1;
        }
        if let Some(sni) = &p.sni {
            c.sni = Some(sni.clone());
            c.domain = Some(sni.clone());
        }
    }

    /// Подтягивание имен: SNI приоритетнее DNS, DNS приоритетнее PTR. DNS-имя
    /// может прийти позже PTR (из кеша Windows или повторного запроса) и заменяет его.
    pub fn enrich_names(&mut self) {
        let dns = &self.dns;
        for c in self.conns.values_mut() {
            if c.sni.is_some() {
                continue;
            }
            let ip = c.remote.parse::<IpAddr>().ok();
            if let Some(name) = ip.as_ref().and_then(|ip| dns.get(ip)) {
                if c.domain.as_ref() != Some(name) {
                    c.domain = Some(name.clone());
                }
                continue;
            }
            if c.domain.is_some() {
                continue;
            }
            if let Some(ptr) = &c.ptr {
                c.domain = Some(ptr.clone());
                continue;
            }
            if let Some(label) = ip.and_then(|ip| well_known_label(&ip, c.rport)) {
                c.domain = Some(label.to_string());
            }
        }
    }
}
