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
/// Пара (en, ru): при смене языка подпись заменяется в уже известных соединениях.
pub fn well_known_label(ip: &IpAddr, port: u16) -> Option<(&'static str, &'static str)> {
    match (ip.to_string().as_str(), port) {
        ("127.0.0.53", 53) => Some((
            "systemd-resolved, local DNS",
            "systemd-resolved, локальный DNS",
        )),
        ("127.0.0.54", _) => Some((
            "systemd-resolved, delegation",
            "systemd-resolved, делегирование",
        )),
        ("127.0.0.1", _) | ("::1", _) => Some(("localhost", "localhost")),
        ("224.0.0.251", _) => Some(("mDNS, multicast", "mDNS, многоадресная рассылка")),
        ("239.255.255.250", _) => Some(("SSDP, device discovery", "SSDP, обнаружение устройств")),
        ("255.255.255.255", _) => Some(("broadcast", "широковещательная рассылка")),
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
    #[serde(skip)]
    udp_generation: Option<u64>,
    #[serde(skip)]
    tcp_cookie: Option<u64>,
    /// История одного кортежа содержит разные сокеты или спорное владение.
    /// Такой ряд нельзя целиком приписать одному процессу.
    #[serde(skip)]
    owner_ambiguous: bool,
}

impl Conn {
    /// Повторно использованный кортеж нельзя подписывать последним владельцем
    /// при обработке всего дампа. Сомнение сохраняется до конца записи.
    pub fn update_recording(&mut self, current: &Self) {
        let same_udp_socket =
            self.udp_generation.is_some() && self.udp_generation == current.udp_generation;
        let ambiguous = self.owner_ambiguous
            || current.owner_ambiguous
            || (self.first_seen != current.first_seen && !same_udp_socket)
            || (self.pid.is_some() && self.pid != current.pid)
            || (self.udp_generation.is_some() && self.udp_generation != current.udp_generation);
        *self = current.clone();
        if ambiguous {
            self.owner_ambiguous = true;
            self.pid = None;
            self.pname = None;
        }
    }
}

#[derive(Clone)]
struct UdpSocket {
    entry: SockEntry,
    generation: u64,
    since: u64,
}

#[derive(Clone, Copy)]
struct UdpOwner {
    generation: u64,
    since: u64,
    pid: Option<i32>,
}

#[derive(Clone, Copy)]
enum UdpMatch {
    Missing,
    Ambiguous,
    Unique(UdpOwner),
}

/// Потолок истории. Каждое TIME_WAIT с новым локальным портом - отдельная запись,
/// за часы работы их набираются десятки тысяч; без потолка растет и память, и время
/// каждого прохода по таблице.
pub const MAX_CONNS: usize = 20_000;

pub struct Store {
    pub conns: HashMap<ConnKey, Conn>,
    /// IP -> имя из DNS-ответов
    pub dns: HashMap<IpAddr, String>,
    /// имя -> каноническое имя
    pub cnames: HashMap<String, String>,
    /// локальные адреса хоста, чтобы понимать направление пакета
    pub local_ips: HashSet<IpAddr>,
    pub packets_seen: u64,
    udp_sockets: HashMap<u16, Vec<UdpSocket>>,
    socket_generation: u64,
    sockets_at: u64,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            conns: HashMap::new(),
            dns: HashMap::new(),
            cnames: HashMap::new(),
            local_ips: HashSet::new(),
            packets_seen: 0,
            udp_sockets: HashMap::new(),
            socket_generation: 0,
            sockets_at: now_ms(),
        }
    }
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
    pub fn set_local_ips(&mut self, ips: Option<HashSet<IpAddr>>) {
        if let Some(ips) = ips {
            self.local_ips = ips
                .into_iter()
                .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
                .collect();
        }
    }

    fn refresh_udp_sockets(&mut self, socks: &[SockEntry], t: u64) {
        let mut previous = std::mem::take(&mut self.udp_sockets);
        for s in socks.iter().filter(|s| s.proto == Proto::Udp) {
            let old = previous.get_mut(&s.lport).and_then(|entries| {
                let pos = entries.iter().position(|old| {
                    let e = &old.entry;
                    e.local == s.local
                        && e.remote == s.remote
                        && e.rport == s.rport
                        && e.cookie == s.cookie
                        && (s.pid.is_none() || e.pid.is_none() || e.pid == s.pid)
                })?;
                Some(entries.swap_remove(pos))
            });
            let socket = match old {
                Some(mut old) => {
                    // При частичном обходе PID неизвестен, но inode тот же:
                    // проверенную привязку этого сокета сохраняем до его исчезновения.
                    let pid = s.pid.or(old.entry.pid);
                    old.entry = s.clone();
                    old.entry.pid = pid;
                    old
                }
                None => {
                    self.socket_generation += 1;
                    UdpSocket {
                        entry: s.clone(),
                        generation: self.socket_generation,
                        // Можно привязать пакет из последнего интервала опроса,
                        // но не старую историю, накопленную до появления сокета.
                        since: self.sockets_at,
                    }
                }
            };
            self.udp_sockets.entry(s.lport).or_default().push(socket);
        }
        self.sockets_at = t;
    }

    fn udp_owner(&self, k: &ConnKey) -> UdpMatch {
        if !self.local_ips.contains(&k.local) {
            return UdpMatch::Missing;
        }
        let Some(entries) = self.udp_sockets.get(&k.lport) else {
            return UdpMatch::Missing;
        };
        let mut matching = entries.iter().filter(|s| {
            let e = &s.entry;
            (e.local == k.local
                || (e.local.is_unspecified() && e.local.is_ipv4() == k.local.is_ipv4()))
                && (e.rport == 0 || (e.remote == k.remote && e.rport == k.rport))
        });
        let Some(s) = matching.next() else {
            return UdpMatch::Missing;
        };
        if matching.next().is_some() {
            return UdpMatch::Ambiguous;
        }
        UdpMatch::Unique(UdpOwner {
            generation: s.generation,
            since: s.since,
            pid: s.entry.pid,
        })
    }

    fn attribute_udp(c: &mut Conn, owner: UdpMatch, procs: Option<&HashMap<i32, ProcInfo>>) {
        if c.owner_ambiguous {
            return;
        }
        match owner {
            UdpMatch::Unique(o)
                if c.first_seen >= o.since
                    && c.udp_generation.is_none_or(|g| g == o.generation) =>
            {
                c.udp_generation = Some(o.generation);
                if let Some(pid) = o.pid {
                    c.pid = Some(pid);
                    if let Some(procs) = procs {
                        c.pname = procs.get(&pid).map(|p| p.name.clone());
                    }
                }
            }
            UdpMatch::Missing if c.udp_generation.is_none() => {}
            _ => {
                c.owner_ambiguous = true;
                c.pid = None;
                c.pname = None;
            }
        }
    }

    /// Вытесняем сначала закрытые соединения, затем самые давние при превышении лимита.
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
            udp_generation: None,
            tcp_cookie: None,
            owner_ambiguous: false,
        })
    }

    /// Применение снимка сокетов: обновляет состояние и владельца.
    pub fn apply_sockets(&mut self, socks: &[SockEntry], procs: &HashMap<i32, ProcInfo>) {
        let t = now_ms();
        let mut alive: HashSet<ConnKey> = HashSet::with_capacity(socks.len());
        for s in socks {
            if !s.local.is_unspecified() && !s.local.is_multicast() {
                self.local_ips.insert(s.local);
            }
        }
        self.refresh_udp_sockets(socks, t);
        for s in socks {
            if s.rport == 0 {
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
            let udp_owner = self.udp_owner(&k);
            let c = self.entry(k, false);
            let terminal = matches!(s.state, "TIME_WAIT" | "CLOSE" | "DELETE_TCB");
            if s.proto == Proto::Tcp {
                let reused = c.pid.zip(pid).is_some_and(|(old, new)| old != new)
                    || c.tcp_cookie
                        .zip(s.cookie)
                        .is_some_and(|(old, new)| old != new)
                    || (c.closed && !terminal && !c.from_packets_only);
                if reused {
                    c.owner_ambiguous = true;
                    c.pid = None;
                    c.pname = None;
                    c.sni = None;
                    c.domain = None;
                }
                c.tcp_cookie = s.cookie.or(c.tcp_cookie);
            }
            c.state = s.state.to_string();
            c.last_seen = t;
            c.from_packets_only = false;
            c.closed = terminal;
            if s.proto == Proto::Udp {
                Self::attribute_udp(c, udp_owner, Some(procs));
            } else if pid.is_some() && !c.owner_ambiguous {
                c.pid = pid;
                c.pname = pname;
            }
        }
        // Владение UDP проверяется для пакетов из последнего интервала.
        // Закрытые записи остаются историей прежнего владельца, новый сокет
        // на том же порту не забирает их себе.
        let keys: Vec<_> = self.conns.keys().copied().collect();
        for k in keys {
            let owner = self.udp_owner(&k);
            let c = self.conns.get_mut(&k).unwrap();
            if k.proto == Proto::Udp && !alive.contains(&k) {
                let active = matches!(owner, UdpMatch::Unique(o)
                    if c.udp_generation.is_none_or(|g| g == o.generation));
                if !c.closed && active {
                    Self::attribute_udp(c, owner, Some(procs));
                    c.state = "ACTIVE".into();
                }
                if !active {
                    c.closed = true;
                    c.state = "CLOSED".into();
                }
                continue;
            }
            if !c.closed && c.state != "NEW" && !alive.contains(&k) {
                c.closed = true;
                if c.state != "TIME_WAIT" {
                    c.state = "CLOSED".into();
                }
            }
        }
    }

    /// Применение пакета: счетчики, SNI, DNS.
    pub fn apply_packet(&mut self, p: &Packet) -> ConnKey {
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
        let udp_owner = self.udp_owner(&k);
        let c = self.entry(k, !known);
        if p.proto == Proto::Udp {
            Self::attribute_udp(c, udp_owner, None);
            c.closed = false;
            c.state = "NEW".into();
        }
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
        k
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
            let known = ip.and_then(|ip| well_known_label(&ip, c.rport));
            if let Some((en, ru)) = known
                && c.domain.as_deref().is_some_and(|d| d == en || d == ru)
            {
                c.domain = Some(crate::i18n::tr(en, ru).to_string());
                continue;
            }
            if c.domain.is_some() {
                continue;
            }
            if let Some(ptr) = &c.ptr {
                c.domain = Some(ptr.clone());
                continue;
            }
            if let Some((en, ru)) = known {
                c.domain = Some(crate::i18n::tr(en, ru).to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn store() -> Store {
        let mut s = Store::default();
        s.set_local_ips(Some(HashSet::from([
            ip("192.0.2.10"),
            ip("192.0.2.11"),
            ip("2001:db8::10"),
        ])));
        s
    }

    fn socket(local: &str, pid: Option<i32>, cookie: u64) -> SockEntry {
        let local = ip(local);
        SockEntry {
            proto: Proto::Udp,
            local,
            lport: 40000,
            remote: if local.is_ipv4() {
                ip("0.0.0.0")
            } else {
                ip("::")
            },
            rport: 0,
            state: "UNCONNECTED",
            pid,
            cookie: Some(cookie),
        }
    }

    fn packet(src: &str, sport: u16, dst: &str, dport: u16) -> Packet {
        Packet {
            proto: Proto::Udp,
            src: ip(src),
            sport,
            dst: ip(dst),
            dport,
            bytes: 128,
            sni: None,
            dns_addrs: Vec::new(),
            dns_cnames: Vec::new(),
        }
    }

    fn outbound() -> Packet {
        packet("192.0.2.10", 40000, "198.51.100.20", 27015)
    }

    fn conn<'a>(s: &'a Store, remote: &str) -> &'a Conn {
        s.conns.values().find(|c| c.remote == remote).unwrap()
    }

    #[test]
    fn foreign_broadcast_and_multicast_do_not_borrow_local_udp_port() {
        let mut s = store();
        let socks = [socket("0.0.0.0", Some(100), 1)];
        s.apply_sockets(&socks, &HashMap::new());
        s.apply_packet(&outbound());
        for dst in ["192.0.2.255", "239.255.255.250"] {
            s.apply_packet(&packet("192.0.2.99", 40000, dst, 1900));
        }
        s.apply_sockets(&socks, &HashMap::new());
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
        assert_eq!(conn(&s, "192.0.2.255").pid, None);
        assert_eq!(conn(&s, "239.255.255.250").pid, None);
    }

    #[test]
    fn wildcard_udp_works_without_connected_tcp_and_counts_replies() {
        let mut s = store();
        let socks = [socket("0.0.0.0", Some(100), 1)];
        s.apply_sockets(&socks, &HashMap::new());
        s.apply_packet(&outbound());
        s.apply_packet(&packet("198.51.100.20", 27015, "192.0.2.10", 40000));
        assert_eq!(s.conns.len(), 1);
        let c = conn(&s, "198.51.100.20");
        assert_eq!((c.pid, c.tx_pkts, c.rx_pkts), (Some(100), 1, 1));
    }

    #[test]
    fn same_port_on_different_addresses_has_different_owners() {
        let mut s = store();
        s.apply_sockets(
            &[
                socket("192.0.2.10", Some(100), 1),
                socket("192.0.2.11", Some(200), 2),
            ],
            &HashMap::new(),
        );
        s.apply_packet(&outbound());
        s.apply_packet(&packet("192.0.2.11", 40000, "198.51.100.21", 27015));
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
        assert_eq!(conn(&s, "198.51.100.21").pid, Some(200));
    }

    #[test]
    fn ipv4_and_ipv6_wildcard_ports_do_not_share_owners() {
        let mut s = store();
        s.apply_sockets(
            &[socket("0.0.0.0", Some(100), 1), socket("::", Some(200), 2)],
            &HashMap::new(),
        );
        s.apply_packet(&outbound());
        s.apply_packet(&packet("2001:db8::10", 40000, "2001:db8::20", 27015));
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
        assert_eq!(conn(&s, "2001:db8::20").pid, Some(200));
    }

    #[test]
    fn shared_udp_endpoint_is_unattributed_in_either_snapshot_order() {
        for other in [Some(200), None] {
            for reverse in [false, true] {
                let mut s = store();
                let mut socks = [socket("0.0.0.0", Some(100), 1), socket("0.0.0.0", other, 2)];
                if reverse {
                    socks.reverse();
                }
                s.apply_sockets(&socks, &HashMap::new());
                s.apply_packet(&outbound());
                s.apply_sockets(&socks, &HashMap::new());
                assert_eq!(conn(&s, "198.51.100.20").pid, None);
            }
        }
    }

    #[test]
    fn connected_udp_does_not_own_another_remote_on_the_same_port() {
        let mut s = store();
        let mut sock = socket("192.0.2.10", Some(100), 1);
        sock.remote = ip("198.51.100.20");
        sock.rport = 27015;
        sock.state = "ACTIVE";
        s.apply_sockets(&[sock], &HashMap::new());
        s.apply_packet(&packet("192.0.2.10", 40000, "198.51.100.21", 27015));
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
        assert_eq!(conn(&s, "198.51.100.21").pid, None);
    }

    #[test]
    fn old_unknown_packets_are_not_claimed_by_a_new_socket() {
        let mut s = store();
        s.apply_packet(&outbound());
        s.conns.values_mut().next().unwrap().first_seen = 1;
        s.sockets_at = 2;
        s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &HashMap::new());
        assert_eq!(conn(&s, "198.51.100.20").pid, None);
    }

    #[test]
    fn pending_packet_is_attributed_on_the_next_poll() {
        let mut s = store();
        s.apply_packet(&outbound());
        s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &HashMap::new());
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
    }

    #[test]
    fn later_owner_scan_can_resolve_the_same_socket() {
        let mut s = store();
        s.apply_sockets(&[socket("0.0.0.0", None, 1)], &HashMap::new());
        s.apply_packet(&outbound());
        s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &HashMap::new());
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
    }

    #[test]
    fn partial_owner_scan_preserves_identity_and_process_name() {
        let mut s = store();
        let procs = HashMap::from([(
            100,
            ProcInfo {
                pid: 100,
                ppid: 0,
                comm: "demo".into(),
                name: "DemoGame.exe".into(),
                cmdline: "DemoGame.exe".into(),
                proton: false,
            },
        )]);
        s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &procs);
        s.apply_packet(&outbound());
        s.apply_sockets(&[socket("0.0.0.0", None, 1)], &procs);
        let c = conn(&s, "198.51.100.20");
        assert_eq!(c.pid, Some(100));
        assert_eq!(c.pname.as_deref(), Some("DemoGame.exe"));
        assert!(!c.closed);
    }

    #[test]
    fn port_reuse_keeps_closed_history_and_attributes_a_new_remote() {
        let mut s = store();
        s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &HashMap::new());
        s.apply_packet(&outbound());
        s.apply_sockets(&[], &HashMap::new());
        s.apply_sockets(&[socket("0.0.0.0", Some(200), 2)], &HashMap::new());
        s.apply_packet(&packet("192.0.2.10", 40000, "198.51.100.21", 27015));
        assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
        assert!(conn(&s, "198.51.100.20").closed);
        assert_eq!(conn(&s, "198.51.100.21").pid, Some(200));
    }

    #[test]
    fn reused_tuple_does_not_relabel_the_combined_history() {
        for pid in [100, 200] {
            let mut s = store();
            s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &HashMap::new());
            s.apply_packet(&outbound());
            // Даже если закрытие прошло между опросами, смена cookie заметна.
            let replacement = [socket("0.0.0.0", Some(pid), 2)];
            s.apply_sockets(&replacement, &HashMap::new());
            assert_eq!(conn(&s, "198.51.100.20").pid, Some(100));
            s.apply_packet(&outbound());
            s.apply_sockets(&replacement, &HashMap::new());
            let c = conn(&s, "198.51.100.20");
            assert_eq!(c.pid, None);
            assert_eq!(c.tx_pkts, 2);
        }
    }

    #[test]
    fn missing_socket_identity_still_detects_owner_changes() {
        let mut s = store();
        let mut first = socket("0.0.0.0", Some(100), 1);
        first.cookie = None;
        s.apply_sockets(&[first.clone()], &HashMap::new());
        s.apply_packet(&outbound());
        first.pid = Some(200);
        s.apply_sockets(&[first], &HashMap::new());
        s.apply_packet(&outbound());
        assert_eq!(conn(&s, "198.51.100.20").pid, None);
    }

    fn tcp_socket(pid: Option<i32>, cookie: Option<u64>) -> SockEntry {
        SockEntry {
            proto: Proto::Tcp,
            local: ip("192.0.2.10"),
            lport: 40000,
            remote: ip("198.51.100.20"),
            rport: 27015,
            state: "ESTABLISHED",
            pid,
            cookie,
        }
    }

    fn tcp_packet() -> Packet {
        Packet {
            proto: Proto::Tcp,
            sni: Some("example.com".into()),
            ..outbound()
        }
    }

    #[test]
    fn tcp_owner_change_does_not_relabel_previous_traffic() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        let k = s.apply_packet(&tcp_packet());
        s.apply_sockets(&[tcp_socket(Some(200), None)], &HashMap::new());
        let c = &s.conns[&k];
        assert_eq!(c.tx_bytes, 128);
        assert_eq!(c.pid, None);
        assert_eq!(c.sni, None);
        assert_eq!(c.domain, None);
        s.apply_sockets(&[tcp_socket(Some(200), None)], &HashMap::new());
        assert_eq!(s.conns[&k].pid, None);
    }

    #[test]
    fn tcp_new_inode_of_same_process_is_a_different_lifetime() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), Some(1))], &HashMap::new());
        let k = s.apply_packet(&tcp_packet());
        s.apply_sockets(&[tcp_socket(Some(100), Some(2))], &HashMap::new());
        assert_eq!(s.conns[&k].pid, None);
    }

    #[test]
    fn tcp_reopened_tuple_without_cookie_stays_unattributed() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        let k = s.apply_packet(&tcp_packet());
        s.apply_sockets(&[], &HashMap::new());
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        assert_eq!(s.conns[&k].pid, None);
        assert_eq!(s.conns[&k].tx_pkts, 1);
    }

    #[test]
    fn tcp_partial_owner_scan_keeps_the_same_socket_owner() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), Some(1))], &HashMap::new());
        let k = s.apply_packet(&tcp_packet());
        s.apply_sockets(&[tcp_socket(None, Some(1))], &HashMap::new());
        assert_eq!(s.conns[&k].pid, Some(100));
        assert_eq!(s.conns[&k].sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn tcp_time_wait_preserves_history_until_a_new_session() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        let k = s.apply_packet(&tcp_packet());
        let mut closed = tcp_socket(None, None);
        closed.state = "TIME_WAIT";
        s.apply_sockets(&[closed], &HashMap::new());
        assert!(s.conns[&k].closed);
        assert_eq!(s.conns[&k].pid, Some(100));
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        assert_eq!(s.conns[&k].pid, None);
    }

    #[test]
    fn shared_udp_port_keeps_old_history_until_an_ambiguous_packet_arrives() {
        let mut s = store();
        s.apply_sockets(&[socket("0.0.0.0", Some(100), 1)], &HashMap::new());
        let k = s.apply_packet(&outbound());
        s.apply_sockets(
            &[
                socket("0.0.0.0", Some(100), 1),
                socket("0.0.0.0", Some(200), 2),
            ],
            &HashMap::new(),
        );
        assert_eq!(s.conns[&k].pid, Some(100));
        s.apply_packet(&outbound());
        assert_eq!(s.conns[&k].pid, None);
    }
}
