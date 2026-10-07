//! Ядро состояния: история соединений, привязка к процессам, имена и счетчики.

use serde::{Deserialize, Serialize};
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

/// DNS остается предположением об IP, а не доказательством имени потока.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DnsEntry {
    pub names: Vec<DnsName>,
    pub overflow_until: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DnsName {
    pub name: String,
    pub expires: u64,
}
impl DnsEntry {
    fn unique(&self, now: u64) -> Option<&String> {
        if self.overflow_until > now {
            return None;
        }
        let mut valid = self.names.iter().filter(|n| n.expires > now);
        let first = valid.next()?;
        valid.next().is_none().then_some(&first.name)
    }
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
            } else if v4.is_private()
                || v4.is_link_local()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && o[1] & 0xc0 == 64)
            {
                // 100.64.0.0/10 - CGNAT и Tailscale, 0/8 и 240/4 зарезервированы:
                // whois и PTR по ним раскрыли бы внешнему DNS адреса своей сети.
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
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xff80) == 0xfe80
            {
                // fc00::/7, а также fe80::/10 и устаревшие site-local fec0::/10
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
    #[serde(skip)]
    pub owner_started: Option<u64>,
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
            || (self.owner_started.is_some() && self.owner_started != current.owner_started)
            || (self.udp_generation.is_some() && self.udp_generation != current.udp_generation);
        *self = current.clone();
        if ambiguous {
            self.owner_ambiguous = true;
            self.pid = None;
            self.owner_started = None;
            self.pname = None;
        }
    }
}

#[derive(Clone)]
struct UdpSocket {
    entry: SockEntry,
    owner_started: Option<u64>,
    generation: u64,
    since: u64,
}

#[derive(Clone, Copy)]
struct UdpOwner {
    generation: u64,
    since: u64,
    pid: Option<i32>,
    started: Option<u64>,
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

/// Потолок карты имен: на Windows ее каждые 3 с пополняет DNS-кеш системы,
/// при захвате - каждый DNS-ответ, включая mDNS от соседей по сети.
pub const MAX_NAMES: usize = 20_000;

/// TCP, замеченное только в пакетах, закрывается после такой тишины: таблица
/// сокетов его не покажет, а без отметки оно навсегда осталось бы живым.
const PACKET_ONLY_IDLE_MS: u64 = 60_000;

pub struct Store {
    pub conns: HashMap<ConnKey, Conn>,
    /// IP -> имя из DNS-ответов, пополняется через remember_name
    pub dns: HashMap<IpAddr, DnsEntry>,
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
            local_ips: HashSet::new(),
            packets_seen: 0,
            udp_sockets: HashMap::new(),
            socket_generation: 0,
            sockets_at: now_ms(),
        }
    }
}

/// Сокращает карту до 90% лимита за счет адресов, которых нет в истории
/// соединений. Адреса из истории остаются: whois запросил бы их снова,
/// а их число и так ограничено MAX_CONNS.
pub fn trim_ip_map<V>(map: &mut HashMap<IpAddr, V>, conns: &HashMap<ConnKey, Conn>, limit: usize) {
    let excess = map.len().saturating_sub(limit * 9 / 10);
    if excess == 0 {
        return;
    }
    let used: HashSet<IpAddr> = conns.keys().map(|k| k.remote).collect();
    let unused: Vec<IpAddr> = map
        .keys()
        .filter(|ip| !used.contains(ip))
        .take(excess)
        .copied()
        .collect();
    for ip in unused {
        map.remove(&ip);
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

    fn refresh_udp_sockets(
        &mut self,
        socks: &[SockEntry],
        procs: &HashMap<i32, &ProcInfo>,
        t: u64,
    ) {
        let mut previous = std::mem::take(&mut self.udp_sockets);
        for s in socks.iter().filter(|s| s.proto == Proto::Udp) {
            let old = previous.get_mut(&s.lport).and_then(|entries| {
                let pos = entries.iter().position(|old| {
                    let e = &old.entry;
                    e.local == s.local
                        && e.remote == s.remote
                        && e.rport == s.rport
                        && e.cookie == s.cookie
                        && old
                            .owner_started
                            .zip(s.pid.and_then(|p| procs.get(&p).map(|p| p.started)))
                            .is_none_or(|(a, b)| a == b)
                        && (s.pid.is_none() || e.pid.is_none() || e.pid == s.pid)
                })?;
                Some(entries.swap_remove(pos))
            });
            let socket = match old {
                Some(mut old) => {
                    // При частичном обходе PID неизвестен, но inode тот же:
                    // проверенную привязку этого сокета сохраняем до его исчезновения.
                    let pid = s.pid.or(old.entry.pid);
                    let ambiguous = s.ambiguous || old.entry.ambiguous;
                    old.entry = s.clone();
                    old.entry.ambiguous = ambiguous;
                    old.entry.pid = if ambiguous { None } else { pid };
                    old.owner_started = pid
                        .and_then(|p| procs.get(&p).map(|p| p.started))
                        .or(old.owner_started);
                    old
                }
                None => {
                    self.socket_generation += 1;
                    UdpSocket {
                        entry: s.clone(),
                        owner_started: s.pid.and_then(|p| procs.get(&p).map(|p| p.started)),
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
        if s.entry.ambiguous || matching.next().is_some() {
            return UdpMatch::Ambiguous;
        }
        UdpMatch::Unique(UdpOwner {
            generation: s.generation,
            since: s.since,
            pid: s.entry.pid,
            started: s.owner_started,
        })
    }

    fn attribute_udp(c: &mut Conn, owner: UdpMatch, procs: Option<&HashMap<i32, &ProcInfo>>) {
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
                    c.owner_started = o.started.or(c.owner_started);
                    if let Some(procs) = procs {
                        c.pname = procs.get(&pid).map(|p| p.name.clone());
                    }
                }
            }
            UdpMatch::Missing if c.udp_generation.is_none() => {}
            _ => {
                c.owner_ambiguous = true;
                c.pid = None;
                c.owner_started = None;
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
            owner_started: None,
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
    pub fn apply_sockets(&mut self, socks: &[SockEntry], procs: &HashMap<i32, &ProcInfo>) {
        let t = now_ms();
        let mut alive: HashSet<ConnKey> = HashSet::with_capacity(socks.len());
        for s in socks {
            if !s.local.is_unspecified() && !s.local.is_multicast() {
                self.local_ips.insert(s.local);
            }
        }
        self.refresh_udp_sockets(socks, procs, t);
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
            let owner_started = pid.and_then(|p| procs.get(&p)).map(|p| p.started);
            let udp_owner = self.udp_owner(&k);
            let c = self.entry(k, false);
            let terminal = matches!(s.state, "TIME_WAIT" | "CLOSE" | "DELETE_TCB");
            if s.proto == Proto::Tcp {
                let reused = c.pid.zip(pid).is_some_and(|(old, new)| old != new)
                    || c.owner_started
                        .zip(owner_started)
                        .is_some_and(|(old, new)| old != new)
                    || s.ambiguous
                    || c.tcp_cookie
                        .zip(s.cookie)
                        .is_some_and(|(old, new)| old != new)
                    || (c.closed && !terminal && !c.from_packets_only);
                if reused {
                    c.owner_ambiguous = true;
                    c.pid = None;
                    c.owner_started = None;
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
                c.owner_started = owner_started.or(c.owner_started);
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
            if c.closed || alive.contains(&k) {
                continue;
            }
            if c.state != "NEW" {
                c.closed = true;
                if c.state != "TIME_WAIT" {
                    c.state = "CLOSED".into();
                }
            } else if t.saturating_sub(c.last_seen) > PACKET_ONLY_IDLE_MS {
                c.closed = true;
                c.state = "CLOSED".into();
            }
        }
    }

    pub fn restore_dns(&mut self, ip: IpAddr, mut names: DnsEntry) -> bool {
        let now = now_ms();
        names
            .names
            .retain(|n| n.expires > now && !n.name.is_empty() && n.name.len() <= 253);
        if names.names.len() > 8 {
            names.overflow_until = names.overflow_until.max(
                names.names[8..]
                    .iter()
                    .map(|n| n.expires)
                    .max()
                    .unwrap_or(0),
            );
            names.names.truncate(8);
        }
        if (names.names.is_empty() && names.overflow_until <= now) || self.dns.len() >= MAX_NAMES {
            return false;
        }
        self.dns.insert(ip, names);
        true
    }

    #[cfg(test)]
    pub fn remember_name(&mut self, ip: IpAddr, name: String) {
        self.remember_name_for(ip, name, 300);
    }

    pub fn remember_name_for(&mut self, ip: IpAddr, name: String, ttl: u32) {
        if name.is_empty() || name.len() > 253 {
            return;
        }
        if self.dns.len() >= MAX_NAMES && !self.dns.contains_key(&ip) {
            trim_ip_map(&mut self.dns, &self.conns, MAX_NAMES);
            if self.dns.len() >= MAX_NAMES {
                return;
            }
        }
        let now = now_ms();
        let name = name.to_ascii_lowercase();
        let entry = self.dns.entry(ip).or_default();
        entry.names.retain(|n| n.expires > now && n.name != name);
        if ttl == 0 {
            return;
        }
        let expires = now.saturating_add(u64::from(ttl).min(86400) * 1000);
        if entry.names.len() < 8 {
            entry.names.push(DnsName { name, expires });
        } else {
            entry.overflow_until = entry.overflow_until.max(expires);
        }
    }

    /// Применение пакета: счетчики, SNI, DNS.
    pub fn apply_packet(&mut self, p: &Packet) -> ConnKey {
        self.packets_seen += 1;

        for (name, ip, ttl) in &p.dns_addrs {
            self.remember_name_for(*ip, name.clone(), *ttl);
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
        } else if c.closed && c.from_packets_only {
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
            let known = ip.and_then(|ip| well_known_label(&ip, c.rport));
            let is_label = |d: &str| known.is_some_and(|(en, ru)| d == en || d == ru);
            // Закрытое соединение сохраняет DNS-имя, под которым шло: позже тот же
            // адрес CDN отвечает за другой домен. PTR и подпись по-прежнему заменяются.
            let frozen = c
                .domain
                .as_deref()
                .is_some_and(|d| c.ptr.as_deref() != Some(d) && !is_label(d));
            if let Some(name) = ip
                .as_ref()
                .and_then(|ip| dns.get(ip).and_then(|d| d.unique(now_ms())))
                && !frozen
            {
                if c.domain.as_ref() != Some(name) {
                    c.domain = Some(name.clone());
                }
                continue;
            }
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
            ambiguous: false,
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
        let game = ProcInfo {
            pid: 100,
            started: 1,
            ppid: 0,
            comm: "demo".into(),
            name: "DemoGame.exe".into(),
            cmdline: "DemoGame.exe".into(),
            proton: false,
        };
        let procs = HashMap::from([(100, &game)]);
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
            ambiguous: false,
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

    #[test]
    fn packet_only_tcp_closes_after_silence_and_reopens_on_traffic() {
        let mut s = store();
        let k = s.apply_packet(&Packet {
            proto: Proto::Tcp,
            ..outbound()
        });
        s.apply_sockets(&[], &HashMap::new());
        assert!(!s.conns[&k].closed);
        s.conns.get_mut(&k).unwrap().last_seen -= PACKET_ONLY_IDLE_MS + 1;
        s.apply_sockets(&[], &HashMap::new());
        assert!(s.conns[&k].closed);
        s.apply_packet(&Packet {
            proto: Proto::Tcp,
            ..outbound()
        });
        assert!(!s.conns[&k].closed);
        assert_eq!(s.conns[&k].state, "NEW");
    }

    #[test]
    fn closed_connection_keeps_the_dns_name_it_was_opened_with() {
        let mut s = store();
        let remote = ip("198.51.100.20");
        s.remember_name(remote, "a.example.com".into());
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        s.enrich_names();
        s.apply_sockets(&[], &HashMap::new());
        s.remember_name(remote, "b.example.com".into());
        s.enrich_names();
        assert_eq!(
            conn(&s, "198.51.100.20").domain.as_deref(),
            Some("a.example.com")
        );
    }

    #[test]
    fn closed_connection_replaces_ptr_with_a_later_dns_name() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        s.apply_sockets(&[], &HashMap::new());
        let c = s.conns.values_mut().next().unwrap();
        c.ptr = Some("host.example.net".into());
        c.domain = c.ptr.clone();
        s.remember_name(ip("198.51.100.20"), "example.com".into());
        s.enrich_names();
        assert_eq!(
            conn(&s, "198.51.100.20").domain.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn name_map_is_capped_and_keeps_names_of_known_connections() {
        let mut s = store();
        s.apply_sockets(&[tcp_socket(Some(100), None)], &HashMap::new());
        let used = ip("198.51.100.20");
        s.remember_name(used, "example.com".into());
        for i in 0..MAX_NAMES as u32 {
            s.remember_name(
                IpAddr::from((0x0a00_0000 + i).to_be_bytes()),
                "x.example".into(),
            );
        }
        assert!(s.dns.len() <= MAX_NAMES);
        assert_eq!(
            s.dns
                .get(&used)
                .and_then(|d| d.unique(now_ms()))
                .map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn shared_and_reserved_ranges_are_not_public() {
        for a in [
            "100.64.0.1",
            "100.127.255.254",
            "0.1.2.3",
            "240.0.0.1",
            "10.0.0.1",
            "fec0::1",
            "fe80::1",
            "fd00::1",
        ] {
            assert_eq!(classify(&ip(a)), "private", "{a}");
        }
        for a in [
            "100.63.255.255",
            "100.128.0.1",
            "198.51.100.20",
            "2001:db8::1",
        ] {
            assert_eq!(classify(&ip(a)), "public", "{a}");
        }
    }

    #[test]
    fn trim_never_drops_addresses_of_known_connections() {
        let mut s = store();
        let mut map = HashMap::new();
        for i in 1..=20u8 {
            let remote = format!("198.51.100.{i}");
            s.apply_packet(&packet("192.0.2.10", 40000, &remote, 443));
            map.insert(ip(&remote), ());
        }
        map.insert(ip("203.0.113.1"), ());
        trim_ip_map(&mut map, &s.conns, 10);
        assert_eq!(map.len(), 20);
        assert!(!map.contains_key(&ip("203.0.113.1")));
    }
    #[test]
    fn active_flow_keeps_its_dns_name_and_shared_ip_has_no_guess() {
        let mut s = store();
        let remote = ip("198.51.100.20");
        s.remember_name(remote, "a.example.com".into());
        s.apply_packet(&packet("192.0.2.10", 40000, "198.51.100.20", 443));
        s.enrich_names();
        s.remember_name(remote, "b.example.com".into());
        let next = s.apply_packet(&packet("192.0.2.10", 40001, "198.51.100.20", 443));
        s.enrich_names();
        assert_eq!(s.conns[&next].domain, None);
        assert_eq!(
            s.conns
                .values()
                .find(|c| c.lport == 40000)
                .unwrap()
                .domain
                .as_deref(),
            Some("a.example.com")
        );
    }
    #[test]
    fn expired_zero_ttl_and_overflowed_dns_cannot_name_new_flows() {
        let mut s = store();
        let remote = ip("198.51.100.20");
        s.remember_name_for(remote, "expired.example.com".into(), 60);
        s.dns.get_mut(&remote).unwrap().names[0].expires = now_ms().saturating_sub(1);
        let k = s.apply_packet(&packet("192.0.2.10", 40000, "198.51.100.20", 443));
        s.enrich_names();
        assert!(s.conns[&k].domain.is_none());
        s.remember_name_for(remote, "zero.example.com".into(), 0);
        assert!(s.dns[&remote].unique(now_ms()).is_none());
        for i in 0..20 {
            s.remember_name_for(remote, format!("{i}.example.com"), 60);
        }
        assert_eq!(s.dns[&remote].names.len(), 8);
        s.dns.get_mut(&remote).unwrap().names.truncate(1);
        assert!(
            s.dns[&remote].unique(now_ms()).is_none(),
            "discarded names still make this address ambiguous"
        );
    }
    #[test]
    fn shared_inode_stays_unattributed_after_partial_scan() {
        for proto in [Proto::Udp, Proto::Tcp] {
            let mut s = store();
            let mut entry = socket("0.0.0.0", None, 1);
            entry.proto = proto;
            entry.ambiguous = true;
            if proto == Proto::Tcp {
                entry.local = ip("192.0.2.10");
                entry.remote = ip("198.51.100.20");
                entry.rport = 443;
                entry.state = "ESTABLISHED";
            }
            s.apply_sockets(&[entry.clone()], &HashMap::new());
            let mut p = packet("192.0.2.10", 40000, "198.51.100.20", 443);
            p.proto = proto;
            let k = s.apply_packet(&p);
            entry.pid = Some(100);
            entry.ambiguous = false;
            s.apply_sockets(&[entry], &HashMap::new());
            assert!(s.conns[&k].pid.is_none());
        }
    }
    #[test]
    fn repeated_pid_with_new_process_start_disputes_socket_history() {
        let mut s = store();
        let mut p = ProcInfo {
            pid: 100,
            started: 1,
            ppid: 0,
            comm: "demo".into(),
            name: "demo".into(),
            cmdline: "demo".into(),
            proton: false,
        };
        let sock = tcp_socket(Some(p.pid), Some(1));
        s.apply_sockets(std::slice::from_ref(&sock), &HashMap::from([(p.pid, &p)]));
        p.started += 1;
        s.apply_sockets(&[sock], &HashMap::from([(p.pid, &p)]));
        assert!(
            s.conns
                .values()
                .all(|c| c.pid.is_none() && c.owner_started.is_none())
        );
    }
    #[test]
    fn restored_cache_keeps_ambiguity_after_remembered_names_expire() {
        let mut s = store();
        let remote = ip("198.51.100.20");
        assert!(s.restore_dns(
            remote,
            DnsEntry {
                names: vec![DnsName {
                    name: "expired.example.com".into(),
                    expires: now_ms().saturating_sub(1)
                }],
                overflow_until: now_ms() + 60_000
            }
        ));
        s.remember_name(remote, "fresh.example.com".into());
        assert!(s.dns[&remote].unique(now_ms()).is_none());
        let missing = ip("198.51.100.21");
        assert!(!s.restore_dns(missing, DnsEntry::default()));
    }
}
