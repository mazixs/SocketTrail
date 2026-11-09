//! Отбор, сортировка и свертка соединений для таблицы. Все тяжелое считается на сервере:
//! клиенту незачем получать десятки тысяч записей, чтобы показать один экран.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::state::Conn;

/// Сеть: адрес с длиной префикса.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Биты адреса вне префикса обнуляются. None - длина больше размера адреса.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let addr = match addr {
            IpAddr::V4(v4) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
            _ => return None,
        };
        Some(Self { addr, prefix })
    }

    /// "198.51.100.7" или "198.51.100.0/24".
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        match s.split_once('/') {
            Some((addr, prefix)) => Self::new(addr.parse().ok()?, prefix.parse().ok()?),
            None => {
                let addr: IpAddr = s.parse().ok()?;
                Self::new(addr, if addr.is_ipv4() { 32 } else { 128 })
            }
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        Self::new(*ip, self.prefix).is_some_and(|n| n.addr == self.addr)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Подсеть для сводок и разбиения дампа: /24 для IPv4, /48 для IPv6.
pub fn subnet_of(ip: &IpAddr) -> IpNet {
    let prefix = if ip.is_ipv4() { 24 } else { 48 };
    IpNet::new(*ip, prefix).unwrap_or(IpNet {
        addr: *ip,
        prefix: 0,
    })
}

/// Регистрируемый домен без списка публичных суффиксов: две последние метки, три при
/// двухбуквенной зоне вида example.co.uk или example.com.au. Имя с пробелами - это не
/// домен, а подпись особого адреса, она остается как есть.
pub fn base_domain(name: &str) -> String {
    if name.contains(' ') {
        return name.to_string();
    }
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return name;
    }
    let second_level = matches!(
        labels[n - 2],
        "com" | "net" | "org" | "co" | "ac" | "edu" | "gov" | "or" | "ne" | "go"
    );
    let keep = if labels[n - 1].len() == 2 && second_level {
        3
    } else {
        2
    };
    labels[n - keep..].join(".")
}

/// Значение совпадает с доменом и всеми его поддоменами.
fn domain_matches(domain: &str, value: &str) -> bool {
    let (d, v) = (domain.as_bytes(), value.as_bytes());
    if d.len() < v.len() || !d[d.len() - v.len()..].eq_ignore_ascii_case(v) {
        return false;
    }
    d.len() == v.len() || d[d.len() - v.len() - 1] == b'.'
}

/// Сравнение текста без учета регистра и без выделения памяти на каждое сравнение.
fn text_cmp(a: &str, b: &str) -> Ordering {
    a.bytes()
        .map(|c| c.to_ascii_lowercase())
        .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

/// Столбец таблицы, по которому можно отбирать.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    State,
    Dom,
    Ip,
    Port,
    Net,
    Proc,
}

impl Column {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "state" => Self::State,
            "dom" => Self::Dom,
            "ip" => Self::Ip,
            "port" => Self::Port,
            "net" => Self::Net,
            "proc" => Self::Proc,
            _ => return None,
        })
    }
}

/// Отбор по спискам: внутри столбца значения объединяются через ИЛИ, столбцы - через И.
/// Пустая строка означает "значения нет": нет имени, владельца сети или процесса.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Filters {
    pub state: Vec<String>,
    pub dom: Vec<String>,
    pub ip: Vec<String>,
    pub port: Vec<String>,
    pub net: Vec<String>,
    pub proc: Vec<String>,
}

impl Filters {
    /// Испорченный параметр не должен молча давать пустую таблицу.
    pub fn from_json(s: &str) -> Self {
        serde_json::from_str(s).unwrap_or_default()
    }

    pub fn compile(self) -> Compiled {
        Compiled {
            ip: self.ip.iter().filter_map(|v| IpNet::parse(v)).collect(),
            port: self
                .port
                .iter()
                .filter_map(|v| v.trim().parse().ok())
                .collect(),
            state: self.state,
            dom: self.dom,
            net: self.net,
            proc: self.proc,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Compiled {
    state: Vec<String>,
    dom: Vec<String>,
    ip: Vec<IpNet>,
    port: Vec<u16>,
    net: Vec<String>,
    proc: Vec<String>,
}

/// Значение или его отсутствие (пустая строка в списке).
fn matches_text(list: &[String], value: Option<&str>, same: impl Fn(&str, &str) -> bool) -> bool {
    list.is_empty()
        || list.iter().any(|v| match value {
            Some(x) => !v.is_empty() && same(x, v),
            None => v.is_empty(),
        })
}

impl Compiled {
    /// `except` - столбец, чей список не применяется: фасет показывает все его значения.
    pub fn matches(&self, c: &Conn, except: Option<Column>) -> bool {
        let on = |col: Column| except != Some(col);
        let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
        (!on(Column::State) || matches_text(&self.state, Some(c.state), same))
            && (!on(Column::Dom) || matches_text(&self.dom, c.domain.as_deref(), domain_matches))
            && (!on(Column::Ip)
                || self.ip.is_empty()
                || self.ip.iter().any(|n| n.contains(&c.remote)))
            && (!on(Column::Port) || self.port.is_empty() || self.port.contains(&c.rport))
            && (!on(Column::Net) || self.matches_net(c))
            && (!on(Column::Proc) || matches_text(&self.proc, c.pname.as_deref(), same))
    }

    fn matches_net(&self, c: &Conn) -> bool {
        self.net.is_empty()
            || self.net.iter().any(|v| {
                if v.is_empty() {
                    c.owner.is_none() && c.asn.is_none()
                } else {
                    [c.owner.as_deref(), c.asn.as_deref()]
                        .into_iter()
                        .flatten()
                        .any(|x| x.eq_ignore_ascii_case(v))
                }
            })
    }
}

/// Какие строки вообще участвуют: процесс или весь хост, протокол, поиск.
pub struct Scope<'a> {
    /// Группа выбранного процесса. None - весь хост.
    pub group: Option<HashSet<i32>>,
    pub self_pids: &'a HashSet<i32>,
    /// Порт окна: подключения браузера к самому SocketTrail в анализ не входят.
    pub ui_port: u16,
    /// tcp | udp, пусто - любой
    pub proto: String,
    pub show_local: bool,
    pub show_self: bool,
    pub text: String,
}

/// Неизвестное значение не должно молча давать пустую таблицу.
pub fn proto_param(s: &str) -> String {
    let s = s.to_ascii_lowercase();
    if s == "tcp" || s == "udp" {
        s
    } else {
        String::new()
    }
}

impl Scope<'_> {
    fn matches(&self, c: &Conn, needle: &str) -> bool {
        if !self.proto.is_empty() && !c.proto.eq_ignore_ascii_case(&self.proto) {
            return false;
        }
        if !self.show_local && c.scope != "public" {
            return false;
        }
        // сам SocketTrail, его dumpcap и подключения браузера к окну утилиты
        if !self.show_self
            && (c.pid.is_some_and(|p| self.self_pids.contains(&p))
                || (c.rport == self.ui_port && c.scope == "loopback"))
        {
            return false;
        }
        if let Some(group) = &self.group
            && !c.pid.is_some_and(|pid| group.contains(&pid))
        {
            return false;
        }
        text_matches(c, needle)
    }
}

fn text_matches(c: &Conn, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    // "tcp" и "udp" выбирают протокол, а не ищут подстроку в имени.
    if q == "tcp" || q == "udp" {
        return c.proto.eq_ignore_ascii_case(q);
    }
    let has = |v: Option<&str>| v.is_some_and(|s| s.to_lowercase().contains(q));
    c.remote.to_string().contains(q)
        || c.rport.to_string().contains(q)
        || has(c.domain.as_deref())
        || has(c.pname.as_deref())
        || has(c.owner.as_deref())
        || has(c.asn.as_deref())
        || has(Some(c.state))
}

/// Отбор строк. Порядок здесь не определен: сортировка отдельно и только для тех
/// представлений, которым она нужна.
pub fn select<'a>(
    conns: impl Iterator<Item = &'a Conn>,
    scope: &Scope,
    filters: &Compiled,
    except: Option<Column>,
) -> Vec<&'a Conn> {
    let needle = scope.text.trim().to_lowercase();
    conns
        .filter(|c| scope.matches(c, &needle) && filters.matches(c, except))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Time,
    Seen,
    State,
    Dom,
    Ip,
    Port,
    Net,
    Proc,
    Tx,
    Rx,
    Total,
}

impl SortKey {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "time" => Self::Time,
            "seen" => Self::Seen,
            "state" => Self::State,
            "dom" => Self::Dom,
            "ip" => Self::Ip,
            "port" => Self::Port,
            "net" => Self::Net,
            "proc" => Self::Proc,
            "tx" => Self::Tx,
            "rx" => Self::Rx,
            "total" => Self::Total,
            _ => return None,
        })
    }
}

/// Порядок строк. По умолчанию - время первого появления, новые сверху: в отличие от
/// времени последней активности оно не меняется, и строки не прыгают.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sort {
    pub key: SortKey,
    pub desc: bool,
}

impl Sort {
    pub fn parse(key: &str, dir: &str) -> Self {
        let key = SortKey::parse(key).unwrap_or(SortKey::Time);
        let desc = match dir {
            "asc" => false,
            "desc" => true,
            _ => !matches!(
                key,
                SortKey::Dom | SortKey::Ip | SortKey::Port | SortKey::Net | SortKey::Proc
            ),
        };
        Self { key, desc }
    }

    fn apply(&self, o: Ordering) -> Ordering {
        if self.desc { o.reverse() } else { o }
    }

    /// Строки без значения всегда внизу, в какую бы сторону ни шла сортировка.
    fn text(&self, a: Option<&str>, b: Option<&str>) -> Ordering {
        match (a.filter(|s| !s.is_empty()), b.filter(|s| !s.is_empty())) {
            (Some(a), Some(b)) => self.apply(text_cmp(a, b)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
    }
}

/// От живых состояний к завершенным: так близкие по смыслу идут рядом.
fn state_rank(state: &str) -> u8 {
    match state {
        "ESTABLISHED" | "OPEN" => 0,
        "ACTIVE" => 1,
        "NEW" => 2,
        "SYN_SENT" => 3,
        "SYN_RECV" => 4,
        "LISTEN" => 5,
        "UNCONNECTED" => 6,
        "CLOSE_WAIT" => 7,
        "FIN_WAIT1" => 8,
        "FIN_WAIT2" => 9,
        "LAST_ACK" => 10,
        "CLOSING" => 11,
        "TIME_WAIT" => 12,
        "DELETE_TCB" => 13,
        "CLOSED" => 14,
        _ => 15,
    }
}

pub fn sort_conns(rows: &mut [&Conn], sort: Sort) {
    let by = |a: &Conn, b: &Conn| match sort.key {
        SortKey::Time => sort.apply(a.first_seen.cmp(&b.first_seen)),
        SortKey::Seen => sort.apply(a.last_seen.cmp(&b.last_seen)),
        SortKey::State => sort.apply(state_rank(a.state).cmp(&state_rank(b.state))),
        SortKey::Dom => sort.text(a.domain.as_deref(), b.domain.as_deref()),
        SortKey::Ip => sort.apply(a.remote.cmp(&b.remote)),
        SortKey::Port => sort.apply(a.rport.cmp(&b.rport)),
        SortKey::Net => sort
            .text(a.owner.as_deref(), b.owner.as_deref())
            .then_with(|| sort.text(a.asn.as_deref(), b.asn.as_deref())),
        SortKey::Proc => sort
            .text(a.pname.as_deref(), b.pname.as_deref())
            .then_with(|| sort.apply(a.pid.cmp(&b.pid))),
        SortKey::Tx => sort.apply(a.tx_bytes.cmp(&b.tx_bytes)),
        SortKey::Rx => sort.apply(a.rx_bytes.cmp(&b.rx_bytes)),
        SortKey::Total => sort.apply((a.tx_bytes + a.rx_bytes).cmp(&(b.tx_bytes + b.rx_bytes))),
    };
    rows.sort_by(|a, b| {
        by(a, b)
            .then_with(|| b.first_seen.cmp(&a.first_seen))
            .then_with(|| a.id.cmp(&b.id))
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    List,
    Address,
    Domain,
    Subnet,
}

impl View {
    pub fn parse(s: &str) -> Self {
        match s {
            "address" | "agg" => Self::Address,
            "domain" => Self::Domain,
            "subnet" => Self::Subnet,
            _ => Self::List,
        }
    }
}

/// Строка сводки: один адрес и порт, один домен или одна подсеть.
#[derive(Debug, Serialize)]
pub struct Group {
    pub id: String,
    /// Значение отбора для перехода к соединениям группы.
    pub key: String,
    /// Подпись группы: домен, подсеть или адрес.
    pub label: String,
    pub proto: &'static str,
    pub remote: Option<IpAddr>,
    pub rport: Option<u16>,
    pub domain: Option<String>,
    pub sni: bool,
    pub asn: Option<String>,
    pub owner: Option<String>,
    pub scope: &'static str,
    pub sessions: usize,
    pub live: usize,
    pub addresses: usize,
    pub ports: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub pname: Option<String>,
}

fn group_key(c: &Conn, view: View) -> (String, String) {
    match view {
        View::Domain => {
            let key = c.domain.as_deref().map(base_domain).unwrap_or_default();
            (format!("D|{key}"), key)
        }
        View::Subnet => {
            let key = subnet_of(&c.remote).to_string();
            (format!("S|{key}"), key)
        }
        _ => (
            format!("{}|{}|{}", c.proto, c.remote, c.rport),
            c.remote.to_string(),
        ),
    }
}

/// Свертка считается на сервере, иначе ради сводки пришлось бы отдавать клиенту всю
/// историю целиком.
pub fn group(conns: &[&Conn], view: View) -> Vec<Group> {
    let mut map: HashMap<String, (Group, HashSet<IpAddr>, HashSet<u16>)> = HashMap::new();
    for c in conns {
        let (id, key) = group_key(c, view);
        let (g, ips, ports) = map.entry(id.clone()).or_insert_with(|| {
            (
                Group {
                    id,
                    label: key.clone(),
                    key,
                    proto: c.proto,
                    remote: None,
                    rport: None,
                    domain: None,
                    sni: false,
                    asn: c.asn.clone(),
                    owner: c.owner.clone(),
                    scope: c.scope,
                    sessions: 0,
                    live: 0,
                    addresses: 0,
                    ports: 0,
                    tx_bytes: 0,
                    rx_bytes: 0,
                    first_seen: c.first_seen,
                    last_seen: c.last_seen,
                    pname: None,
                },
                HashSet::new(),
                HashSet::new(),
            )
        });
        g.sessions += 1;
        if !c.closed {
            g.live += 1;
        }
        g.tx_bytes += c.tx_bytes;
        g.rx_bytes += c.rx_bytes;
        g.first_seen = g.first_seen.min(c.first_seen);
        g.last_seen = g.last_seen.max(c.last_seen);
        if c.proto != g.proto {
            g.proto = "";
        }
        ips.insert(c.remote);
        ports.insert(c.rport);
        if c.sni.is_some() {
            g.sni = true;
            g.domain.clone_from(&c.sni);
        } else if g.domain.is_none() {
            g.domain.clone_from(&c.domain);
        }
        if g.pname.is_none() {
            g.pname.clone_from(&c.pname);
        }
        if g.asn.is_none() {
            g.asn.clone_from(&c.asn);
            g.owner.clone_from(&c.owner);
        }
    }
    map.into_values()
        .map(|(mut g, ips, ports)| {
            g.addresses = ips.len();
            g.ports = ports.len();
            if let (1, Some(ip)) = (ips.len(), ips.iter().next()) {
                g.remote = Some(*ip);
            }
            if let (1, Some(port)) = (ports.len(), ports.iter().next()) {
                g.rport = Some(*port);
            }
            // В сводке по адресам в столбце имени стоит домен, а не сам адрес.
            if view == View::Address {
                g.label = g.domain.clone().unwrap_or_default();
            }
            g
        })
        .collect()
}

pub fn sort_groups(rows: &mut [Group], sort: Sort) {
    let by = |a: &Group, b: &Group| match sort.key {
        SortKey::Time => sort.apply(a.first_seen.cmp(&b.first_seen)),
        SortKey::Seen => sort.apply(a.last_seen.cmp(&b.last_seen)),
        SortKey::State => sort.apply(a.live.cmp(&b.live)),
        SortKey::Dom => sort.text(Some(&a.label), Some(&b.label)),
        SortKey::Ip => sort.apply(
            a.remote
                .cmp(&b.remote)
                .then_with(|| a.addresses.cmp(&b.addresses)),
        ),
        SortKey::Port => sort.apply(a.rport.cmp(&b.rport).then_with(|| a.ports.cmp(&b.ports))),
        SortKey::Net => sort.text(a.owner.as_deref(), b.owner.as_deref()),
        SortKey::Proc => sort.apply(a.sessions.cmp(&b.sessions)),
        SortKey::Tx => sort.apply(a.tx_bytes.cmp(&b.tx_bytes)),
        SortKey::Rx => sort.apply(a.rx_bytes.cmp(&b.rx_bytes)),
        SortKey::Total => sort.apply((a.tx_bytes + a.rx_bytes).cmp(&(b.tx_bytes + b.rx_bytes))),
    };
    rows.sort_by(|a, b| {
        by(a, b)
            .then_with(|| sort.text(Some(&a.label), Some(&b.label)))
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// Значение в списке фильтра столбца. Дети - следующий уровень каскада.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Facet {
    pub value: String,
    pub count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Facet>,
}

/// Значения столбца с числом строк. Порядок не зависит от счетчиков, иначе пункты списка
/// менялись бы местами прямо под курсором. Пустое значение всегда в конце.
pub fn facets(conns: &[&Conn], column: Column) -> Vec<Facet> {
    let mut items = match column {
        Column::State => {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for c in conns {
                *counts.entry(c.state).or_default() += 1;
            }
            let mut v: Vec<_> = counts.into_iter().collect();
            v.sort_by_key(|(state, _)| (state_rank(state), *state));
            return v
                .into_iter()
                .map(|(state, count)| flat(state.to_string(), count))
                .collect();
        }
        Column::Port => {
            let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
            for c in conns {
                *counts.entry(c.rport).or_default() += 1;
            }
            return counts
                .into_iter()
                .map(|(port, count)| flat(port.to_string(), count))
                .collect();
        }
        Column::Dom => cascade(conns.iter().map(|c| {
            let name = c.domain.clone().unwrap_or_default();
            (
                if name.is_empty() {
                    String::new()
                } else {
                    base_domain(&name)
                },
                name,
            )
        })),
        Column::Ip => {
            let mut nets: BTreeMap<IpNet, BTreeMap<IpAddr, usize>> = BTreeMap::new();
            for c in conns {
                *nets
                    .entry(subnet_of(&c.remote))
                    .or_default()
                    .entry(c.remote)
                    .or_default() += 1;
            }
            return nets
                .into_iter()
                .map(|(net, ips)| Facet {
                    value: net.to_string(),
                    count: ips.values().sum(),
                    children: ips
                        .into_iter()
                        .map(|(ip, count)| flat(ip.to_string(), count))
                        .collect(),
                })
                .collect();
        }
        Column::Net => {
            let mut counts: HashMap<String, usize> = HashMap::new();
            for c in conns {
                let value = c.owner.as_ref().or(c.asn.as_ref()).cloned();
                *counts.entry(value.unwrap_or_default()).or_default() += 1;
            }
            counts
                .into_iter()
                .map(|(value, count)| flat(value, count))
                .collect()
        }
        Column::Proc => {
            let mut counts: HashMap<String, usize> = HashMap::new();
            for c in conns {
                *counts
                    .entry(c.pname.clone().unwrap_or_default())
                    .or_default() += 1;
            }
            counts
                .into_iter()
                .map(|(value, count)| flat(value, count))
                .collect()
        }
    };
    items.sort_by(|a, b| {
        a.value
            .is_empty()
            .cmp(&b.value.is_empty())
            .then_with(|| text_cmp(&a.value, &b.value))
    });
    items
}

fn flat(value: String, count: usize) -> Facet {
    Facet {
        value,
        count,
        children: Vec::new(),
    }
}

/// Регистрируемый домен с его поддоменами. Единственный поддомен, совпадающий с самим
/// доменом, отдельным уровнем не показывается.
fn cascade(pairs: impl Iterator<Item = (String, String)>) -> Vec<Facet> {
    let mut map: HashMap<String, BTreeMap<String, usize>> = HashMap::new();
    for (base, name) in pairs {
        *map.entry(base)
            .or_default()
            .entry(name.to_ascii_lowercase())
            .or_default() += 1;
    }
    map.into_iter()
        .map(|(value, names)| {
            let count = names.values().sum();
            let single = names.len() == 1
                && names
                    .keys()
                    .next()
                    .is_some_and(|k| k.eq_ignore_ascii_case(&value));
            Facet {
                count,
                children: if single {
                    Vec::new()
                } else {
                    names
                        .into_iter()
                        .map(|(name, count)| flat(name, count))
                        .collect()
                },
                value,
            }
        })
        .collect()
}

/// Страница результатов. Номер за пределами списка подтягивается к последней странице:
/// выборка могла сузиться, пока пользователь на нее смотрел.
pub fn page_range(total: usize, page: usize, limit: usize) -> (usize, std::ops::Range<usize>) {
    let limit = limit.max(1);
    let last = total.saturating_sub(1) / limit;
    let page = page.min(last);
    let start = page * limit;
    (page, start..(start + limit).min(total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::Packet;
    use crate::sockets::Proto;
    use crate::state::Store;

    fn conn_store(rows: &[(&str, u16, Option<&str>)]) -> Store {
        let mut s = Store::default();
        s.set_local_ips(Some(HashSet::from(["192.0.2.10".parse().unwrap()])));
        for (i, (remote, port, domain)) in rows.iter().enumerate() {
            let key = s.apply_packet(&Packet {
                proto: Proto::Udp,
                src: "192.0.2.10".parse().unwrap(),
                sport: 40000 + i as u16,
                dst: remote.parse().unwrap(),
                dport: *port,
                bytes: 100,
                sni: None,
                dns_addrs: Vec::new(),
            });
            let c = s.conns.get_mut(&key).unwrap();
            c.domain = domain.map(str::to_string);
            c.first_seen = 1000 + i as u64;
            c.last_seen = 1000 + i as u64;
        }
        s
    }

    fn scope(self_pids: &HashSet<i32>) -> Scope<'_> {
        Scope {
            group: None,
            self_pids,
            ui_port: 8787,
            proto: String::new(),
            show_local: true,
            show_self: true,
            text: String::new(),
        }
    }

    fn pick<'a>(s: &'a Store, f: &Filters) -> Vec<&'a Conn> {
        let none = HashSet::new();
        select(s.conns.values(), &scope(&none), &f.clone().compile(), None)
    }

    fn sample() -> Store {
        conn_store(&[
            ("198.51.100.1", 443, Some("api.example.com")),
            ("198.51.100.2", 443, Some("cdn.example.com")),
            ("198.51.100.3", 80, Some("example.com")),
            ("203.0.113.9", 27015, None),
            ("2001:db8:1:2::9", 443, Some("demo.example.co.uk")),
        ])
    }

    #[test]
    fn base_domain_keeps_registrable_part() {
        assert_eq!(base_domain("www.Example.COM."), "example.com");
        assert_eq!(base_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(base_domain("a.example.com.au"), "example.com.au");
        assert_eq!(base_domain("a.example.de"), "example.de");
        assert_eq!(base_domain("localhost"), "localhost");
        assert_eq!(
            base_domain("mDNS, многоадресная рассылка"),
            "mDNS, многоадресная рассылка"
        );
    }

    #[test]
    fn subnet_is_masked_to_slash_24_and_48() {
        let v4: IpAddr = "198.51.100.77".parse().unwrap();
        assert_eq!(subnet_of(&v4).to_string(), "198.51.100.0/24");
        let v6: IpAddr = "2001:db8:1:2::9".parse().unwrap();
        assert_eq!(subnet_of(&v6).to_string(), "2001:db8:1::/48");
    }

    #[test]
    fn network_parsing_and_membership() {
        let net = IpNet::parse("198.51.100.77/24").unwrap();
        assert!(net.contains(&"198.51.100.1".parse().unwrap()));
        assert!(!net.contains(&"198.51.101.1".parse().unwrap()));
        assert!(!net.contains(&"2001:db8::1".parse().unwrap()));
        let one = IpNet::parse("2001:db8::1").unwrap();
        assert!(one.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!one.contains(&"2001:db8::2".parse().unwrap()));
        assert!(
            IpNet::parse("0.0.0.0/0")
                .unwrap()
                .contains(&"203.0.113.1".parse().unwrap())
        );
        assert!(IpNet::parse("198.51.100.0/33").is_none());
        assert!(IpNet::parse("example.com").is_none());
    }

    #[test]
    fn domain_filter_covers_subdomains_but_not_lookalikes() {
        assert!(domain_matches("api.example.com", "example.com"));
        assert!(domain_matches("EXAMPLE.com", "example.COM"));
        assert!(!domain_matches("notexample.com", "example.com"));
        assert!(!domain_matches("example.com", "api.example.com"));

        let s = sample();
        let f = Filters {
            dom: vec!["example.com".into()],
            ..Filters::default()
        };
        assert_eq!(pick(&s, &f).len(), 3);
        let f = Filters {
            dom: vec![String::new()],
            ..Filters::default()
        };
        let none = pick(&s, &f);
        assert_eq!(none.len(), 1);
        assert_eq!(none[0].rport, 27015);
    }

    #[test]
    fn values_in_a_column_are_or_and_columns_are_and() {
        let s = sample();
        let f = Filters {
            port: vec!["443".into(), "80".into()],
            ip: vec!["198.51.100.0/24".into()],
            ..Filters::default()
        };
        assert_eq!(pick(&s, &f).len(), 3);
        let f = Filters {
            port: vec!["80".into()],
            dom: vec!["cdn.example.com".into()],
            ..Filters::default()
        };
        assert!(pick(&s, &f).is_empty());
    }

    #[test]
    fn state_filter_selects_one_state() {
        let mut s = sample();
        let mut rows: Vec<_> = s.conns.values_mut().collect();
        rows.sort_by_key(|c| c.rport);
        rows[0].state = "ESTABLISHED";
        let f = Filters {
            state: vec!["established".into()],
            ..Filters::default()
        };
        assert_eq!(pick(&s, &f).len(), 1);
    }

    #[test]
    fn invalid_filter_json_does_not_empty_the_table() {
        let s = sample();
        assert_eq!(pick(&s, &Filters::from_json("{broken")).len(), 5);
        assert_eq!(
            pick(&s, &Filters::from_json(r#"{"unknown":["x"]}"#)).len(),
            5
        );
    }

    #[test]
    fn default_order_is_first_seen_and_ignores_last_activity() {
        let mut s = sample();
        for c in s.conns.values_mut() {
            c.last_seen = 9_000 - c.first_seen;
        }
        let f = Filters::default();
        let mut rows = pick(&s, &f);
        sort_conns(&mut rows, Sort::parse("", ""));
        let times: Vec<u64> = rows.iter().map(|c| c.first_seen).collect();
        assert_eq!(times, [1004, 1003, 1002, 1001, 1000]);
    }

    #[test]
    fn rows_without_a_value_stay_at_the_bottom_in_both_directions() {
        let s = sample();
        let f = Filters::default();
        for dir in ["asc", "desc"] {
            let mut rows = pick(&s, &f);
            sort_conns(&mut rows, Sort::parse("dom", dir));
            assert!(rows[4].domain.is_none(), "{dir}");
            assert!(rows[0].domain.is_some(), "{dir}");
        }
        let mut rows = pick(&s, &f);
        sort_conns(&mut rows, Sort::parse("dom", "asc"));
        assert_eq!(rows[0].domain.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn equal_keys_have_a_fixed_order_between_requests() {
        let s = sample();
        let f = Filters::default();
        let order = |key: &str| {
            let mut rows = pick(&s, &f);
            sort_conns(&mut rows, Sort::parse(key, "asc"));
            rows.iter().map(|c| c.id.clone()).collect::<Vec<_>>()
        };
        for key in ["state", "port", "net", "proc", "tx"] {
            assert_eq!(order(key), order(key), "{key}");
        }
    }

    #[test]
    fn state_sort_keeps_live_connections_before_closed_ones() {
        let mut s = sample();
        let mut rows: Vec<_> = s.conns.values_mut().collect();
        rows.sort_by_key(|c| c.first_seen);
        for (c, state) in
            rows.iter_mut()
                .zip(["CLOSED", "TIME_WAIT", "ESTABLISHED", "NEW", "ACTIVE"])
        {
            c.state = state;
        }
        let f = Filters::default();
        let mut rows = pick(&s, &f);
        sort_conns(&mut rows, Sort::parse("state", "asc"));
        let states: Vec<&str> = rows.iter().map(|c| c.state).collect();
        assert_eq!(
            states,
            ["ESTABLISHED", "ACTIVE", "NEW", "TIME_WAIT", "CLOSED"]
        );
    }

    #[test]
    fn groups_by_address_domain_and_subnet() {
        let s = sample();
        let f = Filters::default();
        let rows = pick(&s, &f);

        let mut by_domain = group(&rows, View::Domain);
        sort_groups(&mut by_domain, Sort::parse("dom", "asc"));
        let keys: Vec<&str> = by_domain.iter().map(|g| g.key.as_str()).collect();
        assert_eq!(keys, ["example.co.uk", "example.com", ""]);
        let example = &by_domain[1];
        assert_eq!(
            (example.sessions, example.addresses, example.ports),
            (3, 3, 2)
        );
        assert_eq!(example.rport, None);
        assert_eq!(example.remote, None);

        let mut by_subnet = group(&rows, View::Subnet);
        sort_groups(&mut by_subnet, Sort::parse("time", "asc"));
        let keys: Vec<&str> = by_subnet.iter().map(|g| g.key.as_str()).collect();
        assert_eq!(
            keys,
            ["198.51.100.0/24", "203.0.113.0/24", "2001:db8:1::/48"]
        );

        let by_address = group(&rows, View::Address);
        assert_eq!(by_address.len(), 5);
        assert!(
            by_address
                .iter()
                .all(|g| g.remote.is_some() && g.rport.is_some())
        );
    }

    #[test]
    fn facets_are_cascaded_sorted_and_ignore_their_own_filter() {
        let s = sample();
        let f = Filters {
            dom: vec!["example.co.uk".into()],
            ..Filters::default()
        };
        let none = HashSet::new();
        let compiled = f.compile();
        let rows = select(
            s.conns.values(),
            &scope(&none),
            &compiled,
            Some(Column::Dom),
        );
        assert_eq!(rows.len(), 5, "own column does not narrow its list");
        let values = facets(&rows, Column::Dom);
        let names: Vec<&str> = values.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(names, ["example.co.uk", "example.com", ""]);
        assert_eq!(values[1].count, 3);
        let kids: Vec<&str> = values[1]
            .children
            .iter()
            .map(|v| v.value.as_str())
            .collect();
        assert_eq!(kids, ["api.example.com", "cdn.example.com", "example.com"]);
        assert_eq!(values[2].count, 1);

        let nets = facets(&rows, Column::Ip);
        assert_eq!(nets[0].value, "198.51.100.0/24");
        assert_eq!(nets[0].children.len(), 3);

        let ports = facets(&rows, Column::Port);
        let list: Vec<&str> = ports.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(list, ["80", "443", "27015"]);
    }

    #[test]
    fn pages_cover_the_list_and_clamp_past_the_end() {
        assert_eq!(page_range(0, 0, 200), (0, 0..0));
        assert_eq!(page_range(450, 0, 200), (0, 0..200));
        assert_eq!(page_range(450, 2, 200), (2, 400..450));
        assert_eq!(page_range(450, 9, 200), (2, 400..450));
        assert_eq!(page_range(400, 9, 200), (1, 200..400));
        assert_eq!(page_range(10, 3, 0), (3, 3..4));
    }
}
