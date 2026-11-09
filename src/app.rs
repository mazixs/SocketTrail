//! Состояние приложения и фоновые циклы: разбор пакетов, опрос сокетов, опознание адресов.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::dumpfile::Progress;
use crate::i18n::Text;
use crate::pcap::Packet;
use crate::procs::{self, ProcInfo};
use crate::recording::{self, DumpMeta, DumpOutcome, DumpPhase};
use crate::sockets::{self, SockEntry};
use crate::state::{self, Store};
use crate::{cache, capture, resolve};

/// Сколько процесс остается в списке "с трафиком" после последней активности. Без этого
/// удержания строки исчезали и появлялись вместе с паузами в обмене.
const ACTIVE_HOLD_MS: u64 = 30_000;
const PACKET_BATCH: usize = 1024;

pub struct App {
    pub store: Store,
    pub procs: Vec<ProcInfo>,
    /// Процесс считается активным до этого момента.
    pub active_until: HashMap<i32, u64>,
    pub selected: Option<i32>,
    pub selected_instance: Option<procs::Identity>,
    pub selected_name: Option<String>,
    /// Выбранный процесс завершился: его соединения остаются на экране.
    pub selected_gone: bool,
    pub capture_metrics: Arc<capture::Metrics>,
    pub group: Vec<i32>,
    pub dump: capture::Dump,
    pub dump_phase: DumpPhase,
    pub dump_outcome: Option<DumpOutcome>,
    pub dump_meta: Option<DumpMeta>,
    pub dump_progress: Arc<Progress>,
    /// Файл, который сейчас обрабатывается повторно.
    pub dump_job: Option<String>,
    pub job_progress: Arc<Progress>,
    /// последний дамп, остановленный сам после выхода процесса: для уведомления в окне
    pub auto_stopped: Option<String>,
    pub capture_on: bool,
    /// причина, по которой захват недоступен - показывается в интерфейсе
    pub capture_hint: Option<Text>,
    /// как идет захват: движок и интерфейс
    pub capture_how: Option<String>,
    pub iface: String,
    pub whois: HashMap<IpAddr, resolve::Whois>,
    /// корни собственного дерева: сам SocketTrail и поднятый им dumpcap
    pub self_roots: HashSet<i32>,
    /// собственные процессы: корни вместе со всеми потомками
    pub self_pids: HashSet<i32>,
    /// порт интерфейса, чтобы отличать подключения браузера к самому себе
    pub port: u16,
    /// захват доступен после перезапуска с правами администратора (Windows)
    pub can_elevate: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub quit: tokio::sync::mpsc::UnboundedSender<&'static str>,
}

pub type Shared = Arc<Mutex<App>>;

impl App {
    pub fn new(
        store: Store,
        capture_metrics: Arc<capture::Metrics>,
        iface: String,
        port: u16,
        quit: tokio::sync::mpsc::UnboundedSender<&'static str>,
    ) -> Self {
        Self {
            store,
            procs: Vec::new(),
            active_until: HashMap::new(),
            selected: None,
            selected_instance: None,
            selected_name: None,
            selected_gone: false,
            capture_metrics,
            group: Vec::new(),
            dump: capture::Dump::default(),
            dump_phase: DumpPhase::Idle,
            dump_outcome: None,
            dump_meta: None,
            dump_progress: Arc::default(),
            dump_job: None,
            job_progress: Arc::default(),
            auto_stopped: None,
            capture_on: false,
            capture_hint: None,
            capture_how: None,
            iface,
            whois: HashMap::new(),
            self_roots: HashSet::from([std::process::id() as i32]),
            self_pids: HashSet::from([std::process::id() as i32]),
            port,
            can_elevate: false,
            quit,
        }
    }

    pub fn is_active(&self, pid: i32, now: u64) -> bool {
        self.active_until.get(&pid).is_some_and(|t| *t > now)
    }
}

/// Паника одного обработчика не должна замораживать все окно: после нее данные
/// могут быть неполными, но отравленный Mutex остановил бы и API, и фоновые циклы.
pub fn lock(app: &Mutex<App>) -> MutexGuard<'_, App> {
    app.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Фоновый цикл после паники перезапускается, иначе данные в окне молча застынут.
pub fn supervise<F, Fut>(name: &'static str, app: &Shared, task: F)
where
    F: Fn(Shared) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let app = app.clone();
    tokio::spawn(async move {
        while let Err(e) = tokio::spawn(task(app.clone())).await {
            if !e.is_panic() {
                break;
            }
            eprintln!(
                "{}",
                t!(
                    "[{name}] the loop panicked, restarting",
                    "[{name}] цикл завершился паникой, перезапуск"
                )
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// Разбор пакетов пачкой за одну блокировку: под нагрузкой блокировка на каждый пакет
/// отставала бы от захвата, и очередь росла бы в памяти. Паника на одном пакете теряет
/// только его пачку, а не весь разбор.
pub async fn packet_loop(app: Shared, mut rx: tokio::sync::mpsc::Receiver<Packet>) {
    let mut batch = Vec::with_capacity(PACKET_BATCH);
    while rx.recv_many(&mut batch, PACKET_BATCH).await > 0 {
        let mut g = lock(&app);
        let batch_size = batch.len();
        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for p in batch.drain(..) {
                g.store.apply_packet(&p);
            }
        }));
        if applied.is_err() {
            g.capture_metrics
                .dropped
                .fetch_add(batch_size as u64, Ordering::Relaxed);
            batch.clear();
            eprintln!(
                "{}",
                t!(
                    "[capture] a packet batch was dropped after a panic",
                    "[capture] пачка пакетов отброшена после паники"
                )
            );
        }
        g.capture_metrics
            .processed
            .fetch_add(batch_size as u64, Ordering::Release);
    }
}

pub fn refresh_selected_group(g: &mut App, processes: &[ProcInfo], full: bool) {
    let Some(pid) = g.selected else {
        return;
    };
    match processes.iter().find(|p| p.pid == pid) {
        Some(process) if Some(process.identity()) == g.selected_instance => {
            g.selected_gone = false;
            if full {
                g.group = procs::descendants(processes, pid);
            }
        }
        Some(_) => {
            g.selected = None;
            g.selected_instance = None;
            g.selected_name = None;
            g.selected_gone = false;
            g.group.clear();
        }
        // Группа остается: соединения вышедшего процесса - как раз то, что смотрят после
        // его завершения, они не должны исчезать с экрана вместе с ним.
        None => g.selected_gone = true,
    }
}

/// Результат одного опроса, снятый вне блокировки.
struct Scan {
    all_procs: Option<Vec<ProcInfo>>,
    partial_procs: Vec<ProcInfo>,
    scan_pids: Vec<i32>,
    socks: Option<Vec<SockEntry>>,
    local_ips: Option<HashSet<IpAddr>>,
}

fn apply_scan(g: &mut App, scan: Scan, full: bool) {
    // Список забирается на время обновления: копировать сотни процессов на каждом
    // опросе незачем, а поля App нужны здесь одновременно с ним.
    let mut list = std::mem::take(&mut g.procs);
    if let Some(all) = scan.all_procs {
        list = all;
        // пересчет группы выбранного процесса: Proton плодит потомков на ходу
        refresh_selected_group(g, &list, true);
        // Свои - это не только сам процесс: dumpcap и короткоживущие dig
        // тоже наши, их соединения к анализу отношения не имеют.
        let mut mine: HashSet<i32> = g.self_roots.clone();
        for r in &g.self_roots {
            mine.extend(procs::descendants(&list, *r));
        }
        g.self_pids = mine;
    } else {
        let scanned: HashSet<i32> = scan.scan_pids.into_iter().collect();
        list.retain(|p| !scanned.contains(&p.pid));
        list.extend(scan.partial_procs);
        refresh_selected_group(g, &list, false);
    }
    recording::track(g, &list);
    g.procs = list;

    let App { store, procs, .. } = g;
    store.set_local_ips(scan.local_ips);
    if let Some(socks) = &scan.socks {
        let pmap: HashMap<i32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
        store.apply_sockets(socks, &pmap);
    }
    if full {
        update_active(g, scan.socks.as_deref());
    }
    g.store.enrich_names();
    apply_whois(g);
    recording::sync(g);
}

/// UDP без удаленного адреса (так всегда на Windows) активен, если по его порту идут пакеты.
fn update_active(g: &mut App, socks: Option<&[SockEntry]>) {
    let now = state::now_ms();
    let recent = now.saturating_sub(5_000);
    let until = now + ACTIVE_HOLD_MS;
    let App {
        active_until,
        store,
        ..
    } = g;
    active_until.retain(|_, t| *t > now);
    for pid in socks
        .into_iter()
        .flatten()
        .filter(|s| s.rport != 0)
        .filter_map(|s| s.pid)
    {
        active_until.insert(pid, until);
    }
    for pid in store
        .conns
        .values()
        .filter(|c| c.proto == "UDP" && !c.closed && c.last_seen >= recent)
        .filter_map(|c| c.pid)
    {
        active_until.insert(pid, until);
    }
}

/// Опрос сокетов. Выбранная группа опрашивается часто, полная карта - редко.
pub async fn poll_loop(app: Shared) {
    let mut tick: u64 = 0;
    let mut scanner = procs::Scanner::default();
    loop {
        tick += 1;
        let full = tick % 8 == 1; // примерно раз в 2 секунды

        let group = {
            let g = lock(&app);
            let mut group = if g.selected_gone {
                Vec::new()
            } else {
                g.group.clone()
            };
            if let Some(m) = &g.dump_meta {
                group.extend(m.pids.iter().copied());
            }
            group.sort_unstable();
            group.dedup();
            group
        };

        // Обход /proc/<pid>/fd и таблиц сокетов - блокирующий ввод-вывод,
        // на воркере tokio он задерживал бы ответы API.
        let (back, scan) = tokio::task::spawn_blocking(move || {
            let all_procs = full.then(|| scanner.refresh());
            let scan_pids: Vec<i32> = match &all_procs {
                Some(p) => p.iter().map(|x| x.pid).collect(),
                None => group,
            };
            let socks = sockets::snapshot(&scan_pids);
            let partial_procs = if full {
                Vec::new()
            } else {
                scanner.refresh_pids(&scan_pids)
            };
            let local_ips = if full {
                sockets::local_addresses()
            } else {
                None
            };
            (
                scanner,
                Scan {
                    all_procs,
                    partial_procs,
                    scan_pids,
                    socks,
                    local_ips,
                },
            )
        })
        .await
        .expect("socket poll");
        scanner = back;

        let stop = {
            let mut g = lock(&app);
            apply_scan(&mut g, scan, full);
            recording::should_stop(&mut g)
        };
        if stop {
            let a = app.clone();
            tokio::spawn(async move {
                if let Some(e) = recording::finish_dump(&a, true).await.error {
                    eprintln!("[dump] {e}");
                }
            });
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

const WHOIS_BATCH: usize = 8;

/// Адреса для опознания: только публичные и без повторов, иначе одно соединение
/// с CDN занимает всю пачку, а PTR для fe80:: раскрывает резолверу MAC соседей.
fn whois_targets(g: &App, retry: impl Fn(&IpAddr) -> bool) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    g.store
        .conns
        .keys()
        .map(|k| k.remote)
        .filter(|ip| state::classify(ip) == "public" && !ip.is_unspecified())
        .filter(|ip| !g.whois.contains_key(ip) && retry(ip))
        .filter(|ip| seen.insert(*ip))
        .take(WHOIS_BATCH)
        .collect()
}

/// Фоновое опознание адресов, по несколько штук за проход, с кешем.
/// Отказ резолвера кешем не считается: такой адрес пробуем еще несколько раз,
/// иначе в таблице рядом оказываются адреса с именем и без него без причины.
pub async fn whois_loop(app: Shared) {
    const MAX_RETRIES: u8 = 3;
    // Отказ при старте службы часто значит, что сеть еще не поднялась.
    const RETRY_AFTER: Duration = Duration::from_secs(600);
    let mut fails: HashMap<IpAddr, (u8, tokio::time::Instant)> = HashMap::new();
    loop {
        fails.retain(|_, (_, at)| at.elapsed() < RETRY_AFTER);
        let targets = {
            let g = lock(&app);
            whois_targets(&g, |ip| fails.get(ip).is_none_or(|(n, _)| *n < MAX_RETRIES))
        };
        // Разбираем пачкой: каждый запрос упирается в ожидание резолвера,
        // последовательно очередь из сотни адресов тянулась бы минутами.
        let done = lookup_all(targets).await;
        for (ip, w) in done {
            if w.failed {
                let e = fails.entry(ip).or_insert((0, tokio::time::Instant::now()));
                e.0 += 1;
                e.1 = tokio::time::Instant::now();
                // Частичный результат применяем, но в кеш не кладем: вернемся позже.
                if w.asn.is_none() && w.ptr.is_none() {
                    continue;
                }
            } else {
                fails.remove(&ip);
            }
            let mut g = lock(&app);
            if !w.failed {
                g.whois.insert(ip, w.clone());
            }
            for c in g.store.conns.values_mut().filter(|c| c.remote == ip) {
                if w.ptr.is_some() {
                    c.ptr.clone_from(&w.ptr);
                }
                if w.asn.is_some() {
                    c.asn.clone_from(&w.asn);
                    c.owner.clone_from(&w.owner);
                }
                if c.domain.is_none() {
                    c.domain.clone_from(&w.ptr);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

/// Перенос уже известного опознания на соединения. Нужен не только после
/// загрузки кеша с диска: к одному адресу соединения открываются снова и снова,
/// и спрашивать резолвер второй раз незачем.
fn apply_whois(g: &mut App) {
    if g.whois.is_empty() {
        return;
    }
    let App { store, whois, .. } = g;
    for c in store.conns.values_mut() {
        if c.asn.is_some() && c.domain.is_some() {
            continue;
        }
        let Some(w) = whois.get(&c.remote) else {
            continue;
        };
        if c.ptr.is_none() {
            c.ptr.clone_from(&w.ptr);
        }
        if c.asn.is_none() {
            c.asn.clone_from(&w.asn);
            c.owner.clone_from(&w.owner);
        }
        if c.domain.is_none() {
            c.domain.clone_from(&w.ptr);
        }
    }
}

async fn lookup_all(ips: Vec<IpAddr>) -> Vec<(IpAddr, resolve::Whois)> {
    let tasks: Vec<_> = ips
        .into_iter()
        .map(|ip| tokio::spawn(async move { (ip, resolve::lookup(ip).await) }))
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        if let Ok(v) = t.await {
            out.push(v);
        }
    }
    out
}

/// Имена из DNS-кеша Windows: без захвата это основной источник доменов.
#[cfg(windows)]
pub async fn dnscache_loop(app: Shared) {
    loop {
        if let Ok(pairs) = tokio::task::spawn_blocking(crate::dnscache::snapshot).await {
            let mut g = lock(&app);
            for (name, ip, ttl) in pairs {
                g.store.remember_name_for(ip, name, ttl);
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Сохранение имен на диск. Интервал редкий: файл нужен только между запусками.
pub async fn cache_loop(app: Shared) {
    let mut round: u32 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(45)).await;
        let a = app.clone();
        tokio::task::spawn_blocking(move || cache::save(|| cache_snapshot(&lock(&a))));

        // Пустой ответ резолвера держим недолго: отрицательный кеш DNS живет
        // минуты, и адрес, сегодня безымянный, через пять минут имя отдает.
        round += 1;
        let mut g = lock(&app);
        if round.is_multiple_of(8) {
            g.whois.retain(|_, w| w.ptr.is_some() || w.asn.is_some());
        }
        if g.whois.len() > state::MAX_NAMES {
            let App { whois, store, .. } = &mut *g;
            state::trim_ip_map(whois, &store.conns, state::MAX_NAMES);
        }
    }
}

pub fn cache_snapshot(g: &App) -> cache::Disk {
    cache::Disk {
        dns: HashMap::new(),
        dns_names: g
            .store
            .dns
            .iter()
            .map(|(ip, n)| (ip.to_string(), n.clone()))
            .collect(),
        whois: g
            .whois
            .iter()
            .filter(|(_, w)| w.ptr.is_some() || w.asn.is_some())
            .map(|(ip, w)| {
                (
                    ip.to_string(),
                    cache::Entry {
                        ptr: w.ptr.clone(),
                        asn: w.asn.clone(),
                        owner: w.owner.clone(),
                    },
                )
            })
            .collect(),
    }
}

/// Имена из прошлых запусков: DNS-ответ пролетает один раз, второго шанса нет.
pub fn restore_cache(g: &mut App) {
    let disk = cache::load();
    let mut restored = 0usize;
    for (ip, names) in disk.dns_names {
        if let Ok(ip) = ip.parse::<IpAddr>()
            && g.store.restore_dns(ip, names)
        {
            restored += 1;
        }
    }
    for (ip, e) in disk.whois {
        if let Ok(ip) = ip.parse::<IpAddr>() {
            g.whois.insert(
                ip,
                resolve::Whois {
                    ptr: e.ptr,
                    asn: e.asn,
                    owner: e.owner,
                    failed: false,
                },
            );
        }
    }
    if restored > 0 {
        eprintln!(
            "{}",
            t!(
                "[cache] names from cache: {restored}",
                "[cache] имен из кеша: {restored}"
            )
        );
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::sockets::Proto;

    pub fn app() -> App {
        let process = ProcInfo {
            pid: 100,
            started: 1,
            ppid: 0,
            comm: "demo".into(),
            name: "DemoGame.exe".into(),
            cmdline: "DemoGame.exe".into(),
            proton: false,
        };
        let mut store = Store::default();
        store.set_local_ips(Some(HashSet::from(["192.0.2.10".parse().unwrap()])));
        let mut app = App::new(
            store,
            Arc::default(),
            "any".into(),
            8787,
            tokio::sync::mpsc::unbounded_channel().0,
        );
        app.self_roots.clear();
        app.self_pids.clear();
        app.procs = vec![process.clone()];
        app.selected = Some(100);
        app.selected_instance = Some(process.identity());
        app.selected_name = Some(process.name.clone());
        app.group = vec![100];
        app.dump_meta = Some(recording::tests_support::meta(process));
        app
    }

    pub fn socket(cookie: u64) -> SockEntry {
        SockEntry {
            proto: Proto::Udp,
            local: "0.0.0.0".parse().unwrap(),
            lport: 40000,
            remote: "0.0.0.0".parse().unwrap(),
            rport: 0,
            state: "UNCONNECTED",
            pid: Some(100),
            ambiguous: false,
            cookie: Some(cookie),
        }
    }

    pub fn packet(port: u16) -> Packet {
        Packet {
            proto: Proto::Udp,
            src: "192.0.2.10".parse().unwrap(),
            sport: port,
            dst: "198.51.100.20".parse().unwrap(),
            dport: 27015,
            bytes: 128,
            sni: None,
            dns_addrs: Vec::new(),
        }
    }

    #[test]
    fn whois_targets_are_public_and_unique() {
        let mut g = app();
        for port in 40000..40003 {
            g.store.apply_packet(&packet(port));
        }
        for dst in [
            "224.0.0.251",
            "255.255.255.255",
            "10.0.0.1",
            "fe80::1",
            "fec0::1",
            "0.0.0.0",
            "100.64.0.1",
            "240.0.0.1",
        ] {
            g.store.apply_packet(&Packet {
                dst: dst.parse().unwrap(),
                ..packet(40010)
            });
        }
        let public: IpAddr = "198.51.100.20".parse().unwrap();
        assert_eq!(whois_targets(&g, |_| true), [public]);
        assert!(whois_targets(&g, |_| false).is_empty());
        g.whois.insert(public, resolve::Whois::default());
        assert!(whois_targets(&g, |_| true).is_empty());
    }

    #[test]
    fn selection_is_cleared_when_a_different_process_reuses_the_pid() {
        let mut g = app();
        let mut new_process = g.procs[0].clone();
        new_process.started += 1;
        refresh_selected_group(&mut g, &[new_process], false);
        assert!(g.selected.is_none() && g.selected_instance.is_none() && g.group.is_empty());
        assert!(g.selected_name.is_none());
    }

    #[test]
    fn exited_process_keeps_its_group_and_returns_if_it_is_found_again() {
        let mut g = app();
        let process = g.procs[0].clone();
        refresh_selected_group(&mut g, &[], true);
        assert_eq!(g.selected, Some(100));
        assert_eq!(g.group, [100]);
        assert!(g.selected_gone);
        refresh_selected_group(&mut g, &[process], true);
        assert!(!g.selected_gone);
    }

    #[test]
    fn process_stays_active_for_a_while_after_its_last_packet() {
        let mut g = app();
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        g.store.apply_packet(&packet(40000));
        update_active(&mut g, None);
        let now = state::now_ms();
        assert!(g.is_active(100, now));
        assert!(g.is_active(100, now + ACTIVE_HOLD_MS - 1000));
        assert!(!g.is_active(100, now + ACTIVE_HOLD_MS + 1000));
        assert!(!g.is_active(200, now));
    }

    #[test]
    fn unreadable_socket_table_skips_the_tick_instead_of_closing_everything() {
        let mut g = app();
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        let key = g.store.apply_packet(&packet(40000));
        let scan = Scan {
            all_procs: None,
            partial_procs: Vec::new(),
            scan_pids: Vec::new(),
            socks: None,
            local_ips: None,
        };
        apply_scan(&mut g, scan, false);
        assert!(!g.store.conns[&key].closed);
        assert_eq!(g.store.conns[&key].pid, Some(100));
        assert_eq!(g.procs.len(), 1, "the process list is kept between ticks");
    }
}
