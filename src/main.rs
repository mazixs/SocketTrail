//! SocketTrail - привязанный к процессу монитор сетевых соединений.

// первым: макросы t! и text! нужны остальным модулям
#[macro_use]
mod i18n;

mod alive;
mod annotate;
mod cache;
mod capture;
#[cfg(windows)]
mod dnscache;
#[cfg(windows)]
mod elevate;
#[cfg(windows)]
mod etw;
mod paths;
mod pcap;
mod procs;
mod report;
mod resolve;
mod sockets;
mod state;
mod window;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use axum::extract::Request;
use axum::extract::{Query, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::procs::ProcInfo;
use crate::state::Store;

/// Что снимает текущий дамп. Запоминается при старте: игра может закрыться раньше,
/// чем запись остановят, и в списке процессов ее к тому времени уже не будет.
struct DumpMeta {
    process: Option<ProcInfo>,
    only_group: bool,
    /// все процессы группы, замеченные за время записи
    pids: HashSet<i32>,
    started: u64,
    last_alive: u64,
}

/// Через столько после выхода всех процессов группы запись "только процесс" останавливается сама.
const DUMP_IDLE_MS: u64 = 15_000;

struct App {
    store: Store,
    procs: Vec<ProcInfo>,
    /// процессы, у которых сейчас есть внешние соединения
    active_pids: HashSet<i32>,
    selected: Option<i32>,
    group: Vec<i32>,
    dump: capture::Dump,
    dump_meta: Option<DumpMeta>,
    /// последний дамп, остановленный сам после выхода процесса: для уведомления в окне
    auto_stopped: Option<String>,
    capture_on: bool,
    /// причина, по которой захват недоступен - показывается в интерфейсе
    capture_hint: Option<i18n::Text>,
    iface: String,
    whois: HashMap<IpAddr, resolve::Whois>,
    /// корни собственного дерева: сам SocketTrail и поднятый им dumpcap
    self_roots: HashSet<i32>,
    /// собственные процессы: корни вместе со всеми потомками
    self_pids: HashSet<i32>,
    /// порт интерфейса, чтобы отличать подключения браузера к самому себе
    port: u16,
    /// захват доступен после перезапуска с правами администратора (Windows)
    can_elevate: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    quit: tokio::sync::mpsc::UnboundedSender<&'static str>,
}

type Shared = Arc<Mutex<App>>;

const HELP_EN: &str = "\
SocketTrail - network connection monitor tied to processes.

Usage: sockettrail [options]

  -i, --iface <name>  dumpcap interface, several separated by commas (default any:
                      all at once on Linux, all Npcap adapters except loopback on Windows).
                      Capture through PktMon (Windows, as administrator) uses all adapters
      --port <port>   port of the local UI (default 8787)
      --no-open       do not open the window, only start the server (background collection)
      --lang <en|ru>  language of the window and messages for this run
                      (the choice made in the window is remembered)
  -h, --help          this help

The server listens on 127.0.0.1 only. If the port is taken by a running SocketTrail,
a second launch just opens its window; if another program holds the port,
the next free one is used.

The window is Chrome, Chromium, Edge or Brave in app mode with its own profile.
Closing the window exits the program, an ongoing dump is finished and closed.
Without a Chromium browser a regular tab opens, and the program runs until Ctrl+C.
";

const HELP_RU: &str = "\
SocketTrail - монитор сетевых соединений с привязкой к процессу.

Использование: sockettrail [ключи]

  -i, --iface <имя>   интерфейс dumpcap, несколько - через запятую (по умолчанию any:
                      на Linux все сразу, на Windows все адаптеры Npcap кроме loopback).
                      Захват через PktMon (Windows, от администратора) идет со всех адаптеров
      --port <порт>   порт локального интерфейса (по умолчанию 8787)
      --no-open       не открывать окно, только поднять сервер (фоновый сбор)
      --lang <en|ru>  язык окна и сообщений на этот запуск
                      (выбор, сделанный в окне, запоминается)
  -h, --help          эта справка

Сервер слушает только 127.0.0.1. Если порт занят уже запущенным SocketTrail,
повторный запуск просто откроет его окно; если порт занят чужой программой,
берется следующий свободный.

Окно - Chrome, Chromium, Edge или Brave в режиме приложения со своим профилем.
Закрытие окна завершает программу, дамп при этом дописывается и закрывается.
Без Chromium-браузера открывается обычная вкладка, и программа работает до Ctrl+C.
";

struct Args {
    iface: String,
    port: u16,
    open: bool,
    /// перезапуск с правами: дождаться выхода прежнего экземпляра
    wait_pid: Option<u32>,
    /// окно уже открыто прежним экземпляром, оно само переподключится
    adopt: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // язык нужен раньше остальных ключей: от него зависит текст справки
    i18n::load();
    if let Some(v) = argv
        .iter()
        .position(|x| x == "--lang")
        .and_then(|i| argv.get(i + 1))
    {
        i18n::set(v);
    }
    let mut a = Args {
        iface: "any".into(),
        port: 8787,
        open: true,
        wait_pid: None,
        adopt: false,
    };
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "-h" | "--help" => {
                print!("{}", i18n::tr(HELP_EN, HELP_RU));
                std::process::exit(0);
            }
            "-i" | "--iface" => {
                if let Some(v) = argv.get(i + 1) {
                    a.iface = v.clone();
                    i += 1;
                }
            }
            "--port" => {
                if let Some(v) = argv.get(i + 1).and_then(|v| v.parse().ok()) {
                    a.port = v;
                    i += 1;
                }
            }
            "--no-open" => a.open = false,
            "--wait-pid" => {
                a.wait_pid = argv.get(i + 1).and_then(|v| v.parse().ok());
                i += 1;
            }
            "--adopt" => a.adopt = true,
            "--lang" => i += 1,
            other => eprintln!(
                "{}",
                t!(
                    "[args] unknown option {other}, ignored",
                    "[аргументы] неизвестный ключ {other}, пропущен"
                )
            ),
        }
        i += 1;
    }
    a
}

/// Проверка, что на порту отвечает именно SocketTrail, а не чужая программа.
async fn is_ours(port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    let req =
        format!("GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_millis(800), s.read_to_end(&mut buf)).await;
    matches!(read, Ok(Ok(_))) && String::from_utf8_lossy(&buf).contains("sockettrail")
}

/// Занимает порт. Если там уже работает наш экземпляр - открывает его окно и выходит,
/// чтобы повторный клик по ярлыку не плодил копии. Чужой порт - берем следующий.
async fn bind_port(pref: u16, open: bool) -> (tokio::net::TcpListener, u16) {
    for port in pref..pref.saturating_add(20) {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => return (l, port),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if is_ours(port).await {
                    let url = format!("http://127.0.0.1:{port}/");
                    eprintln!(
                        "{}",
                        t!(
                            "SocketTrail is already running: {url}",
                            "SocketTrail уже запущен: {url}"
                        )
                    );
                    if open {
                        window::open(&url);
                    }
                    std::process::exit(0);
                }
                eprintln!(
                    "{}",
                    t!(
                        "[port] {port} is used by another program, trying the next one",
                        "[порт] {port} занят другой программой, пробую следующий"
                    )
                );
            }
            Err(e) => {
                eprintln!("[port] {port}: {e}");
                std::process::exit(1);
            }
        }
    }
    let last = pref + 20;
    eprintln!(
        "{}",
        t!(
            "[port] no free port in range {pref}..{last}",
            "[порт] свободный порт не найден в диапазоне {pref}..{last}"
        )
    );
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let iface = args.iface.clone();

    #[cfg(windows)]
    if let Some(pid) = args.wait_pid {
        elevate::wait_pid(pid, 20);
    }

    // Порт занимаем до запуска dumpcap: иначе повторный клик по ярлыку
    // успел бы поднять лишний процесс захвата.
    let (listener, port) = bind_port(args.port, args.open).await;
    let (quit_tx, mut quit_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();

    let app: Shared = Arc::new(Mutex::new(App {
        store: Store::default(),
        procs: Vec::new(),
        active_pids: HashSet::new(),
        selected: None,
        group: Vec::new(),
        dump: capture::Dump::default(),
        dump_meta: None,
        auto_stopped: None,
        capture_on: false,
        capture_hint: None,
        iface: iface.clone(),
        whois: HashMap::new(),
        self_roots: HashSet::from([std::process::id() as i32]),
        self_pids: HashSet::from([std::process::id() as i32]),
        port,
        can_elevate: false,
        quit: quit_tx.clone(),
    }));

    // Имена из прошлых запусков: DNS-ответ пролетает один раз, второго шанса нет.
    {
        let disk = cache::load();
        let mut g = app.lock().unwrap();
        let mut restored = 0usize;
        for (ip, name) in disk.dns {
            if let Ok(ip) = ip.parse::<IpAddr>() {
                g.store.dns.insert(ip, name);
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

    // Живой захват держим до выхода: Drop гасит dumpcap или сессию PktMon.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let live_capture = match capture::start_live(&iface, tx) {
        Ok(live) => {
            let mut g = app.lock().unwrap();
            if let Some(pid) = live.pid() {
                g.self_roots.insert(pid as i32);
                g.self_pids.insert(pid as i32);
            }
            g.capture_on = true;
            drop(g);
            let a = app.clone();
            tokio::spawn(async move {
                while let Some(p) = rx.recv().await {
                    if let Ok(mut g) = a.lock() {
                        g.store.apply_packet(&p);
                    }
                }
            });
            let how = live.describe(&iface);
            eprintln!(
                "{}",
                t!(
                    "[capture] live packet parsing: {how}",
                    "[capture] живой разбор пакетов: {how}"
                )
            );
            Some(live)
        }
        Err(hint) => {
            let h = hint.get();
            eprintln!(
                "{}",
                t!(
                    "[capture] packet parsing is off, only socket polling remains.\n{h}",
                    "[capture] пакетный разбор выключен, остается опрос сокетов.\n{h}"
                )
            );
            let mut g = app.lock().unwrap();
            g.capture_hint = Some(hint);
            #[cfg(windows)]
            {
                g.can_elevate = etw::can_elevate();
            }
            None
        }
    };

    #[cfg(windows)]
    tokio::spawn(dnscache_loop(app.clone()));
    tokio::spawn(poll_loop(app.clone()));
    tokio::spawn(whois_loop(app.clone()));
    tokio::spawn(cache_loop(app.clone()));

    let alive = Arc::new(alive::Alive::default());
    let router = Router::new()
        .route("/", get(index))
        .route("/api/alive", {
            let a = alive.clone();
            get(move || async move { alive::stream(a) })
        })
        .route(window::UI_PATH, get(index))
        .route("/api/ping", get(api_ping))
        .route("/api/procs", get(api_procs))
        .route("/api/state", get(api_state))
        .route("/api/select", post(api_select))
        .route("/api/dump/start", post(api_dump_start))
        .route("/api/dump/stop", post(api_dump_stop))
        .route("/api/clear", post(api_clear))
        .route("/api/dumps", get(api_dumps))
        .route("/api/reveal", post(api_reveal))
        .route("/api/export", get(api_export))
        .route("/api/elevate", post(api_elevate))
        .route("/api/lang", post(api_lang))
        .layer(axum::middleware::from_fn(move |req, next| {
            guard(port, req, next)
        }))
        .with_state(app.clone());

    let url = format!("http://127.0.0.1:{port}/");
    eprintln!("SocketTrail: {url}");

    if args.open {
        spawn_window(url.clone(), quit_tx.clone(), alive.clone());
    } else if args.adopt {
        // Окно прежнего экземпляра переподключается само; если его уже нет - открываем свое.
        let (a, tx, url) = (alive.clone(), quit_tx.clone(), url.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            if a.seen() {
                alive::wait_closed(a, 10).await;
                let _ = tx.send(closed_page());
            } else {
                spawn_window(url, tx, a);
            }
        });
    }
    spawn_signal_watch(quit_tx);

    axum::serve(listener, router)
        .with_graceful_shutdown({
            let alive = alive.clone();
            async move {
                let why = quit_rx.recv().await.unwrap_or("channel closed");
                eprintln!("{} {why}", i18n::tr("[exit]", "[выход]"));
                // открытые SSE-каналы иначе держали бы сервер бесконечно
                alive.close();
            }
        })
        .await
        .unwrap();

    shutdown(&app).await;
    drop(live_capture);
}

fn closed_page() -> &'static str {
    i18n::tr(
        "window closed (page disconnected)",
        "окно закрыто (страница отключилась)",
    )
}

/// Окно в отдельном потоке: ожидание браузера блокирующее. Окно считается
/// закрытым по любому из признаков: вышел процесс профиля или страница
/// 10 секунд не держит канал /api/alive.
fn spawn_window(
    url: String,
    tx: tokio::sync::mpsc::UnboundedSender<&'static str>,
    alive: Arc<alive::Alive>,
) {
    let rt = tokio::runtime::Handle::current();
    std::thread::spawn(move || match window::open(&url) {
        window::Opened::Window(w) => {
            let t = tx.clone();
            rt.spawn(async move {
                alive::wait_closed(alive, 10).await;
                let _ = t.send(closed_page());
            });
            w.wait();
            let _ = tx.send(i18n::tr("window closed", "окно закрыто"));
        }
        window::Opened::Detached => {
            eprintln!(
                "{}",
                t!(
                    "[window] opened without tracking - exit with Ctrl+C",
                    "[окно] открыто без отслеживания - завершение по Ctrl+C"
                )
            );
        }
        window::Opened::Failed => {
            eprintln!(
                "{}",
                t!(
                    "[window] no browser found, open {url} manually",
                    "[окно] браузер не найден, откройте {url} вручную"
                )
            );
        }
    });
}

/// Перезапуск с правами администратора. Новый экземпляр ждет нашего выхода,
/// занимает тот же порт, и открытое окно продолжает работать с ним.
async fn api_elevate(State(app): State<Shared>) -> impl IntoResponse {
    #[cfg(windows)]
    {
        let (port, iface, quit) = {
            let g = app.lock().unwrap();
            (g.port, g.iface.clone(), g.quit.clone())
        };
        let mut args = format!(
            "--port {port} --no-open --adopt --lang {} --wait-pid {}",
            i18n::code(),
            std::process::id()
        );
        if iface != "any" {
            args += &format!(" -i \"{iface}\"");
        }
        let r = tokio::task::spawn_blocking(move || elevate::relaunch(&args))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        match r {
            Ok(()) => {
                let _ = quit.send(i18n::tr(
                    "restarting as administrator",
                    "перезапуск от имени администратора",
                ));
                Json(json!({ "ok": true }))
            }
            Err(e) => Json(json!({ "ok": false, "error": e })),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Json(json!({ "ok": false, "error": t!("Windows only", "только для Windows") }))
    }
}

/// Имена из DNS-кеша Windows: без захвата это основной источник доменов.
#[cfg(windows)]
async fn dnscache_loop(app: Shared) {
    loop {
        if let Ok(pairs) = tokio::task::spawn_blocking(dnscache::snapshot).await {
            let mut g = app.lock().unwrap();
            for (name, ip) in pairs {
                g.store.dns.insert(ip, name);
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Ctrl+C и SIGTERM (systemctl --user stop) ведут к тому же аккуратному выходу.
fn spawn_signal_watch(tx: tokio::sync::mpsc::UnboundedSender<&'static str>) {
    let t = tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = t.send("Ctrl+C");
        }
    });
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
            let _ = tx.send("SIGTERM");
        }
    });
    // Закрытие консольного окна, выход из системы, выключение: на очистку ~5 с.
    #[cfg(windows)]
    tokio::spawn(async move {
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let (Ok(mut a), Ok(mut b), Ok(mut c), Ok(mut d)) =
            (ctrl_close(), ctrl_shutdown(), ctrl_logoff(), ctrl_break())
        else {
            return;
        };
        let why = tokio::select! {
            _ = a.recv() => i18n::tr("console closed", "закрытие консоли"),
            _ = b.recv() => i18n::tr("shutdown", "выключение"),
            _ = c.recv() => i18n::tr("logoff", "выход из системы"),
            _ = d.recv() => "Ctrl+Break",
        };
        let _ = tx.send(why);
    });
}

/// Перед выходом: закрыть незавершенный дамп (иначе .pcapng останется без
/// карты соединений) и сохранить кеш имен.
async fn shutdown(app: &Shared) {
    let running = app.lock().unwrap().dump.is_running();
    if running {
        let (path, _, _) = finish_dump(app).await;
        if let Some(p) = path {
            eprintln!(
                "{}",
                t!("[exit] dump closed: {p}", "[выход] дамп закрыт: {p}")
            );
        }
    }
    let disk = cache_snapshot(&app.lock().unwrap());
    cache::save(&disk);
}

/// Защита локального API от чужих страниц в браузере. Проверка Host отсекает
/// DNS rebinding (чужой домен, указывающий на 127.0.0.1), проверка Origin -
/// запросы со сторонних сайтов, которые браузер отправляет без спроса (CSRF).
async fn guard(port: u16, req: Request, next: Next) -> Response {
    let allowed = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| allowed.iter().any(|a| a == h))
        .unwrap_or(false);
    let origin_ok = req.method() == Method::GET
        || match req
            .headers()
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
        {
            None => true,
            Some(o) => allowed.iter().any(|a| o == format!("http://{a}")),
        };
    if host_ok && origin_ok {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "forbidden").into_response()
    }
}

/// Опрос сокетов. Выбранная группа опрашивается часто, полная карта - редко.
async fn poll_loop(app: Shared) {
    let mut tick: u64 = 0;
    let mut scanner = procs::Scanner::default();
    loop {
        tick += 1;
        let full = tick % 8 == 1; // примерно раз в 2 секунды

        let (selected, group) = {
            let g = app.lock().unwrap();
            (g.selected, g.group.clone())
        };

        let all_procs = if full { Some(scanner.refresh()) } else { None };
        let scan_pids: Vec<i32> = match (&all_procs, selected) {
            (Some(p), _) => p.iter().map(|x| x.pid).collect(),
            (None, Some(_)) => group,
            (None, None) => Vec::new(),
        };

        let socks = sockets::snapshot(&scan_pids);

        {
            let mut g = app.lock().unwrap();
            if let Some(p) = all_procs {
                // пересчет группы выбранного процесса: Proton плодит потомков на ходу
                if let Some(sel) = g.selected {
                    g.group = procs::descendants(&p, sel);
                }
                // Свои - это не только сам процесс: dumpcap и короткоживущие dig
                // тоже наши, их соединения к анализу отношения не имеют.
                let roots: Vec<i32> = g.self_roots.iter().copied().collect();
                let mut mine: HashSet<i32> = g.self_roots.clone();
                for r in roots {
                    mine.extend(procs::descendants(&p, r));
                }
                g.self_pids = mine;
                track_dump(&mut g, &p);
                g.procs = p;
            }
            let pmap: HashMap<i32, ProcInfo> = g.procs.iter().map(|p| (p.pid, p.clone())).collect();
            g.store.apply_sockets(&socks, &pmap);
            if full {
                // UDP без удаленного адреса (так всегда на Windows) активен, если по его порту идут пакеты
                let recent = state::now_ms().saturating_sub(5_000);
                let mut active: HashSet<i32> = socks
                    .iter()
                    .filter(|s| s.rport != 0)
                    .filter_map(|s| s.pid)
                    .collect();
                active.extend(
                    g.store
                        .conns
                        .values()
                        .filter(|c| c.proto == "UDP" && !c.closed && c.last_seen >= recent)
                        .filter_map(|c| c.pid),
                );
                g.active_pids = active;
            }
            g.store.enrich_names();
            apply_whois(&mut g);
        }
        if full {
            let a = app.clone();
            tokio::spawn(async move { auto_stop_dump(&a).await });
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Фоновое опознание адресов, по несколько штук за проход, с кешем.
/// Отказ резолвера кешем не считается: такой адрес пробуем еще несколько раз,
/// иначе в таблице рядом оказываются адреса с именем и без него без причины.
async fn whois_loop(app: Shared) {
    const MAX_RETRIES: u8 = 3;
    let mut fails: HashMap<IpAddr, u8> = HashMap::new();
    loop {
        let targets: Vec<IpAddr> = {
            let g = app.lock().unwrap();
            g.store
                .conns
                .values()
                .filter_map(|c| c.remote.parse::<IpAddr>().ok())
                .filter(|ip| !g.whois.contains_key(ip) && !is_private(ip))
                .filter(|ip| fails.get(ip).copied().unwrap_or(0) < MAX_RETRIES)
                .take(8)
                .collect()
        };
        // Разбираем пачкой: каждый запрос упирается в ожидание резолвера,
        // последовательно очередь из сотни адресов тянулась бы минутами.
        let done = futures_join(targets).await;
        for (ip, w) in done {
            if w.failed {
                *fails.entry(ip).or_insert(0) += 1;
                // Частичный результат применяем, но в кеш не кладем: вернемся позже.
                if w.asn.is_none() && w.ptr.is_none() {
                    continue;
                }
            } else {
                fails.remove(&ip);
            }
            let mut g = app.lock().unwrap();
            if !w.failed {
                g.whois.insert(ip, w.clone());
            }
            let ip_s = ip.to_string();
            for c in g.store.conns.values_mut() {
                if c.remote == ip_s {
                    if w.ptr.is_some() {
                        c.ptr = w.ptr.clone();
                    }
                    if w.asn.is_some() {
                        c.asn = w.asn.clone();
                        c.owner = w.owner.clone();
                    }
                    if c.domain.is_none() {
                        c.domain = w.ptr.clone();
                    }
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
    for c in g.store.conns.values_mut() {
        if c.asn.is_some() && c.domain.is_some() {
            continue;
        }
        let Ok(ip) = c.remote.parse::<IpAddr>() else {
            continue;
        };
        let Some(w) = g.whois.get(&ip) else {
            continue;
        };
        if c.ptr.is_none() {
            c.ptr = w.ptr.clone();
        }
        if c.asn.is_none() {
            c.asn = w.asn.clone();
            c.owner = w.owner.clone();
        }
        if c.domain.is_none() {
            c.domain = w.ptr.clone();
        }
    }
}

async fn futures_join(ips: Vec<IpAddr>) -> Vec<(IpAddr, resolve::Whois)> {
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

/// Сохранение имен на диск. Интервал редкий: файл нужен только между запусками.
async fn cache_loop(app: Shared) {
    let mut round: u32 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(45)).await;
        let disk = cache_snapshot(&app.lock().unwrap());
        tokio::task::spawn_blocking(move || cache::save(&disk));

        // Пустой ответ резолвера держим недолго: отрицательный кеш DNS живет
        // минуты, и адрес, сегодня безымянный, через пять минут имя отдает.
        round += 1;
        if round.is_multiple_of(8) {
            let mut g = app.lock().unwrap();
            g.whois.retain(|_, w| w.ptr.is_some() || w.asn.is_some());
        }
    }
}

fn cache_snapshot(g: &App) -> cache::Disk {
    cache::Disk {
        dns: g
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

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Язык подставляется в разметку сразу, чтобы окно не мигало английским перед русским.
async fn index() -> impl IntoResponse {
    Html(include_str!("../ui/index.html").replacen("__LANG__", i18n::code(), 1))
}

#[derive(Deserialize)]
struct LangBody {
    lang: String,
}

async fn api_lang(Json(b): Json<LangBody>) -> impl IntoResponse {
    let ok = i18n::set(&b.lang);
    if ok {
        i18n::save();
    }
    Json(json!({ "ok": ok, "lang": i18n::code() }))
}

/// Метка своего экземпляра: по ней повторный запуск понимает, что окно уже есть.
async fn api_ping() -> impl IntoResponse {
    Json(json!({ "app": "sockettrail", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Deserialize)]
struct ProcsQuery {
    /// active | proton | all
    #[serde(default)]
    filter: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    show_self: Option<u8>,
}

async fn api_procs(State(app): State<Shared>, Query(q): Query<ProcsQuery>) -> impl IntoResponse {
    let g = app.lock().unwrap();

    // Живые соединения по процессам - показываются счетчиком в дереве.
    let mut live: HashMap<i32, usize> = HashMap::new();
    for c in g.store.conns.values() {
        if !c.closed
            && c.scope == "public"
            && let Some(pid) = c.pid
        {
            *live.entry(pid).or_insert(0) += 1;
        }
    }

    let show_self = q.show_self.unwrap_or(0) == 1;
    let needle = q.q.to_lowercase();
    let want = |p: &ProcInfo| -> bool {
        if !show_self && g.self_pids.contains(&p.pid) {
            return false;
        }
        let by_filter = match q.filter.as_str() {
            "proton" => p.proton,
            "all" => true,
            _ => g.active_pids.contains(&p.pid),
        };
        let by_query = needle.is_empty()
            || p.name.to_lowercase().contains(&needle)
            || p.pid.to_string().contains(&needle)
            || p.cmdline.to_lowercase().contains(&needle);
        by_filter && by_query
    };

    // Отобранные процессы плюс их предки: без предков дерево рассыпается на
    // отдельные ветки и связь "игра - wineserver - GameThread" теряется.
    let by_pid: HashMap<i32, &ProcInfo> = g.procs.iter().map(|p| (p.pid, p)).collect();
    let mut keep: HashSet<i32> = HashSet::new();
    let mut matched: HashSet<i32> = HashSet::new();
    for p in g.procs.iter().filter(|p| want(p)) {
        matched.insert(p.pid);
        keep.insert(p.pid);
        let mut cur = p.ppid;
        let mut guard = 0;
        while cur > 1 && guard < 64 {
            guard += 1;
            if !keep.insert(cur) {
                break;
            }
            match by_pid.get(&cur) {
                Some(parent) => cur = parent.ppid,
                None => break,
            }
        }
    }

    let list: Vec<_> = g
        .procs
        .iter()
        .filter(|p| keep.contains(&p.pid))
        .map(|p| {
            json!({
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "comm": p.comm,
                "cmdline": p.cmdline,
                "proton": p.proton,
                "active": g.active_pids.contains(&p.pid),
                "conns": live.get(&p.pid).copied().unwrap_or(0),
                "matched": matched.contains(&p.pid),
                "own": g.self_pids.contains(&p.pid),
            })
        })
        .collect();

    Json(json!({ "procs": list, "selected": g.selected, "total": g.procs.len() }))
}

#[derive(Deserialize)]
struct StateQuery {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    view: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    show_local: Option<u8>,
    #[serde(default)]
    show_self: Option<u8>,
}

struct Filter {
    only_selected: bool,
    query: String,
    show_local: bool,
    show_self: bool,
}

fn conn_matches(c: &state::Conn, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    c.remote.contains(q)
        || c.rport.to_string().contains(q)
        || c.domain
            .as_deref()
            .map(|d| d.to_lowercase().contains(q))
            .unwrap_or(false)
        || c.pname
            .as_deref()
            .map(|p| p.to_lowercase().contains(q))
            .unwrap_or(false)
        || c.owner
            .as_deref()
            .map(|o| o.to_lowercase().contains(q))
            .unwrap_or(false)
        || c.asn
            .as_deref()
            .map(|a| a.to_lowercase().contains(q))
            .unwrap_or(false)
}

/// Отбор соединений. Все тяжелое - фильтр, поиск, сортировка и срез - делается
/// здесь: клиенту незачем получать десятки тысяч записей, чтобы показать три экрана.
fn select_conns<'a>(g: &'a App, f: &Filter) -> Vec<&'a state::Conn> {
    let group: HashSet<i32> = g.group.iter().copied().collect();
    let known_hosts: HashSet<&str> = if f.only_selected {
        g.store
            .conns
            .values()
            .filter(|c| c.pid.map(|p| group.contains(&p)).unwrap_or(false))
            .map(|c| c.remote.as_str())
            .collect()
    } else {
        HashSet::new()
    };
    let q = f.query.to_lowercase();

    let mut out: Vec<&state::Conn> = g
        .store
        .conns
        .values()
        .filter(|c| {
            if !f.show_local && c.scope != "public" {
                return false;
            }
            if !f.show_self {
                // сам SocketTrail, его dumpcap и подключения браузера к окну утилиты
                if c.pid.map(|p| g.self_pids.contains(&p)).unwrap_or(false) {
                    return false;
                }
                if c.rport == g.port && c.scope == "loopback" {
                    return false;
                }
            }
            if f.only_selected {
                match c.pid {
                    Some(pid) => {
                        if !group.contains(&pid) {
                            return false;
                        }
                    }
                    None => {
                        if !(c.from_packets_only && known_hosts.contains(c.remote.as_str())) {
                            return false;
                        }
                    }
                }
            }
            conn_matches(c, &q)
        })
        .collect();
    out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.id.cmp(&b.id)));
    out
}

#[derive(Serialize)]
struct Target {
    id: String,
    proto: &'static str,
    remote: String,
    rport: u16,
    domain: Option<String>,
    sni: bool,
    asn: Option<String>,
    owner: Option<String>,
    scope: &'static str,
    sessions: usize,
    live: usize,
    tx_bytes: u64,
    rx_bytes: u64,
    first_seen: u64,
    last_seen: u64,
    pname: Option<String>,
}

/// Свертка по цели: один адрес и порт - одна строка. Считается на сервере,
/// иначе ради сводки пришлось бы отдавать клиенту всю историю целиком.
fn aggregate(conns: &[&state::Conn]) -> Vec<Target> {
    let mut map: HashMap<(&str, &str, u16), Target> = HashMap::new();
    for c in conns {
        let key = (c.proto, c.remote.as_str(), c.rport);
        let t = map.entry(key).or_insert_with(|| Target {
            id: format!("{}|{}|{}", c.proto, c.remote, c.rport),
            proto: c.proto,
            remote: c.remote.clone(),
            rport: c.rport,
            domain: None,
            sni: false,
            asn: c.asn.clone(),
            owner: c.owner.clone(),
            scope: c.scope,
            sessions: 0,
            live: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            first_seen: c.first_seen,
            last_seen: c.last_seen,
            pname: None,
        });
        t.sessions += 1;
        if !c.closed {
            t.live += 1;
        }
        t.tx_bytes += c.tx_bytes;
        t.rx_bytes += c.rx_bytes;
        t.first_seen = t.first_seen.min(c.first_seen);
        t.last_seen = t.last_seen.max(c.last_seen);
        if c.sni.is_some() {
            t.sni = true;
            t.domain = c.sni.clone();
        } else if t.domain.is_none() {
            t.domain = c.domain.clone();
        }
        if t.pname.is_none() {
            t.pname = c.pname.clone();
        }
        if t.asn.is_none() {
            t.asn = c.asn.clone();
            t.owner = c.owner.clone();
        }
    }
    let mut v: Vec<Target> = map.into_values().collect();
    v.sort_by(|a, b| {
        (b.tx_bytes + b.rx_bytes)
            .cmp(&(a.tx_bytes + a.rx_bytes))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
    });
    v
}

async fn api_state(State(app): State<Shared>, Query(q): Query<StateQuery>) -> impl IntoResponse {
    let g = app.lock().unwrap();
    let f = Filter {
        only_selected: q.scope != "host" && g.selected.is_some(),
        query: q.q.clone(),
        show_local: q.show_local.unwrap_or(0) == 1,
        show_self: q.show_self.unwrap_or(0) == 1,
    };
    let limit = q.limit.unwrap_or(400).clamp(1, 5000);
    let picked = select_conns(&g, &f);

    let attributed = picked.iter().filter(|c| c.pid.is_some()).count();
    let matched = picked.len();
    let (rows, targets, shown) = if q.view == "agg" {
        let all = aggregate(&picked);
        let total_targets = all.len();
        let head: Vec<Target> = all.into_iter().take(limit).collect();
        let shown = head.len();
        (
            json!([]),
            json!({ "items": head, "total": total_targets }),
            shown,
        )
    } else {
        let head: Vec<&state::Conn> = picked.iter().take(limit).copied().collect();
        let shown = head.len();
        (json!(head), json!(null), shown)
    };

    Json(json!({
        "conns": rows,
        "targets": targets,
        "stats": {
            "matched": matched,
            "shown": shown,
            "stored": g.store.conns.len(),
            "attributed": attributed,
            "packets": g.store.packets_seen,
            "capture": g.capture_on,
            "capture_hint": g.capture_hint.as_ref().map(|t| t.get()),
            "elevate": g.can_elevate,
            "iface": g.iface,
        },
        "dump": {
            "running": g.dump.is_running(),
            "path": g.dump.path,
            "started": g.dump.started_ms,
            "only": g.dump_meta.as_ref().is_some_and(|m| m.only_group),
            "auto_stopped": g.auto_stopped,
        },
        "group": g.group,
        "selected": g.selected,
    }))
}

#[derive(Deserialize)]
struct SelectBody {
    pid: Option<i32>,
}

async fn api_select(State(app): State<Shared>, Json(b): Json<SelectBody>) -> impl IntoResponse {
    let mut g = app.lock().unwrap();
    g.selected = b.pid;
    g.group = match b.pid {
        Some(pid) => procs::descendants(&g.procs, pid),
        None => Vec::new(),
    };
    Json(json!({ "ok": true, "group": g.group }))
}

#[derive(Deserialize)]
struct DumpBody {
    #[serde(default)]
    filtered: bool,
}

async fn api_dump_start(State(app): State<Shared>, Json(b): Json<DumpBody>) -> impl IntoResponse {
    let mut g = app.lock().unwrap();
    let name = g
        .selected
        .and_then(|pid| {
            g.procs
                .iter()
                .find(|p| p.pid == pid)
                .map(|p| p.name.clone())
        })
        .unwrap_or_else(|| "host".into());
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = dirs_dumps();
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{dir}/{safe}-{}.pcapng", stamp());
    let iface = g.iface.clone();
    if let Err(e) = g.dump.start(&iface, &path) {
        return Json(json!({ "ok": false, "error": e.to_string() }));
    }
    let process = g
        .selected
        .and_then(|pid| g.procs.iter().find(|p| p.pid == pid).cloned());
    let only_group = b.filtered && process.is_some();
    let t = state::now_ms();
    g.dump_meta = Some(DumpMeta {
        only_group,
        pids: g.group.iter().copied().collect(),
        process,
        started: t,
        last_alive: t,
    });
    let only = only_group.then_some(name);
    Json(json!({ "ok": true, "path": path, "only": only }))
}

async fn api_dump_stop(State(app): State<Shared>) -> impl IntoResponse {
    let (path, size, sidecar) = finish_dump(&app).await;
    Json(json!({ "ok": true, "path": path, "size": size, "sidecar": sidecar }))
}

async fn finish_dump(app: &Shared) -> (Option<String>, u64, Option<String>) {
    // Child нужно забрать из-под мьютекса, ожидание делаем уже без блокировки.
    let (mut dump, meta) = {
        let mut g = app.lock().unwrap();
        (std::mem::take(&mut g.dump), g.dump_meta.take())
    };
    let path = dump.stop().await;

    // Рядом с дампом кладем карту: какой процесс, какие адреса и домены.
    // Через неделю по одному .pcapng уже не вспомнить, что именно снимали.
    let mut sidecar = None;
    if let (Some(p), Some(m)) = (&path, &meta) {
        let (plan, info) = {
            let g = app.lock().unwrap();
            dump_plan(&g, m, p)
        };
        let file = p.clone();
        let stats = tokio::task::spawn_blocking(move || plan.rewrite(&file))
            .await
            .map_err(std::io::Error::other)
            .and_then(|r| r);
        let mut info = info;
        match stats {
            Ok(st) => {
                info["packets"] =
                    json!({"total": st.packets, "kept": st.kept, "labeled": st.labeled});
            }
            Err(e) => eprintln!(
                "{}",
                t!(
                    "[dump] labels not added: {e}",
                    "[дамп] подписи не добавлены: {e}"
                )
            ),
        }
        let jp = p.trim_end_matches(".pcapng").to_string() + ".json";
        if std::fs::write(&jp, serde_json::to_string_pretty(&info).unwrap_or_default()).is_ok() {
            sidecar = Some(jp);
        }
    }
    let size = path
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    // Вернуть dump обратно, чтобы путь к последнему файлу оставался виден в интерфейсе.
    app.lock().unwrap().dump = dump;
    (path, size, sidecar)
}

/// Соединения за время записи: владелец и домен для подписи пакетов, отбор
/// трафика группы и карта для .json.
fn dump_plan(g: &App, m: &DumpMeta, path: &str) -> (annotate::Plan, serde_json::Value) {
    let mine = |c: &state::Conn| c.pid.is_some_and(|p| m.pids.contains(&p));
    let group: Vec<&state::Conn> = g.store.conns.values().filter(|c| mine(c)).collect();
    let hosts: HashSet<IpAddr> = group
        .iter()
        .filter(|c| c.scope == "public")
        .filter_map(|c| c.remote.parse().ok())
        .collect();
    let domains: HashSet<&str> = group.iter().filter_map(|c| c.domain.as_deref()).collect();
    let mut owners = HashMap::new();
    let mut conns: Vec<&state::Conn> = Vec::new();
    for (k, c) in &g.store.conns {
        if c.last_seen < m.started {
            continue;
        }
        // Соединение без владельца (короткое или замеченное уже в TIME_WAIT) относим к группе
        // по адресу, а при известном домене - еще и по домену: за прокси и CDN адрес общий.
        let keep = mine(c)
            || (c.pid.is_none()
                && hosts.contains(&k.remote)
                && c.domain.as_deref().is_none_or(|d| domains.contains(d)));
        owners.insert(
            *k,
            annotate::Owner {
                label: annotate::label(c.pname.as_deref(), c.pid, c.domain.as_deref()),
                keep,
            },
        );
        if (keep || !m.only_group) && !c.pid.is_some_and(|p| g.self_pids.contains(&p)) {
            conns.push(c);
        }
    }
    conns.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.id.cmp(&b.id)));

    let who = m
        .process
        .as_ref()
        .map(|p| format!("{} [{}]", p.name, p.pid));
    let comment = match (&who, m.only_group) {
        (Some(w), true) => t!(
            "SocketTrail: only traffic of {w} and its child processes",
            "SocketTrail: только трафик {w} и его дочерних процессов"
        ),
        (Some(w), false) => t!(
            "SocketTrail: all traffic of the computer, selected {w}",
            "SocketTrail: весь трафик компьютера, выбран {w}"
        ),
        (None, _) => t!(
            "SocketTrail: all traffic of the computer",
            "SocketTrail: весь трафик компьютера"
        ),
    };
    let mut pids: Vec<i32> = m.pids.iter().copied().collect();
    pids.sort_unstable();
    let info = json!({
        "dump": path,
        "captured_from": human_time(m.started),
        "captured_until": human_time(state::now_ms()),
        "only_process": m.only_group,
        "process": m.process.as_ref()
            .map(|x| json!({"pid": x.pid, "name": x.name, "cmdline": x.cmdline})),
        "group_pids": pids,
        "conns": conns,
    });
    let plan = annotate::Plan {
        owners,
        hosts,
        only_group: m.only_group,
        comment,
    };
    (plan, info)
}

/// Во время записи: копим PID группы (Proton порождает процессы на ходу) и
/// отмечаем, жива ли она. Потомков ищем и от вышедшего корня: их могли переподвесить.
fn track_dump(g: &mut App, list: &[ProcInfo]) {
    let Some(m) = g.dump_meta.as_mut() else {
        return;
    };
    let Some(root) = m.process.as_ref().map(|p| p.pid) else {
        return;
    };
    let live: HashSet<i32> = list.iter().map(|p| p.pid).collect();
    let roots: Vec<i32> = std::iter::once(root)
        .chain(m.pids.iter().copied().filter(|p| live.contains(p)))
        .collect();
    for r in roots {
        m.pids.extend(procs::descendants(list, r));
    }
    if m.pids.iter().any(|p| live.contains(p)) {
        m.last_alive = state::now_ms();
    }
}

/// Запись "только процесс" незачем держать после выхода игры: останавливаем сами.
async fn auto_stop_dump(app: &Shared) {
    let due = {
        let g = app.lock().unwrap();
        g.dump.is_running()
            && g.dump_meta.as_ref().is_some_and(|m| {
                m.only_group && state::now_ms().saturating_sub(m.last_alive) > DUMP_IDLE_MS
            })
    };
    if !due {
        return;
    }
    let (path, _, _) = finish_dump(app).await;
    if let Some(p) = path {
        eprintln!(
            "{}",
            t!(
                "[dump] process exited, recording stopped: {p}",
                "[дамп] процесс завершился, запись остановлена: {p}"
            )
        );
        app.lock().unwrap().auto_stopped = Some(p);
    }
}

/// Список уже собранных дампов. Каталог называется так же, как репозиторий
/// проекта, и спутать их легко - поэтому путь показываем прямо в окне.
async fn api_dumps() -> impl IntoResponse {
    let dir = dirs_dumps();
    let mut files: Vec<serde_json::Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".pcapng") {
                continue;
            }
            let (size, mtime) = e
                .metadata()
                .map(|m| {
                    let t = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    (m.len(), t)
                })
                .unwrap_or((0, 0));
            files.push(json!({ "name": name, "size": size, "mtime": mtime }));
        }
    }
    files.sort_by_key(|f| std::cmp::Reverse(f["mtime"].as_u64().unwrap_or(0)));
    files.truncate(20);
    Json(json!({ "dir": dir, "files": files }))
}

/// Открытие каталога дампов в файловом менеджере.
async fn api_reveal() -> impl IntoResponse {
    let dir = dirs_dumps();
    let _ = std::fs::create_dir_all(&dir);
    let ok = window::open_default(&dir);
    Json(json!({ "ok": ok, "dir": dir }))
}

async fn api_clear(State(app): State<Shared>) -> impl IntoResponse {
    let mut g = app.lock().unwrap();
    g.store.conns.clear();
    g.store.packets_seen = 0;
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default)]
    format: String,
    #[serde(default)]
    scope: String,
}

async fn api_export(State(app): State<Shared>, Query(q): Query<ExportQuery>) -> impl IntoResponse {
    let g = app.lock().unwrap();
    let f = Filter {
        only_selected: q.scope != "host" && g.selected.is_some(),
        query: String::new(),
        show_local: true,
        show_self: false,
    };
    let mut conns: Vec<state::Conn> = select_conns(&g, &f).into_iter().cloned().collect();
    conns.sort_by_key(|a| a.first_seen);
    let pname = g
        .selected
        .and_then(|pid| g.procs.iter().find(|p| p.pid == pid))
        .map(|p| format!("{} (pid {})", p.name, p.pid))
        .unwrap_or_else(|| t!("whole host", "весь хост"));
    let now = human_time(state::now_ms());

    if q.format == "html" {
        let html = report::render(
            &t!(
                "Network connections: {pname}",
                "Сетевые соединения: {pname}"
            ),
            &now,
            &conns,
        );
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"sockettrail-report.html\"",
                ),
            ],
            html,
        );
    }

    let body = serde_json::to_string_pretty(&json!({
        "generated": now,
        "process": pname,
        "group": g.group,
        "conns": conns,
    }))
    .unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"sockettrail.json\"",
            ),
        ],
        body,
    )
}

fn dirs_dumps() -> String {
    paths::dumps_dir().to_string_lossy().into_owned()
}

/// Смещение локальной зоны в секундах, снимается один раз при старте.
fn tz_offset() -> i64 {
    use std::sync::OnceLock;
    static OFF: OnceLock<i64> = OnceLock::new();
    *OFF.get_or_init(tz_offset_os)
}

/// Bias в минутах со знаком "UTC минус местное", плюс поправка текущего сезона.
#[cfg(windows)]
fn tz_offset_os() -> i64 {
    use windows_sys::Win32::System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, GetDynamicTimeZoneInformation,
    };
    let mut tz: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let bias = match unsafe { GetDynamicTimeZoneInformation(&mut tz) } {
        1 => tz.Bias + tz.StandardBias,
        2 => tz.Bias + tz.DaylightBias,
        _ => tz.Bias,
    };
    -(bias as i64) * 60
}

#[cfg(not(windows))]
fn tz_offset_os() -> i64 {
    {
        let out = std::process::Command::new("date").arg("+%z").output();
        let s = out
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        // формат +0300
        if s.len() == 5 {
            let sign = if s.starts_with('-') { -1 } else { 1 };
            let h: i64 = s[1..3].parse().unwrap_or(0);
            let m: i64 = s[3..5].parse().unwrap_or(0);
            sign * (h * 3600 + m * 60)
        } else {
            0
        }
    }
}

fn human_time(ms: u64) -> String {
    let secs = ms as i64 / 1000 + tz_offset();
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let t = secs.rem_euclid(86400);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}",
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

fn stamp() -> String {
    let secs = state::now_ms() as i64 / 1000 + tz_offset();
    // без внешних зависимостей: метка вида 20260920-153045 по локальному времени
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Алгоритм Говарда Хиннанта: число дней от эпохи -> календарная дата.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
