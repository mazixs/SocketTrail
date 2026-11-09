//! SocketTrail - привязанный к процессу монитор сетевых соединений.
//!
//! Здесь только разбор аргументов и запуск. Состояние и фоновые циклы - в `app`, HTTP API -
//! в `api`, отбор строк таблицы - в `query`, запись дампа - в `recording` и `dumpfile`.

#![cfg_attr(windows, windows_subsystem = "windows")]

// первым: макросы t! и text! нужны остальным модулям
#[macro_use]
mod i18n;

mod alive;
mod annotate;
mod api;
mod app;
mod cache;
mod capture;
#[cfg(windows)]
mod dnscache;
mod dumpfile;
#[cfg(windows)]
mod elevate;
#[cfg(windows)]
mod etw;
mod localtime;
mod paths;
mod pcap;
mod procs;
mod query;
mod quic;
mod recording;
mod report;
mod resolve;
mod sockets;
mod state;
mod tls;
#[cfg(windows)]
mod win_startup;
mod window;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::{App, Shared, lock};
use crate::recording::DumpPhase;
use crate::state::Store;

const HELP_EN: &str = "\
SocketTrail - network connection monitor tied to processes.

Usage: sockettrail [options]

  -i, --iface <name>  dumpcap interface, several separated by commas (default any:
                      all at once on Linux). This option is Linux-only.
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
Without a Chromium browser a regular tab opens; closing it also exits the program.
";

const HELP_RU: &str = "\
SocketTrail - монитор сетевых соединений с привязкой к процессу.

Использование: sockettrail [ключи]

  -i, --iface <имя>   интерфейс dumpcap, несколько - через запятую (по умолчанию any:
                      на Linux все сразу). Этот ключ действует только на Linux.
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
Без Chromium-браузера открывается обычная вкладка; ее закрытие тоже завершает программу.
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
                #[cfg(windows)]
                win_startup::help(i18n::tr(HELP_EN, HELP_RU));
                #[cfg(not(windows))]
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
    let last = pref.saturating_add(19);
    for port in pref..=last {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            // При --port 0 порт выбирает система, Host проверяется по настоящему.
            Ok(l) => {
                let port = l.local_addr().map_or(port, |a| a.port());
                return (l, port);
            }
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
    #[cfg(windows)]
    let _log = win_startup::init();
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
    let mut store = Store::default();
    store.set_local_ips(sockets::local_addresses());

    let capture_metrics = Arc::new(capture::Metrics::default());
    let app: Shared = Arc::new(Mutex::new(App::new(
        store,
        capture_metrics.clone(),
        iface.clone(),
        port,
        quit_tx.clone(),
    )));
    app::restore_cache(&mut lock(&app));

    // Живой захват держим до выхода: Drop гасит dumpcap или сессию PktMon.
    let (tx, rx) = tokio::sync::mpsc::channel(capture::QUEUE_CAPACITY);
    let tx = capture::PacketSender::new(tx, capture_metrics);
    let live_capture = match capture::start_live(&iface, tx).await {
        Ok(live) => {
            let how = live.describe(&iface);
            let mut g = lock(&app);
            if let Some(pid) = live.pid() {
                g.self_roots.insert(pid as i32);
                g.self_pids.insert(pid as i32);
            }
            g.capture_on = true;
            g.capture_how = Some(how.clone());
            drop(g);
            tokio::spawn(app::packet_loop(app.clone(), rx));
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
            let mut g = lock(&app);
            g.capture_hint = Some(hint);
            #[cfg(windows)]
            {
                g.can_elevate = etw::can_elevate();
            }
            None
        }
    };

    let (capture_quit, mut capture_quit_rx) = tokio::sync::oneshot::channel::<()>();
    let capture_app = app.clone();
    let capture_watch = tokio::spawn(async move {
        let Some(mut live) = live_capture else {
            return;
        };
        loop {
            tokio::select! {
                _ = &mut capture_quit_rx => break,
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
            if let Err(hint) = live.check() {
                eprintln!("[capture] {}", hint.get());
                let mut g = lock(&capture_app);
                g.capture_on = false;
                g.capture_hint = Some(hint);
                break;
            }
        }
    });

    #[cfg(windows)]
    app::supervise("dnscache", &app, app::dnscache_loop);
    app::supervise("poll", &app, app::poll_loop);
    app::supervise("whois", &app, app::whois_loop);
    app::supervise("cache", &app, app::cache_loop);

    let alive = Arc::new(alive::Alive::default());
    let router = api::router(app.clone(), alive.clone(), port);

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
    let _ = capture_quit.send(());
    let _ = capture_watch.await;
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
            let (t, a) = (tx.clone(), alive.clone());
            rt.spawn(async move {
                alive::wait_closed(a, 10).await;
                let _ = t.send(closed_page());
            });
            if w.wait(|| alive.seen()) {
                let _ = tx.send(i18n::tr("window closed", "окно закрыто"));
            } else {
                eprintln!(
                    "{}",
                    t!(
                        "[window] browser process not found, the window is tracked by the page",
                        "[окно] процесс браузера не найден, окно отслеживается по странице"
                    )
                );
            }
        }
        window::Opened::Detached => {
            rt.spawn(async move {
                alive::wait_closed(alive, 10).await;
                let _ = tx.send(closed_page());
            });
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
    let running = lock(app).dump_phase == DumpPhase::Recording;
    if running {
        let outcome = recording::finish_dump(app, false).await;
        if let Some(p) = outcome.path {
            eprintln!(
                "{}",
                t!("[exit] dump closed: {p}", "[выход] дамп закрыт: {p}")
            );
        }
    }
    cache::save(|| app::cache_snapshot(&lock(app)));
}
