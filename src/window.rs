//! Окно интерфейса: Chromium-браузер в режиме приложения с собственным профилем.
//!
//! Свой `--user-data-dir` дает отдельный процесс браузера: окно не сливается с
//! обычным Chrome, получает свой класс окна (иконка из ярлыка SocketTrail), а
//! завершение этого процесса означает, что пользователь закрыл окно.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const WM_CLASS: &str = "SocketTrail";

/// Отдельный путь окна. На Wayland Chrome игнорирует --class и выводит app_id из
/// адреса: для /sockettrail это chrome-127.0.0.1__sockettrail-Default без порта.
/// По нему док GNOME находит ярлык (StartupWMClass в install.sh) и берет иконку.
pub const UI_PATH: &str = "/sockettrail";

pub enum Opened {
    /// Окно в своем профиле: закрытие последнего окна профиля - сигнал выйти.
    Window(Watch),
    /// Обычная вкладка или окно уже работающего профиля - жизнь окна не отслеживается.
    Detached,
    Failed,
}

#[cfg(unix)]
const CANDIDATES: &[&str] = &[
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "microsoft-edge",
    "microsoft-edge-stable",
    "brave-browser",
    "vivaldi",
];

#[cfg(windows)]
const CANDIDATES: &[&str] = &["msedge.exe", "chrome.exe", "brave.exe"];

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Edge на Windows есть всегда, но в PATH его обычно нет.
#[cfg(windows)]
fn find_browser() -> Option<PathBuf> {
    let roots = ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .collect::<Vec<_>>();
    let rel = [
        r"Microsoft\Edge\Application\msedge.exe",
        r"Google\Chrome\Application\chrome.exe",
    ];
    for r in rel {
        for root in &roots {
            let p = root.join(r);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    CANDIDATES.iter().find_map(|n| find_in_path(n))
}

#[cfg(unix)]
fn find_browser() -> Option<PathBuf> {
    CANDIDATES.iter().find_map(|n| find_in_path(n))
}

/// Каталог профиля. Snap-браузеру доступен только его собственный каталог в ~/snap.
fn profile_dir(browser: &Path) -> PathBuf {
    let resolved = std::fs::canonicalize(browser).unwrap_or_else(|_| browser.to_path_buf());
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(home) = &home
        && (browser.starts_with("/snap") || resolved.starts_with("/snap"))
    {
        let name = browser.file_name().unwrap_or_default();
        return home.join("snap").join(name).join("common/sockettrail-ui");
    }
    crate::paths::cache_dir().join("ui-profile")
}

/// `base` - корень сервера вида http://127.0.0.1:8787/.
pub fn open(base: &str) -> Opened {
    let url = format!("{}{UI_PATH}", base.trim_end_matches('/'));
    let url = url.as_str();
    if let Some(browser) = find_browser() {
        let profile = profile_dir(&browser);
        let _ = std::fs::create_dir_all(&profile);
        let spawned = Command::new(&browser)
            .arg(format!("--app={url}"))
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg(format!("--class={WM_CLASS}"))
            .args([
                "--window-size=1500,900",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-sync",
                "--disable-background-mode",
                "--disable-features=Translate,MediaRouter",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match spawned {
            Ok(mut child) => {
                // Если профиль уже открыт (второй запуск, окно от прошлого экземпляра),
                // браузер передает адрес работающему процессу и сразу выходит.
                let t = Instant::now();
                while t.elapsed() < Duration::from_millis(1500) {
                    match child.try_wait() {
                        Ok(Some(_)) => return Opened::Detached,
                        Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                        Err(_) => return Opened::Detached,
                    }
                }
                return Opened::Window(Watch { child, profile });
            }
            Err(e) => eprintln!("[окно] {} не запустился: {e}", browser.display()),
        }
    }
    if open_default(url) {
        Opened::Detached
    } else {
        Opened::Failed
    }
}

/// Системный обработчик: браузер по умолчанию для адреса, файловый менеджер для папки.
pub fn open_default(target: &str) -> bool {
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("explorer");
        c.arg(target);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(target);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(target);
        c
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

/// Отслеживание окна. Запущенный процесс ждать нельзя: Chrome, запущенный из
/// GNOME, переносит себя в свой systemd-scope, и исходный PID завершается через
/// пару секунд при открытом окне. Поэтому ждем исчезновения главного процесса
/// браузера с нашим --user-data-dir.
pub struct Watch {
    child: Child,
    profile: PathBuf,
}

impl Watch {
    pub fn wait(mut self) {
        #[cfg(target_os = "linux")]
        {
            let arg = format!("--user-data-dir={}", self.profile.display());
            let mut seen = false;
            let started = Instant::now();
            loop {
                let _ = self.child.try_wait(); // забрать зомби, если исходный процесс вышел
                if profile_browser_alive(&arg) {
                    seen = true;
                } else if seen || started.elapsed() > Duration::from_secs(15) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(700));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &self.profile;
            let _ = self.child.wait();
        }
    }
}

/// Есть ли главный процесс браузера (без --type=) с данным профилем.
#[cfg(target_os = "linux")]
fn profile_browser_alive(profile_arg: &str) -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    dir.flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .any(|raw| {
            let args: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
            args.contains(&profile_arg.as_bytes())
                && !args.iter().any(|a| a.starts_with(b"--type="))
        })
}
