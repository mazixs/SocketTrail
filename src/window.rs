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
            Err(e) => {
                let b = browser.display();
                eprintln!(
                    "{}",
                    t!(
                        "[window] {b} did not start: {e}",
                        "[окно] {b} не запустился: {e}"
                    )
                );
            }
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
    /// `true` - окно закрыто. `false` - процесс браузера не найден, но страница на
    /// связи: закрытие окна тогда замечает только канал /api/alive.
    pub fn wait(mut self, page_seen: impl Fn() -> bool) -> bool {
        #[cfg(target_os = "linux")]
        {
            let mut seen = false;
            let started = Instant::now();
            loop {
                let _ = self.child.try_wait(); // забрать зомби, если исходный процесс вышел
                if profile_browser_alive(&self.profile) {
                    seen = true;
                } else if seen {
                    return true;
                } else if started.elapsed() > Duration::from_secs(15) {
                    return !page_seen();
                }
                std::thread::sleep(Duration::from_millis(700));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&self.profile, page_seen);
            let _ = self.child.wait();
            true
        }
    }
}

/// Chromium держит в профиле ссылку SingletonLock -> "<host>-<pid>" на главный
/// процесс. Командную строку не разобрать по NUL: Chrome 154 склеивает ее через
/// пробелы. Проверка пути в ней отсекает PID, занятый другим процессом.
#[cfg(target_os = "linux")]
fn profile_browser_alive(profile: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(lock) = std::fs::read_link(profile.join("SingletonLock")) else {
        return false;
    };
    let Some(pid) = lock
        .to_str()
        .and_then(|s| s.rsplit_once('-'))
        .and_then(|(_, p)| p.parse::<u32>().ok())
    else {
        return false;
    };
    let path = profile.as_os_str().as_bytes();
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .is_ok_and(|c| c.windows(path.len()).any(|w| w == path))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn profile_lock() {
        let dir = std::env::temp_dir().join(format!("sockettrail-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("SingletonLock");
        let mut child = Command::new("sh")
            .args(["-c", "read x", "chrome"])
            .arg(format!("--user-data-dir={}", dir.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let point = |pid: u32| {
            let _ = std::fs::remove_file(&lock);
            std::os::unix::fs::symlink(format!("my-host-{pid}"), &lock).unwrap();
        };

        assert!(!profile_browser_alive(&dir), "нет ссылки");
        point(child.id());
        let t = Instant::now(); // exec дочернего процесса может еще идти
        while !profile_browser_alive(&dir) && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(profile_browser_alive(&dir));
        point(std::process::id());
        assert!(!profile_browser_alive(&dir), "PID другого процесса");
        child.kill().unwrap();
        child.wait().unwrap();
        point(child.id());
        assert!(
            !profile_browser_alive(&dir),
            "ссылка осталась после падения"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
