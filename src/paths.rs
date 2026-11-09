//! Каталоги программы: кеш (имена, профиль окна) и дампы.

use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};

fn home() -> Option<PathBuf> {
    #[cfg(windows)]
    let v = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let v = std::env::var_os("HOME");
    v.filter(|s| !s.is_empty()).map(PathBuf::from)
}

/// ~/.cache/sockettrail. XDG_CACHE_HOME из snap-песочницы указывает внутрь snap, его пропускаем.
#[cfg(not(windows))]
pub fn cache_dir() -> PathBuf {
    std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|s| !s.is_empty() && !s.contains("/snap/"))
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("sockettrail")
}

#[cfg(windows)]
pub fn cache_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("SocketTrail")
}

/// ~/SocketTrail - папка дампов, показывается пользователю.
pub fn dumps_dir() -> PathBuf {
    home()
        .unwrap_or_else(std::env::temp_dir)
        .join("SocketTrail")
}

/// Имя с дописанным окончанием: "dump.pcapng" и ".part" дают "dump.pcapng.part".
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path);
    name.push(suffix);
    PathBuf::from(name)
}

/// Новый файл, недоступный другим пользователям: дамп содержит чужой трафик машины.
/// Существующий файл не перезаписывается.
pub fn new_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Переименование с повторами: на Windows антивирус и индексатор ненадолго держат только
/// что записанный файл, и первая попытка получает отказ в доступе.
pub fn rename_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    for attempt in 1..=20u64 {
        match std::fs::rename(from, to) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                std::thread::sleep(std::time::Duration::from_millis(50 * attempt.min(10)));
            }
            other => return other,
        }
    }
    std::fs::rename(from, to)
}

/// Замена файла целиком: при сбое остается прежняя версия.
pub fn write_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = with_suffix(path, ".tmp");
    let _ = std::fs::remove_file(&tmp);
    let result = new_private_file(&tmp)
        .and_then(|mut file| file.write_all(bytes))
        .and_then(|()| rename_retry(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
pub struct TestDir(pub PathBuf);

#[cfg(test)]
impl TestDir {
    pub fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "sockettrail-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
