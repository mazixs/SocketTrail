//! Каталоги программы: кеш (имена, профиль окна) и дампы.

use std::path::PathBuf;

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
