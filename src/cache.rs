//! Кеш имен на диске. DNS-ответ пролетает один раз: если приложение резолвило
//! домен до запуска SocketTrail (или в прошлый запуск), имя взять неоткуда и
//! в таблице остается голый IP. Сохраненный кеш это закрывает.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

/// Потолок на каждую карту, чтобы файл не рос бесконечно.
const MAX_ENTRIES: usize = 20_000;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Entry {
    pub ptr: Option<String>,
    pub asn: Option<String>,
    pub owner: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Disk {
    /// IP -> имя из DNS-ответов и SNI
    #[serde(default)]
    pub dns: HashMap<String, String>,
    #[serde(default)]
    pub dns_names: HashMap<String, crate::state::DnsEntry>,
    /// IP -> PTR и ASN
    #[serde(default)]
    pub whois: HashMap<String, Entry>,
}

pub fn path() -> String {
    crate::paths::cache_dir()
        .join("names.json")
        .to_string_lossy()
        .into_owned()
}

pub fn load() -> Disk {
    load_from(&path())
}

fn load_from(p: &str) -> Disk {
    remove_stale_tmp(Path::new(p));
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Временные файлы, оставшиеся после аварийного завершения.
fn remove_stale_tmp(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let prefix = format!("{name}.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if e.file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".tmp"))
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Снимок берется уже в очереди на запись: фоновая запись по таймеру и запись
/// при выходе иначе могли бы закончиться в любом порядке, и старый снимок
/// затер бы свежий.
pub fn save(snapshot: impl FnOnce() -> Disk) {
    save_to(&path(), snapshot);
}

fn save_to(p: &str, snapshot: impl FnOnce() -> Disk) {
    static WRITING: Mutex<()> = Mutex::new(());
    let _turn = WRITING.lock().unwrap_or_else(PoisonError::into_inner);
    let d = snapshot();
    if let Some(dir) = Path::new(p).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let trim = |m: &HashMap<String, String>| -> HashMap<String, String> {
        m.iter()
            .take(MAX_ENTRIES)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let slim = Disk {
        dns: trim(&d.dns),
        dns_names: d
            .dns_names
            .iter()
            .take(MAX_ENTRIES)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        whois: d
            .whois
            .iter()
            .take(MAX_ENTRIES)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    let Ok(txt) = serde_json::to_string(&slim) else {
        return;
    };
    let _ = write_atomic(p, txt.as_bytes());
}

/// Через временный файл: обрыв на середине не должен оставить битый кеш.
/// История доменов - личные данные, файл доступен только владельцу.
fn write_atomic(path: &str, data: &[u8]) -> std::io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = format!(
        "{path}.{}-{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let res = options.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    });
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_the_file_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("sockettrail-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("names.json");
        let p = path.to_str().unwrap();
        write_atomic(p, b"{}").unwrap();
        write_atomic(p, br#"{"dns":{}}"#).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"dns":{}}"#);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn disk(name: &str) -> Disk {
        Disk {
            dns: HashMap::from([("198.51.100.20".into(), name.into())]),
            whois: HashMap::new(),
            dns_names: HashMap::new(),
        }
    }

    #[test]
    fn snapshot_taken_later_is_written_later() {
        let dir = crate::paths::TestDir::new("cache-order");
        let p = dir.0.join("names.json").to_string_lossy().into_owned();
        let (started, wait_started) = std::sync::mpsc::channel();
        let (go, wait_go) = std::sync::mpsc::channel::<()>();
        let old = {
            let p = p.clone();
            std::thread::spawn(move || {
                save_to(&p, || {
                    started.send(()).unwrap();
                    wait_go.recv().unwrap();
                    disk("old.example.com")
                })
            })
        };
        wait_started.recv().unwrap();
        let new = {
            let p = p.clone();
            std::thread::spawn(move || save_to(&p, || disk("new.example.com")))
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        go.send(()).unwrap();
        old.join().unwrap();
        new.join().unwrap();
        assert_eq!(
            load_from(&p).dns["198.51.100.20"],
            "new.example.com".to_string()
        );
    }

    #[test]
    fn load_removes_temporaries_left_by_a_crash() {
        let dir = crate::paths::TestDir::new("cache-stale");
        let path = dir.0.join("names.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::write(dir.0.join("names.json.123-0.tmp"), "{").unwrap();
        std::fs::write(dir.0.join("window.json"), "{}").unwrap();
        load_from(path.to_str().unwrap());
        let mut left: Vec<String> = std::fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["names.json", "window.json"]);
    }
    #[test]
    fn ttl_and_ambiguous_names_survive_cache_roundtrip() {
        let dir = crate::paths::TestDir::new("dns-ttl-cache");
        let path = dir.0.join("names.json").to_string_lossy().into_owned();
        let expires = crate::state::now_ms() + 60_000;
        save_to(&path, || Disk {
            dns_names: HashMap::from([(
                "198.51.100.20".into(),
                crate::state::DnsEntry {
                    names: vec![
                        crate::state::DnsName {
                            name: "a.example.com".into(),
                            expires,
                        },
                        crate::state::DnsName {
                            name: "b.example.com".into(),
                            expires,
                        },
                    ],
                    overflow_until: expires,
                },
            )]),
            ..Disk::default()
        });
        let restored = load_from(&path);
        let names = &restored.dns_names["198.51.100.20"];
        assert_eq!(names.names.len(), 2);
        assert_eq!(names.names[0].expires, expires);
        assert_eq!(names.overflow_until, expires);
    }
}
