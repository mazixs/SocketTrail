//! Кеш имен на диске. DNS-ответ пролетает один раз: если приложение резолвило
//! домен до запуска SocketTrail (или в прошлый запуск), имя взять неоткуда и
//! в таблице остается голый IP. Сохраненный кеш это закрывает.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;

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
    /// IP -> PTR и ASN
    #[serde(default)]
    pub whois: HashMap<String, Entry>,
}

pub fn path() -> String {
    let base = std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|s| !s.is_empty() && !s.contains("/snap/"))
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.cache")))
        .unwrap_or_else(|| "/tmp".into());
    format!("{base}/sockettrail/names.json")
}

pub fn load() -> Disk {
    std::fs::read_to_string(path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(d: &Disk) {
    let p = path();
    if let Some(dir) = std::path::Path::new(&p).parent() {
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
        whois: d
            .whois
            .iter()
            .take(MAX_ENTRIES)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    // Пишем через временный файл: обрыв на середине не должен оставить битый кеш.
    let tmp = format!("{p}.tmp");
    if let Ok(txt) = serde_json::to_string(&slim)
        && let Ok(mut f) = std::fs::File::create(&tmp)
        && f.write_all(txt.as_bytes()).is_ok()
    {
        let _ = std::fs::rename(&tmp, &p);
    }
}
