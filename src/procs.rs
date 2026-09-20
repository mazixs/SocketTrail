//! Инвентаризация процессов: чтение /proc без внешних утилит.

use serde::Serialize;
use std::collections::HashMap;
use std::fs;

#[derive(Clone, Debug, Serialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    /// Человекочитаемое имя: для Proton/Wine - имя .exe, иначе comm.
    pub name: String,
    pub cmdline: String,
    pub uid: u32,
    /// Процесс исполняется под Proton/Wine.
    pub proton: bool,
}

fn read_uid(status: &str) -> u32 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:")
            && let Some(tok) = rest.split_whitespace().next()
        {
            return tok.parse().unwrap_or(0);
        }
    }
    0
}

fn read_ppid(status: &str) -> i32 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Имя .exe из аргументов wine-процесса. Windows-пути приводятся к базовому имени.
fn exe_from_cmdline(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .filter(|t| {
            let l = t.to_ascii_lowercase();
            l.ends_with(".exe")
        })
        .map(|t| {
            t.rsplit(['/', '\\'])
                .next()
                .unwrap_or(t)
                .trim_matches('"')
                .to_string()
        })
        .next_back()
}

/// Сканер с кешем: cmdline и uid у процесса не меняются, поэтому для уже
/// известного PID незачем каждый раз перечитывать три файла в /proc. На тысяче
/// процессов это разница между 70 мс и единицами миллисекунд на проход.
#[derive(Default)]
pub struct Scanner {
    cache: HashMap<i32, ProcInfo>,
}

impl Scanner {
    pub fn refresh(&mut self) -> Vec<ProcInfo> {
        let mut alive: Vec<i32> = Vec::with_capacity(self.cache.len() + 32);
        let dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        for entry in dir.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                alive.push(pid);
                if !self.cache.contains_key(&pid)
                    && let Some(info) = read_proc(pid)
                {
                    self.cache.insert(pid, info);
                }
            }
        }
        let alive_set: std::collections::HashSet<i32> = alive.iter().copied().collect();
        self.cache.retain(|pid, _| alive_set.contains(pid));

        let mut out: Vec<ProcInfo> = self.cache.values().cloned().collect();
        out.sort_by_key(|p| p.pid);
        out
    }
}

/// Разовое чтение одного процесса.
fn read_proc(pid: i32) -> Option<ProcInfo> {
    let base = format!("/proc/{pid}");
    let comm = fs::read_to_string(format!("{base}/comm"))
        .ok()?
        .trim()
        .to_string();
    if comm.is_empty() {
        return None;
    }
    let raw_cmd = fs::read(format!("{base}/cmdline")).unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&raw_cmd)
        .replace('\0', " ")
        .trim()
        .to_string();
    let status = fs::read_to_string(format!("{base}/status")).unwrap_or_default();

    let lower = cmdline.to_ascii_lowercase();
    let proton = lower.contains("proton")
        || lower.contains("/wine")
        || lower.contains("pressure-vessel")
        || comm.starts_with("wine")
        || comm.ends_with(".exe");

    // Для wine comm обрезан до 15 символов и часто бесполезен ("AION2.exe" -> "GameThread").
    let name = if proton {
        exe_from_cmdline(&cmdline).unwrap_or_else(|| comm.clone())
    } else {
        comm.clone()
    };

    Some(ProcInfo {
        pid,
        ppid: read_ppid(&status),
        comm,
        name,
        cmdline,
        uid: read_uid(&status),
        proton,
    })
}

#[allow(dead_code)]
pub fn snapshot() -> Vec<ProcInfo> {
    let mut out = Vec::with_capacity(512);
    let dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return out,
    };
    for entry in dir.flatten() {
        let fname = entry.file_name();
        let pid: i32 = match fname.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let base = format!("/proc/{pid}");
        let comm = fs::read_to_string(format!("{base}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if comm.is_empty() {
            continue;
        }
        let raw_cmd = fs::read(format!("{base}/cmdline")).unwrap_or_default();
        let cmdline = String::from_utf8_lossy(&raw_cmd)
            .replace('\0', " ")
            .trim()
            .to_string();
        let status = fs::read_to_string(format!("{base}/status")).unwrap_or_default();

        let lower = cmdline.to_ascii_lowercase();
        let proton = lower.contains("proton")
            || lower.contains("/wine")
            || lower.contains("pressure-vessel")
            || comm.starts_with("wine")
            || comm.ends_with(".exe");

        // Для wine comm обрезан до 15 символов и часто бесполезен ("AION2.exe" -> "GameThread").
        let name = if proton {
            exe_from_cmdline(&cmdline).unwrap_or_else(|| comm.clone())
        } else {
            comm.clone()
        };

        out.push(ProcInfo {
            pid,
            ppid: read_ppid(&status),
            comm,
            name,
            cmdline,
            uid: read_uid(&status),
            proton,
        });
    }
    out.sort_by_key(|p| p.pid);
    out
}

/// PID процесса и всех его потомков. Практика из разбора AION 2: сокеты игры
/// висят на дочерних процессах (wineserver, GameThread), выбор одного PID теряет половину.
pub fn descendants(procs: &[ProcInfo], root: i32) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for p in procs {
        children.entry(p.ppid).or_default().push(p.pid);
    }
    let mut out = vec![root];
    let mut stack = vec![root];
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children.get(&pid) {
            for &k in kids {
                if !out.contains(&k) {
                    out.push(k);
                    stack.push(k);
                }
            }
        }
    }
    out
}
