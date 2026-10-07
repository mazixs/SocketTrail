//! Linux: инвентаризация процессов чтением /proc без внешних утилит.

use std::collections::{HashMap, HashSet};
use std::fs;

use super::ProcInfo;

/// Поля /proc/<pid>/stat, которые читаются на каждом проходе.
struct Stat {
    comm: String,
    ppid: i32,
    /// Время старта в тиках от загрузки: отличает новый процесс со старым PID.
    started: u64,
}

/// comm стоит в скобках и сам может содержать пробелы и скобки, поэтому
/// поля отсчитываются от последней ")".
fn parse_stat(s: &str) -> Option<Stat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let mut fields = s.get(close + 1..)?.split_whitespace();
    let ppid = fields.nth(1)?.parse().ok()?;
    let started = fields.nth(17)?.parse().ok()?;
    Some(Stat {
        comm,
        ppid,
        started,
    })
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

struct Entry {
    info: ProcInfo,
    started: u64,
}

/// Сканер с кешем. На каждом проходе читается только /proc/<pid>/stat:
/// PPID меняется, когда умирает родитель, а comm - после exec. cmdline
/// перечитывается при смене comm или времени старта (PID занял новый процесс).
#[derive(Default)]
pub struct Scanner {
    cache: HashMap<i32, Entry>,
}

impl Scanner {
    pub fn refresh(&mut self) -> Vec<ProcInfo> {
        let dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let mut alive: HashSet<i32> = HashSet::with_capacity(self.cache.len() + 32);
        for entry in dir.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                self.update(pid);
                alive.insert(pid);
            }
        }
        self.cache.retain(|pid, _| alive.contains(pid));

        let mut out: Vec<ProcInfo> = self.cache.values().map(|e| e.info.clone()).collect();
        out.sort_by_key(|p| p.pid);
        out
    }

    pub fn refresh_pids(&mut self, pids: &[i32]) -> Vec<ProcInfo> {
        for &pid in pids {
            self.update(pid);
        }
        pids.iter()
            .filter_map(|pid| self.cache.get(pid).map(|e| e.info.clone()))
            .collect()
    }

    fn update(&mut self, pid: i32) {
        let Some(st) = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| parse_stat(&s))
        else {
            self.cache.remove(&pid);
            return;
        };
        if let Some(e) = self.cache.get_mut(&pid)
            && e.started == st.started
            && e.info.comm == st.comm
        {
            e.info.ppid = st.ppid;
            return;
        }
        let started = st.started;
        match read_proc(pid, st) {
            Some(info) => {
                self.cache.insert(pid, Entry { info, started });
            }
            None => {
                self.cache.remove(&pid);
            }
        }
    }
}

/// Полное чтение процесса, которого нет в кеше или который сменил образ.
fn read_proc(pid: i32, st: Stat) -> Option<ProcInfo> {
    let comm = st.comm;
    if comm.is_empty() {
        return None;
    }
    let raw_cmd = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&raw_cmd)
        .replace('\0', " ")
        .trim()
        .to_string();

    let lower = cmdline.to_ascii_lowercase();
    let proton = lower.contains("proton")
        || lower.contains("/wine")
        || lower.contains("pressure-vessel")
        || comm.starts_with("wine")
        || comm.ends_with(".exe");

    // У Wine comm ограничен 15 символами и может содержать имя потока вместо .exe.
    let name = if proton {
        exe_from_cmdline(&cmdline).unwrap_or_else(|| comm.clone())
    } else {
        comm.clone()
    };

    Some(ProcInfo {
        pid,
        started: st.started,
        ppid: st.ppid,
        comm,
        name,
        cmdline,
        proton,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_are_counted_from_the_last_parenthesis() {
        let line = "4242 (Web (Content) x) S 17 4242 4242 0 -1 4194560 1 0 0 0 \
                    5 3 0 0 20 0 9 0 987654 1000 200 18446744073709551615";
        let st = parse_stat(line).unwrap();
        assert_eq!(st.comm, "Web (Content) x");
        assert_eq!(st.ppid, 17);
        assert_eq!(st.started, 987654);
        assert!(parse_stat("4242 (cut").is_none());
        assert!(parse_stat("4242 (short) S 1 2").is_none());
    }

    #[test]
    fn cached_process_is_reread_after_exec_or_pid_reuse_and_follows_reparenting() {
        let pid = std::process::id() as i32;
        let real = parse_stat(&fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        let fake = |comm: &str, ppid: i32, started: u64| Entry {
            info: ProcInfo {
                pid,
                started,
                ppid,
                comm: comm.into(),
                name: comm.into(),
                cmdline: "stale".into(),
                proton: false,
            },
            started,
        };
        let mut s = Scanner::default();

        s.cache.insert(pid, fake(&real.comm, 1, real.started));
        s.update(pid);
        let e = &s.cache[&pid];
        assert_eq!(e.info.ppid, real.ppid);
        assert_eq!(e.info.cmdline, "stale");

        s.cache.insert(pid, fake("old-image", 1, real.started));
        s.update(pid);
        assert_eq!(s.cache[&pid].info.comm, real.comm);
        assert_ne!(s.cache[&pid].info.cmdline, "stale");

        s.cache.insert(pid, fake(&real.comm, 1, real.started + 1));
        s.update(pid);
        assert_eq!(s.cache[&pid].started, real.started);
        assert_ne!(s.cache[&pid].info.cmdline, "stale");
    }
}
