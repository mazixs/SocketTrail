//! Инвентаризация процессов: дерево, имена и командные строки.

use serde::Serialize;
use std::collections::HashMap;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Scanner;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Scanner;

#[derive(Clone, Debug, Serialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    /// Человекочитаемое имя: для Proton/Wine - имя .exe, иначе comm.
    pub name: String,
    pub cmdline: String,
    /// Процесс исполняется под Proton/Wine (только Linux).
    pub proton: bool,
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
