//! Инвентаризация процессов: дерево, имена и командные строки.

use serde::Serialize;
use std::collections::{HashMap, HashSet};

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
    /// Идентичность процесса сохраняется при exec и меняется при повторном PID.
    pub started: u64,
    pub ppid: i32,
    pub comm: String,
    /// Человекочитаемое имя: для Proton/Wine - имя .exe, иначе comm.
    pub name: String,
    pub cmdline: String,
    /// Процесс исполняется под Proton/Wine (только Linux).
    pub proton: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub pid: i32,
    pub started: u64,
}

impl ProcInfo {
    pub fn identity(&self) -> Identity {
        Identity {
            pid: self.pid,
            started: self.started,
        }
    }
}

/// PID процесса и всех его потомков, включая дочерние процессы Proton/Wine.
pub fn descendants(procs: &[ProcInfo], root: i32) -> Vec<i32> {
    descendants_from(procs, [root])
}

/// Несколько известных корней обходятся одним проходом по дереву.
pub fn descendants_from(procs: &[ProcInfo], roots: impl IntoIterator<Item = i32>) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for p in procs {
        children.entry(p.ppid).or_default().push(p.pid);
    }
    let mut seen = HashSet::new();
    let mut out: Vec<i32> = roots.into_iter().filter(|p| seen.insert(*p)).collect();
    let mut stack = out.clone();
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children.get(&pid) {
            for &k in kids {
                if seen.insert(k) {
                    out.push(k);
                    stack.push(k);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: i32, ppid: i32) -> ProcInfo {
        ProcInfo {
            pid,
            started: 1,
            ppid,
            comm: "demo".into(),
            name: "demo".into(),
            cmdline: String::new(),
            proton: false,
        }
    }

    #[test]
    fn descendants_cover_the_whole_subtree_once_even_with_a_cycle() {
        let list = [
            p(10, 1),
            p(11, 10),
            p(12, 11),
            p(13, 10),
            p(20, 1),
            p(30, 31),
            p(31, 30),
        ];
        let mut sub = descendants(&list, 10);
        assert_eq!(sub[0], 10);
        sub.sort();
        assert_eq!(sub, [10, 11, 12, 13]);
        let mut cycle = descendants(&list, 30);
        cycle.sort();
        assert_eq!(cycle, [30, 31]);
        let mut merged = descendants_from(&list, [10, 11, 10]);
        merged.sort_unstable();
        assert_eq!(merged, [10, 11, 12, 13]);
    }
}
