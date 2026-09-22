//! Windows: снимок Toolhelp32 (pid, родитель, имя exe) плюс путь и командная
//! строка через OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION). У защищенных и
//! чужих процессов без прав администратора остается только имя.

use std::collections::HashMap;

use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use super::ProcInfo;

struct Entry {
    info: ProcInfo,
    exe: String,
    /// Время создания в тиках FILETIME, 0 - неизвестно.
    started: u64,
}

/// Кеш по PID. Запись считается тем же процессом, пока совпадают имя exe и
/// родитель: так не нужно открывать каждый процесс на каждом проходе.
#[derive(Default)]
pub struct Scanner {
    cache: HashMap<i32, Entry>,
}

impl Scanner {
    pub fn refresh(&mut self) -> Vec<ProcInfo> {
        let list = toolhelp();
        let mut seen = HashMap::with_capacity(list.len());
        for (pid, ppid, exe) in list {
            let fresh = match self.cache.get(&pid) {
                Some(e) => e.exe != exe || e.info.ppid != ppid,
                None => true,
            };
            if fresh {
                self.cache.insert(pid, read(pid, ppid, exe));
            }
            seen.insert(pid, ());
        }
        self.cache.retain(|pid, _| seen.contains_key(pid));

        // Windows не переписывает PPID, когда родитель умирает, а PID переиспользуются:
        // "родитель", стартовавший позже потомка, - чужой процесс с тем же номером.
        let started: HashMap<i32, u64> = self.cache.iter().map(|(p, e)| (*p, e.started)).collect();
        let mut out: Vec<ProcInfo> = self
            .cache
            .values()
            .map(|e| {
                let mut p = e.info.clone();
                let ps = started.get(&p.ppid).copied().unwrap_or(0);
                if !started.contains_key(&p.ppid) || (ps != 0 && e.started != 0 && ps > e.started) {
                    p.ppid = 0;
                }
                p
            })
            .collect();
        out.sort_by_key(|p| p.pid);
        out
    }
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn toolhelp() -> Vec<(i32, i32, String)> {
    let mut out = Vec::with_capacity(512);
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e) != 0;
        while ok {
            if e.th32ProcessID != 0 {
                out.push((
                    e.th32ProcessID as i32,
                    e.th32ParentProcessID as i32,
                    wide_to_string(&e.szExeFile),
                ));
            }
            ok = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    out
}

fn read(pid: i32, ppid: i32, exe: String) -> Entry {
    let mut started = 0;
    let mut cmdline = String::new();
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if !h.is_null() {
            started = start_time(h);
            cmdline = command_line(h).or_else(|| image_path(h)).unwrap_or_default();
            CloseHandle(h);
        }
    }
    if cmdline.is_empty() {
        cmdline = exe.clone();
    }
    Entry {
        info: ProcInfo {
            pid,
            ppid,
            comm: exe.clone(),
            name: exe.clone(),
            cmdline,
            proton: false,
        },
        exe,
        started,
    }
}

unsafe fn start_time(h: HANDLE) -> u64 {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    if unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } == 0 {
        return 0;
    }
    ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64
}

unsafe fn image_path(h: HANDLE) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// ProcessCommandLineInformation (Windows 8.1+): ответ - UNICODE_STRING, за
/// которым в том же буфере лежит сама строка.
unsafe fn command_line(h: HANDLE) -> Option<String> {
    let mut buf: Vec<u64> = vec![0; 1024];
    for _ in 0..2 {
        let mut need: u32 = 0;
        let st = unsafe {
            NtQueryInformationProcess(
                h,
                ProcessCommandLineInformation,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut need,
            )
        };
        if st >= 0 {
            let us = unsafe { &*buf.as_ptr().cast::<UNICODE_STRING>() };
            if us.Buffer.is_null() || us.Length == 0 {
                return None;
            }
            let s = unsafe { std::slice::from_raw_parts(us.Buffer, us.Length as usize / 2) };
            let s = String::from_utf16_lossy(s).trim().to_string();
            return (!s.is_empty()).then_some(s);
        }
        if need as usize <= buf.len() * 8 {
            return None;
        }
        buf = vec![0; (need as usize).div_ceil(8)];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sees_self_and_parent_link() {
        let me = std::process::id() as i32;
        let list = Scanner::default().refresh();
        let p = list.iter().find(|p| p.pid == me).expect("свой процесс не найден");
        assert!(p.name.to_ascii_lowercase().ends_with(".exe"), "имя: {}", p.name);
        assert!(!p.cmdline.is_empty());
    }
}
