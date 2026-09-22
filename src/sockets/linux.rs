//! Linux: сокеты из /proc/net/* и привязка их к процессам через inode.
//!
//! Замена `ss -tunp` в цикле: без форка на каждый опрос, поэтому интервал
//! можно держать в районе 200 мс и ловить короткоживущие соединения.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{Proto, SockEntry, udp_state};

/// Состояния TCP из /proc/net/tcp (поле st, шестнадцатеричное).
fn tcp_state(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// "0100007F:0035" -> 127.0.0.1:53. Слова адреса лежат в порядке хоста (little-endian).
fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match addr.len() {
        8 => {
            let v = u32::from_str_radix(addr, 16).ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(v.to_be())), port))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for word in 0..4 {
                let v = u32::from_str_radix(&addr[word * 8..word * 8 + 8], 16).ok()?;
                bytes[word * 4..word * 4 + 4].copy_from_slice(&v.to_be_bytes());
                // внутри слова порядок обратный
                bytes[word * 4..word * 4 + 4].reverse();
            }
            let ip = Ipv6Addr::from(bytes);
            // IPv4-mapped показываем как IPv4 - так читается привычнее
            match ip.to_ipv4_mapped() {
                Some(v4) => Some((IpAddr::V4(v4), port)),
                None => Some((IpAddr::V6(ip), port)),
            }
        }
        _ => None,
    }
}

fn parse_table(path: &str, proto: Proto, out: &mut Vec<(SockEntry, u64)>) {
    let data = match fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return,
    };
    for line in data.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (local, lport) = match parse_addr(f[1]) {
            Some(v) => v,
            None => continue,
        };
        let (remote, rport) = match parse_addr(f[2]) {
            Some(v) => v,
            None => continue,
        };
        let st = u8::from_str_radix(f[3], 16).unwrap_or(0);
        let state = match proto {
            Proto::Tcp => tcp_state(st),
            Proto::Udp => udp_state(rport),
        };
        let inode: u64 = f[9].parse().unwrap_or(0);
        out.push((
            SockEntry {
                proto,
                local,
                lport,
                remote,
                rport,
                state,
                pid: None,
            },
            inode,
        ));
    }
}

/// Владелец ищется только среди `scan_pids`: обход /proc/<pid>/fd всех процессов
/// дорогой, поэтому полную карту строим редко, а в остальное время - по выбранной группе.
pub fn snapshot(scan_pids: &[i32]) -> Vec<SockEntry> {
    let mut raw = Vec::with_capacity(512);
    parse_table("/proc/net/tcp", Proto::Tcp, &mut raw);
    parse_table("/proc/net/tcp6", Proto::Tcp, &mut raw);
    parse_table("/proc/net/udp", Proto::Udp, &mut raw);
    parse_table("/proc/net/udp6", Proto::Udp, &mut raw);
    let owners = inode_owners(scan_pids);
    raw.into_iter()
        .map(|(mut s, ino)| {
            s.pid = owners.get(&ino).copied();
            s
        })
        .collect()
}

/// inode сокета -> PID. Файловые дескрипторы общие для всех потоков процесса,
/// поэтому обхода /proc/<pid>/fd достаточно, в /proc/<pid>/task лезть не нужно.
fn inode_owners(pids: &[i32]) -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    for &pid in pids {
        let dir = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d,
            Err(_) => continue, // процесс умер или чужой uid - это нормально
        };
        for fd in dir.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(rest) = t.strip_prefix("socket:[")
                    && let Ok(ino) = rest.trim_end_matches(']').parse::<u64>()
                {
                    map.insert(ino, pid);
                }
            }
        }
    }
    map
}
