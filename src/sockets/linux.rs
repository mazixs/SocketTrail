//! Linux: сокеты из /proc/net/* и привязка их к процессам через inode.
//!
//! Замена `ss -tunp` в цикле: без форка на каждый опрос, поэтому интервал
//! можно держать в районе 200 мс и ловить короткоживущие соединения.

use std::collections::{HashMap, HashSet};
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
                cookie: (inode != 0).then_some(inode),
            },
            inode,
        ));
    }
}

/// Адреса интерфейсов нужны и для UDP, привязанного к 0.0.0.0 или ::.
/// Таблица сокетов сама по себе не перечисляет все адреса компьютера.
pub fn local_addresses() -> Option<HashSet<IpAddr>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs создает список, освобождаемый freeifaddrs ровно один раз.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut ips = HashSet::new();
    let mut cur = head;
    // SAFETY: узлы и sockaddr действительны до freeifaddrs; семейство проверяем
    // перед приведением указателя к sockaddr_in или sockaddr_in6.
    unsafe {
        while let Some(entry) = cur.as_ref() {
            if !entry.ifa_addr.is_null() {
                match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let addr = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                        ips.insert(IpAddr::V4(Ipv4Addr::from(
                            addr.sin_addr.s_addr.to_ne_bytes(),
                        )));
                    }
                    libc::AF_INET6 => {
                        let addr = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                        ips.insert(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    Some(ips)
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
    let mut wine = HashMap::new();
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
                    let mut is_wine = |p: i32| *wine.entry(p).or_insert_with(|| is_wineserver(p));
                    match map.get(&ino) {
                        Some(&prev) if is_wine(pid) && !is_wine(prev) => {}
                        _ => {
                            map.insert(ino, pid);
                        }
                    }
                }
            }
        }
    }
    map
}

/// Wine держит копию каждого сокета программы в wineserver. Владелец - сам .exe,
/// иначе соединения игры уходят к wineserver, если его PID больше.
fn is_wineserver(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim_end() == "wineserver")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn interface_addresses_include_loopback_without_socket_connections() {
        let ips = local_addresses().unwrap();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!ips.contains(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn udp_snapshot_has_own_pid_and_inode() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let pid = std::process::id() as i32;
        let socks = snapshot(&[pid]);
        let s = socks
            .iter()
            .find(|s| s.proto == Proto::Udp && s.local == addr.ip() && s.lport == addr.port())
            .unwrap();
        assert_eq!(s.pid, Some(pid));
        assert!(s.cookie.is_some_and(|inode| inode != 0));
    }
}
