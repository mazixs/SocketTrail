//! Windows: таблицы IP Helper с PID владельца. Прав администратора не требуют.
//!
//! У UDP в таблице нет удаленного адреса, поэтому UDP-сокеты всегда приходят
//! как UNCONNECTED; соединения по ним складываются из пакетов (владелец - по
//! локальному порту, см. Store::apply_sockets).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::{Proto, SockEntry, udp_state};

/// MIB_TCP_STATE.
fn tcp_state(code: u32) -> &'static str {
    match code {
        1 => "CLOSE",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECV",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// Порт лежит в DWORD в сетевом порядке, значимы младшие 16 бит.
fn port(dw: u32) -> u16 {
    u16::from_be(dw as u16)
}

/// IPv4 в DWORD в сетевом порядке: байты в памяти уже идут как a.b.c.d.
fn v4(dw: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(dw.to_ne_bytes()))
}

fn v6(b: [u8; 16]) -> IpAddr {
    let ip = Ipv6Addr::from(b);
    match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    }
}

fn owner(pid: u32) -> Option<i32> {
    // 0 - System Idle (строки TIME_WAIT), своего процесса у таких сокетов нет
    if pid == 0 { None } else { Some(pid as i32) }
}

/// Таблица растет между вызовами, поэтому размер подбирается в цикле с запасом.
/// Буфер из u64 - чтобы строки таблицы были выровнены.
fn fetch(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size: u32 = 0;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..8 {
        let rc = call(buf.as_mut_ptr().cast(), &mut size);
        if rc == NO_ERROR {
            return Some(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        let want = (size as usize + size as usize / 8 + 256).div_ceil(8);
        buf = vec![0u64; want];
        size = (buf.len() * 8) as u32;
    }
    None
}

/// Строки таблицы вида { dwNumEntries: u32, table: [Row; N] }.
fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    let base = buf.as_ptr().cast::<u8>();
    let n = unsafe { *base.cast::<u32>() } as usize;
    let off = std::mem::align_of::<T>().max(4);
    let avail = (buf.len() * 8).saturating_sub(off) / std::mem::size_of::<T>();
    let first = unsafe { base.add(off).cast::<T>() };
    (0..n.min(avail))
        .map(|i| unsafe { first.add(i).read_unaligned() })
        .collect()
}

fn tcp(af: u16) -> Option<Vec<u64>> {
    fetch(|p, s| unsafe { GetExtendedTcpTable(p, s, 0, af as u32, TCP_TABLE_OWNER_PID_ALL, 0) })
}

fn udp(af: u16) -> Option<Vec<u64>> {
    fetch(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, af as u32, UDP_TABLE_OWNER_PID, 0) })
}

pub fn snapshot(_scan_pids: &[i32]) -> Vec<SockEntry> {
    let mut out = Vec::with_capacity(512);
    if let Some(b) = tcp(AF_INET) {
        for r in rows::<MIB_TCPROW_OWNER_PID>(&b) {
            out.push(SockEntry {
                proto: Proto::Tcp,
                local: v4(r.dwLocalAddr),
                lport: port(r.dwLocalPort),
                remote: v4(r.dwRemoteAddr),
                rport: port(r.dwRemotePort),
                state: tcp_state(r.dwState),
                pid: owner(r.dwOwningPid),
            });
        }
    }
    if let Some(b) = tcp(AF_INET6) {
        for r in rows::<MIB_TCP6ROW_OWNER_PID>(&b) {
            out.push(SockEntry {
                proto: Proto::Tcp,
                local: v6(r.ucLocalAddr),
                lport: port(r.dwLocalPort),
                remote: v6(r.ucRemoteAddr),
                rport: port(r.dwRemotePort),
                state: tcp_state(r.dwState),
                pid: owner(r.dwOwningPid),
            });
        }
    }
    let unspec4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let unspec6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    if let Some(b) = udp(AF_INET) {
        for r in rows::<MIB_UDPROW_OWNER_PID>(&b) {
            out.push(SockEntry {
                proto: Proto::Udp,
                local: v4(r.dwLocalAddr),
                lport: port(r.dwLocalPort),
                remote: unspec4,
                rport: 0,
                state: udp_state(0),
                pid: owner(r.dwOwningPid),
            });
        }
    }
    if let Some(b) = udp(AF_INET6) {
        for r in rows::<MIB_UDP6ROW_OWNER_PID>(&b) {
            out.push(SockEntry {
                proto: Proto::Udp,
                local: v6(r.ucLocalAddr),
                lport: port(r.dwLocalPort),
                remote: unspec6,
                rport: 0,
                state: udp_state(0),
                pid: owner(r.dwOwningPid),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn byte_order() {
        assert_eq!(port(0x5000), 80); // 80 в сетевом порядке: байты 00 50
        assert_eq!(v4(u32::from_ne_bytes([192, 168, 1, 2])).to_string(), "192.168.1.2");
    }

    /// Свое соединение должно быть в таблице со своим PID. Работает и под Wine:
    /// сокет принадлежит Wine-процессу, такие wineserver в таблицу отдает.
    #[test]
    fn sees_own_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let lp = l.local_addr().unwrap().port();
        let c = TcpStream::connect(("127.0.0.1", lp)).unwrap();
        let cp = c.local_addr().unwrap().port();
        let (mut a, _) = l.accept().unwrap();
        a.set_nonblocking(true).unwrap();
        let _ = a.read(&mut [0u8; 1]);
        let me = std::process::id() as i32;
        let s = snapshot(&[]);
        assert!(
            s.iter().any(|e| e.proto == Proto::Tcp
                && e.lport == cp
                && e.rport == lp
                && e.state == "ESTABLISHED"
                && e.pid == Some(me)),
            "соединение {cp}->{lp} с PID {me} не найдено среди {} сокетов",
            s.len()
        );
    }
}
