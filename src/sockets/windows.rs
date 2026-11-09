//! Windows: таблицы IP Helper с PID владельца. Прав администратора не требуют.
//!
//! У UDP в таблице нет удаленного адреса, поэтому UDP-сокеты всегда приходят
//! как UNCONNECTED; соединения по ним складываются из пакетов (владелец - по
//! локальному адресу и порту, см. Store::apply_sockets).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetExtendedUdpTable, GetUnicastIpAddressTable,
    MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_MODULE, MIB_UDPROW_OWNER_PID, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_MODULE,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

use super::{Proto, STATE_OPEN, SockEntry, udp_state};

const LISTEN: u32 = 2;
const STATE_LISTEN: &str = "LISTEN";

/// MIB_TCP_STATE.
fn tcp_state(code: u32) -> &'static str {
    match code {
        1 => "CLOSED",
        2 => STATE_LISTEN,
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

/// На некоторых системах поле состояния в таблице TCP смещено относительно строк: вместо
/// него читаются соседние служебные значения (LISTEN, CLOSED, 0, FIN_WAIT1), и они меняются
/// у десятков строк разом. netstat показывает то же самое, адрес и PID при этом верны.
/// Смещение видно по самой таблице: слушающий сокет с другим состоянием или соединение
/// с адресом, которое якобы слушает. Без такого признака таблице верим как есть.
fn state_field_is_shifted(mut rows: impl Iterator<Item = (u32, bool)>) -> bool {
    rows.any(|(code, connected)| {
        if connected {
            code == 0 || code == LISTEN
        } else {
            code != LISTEN
        }
    })
}

/// Состояние строки с учетом смещения. Настоящее значение отличается от служебных, поэтому
/// ему верим и тут. Строка без владельца остается только после закрытия: это TIME_WAIT.
fn connection_state(code: u32, pid: u32, shifted: bool) -> &'static str {
    if !shifted {
        tcp_state(code)
    } else if pid == 0 {
        "TIME_WAIT"
    } else if matches!(code, 0 | 1 | LISTEN | 6) {
        STATE_OPEN
    } else {
        tcp_state(code)
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

pub fn local_addresses() -> Option<HashSet<IpAddr>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: API выделяет таблицу с NumEntries строками, освобождаем FreeMibTable.
    unsafe {
        if GetUnicastIpAddressTable(AF_UNSPEC, &mut table) != NO_ERROR || table.is_null() {
            return None;
        }
        let mut ips = HashSet::new();
        let first = std::ptr::addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>();
        let entries = std::slice::from_raw_parts(first, (*table).NumEntries as usize);
        for row in entries {
            let addr = &row.Address;
            match addr.si_family {
                AF_INET => {
                    ips.insert(v4(addr.Ipv4.sin_addr.S_un.S_addr));
                }
                AF_INET6 => {
                    ips.insert(v6(addr.Ipv6.sin6_addr.u.Byte));
                }
                _ => {}
            }
        }
        FreeMibTable(table.cast());
        Some(ips)
    }
}

fn udp(af: u16, class: i32) -> Option<Vec<u64>> {
    fetch(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, af as u32, class, 0) })
}

/// None - таблицу прочитать не удалось. Пустой снимок в этом случае закрыл бы все
/// соединения разом, и при следующем чтении они выглядели бы повторно занятыми.
/// Таблицы IPv6 необязательны: стека IPv6 в системе может не быть.
pub fn snapshot(_scan_pids: &[i32]) -> Option<Vec<SockEntry>> {
    let mut out = Vec::with_capacity(512);
    let table = rows::<MIB_TCPROW_OWNER_PID>(&tcp(AF_INET)?);
    let shifted = state_field_is_shifted(table.iter().map(|r| (r.dwState, r.dwRemoteAddr != 0)));
    for r in table {
        out.push(SockEntry {
            proto: Proto::Tcp,
            local: v4(r.dwLocalAddr),
            lport: port(r.dwLocalPort),
            remote: v4(r.dwRemoteAddr),
            rport: port(r.dwRemotePort),
            state: connection_state(r.dwState, r.dwOwningPid, shifted),
            pid: owner(r.dwOwningPid),
            ambiguous: false,
            cookie: None,
        });
    }
    if let Some(b) = tcp(AF_INET6) {
        let table = rows::<MIB_TCP6ROW_OWNER_PID>(&b);
        let shifted =
            state_field_is_shifted(table.iter().map(|r| (r.dwState, r.ucRemoteAddr != [0; 16])));
        for r in table {
            out.push(SockEntry {
                proto: Proto::Tcp,
                local: v6(r.ucLocalAddr),
                lport: port(r.dwLocalPort),
                remote: v6(r.ucRemoteAddr),
                rport: port(r.dwRemotePort),
                state: connection_state(r.dwState, r.dwOwningPid, shifted),
                pid: owner(r.dwOwningPid),
                ambiguous: false,
                cookie: None,
            });
        }
    }
    let unspec4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let unspec6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    if let Some(b) = udp(AF_INET, UDP_TABLE_OWNER_MODULE) {
        for r in rows::<MIB_UDPROW_OWNER_MODULE>(&b) {
            out.push(SockEntry {
                proto: Proto::Udp,
                local: v4(r.dwLocalAddr),
                lport: port(r.dwLocalPort),
                remote: unspec4,
                rport: 0,
                state: udp_state(0),
                pid: owner(r.dwOwningPid),
                ambiguous: false,
                cookie: (r.liCreateTimestamp != 0).then_some(r.liCreateTimestamp as u64),
            });
        }
    } else {
        for r in rows::<MIB_UDPROW_OWNER_PID>(&udp(AF_INET, UDP_TABLE_OWNER_PID)?) {
            out.push(SockEntry {
                proto: Proto::Udp,
                local: v4(r.dwLocalAddr),
                lport: port(r.dwLocalPort),
                remote: unspec4,
                rport: 0,
                state: udp_state(0),
                pid: owner(r.dwOwningPid),
                ambiguous: false,
                cookie: None,
            });
        }
    }
    if let Some(b) = udp(AF_INET6, UDP_TABLE_OWNER_MODULE) {
        for r in rows::<MIB_UDP6ROW_OWNER_MODULE>(&b) {
            out.push(SockEntry {
                proto: Proto::Udp,
                local: v6(r.ucLocalAddr),
                lport: port(r.dwLocalPort),
                remote: unspec6,
                rport: 0,
                state: udp_state(0),
                pid: owner(r.dwOwningPid),
                ambiguous: false,
                cookie: (r.liCreateTimestamp != 0).then_some(r.liCreateTimestamp as u64),
            });
        }
    } else if let Some(b) = udp(AF_INET6, UDP_TABLE_OWNER_PID) {
        for r in rows::<MIB_UDP6ROW_OWNER_PID>(&b) {
            out.push(SockEntry {
                proto: Proto::Udp,
                local: v6(r.ucLocalAddr),
                lport: port(r.dwLocalPort),
                remote: unspec6,
                rport: 0,
                state: udp_state(0),
                pid: owner(r.dwOwningPid),
                ambiguous: false,
                cookie: None,
            });
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn interface_addresses_include_loopback() {
        let ips = local_addresses().unwrap();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn sees_own_udp_endpoint() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let pid = std::process::id() as i32;
        let socks = snapshot(&[]).unwrap();
        assert!(socks.iter().any(|s| s.proto == Proto::Udp
            && s.local == addr.ip()
            && s.lport == addr.port()
            && s.pid == Some(pid)));
    }

    #[test]
    fn healthy_table_is_taken_as_it_is() {
        let rows = [(LISTEN, false), (5, true), (6, true), (1, true), (11, true)];
        assert!(!state_field_is_shifted(rows.into_iter()));
        assert_eq!(connection_state(6, 100, false), "FIN_WAIT1");
        assert_eq!(connection_state(1, 100, false), "CLOSED");
        assert_eq!(connection_state(5, 0, false), "ESTABLISHED");
    }

    #[test]
    fn shifted_table_is_recognized_by_impossible_rows() {
        assert!(state_field_is_shifted([(5, true), (1, false)].into_iter()));
        assert!(state_field_is_shifted(
            [(5, true), (LISTEN, true)].into_iter()
        ));
        assert!(state_field_is_shifted([(0, true)].into_iter()));
    }

    #[test]
    fn shifted_values_do_not_pass_for_connection_states() {
        for code in [0, 1, LISTEN, 6] {
            assert_eq!(connection_state(code, 100, true), STATE_OPEN);
            assert_eq!(connection_state(code, 0, true), "TIME_WAIT");
        }
        assert_eq!(connection_state(5, 100, true), "ESTABLISHED");
        assert_eq!(connection_state(8, 100, true), "CLOSE_WAIT");
        assert_eq!(connection_state(3, 100, true), "SYN_SENT");
    }

    #[test]
    fn byte_order() {
        assert_eq!(port(0x5000), 80); // 80 в сетевом порядке: байты 00 50
        assert_eq!(
            v4(u32::from_ne_bytes([192, 168, 1, 2])).to_string(),
            "192.168.1.2"
        );
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
        let s = snapshot(&[]).unwrap();
        assert!(
            s.iter().any(|e| e.proto == Proto::Tcp
                && e.lport == cp
                && e.rport == lp
                && (e.state == "ESTABLISHED" || e.state == STATE_OPEN)
                && e.pid == Some(me)),
            "соединение {cp}->{lp} с PID {me} не найдено среди {} сокетов",
            s.len()
        );
    }
}
