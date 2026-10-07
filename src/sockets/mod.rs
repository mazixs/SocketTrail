//! Снимок сокетов системы с владельцем-процессом.
//!
//! Linux: /proc/net/* и связь с процессом через inode.
//! Windows: GetExtendedTcpTable/GetExtendedUdpTable, PID приходит в строке таблицы.

use serde::Serialize;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{local_addresses, snapshot};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{local_addresses, snapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SockEntry {
    pub proto: Proto,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    pub state: &'static str,
    /// Владелец. На Linux известен только для PID из `scan_pids` снимка.
    pub pid: Option<i32>,
    /// Сокет подтвержденно разделяют несколько процессов.
    pub ambiguous: bool,
    /// Идентичность сокета: inode на Linux, время создания UDP на Windows.
    /// None, если платформа не предоставляет эту информацию.
    pub cookie: Option<u64>,
}

/// Имя состояния UDP-сокета: без удаленного адреса он просто слушает порт.
pub fn udp_state(rport: u16) -> &'static str {
    if rport == 0 { "UNCONNECTED" } else { "ACTIVE" }
}
