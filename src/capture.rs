//! Захват пакетов: живой поток и запись дампа в файл.
//!
//! Linux: dumpcap с cap_net_admin,cap_net_raw, пользователь в группе wireshark -
//! захват идет без root и без запроса пароля.
//! Windows: свой захват через PktMon и ETW (src/etw.rs), с правами администратора.
//! dumpcap из Wireshark остается запасным путем, если он установлен.

use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;

use crate::i18n::Text;
use crate::pcap::{Packet, PcapngReader};

/// Путь к dumpcap. На Windows его нет в PATH: берем каталог установки Wireshark.
pub fn dumpcap() -> &'static std::path::Path {
    use std::sync::OnceLock;
    static P: OnceLock<std::path::PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        #[cfg(windows)]
        {
            let dirs = win::wireshark_dir().into_iter().chain(
                ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
                    .iter()
                    .filter_map(|v| {
                        std::env::var_os(v).map(|d| std::path::PathBuf::from(d).join("Wireshark"))
                    }),
            );
            for d in dirs {
                let exe = d.join("dumpcap.exe");
                if exe.is_file() {
                    return exe;
                }
            }
        }
        "dumpcap".into()
    })
}

#[cfg(not(windows))]
fn install_hint() -> Text {
    text!(
        "dumpcap not found. Install the wireshark-common package.",
        "dumpcap не найден. Установите пакет wireshark-common."
    )
}
#[cfg(windows)]
fn install_hint() -> Text {
    text!(
        "dumpcap not found. Install Wireshark (https://www.wireshark.org) \
         together with Npcap - the installer offers it as a checkbox.",
        "dumpcap не найден. Установите Wireshark (https://www.wireshark.org) \
         вместе с Npcap - галочка предлагается в установщике."
    )
}

#[cfg(not(windows))]
fn rights_hint() -> Text {
    text!(
        "Capture rights are granted like this:\n  \
         sudo dpkg-reconfigure wireshark-common   (answer \"yes\")\n  \
         sudo usermod -aG wireshark \"$USER\"       (then log in again)",
        "Права на захват выдаются так:\n  \
         sudo dpkg-reconfigure wireshark-common   (ответить \"да\")\n  \
         sudo usermod -aG wireshark \"$USER\"       (затем перелогиниться)"
    )
}
#[cfg(windows)]
fn rights_hint() -> Text {
    text!(
        "Npcap sees no network adapters. If Npcap was installed with \
         \"Restrict Npcap driver's access to Administrators only\", run \
         SocketTrail as administrator or reinstall Npcap without this option.",
        "Npcap не видит сетевых адаптеров. Если при установке Npcap была \
         включена опция \"Restrict Npcap driver's access to Administrators only\", запустите \
         SocketTrail от имени администратора или переустановите Npcap без этой опции."
    )
}

/// Проверка готовности захвата. `dumpcap -D` требует тех же прав, что и сам
/// захват, поэтому отказ виден сразу, а не пустым окном через минуту.
pub fn probe() -> Result<(), Text> {
    let out = std::process::Command::new(dumpcap()).arg("-D").output();
    match out {
        Err(_) => Err(install_hint()),
        Ok(o) if o.status.success() => {
            if cfg!(windows) && list_ifaces(&String::from_utf8_lossy(&o.stdout)).is_empty() {
                return Err(rights_hint());
            }
            Ok(())
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let first = err.lines().next().unwrap_or("unknown error").trim();
            let r = rights_hint();
            Err(Text {
                en: format!("{first}\n{}", r.en),
                ru: format!("{first}\n{}", r.ru),
            })
        }
    }
}

/// Адаптеры из вывода `dumpcap -D` вида "1. \Device\NPF_{GUID} (Ethernet)".
/// Loopback и WAN Miniport пропускаются: соединений наружу там нет, а на части
/// виртуальных адаптеров захват не открывается и роняет весь dumpcap.
fn list_ifaces(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split_once(". ").map(|(_, rest)| rest.trim()))
        .filter(|rest| rest.starts_with("\\Device\\NPF_"))
        .filter(|rest| !rest.contains("NPF_Loopback") && !rest.contains("WAN Miniport"))
        .filter_map(|rest| rest.split_whitespace().next().map(str::to_string))
        .collect()
}

/// Аргументы -i. "any" на Windows не существует: вместо него все подходящие
/// адаптеры сразу. Несколько интерфейсов можно перечислить через запятую.
fn iface_args(iface: &str) -> Vec<String> {
    let mut names: Vec<String> = iface
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cfg!(windows) && (names.is_empty() || names == ["any"]) {
        names = std::process::Command::new(dumpcap())
            .arg("-D")
            .output()
            .map(|o| list_ifaces(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
    }
    names
        .into_iter()
        .flat_map(|n| ["-i".to_string(), n])
        .collect()
}

/// Общие для живого потока и дампа параметры. -s, -f и -p до первого -i
/// задают значения по умолчанию для всех интерфейсов. Без promiscuous-режима:
/// нужен только трафик этого компьютера, а часть адаптеров его не поддерживает.
fn command(iface: &str, snaplen: &str, filter: &str) -> Command {
    let mut cmd = Command::new(dumpcap());
    cmd.args(["-s", snaplen, "-f", filter, "-p"]);
    cmd.args(iface_args(iface));
    cmd.arg("-q");
    #[cfg(windows)]
    cmd.creation_flags(win::CREATE_NEW_PROCESS_GROUP);
    cmd
}

/// Трафик loopback, кроме DNS. Локальные сервисы гоняют через lo гигабайты в
/// секунду (на тестовой машине 8 ГБ/с): это забивает разбор и раздувает дамп,
/// а соединений наружу там нет. DNS оставлен - через 127.0.0.53 идут имена.
pub const NO_LOOPBACK: &str = "not ((net 127.0.0.0/8 or host ::1) and not port 53)";

/// Живой разбор: snaplen 2048 байт хватает для DNS-ответа и TLS ClientHello,
/// полезную нагрузку целиком тут держать незачем - для нее есть режим дампа.
fn spawn_live(iface: &str, tx: UnboundedSender<Packet>) -> std::io::Result<Child> {
    let mut child = command(iface, "2048", NO_LOOPBACK)
        .args(["-w", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().expect("stdout запрошен как piped");
    tokio::spawn(async move {
        let mut reader = PcapngReader::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut packets = Vec::new();
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    packets.clear();
                    reader.push(&buf[..n], &mut packets);
                    for p in packets.drain(..) {
                        if tx.send(p).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
    Ok(child)
}

/// Работающий живой захват. Drop останавливает его.
pub enum Live {
    Dumpcap(Box<Child>),
    #[cfg(windows)]
    Etw(#[allow(dead_code)] crate::etw::Session), // держится ради Drop
}

impl Live {
    /// PID собственного процесса захвата, чтобы не показывать его соединения.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Live::Dumpcap(c) => c.id(),
            #[cfg(windows)]
            Live::Etw(_) => None,
        }
    }

    pub fn describe(&self, iface: &str) -> String {
        match self {
            Live::Dumpcap(_) => t!("dumpcap, interface {iface}", "dumpcap, интерфейс {iface}"),
            #[cfg(windows)]
            Live::Etw(_) => t!(
                "PktMon (ETW), all network adapters",
                "PktMon (ETW), все сетевые адаптеры"
            ),
        }
    }
}

/// Запуск живого разбора. Err - подсказка для интерфейса, почему захвата нет.
pub fn start_live(iface: &str, tx: UnboundedSender<Packet>) -> Result<Live, Text> {
    #[cfg(windows)]
    let own_err = match crate::etw::start(tx.clone()) {
        Ok(s) => return Ok(Live::Etw(s)),
        Err(e) => e,
    };
    match probe() {
        Ok(()) => spawn_live(iface, tx)
            .map(|c| Live::Dumpcap(Box::new(c)))
            .map_err(|e| text!("dumpcap did not start: {e}", "dumpcap не запустился: {e}")),
        #[cfg(windows)]
        Err(_) => Err(own_err),
        #[cfg(not(windows))]
        Err(e) => Err(e),
    }
}

#[derive(Default)]
pub struct Dump {
    child: Option<Child>,
    /// дамп пишет свой захват (Windows, PktMon), а не отдельный dumpcap
    own: bool,
    pub path: Option<String>,
    pub started_ms: Option<u64>,
}

impl Dump {
    pub fn is_running(&self) -> bool {
        self.child.is_some() || self.own
    }

    /// Запись полных пакетов в один файл. Трафик процесса отбирается при остановке
    /// (src/annotate.rs): фильтр по адресам на старте потерял бы новые серверы.
    pub fn start(&mut self, iface: &str, path: &str) -> std::io::Result<()> {
        if self.is_running() {
            return Ok(());
        }
        #[cfg(windows)]
        if crate::etw::running() {
            crate::etw::dump_start(path)?;
            self.own = true;
            self.path = Some(path.to_string());
            self.started_ms = Some(crate::state::now_ms());
            return Ok(());
        }
        let child = command(iface, "0", NO_LOOPBACK)
            .args(["-w", path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        self.child = Some(child);
        self.path = Some(path.to_string());
        self.started_ms = Some(crate::state::now_ms());
        Ok(())
    }

    /// Мягкая остановка: по SIGTERM (Linux) или CTRL_BREAK (Windows) dumpcap
    /// дописывает и корректно закрывает файл. Если не успел - снимаем принудительно.
    pub async fn stop(&mut self) -> Option<String> {
        if self.own {
            #[cfg(windows)]
            crate::etw::dump_stop();
            self.own = false;
            self.started_ms = None;
            return self.path.clone();
        }
        let mut child = self.child.take()?;
        if let Some(pid) = child.id() {
            soft_stop(pid);
        }
        let waited = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
        if waited.is_err() {
            let _ = child.kill().await;
        }
        self.started_ms = None;
        self.path.clone()
    }
}

#[cfg(unix)]
fn soft_stop(pid: u32) {
    // Минимальный внешний вызов вместо зависимости на весь крейт libc.
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

/// CTRL_BREAK доходит только до группы процессов, поэтому dumpcap запускается
/// с CREATE_NEW_PROCESS_GROUP; консоль у него общая с нами.
#[cfg(windows)]
fn soft_stop(pid: u32) {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    unsafe {
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};

    pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// Каталог, который установщик Wireshark пишет в реестр.
    pub fn wireshark_dir() -> Option<std::path::PathBuf> {
        let key = wide(r"SOFTWARE\Wireshark");
        let val = wide("InstallDir");
        let mut buf = [0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                val.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let n = (len as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buf[..n]).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npcap_list() {
        let out = "1. \\Device\\NPF_{A1B2} (Ethernet)\n\
                   2. \\Device\\NPF_{C3D4} (Wi-Fi)\n\
                   3. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n\
                   4. \\Device\\NPF_{E5F6} (WAN Miniport (IP))\n\
                   5. etwdump (Event Tracing for Windows (ETW) reader)\n";
        assert_eq!(
            list_ifaces(out),
            ["\\Device\\NPF_{A1B2}", "\\Device\\NPF_{C3D4}"]
        );
    }
}
