//! Захват пакетов: живой поток и запись дампа в файл.
//!
//! Linux: dumpcap с cap_net_admin,cap_net_raw, пользователь в группе wireshark -
//! захват идет без root и без запроса пароля.

use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;

use crate::i18n::Text;
use crate::pcap::{Packet, PcapngReader};

pub fn dumpcap() -> &'static std::path::Path {
    std::path::Path::new("dumpcap")
}

fn install_hint() -> Text {
    text!(
        "dumpcap not found. Install the wireshark-common package.",
        "dumpcap не найден. Установите пакет wireshark-common."
    )
}

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

/// Проверка готовности захвата. `dumpcap -D` требует тех же прав, что и сам
/// захват, поэтому отказ виден сразу, а не пустым окном через минуту.
pub fn probe() -> Result<(), Text> {
    let out = std::process::Command::new(dumpcap()).arg("-D").output();
    match out {
        Err(_) => Err(install_hint()),
        Ok(o) if o.status.success() => Ok(()),
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

/// Несколько интерфейсов можно перечислить через запятую.
fn iface_args(iface: &str) -> Vec<String> {
    let names: Vec<String> = iface
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
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
}

impl Live {
    /// PID собственного процесса захвата, чтобы не показывать его соединения.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Live::Dumpcap(c) => c.id(),
        }
    }

    pub fn describe(&self, iface: &str) -> String {
        match self {
            Live::Dumpcap(_) => t!("dumpcap, interface {iface}", "dumpcap, интерфейс {iface}"),
        }
    }
}

/// Запуск живого разбора. Err - подсказка для интерфейса, почему захвата нет.
pub fn start_live(iface: &str, tx: UnboundedSender<Packet>) -> Result<Live, Text> {
    match probe() {
        Ok(()) => spawn_live(iface, tx)
            .map(|c| Live::Dumpcap(Box::new(c)))
            .map_err(|e| text!("dumpcap did not start: {e}", "dumpcap не запустился: {e}")),
        Err(e) => Err(e),
    }
}

#[derive(Default)]
pub struct Dump {
    child: Option<Child>,
    pub path: Option<String>,
    pub started_ms: Option<u64>,
}

impl Dump {
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// Запись полных пакетов в один файл. Трафик процесса отбирается при остановке
    /// (src/annotate.rs): фильтр по адресам на старте потерял бы новые серверы.
    pub fn start(&mut self, iface: &str, path: &str) -> std::io::Result<()> {
        if self.is_running() {
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

    /// Мягкая остановка: по SIGTERM dumpcap
    /// дописывает и корректно закрывает файл. Если не успел - снимаем принудительно.
    pub async fn stop(&mut self) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_arguments() {
        assert_eq!(iface_args("any"), ["-i", "any"]);
        assert_eq!(iface_args(" eth0, , wlan0 "), ["-i", "eth0", "-i", "wlan0"]);
    }
}
