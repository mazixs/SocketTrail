//! Работа с dumpcap: живой поток пакетов и запись дампа в файл.
//!
//! dumpcap в системе несет cap_net_admin,cap_net_raw, а пользователь состоит
//! в группе wireshark - поэтому захват идет без root и без запроса пароля.

use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;

use crate::pcap::{Packet, PcapngReader};

/// Проверка готовности захвата. `dumpcap -D` требует тех же прав, что и сам
/// захват, поэтому отказ виден сразу, а не пустым окном через минуту.
pub fn probe() -> Result<(), String> {
    let out = std::process::Command::new("dumpcap").arg("-D").output();
    match out {
        Err(_) => Err("dumpcap не найден. Установите пакет wireshark-common.".into()),
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let first = err.lines().next().unwrap_or("неизвестная ошибка").trim();
            Err(format!(
                "{first}\nПрава на захват выдаются так:\n  \
                 sudo dpkg-reconfigure wireshark-common   (ответить \"да\")\n  \
                 sudo usermod -aG wireshark \"$USER\"       (затем перелогиниться)"
            ))
        }
    }
}

/// Трафик loopback, кроме DNS. Локальные сервисы гоняют через lo гигабайты в
/// секунду (на тестовой машине 8 ГБ/с): это забивает разбор и раздувает дамп,
/// а соединений наружу там нет. DNS оставлен - через 127.0.0.53 идут имена.
pub const NO_LOOPBACK: &str = "not ((net 127.0.0.0/8 or host ::1) and not port 53)";

/// Живой разбор: snaplen 2048 байт хватает для DNS-ответа и TLS ClientHello,
/// полезную нагрузку целиком тут держать незачем - для нее есть режим дампа.
pub fn spawn_live(iface: &str, tx: UnboundedSender<Packet>) -> std::io::Result<Child> {
    let mut child = Command::new("dumpcap")
        .args(["-i", iface, "-s", "2048", "-q", "-w", "-", "-f", NO_LOOPBACK])
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

    /// Запись полных пакетов в один файл. Фильтр BPF ограничивает дамп
    /// адресами выбранного процесса, иначе в файл попадет весь трафик хоста.
    pub fn start(&mut self, iface: &str, path: &str, bpf: Option<&str>) -> std::io::Result<()> {
        if self.is_running() {
            return Ok(());
        }
        let mut cmd = Command::new("dumpcap");
        cmd.args(["-i", iface, "-s", "0", "-q", "-w", path]);
        let filter = match bpf {
            Some(f) if !f.is_empty() => f,
            _ => NO_LOOPBACK,
        };
        cmd.args(["-f", filter]);
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        self.child = Some(child);
        self.path = Some(path.to_string());
        self.started_ms = Some(crate::state::now_ms());
        Ok(())
    }

    /// Мягкая остановка: dumpcap по SIGTERM дописывает и корректно закрывает файл.
    pub async fn stop(&mut self) -> Option<String> {
        let mut child = self.child.take()?;
        if let Some(pid) = child.id() {
            unsafe {
                libc_kill(pid as i32, 15);
            }
        }
        let _ = child.wait().await;
        self.started_ms = None;
        self.path.clone()
    }
}

// Минимальный внешний вызов вместо зависимости на весь крейт libc.
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}
