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

/// Параметры до -i применяются ко всем интерфейсам; promiscuous отключен.
fn command(iface: &str, snaplen: &str, filter: &str) -> Command {
    let mut cmd = Command::new(dumpcap());
    cmd.args(["-s", snaplen, "-f", filter, "-p"]);
    cmd.args(iface_args(iface));
    cmd.arg("-q");
    cmd
}

/// Loopback исключен, кроме DNS, чтобы локальный трафик не перегружал захват.
pub const NO_LOOPBACK: &str = "not ((net 127.0.0.0/8 or host ::1) and not port 53)";

const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

struct Process {
    child: Child,
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Process {
    fn spawn(mut cmd: Command) -> std::io::Result<Self> {
        let mut child = cmd.stderr(Stdio::piped()).kill_on_drop(true).spawn()?;
        let mut pipe = child.stderr.take().expect("stderr piped");
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let captured = stderr.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n) = pipe.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let mut text = captured.lock().unwrap();
                if text.len() < 4096 {
                    text.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        });
        Ok(Self { child, stderr })
    }

    fn failure(&self) -> std::io::Error {
        let detail = self.stderr.lock().unwrap().trim().to_string();
        std::io::Error::other(t!(
            "dumpcap stopped unexpectedly. {detail}",
            "dumpcap неожиданно остановился. {detail}"
        ))
    }

    fn check(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Err(self.failure());
        }
        Ok(())
    }

    async fn ready(&mut self, ready: impl Fn() -> bool) -> std::io::Result<()> {
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        loop {
            self.check()?;
            if ready() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    t!(
                        "dumpcap did not begin capturing within 3 seconds",
                        "dumpcap не начал захват за 3 секунды"
                    ),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    async fn stop(&mut self) -> std::io::Result<()> {
        self.check()?;
        if let Some(pid) = self.child.id() {
            soft_stop(pid);
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), self.child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(_)) => Err(self.failure()),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                let _ = self.child.kill().await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    t!(
                        "dumpcap did not stop cleanly",
                        "dumpcap не завершил запись корректно"
                    ),
                ))
            }
        }
    }
}

pub struct Live {
    process: Process,
    stream_closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Live {
    pub fn pid(&self) -> Option<u32> {
        self.process.child.id()
    }

    pub fn describe(&self, iface: &str) -> String {
        t!("dumpcap, interface {iface}", "dumpcap, интерфейс {iface}")
    }

    pub fn check(&mut self) -> Result<(), Text> {
        self.process
            .check()
            .map_err(|e| Text::from(e.to_string()))?;
        if self
            .stream_closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(text!("Packet stream ended", "Поток пакетов завершился"));
        }
        Ok(())
    }
}

pub async fn start_live(iface: &str, tx: UnboundedSender<Packet>) -> Result<Live, Text> {
    probe()?;
    spawn_live(iface, tx)
        .await
        .map_err(|e| text!("dumpcap did not start: {e}", "dumpcap не запустился: {e}"))
}

async fn spawn_live(iface: &str, tx: UnboundedSender<Packet>) -> std::io::Result<Live> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let mut cmd = command(iface, "2048", NO_LOOPBACK);
    cmd.args(["-w", "-"]).stdout(Stdio::piped());
    let mut process = Process::spawn(cmd)?;
    let mut stdout = process.child.stdout.take().expect("stdout piped");
    let ready = Arc::new(AtomicBool::new(false));
    let stream_closed = Arc::new(AtomicBool::new(false));
    let (started, closed) = (ready.clone(), stream_closed.clone());
    tokio::spawn(async move {
        let mut reader = PcapngReader::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut packets = Vec::new();
        let mut prefix = Vec::new();
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if prefix.len() < 4 {
                        prefix.extend_from_slice(&buf[..n.min(4 - prefix.len())]);
                        if prefix.len() == 4 {
                            if prefix != [0x0a, 0x0d, 0x0d, 0x0a] {
                                break;
                            }
                            started.store(true, Ordering::Release);
                        }
                    }
                    packets.clear();
                    reader.push(&buf[..n], &mut packets);
                    for p in packets.drain(..) {
                        if tx.send(p).is_err() {
                            closed.store(true, Ordering::Release);
                            return;
                        }
                    }
                }
            }
        }
        closed.store(true, Ordering::Release);
    });
    process.ready(|| ready.load(Ordering::Acquire)).await?;
    Ok(Live {
        process,
        stream_closed,
    })
}

#[derive(Default)]
pub struct Dump {
    process: Option<Process>,
    error: Option<String>,
    pub path: Option<String>,
    pub started_ms: Option<u64>,
}

impl Dump {
    pub fn is_running(&self) -> bool {
        self.process.is_some() && self.error.is_none()
    }

    pub fn poll_error(&mut self) -> Option<String> {
        if self.error.is_none()
            && let Some(p) = &mut self.process
            && let Err(e) = p.check()
        {
            self.error = Some(e.to_string());
        }
        self.error.clone()
    }

    /// Полные пакеты записываются сразу, отбор процесса выполняется при остановке.
    pub async fn start(&mut self, iface: &str, path: &str) -> std::io::Result<()> {
        if self.process.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                t!("Recording is already running", "Запись уже идет"),
            ));
        }
        self.error = None;
        self.path = Some(path.to_string());
        let started = crate::state::now_ms();
        let mut cmd = command(iface, "0", NO_LOOPBACK);
        cmd.args(["-w", path]).stdout(Stdio::null());
        let mut process = Process::spawn(cmd)?;
        process
            .ready(|| {
                let mut header = [0u8; 4];
                std::fs::File::open(path).ok().is_some_and(|mut file| {
                    std::io::Read::read_exact(&mut file, &mut header).is_ok()
                        && header == [0x0a, 0x0d, 0x0d, 0x0a]
                })
            })
            .await?;
        self.process = Some(process);
        self.started_ms = Some(started);
        Ok(())
    }

    pub async fn stop(&mut self) -> std::io::Result<Option<String>> {
        let Some(mut process) = self.process.take() else {
            return Ok(None);
        };
        self.started_ms = None;
        process.stop().await?;
        Ok(self.path.clone())
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

    fn script(code: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", code]).stdout(Stdio::null());
        cmd
    }

    #[tokio::test]
    async fn child_exit_is_not_successful_capture_start() {
        let mut process =
            Process::spawn(script("printf 'demo capture failure' >&2; exit 1")).unwrap();
        assert!(process.ready(|| false).await.is_err());
        assert!(
            process
                .failure()
                .to_string()
                .contains("demo capture failure")
        );
    }

    #[tokio::test]
    async fn terminated_dump_is_not_running_and_cannot_stop_successfully() {
        let mut process = Process::spawn(script("exit 1")).unwrap();
        process.child.wait().await.unwrap();
        let mut dump = Dump {
            process: Some(process),
            path: Some("demo.pcapng".into()),
            ..Dump::default()
        };
        assert!(dump.poll_error().is_some());
        assert!(!dump.is_running());
        assert!(dump.stop().await.is_err());
    }

    #[tokio::test]
    async fn repeated_dump_start_keeps_its_original_path_and_child() {
        let process = Process::spawn(script("exec sleep 30")).unwrap();
        let pid = process.child.id();
        let mut dump = Dump {
            process: Some(process),
            path: Some("demo.pcapng".into()),
            ..Dump::default()
        };
        assert!(dump.start("any", "other.pcapng").await.is_err());
        assert_eq!(dump.path.as_deref(), Some("demo.pcapng"));
        assert_eq!(dump.process.as_ref().unwrap().child.id(), pid);
        dump.process.as_mut().unwrap().child.kill().await.unwrap();
    }

    #[tokio::test]
    async fn healthy_live_capture_reports_a_closed_stream() {
        let process = Process::spawn(script("exec sleep 30")).unwrap();
        let mut live = Live {
            process,
            stream_closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        assert!(live.check().is_err());
        live.process.child.kill().await.unwrap();
    }
}
