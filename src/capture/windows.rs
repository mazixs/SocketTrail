//! Собственный движок Windows: пакеты из ETW, разбор и запись pcapng внутри SocketTrail.

use crate::capture::PacketSender;
use crate::i18n::Text;

pub struct Live {
    // Сессия должна жить до завершения приложения.
    _session: crate::etw::Session,
}

impl Live {
    pub fn pid(&self) -> Option<u32> {
        None
    }

    pub fn describe(&self, _iface: &str) -> String {
        t!(
            "PktMon (ETW), all network adapters",
            "PktMon (ETW), все сетевые адаптеры"
        )
    }

    pub fn check(&mut self) -> Result<(), Text> {
        if crate::etw::is_active() {
            Ok(())
        } else {
            Err(text!(
                "Packet capture stopped",
                "Пакетный захват остановился"
            ))
        }
    }
}

pub async fn start_live(_iface: &str, tx: PacketSender) -> Result<Live, Text> {
    crate::etw::start(tx).map(|session| Live { _session: session })
}

#[derive(Default)]
pub struct Dump {
    recording: bool,
    pub path: Option<String>,
    pub started_ms: Option<u64>,
}

impl Dump {
    pub fn is_running(&self) -> bool {
        self.recording && crate::etw::dump_error().is_none()
    }

    pub fn poll_error(&mut self) -> Option<String> {
        self.recording.then(crate::etw::dump_error).flatten()
    }

    pub async fn start(&mut self, _iface: &str, path: &str) -> std::io::Result<()> {
        if self.recording {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                t!("Recording is already running", "Запись уже идет"),
            ));
        }
        let file = path.to_string();
        tokio::task::spawn_blocking(move || crate::etw::dump_start(&file))
            .await
            .map_err(std::io::Error::other)??;
        self.recording = true;
        self.path = Some(path.to_string());
        self.started_ms = Some(crate::state::now_ms());
        Ok(())
    }

    pub async fn stop(&mut self) -> std::io::Result<Option<String>> {
        if !self.recording {
            return Ok(None);
        }
        let error = crate::etw::dump_error();
        let result = tokio::task::spawn_blocking(crate::etw::dump_stop)
            .await
            .map_err(std::io::Error::other)?;
        self.recording = false;
        self.started_ms = None;
        result?;
        if let Some(e) = error {
            return Err(std::io::Error::other(e));
        }
        Ok(self.path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dump_without_capture_fails_without_creating_file() {
        let path = std::env::temp_dir().join(format!(
            "sockettrail-no-capture-{}.pcapng",
            std::process::id()
        ));
        let mut dump = Dump::default();
        assert!(dump.start("any", path.to_str().unwrap()).await.is_err());
        assert!(!dump.is_running());
        assert!(dump.path.is_none());
        assert!(dump.stop().await.unwrap().is_none());
        assert!(!path.exists());
    }
}
