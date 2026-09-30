//! Собственный движок Windows: пакеты из ETW, разбор и запись pcapng внутри SocketTrail.

use crate::i18n::Text;
use crate::pcap::Packet;
use tokio::sync::mpsc::UnboundedSender;

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
}

pub fn start_live(_iface: &str, tx: UnboundedSender<Packet>) -> Result<Live, Text> {
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
        self.recording
    }

    pub fn start(&mut self, _iface: &str, path: &str) -> std::io::Result<()> {
        if self.recording {
            return Ok(());
        }
        crate::etw::dump_start(path)?;
        self.recording = true;
        self.path = Some(path.to_string());
        self.started_ms = Some(crate::state::now_ms());
        Ok(())
    }

    pub async fn stop(&mut self) -> Option<String> {
        if !self.recording {
            return None;
        }
        crate::etw::dump_stop();
        self.recording = false;
        self.started_ms = None;
        self.path.clone()
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
        assert!(dump.start("any", path.to_str().unwrap()).is_err());
        assert!(!dump.is_running());
        assert!(dump.path.is_none());
        assert!(dump.stop().await.is_none());
        assert!(!path.exists());
    }
}
