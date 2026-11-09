//! Платформенный захват: PktMon/ETW на Windows, dumpcap на Linux.

#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

use crate::pcap::Packet;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc;

/// Очередь разбора к таблице соединений. Держит всплеск на несколько секунд, пока
/// таблицу блокирует опрос или API.
pub const QUEUE_CAPACITY: usize = 65_536;

#[derive(Default)]
pub struct Metrics {
    /// Пакеты, не попавшие в учет соединений: очередь к таблице переполнена.
    pub dropped: AtomicU64,
    pub accepted: AtomicU64,
    pub processed: AtomicU64,
    /// Кадры, не попавшие в файл дампа: захват не успевал за трафиком.
    pub lost_frames: AtomicU64,
    /// Кадры неизвестного формата. В дамп не идут, но и потерями не считаются:
    /// это не трафик приложений, а служебные типы пакетов драйвера.
    pub unsupported: AtomicU64,
}

/// Значения счетчиков потерь на момент снимка: запись сравнивает их со стартовыми.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Losses {
    pub dropped: u64,
    pub lost_frames: u64,
    pub unsupported: u64,
}

impl Metrics {
    pub fn losses(&self) -> Losses {
        Losses {
            dropped: self.dropped.load(Ordering::Relaxed),
            lost_frames: self.lost_frames.load(Ordering::Relaxed) + system_lost(),
            unsupported: self.unsupported.load(Ordering::Relaxed),
        }
    }
}

impl Losses {
    pub fn since(self, start: Self) -> Self {
        Self {
            dropped: self.dropped.saturating_sub(start.dropped),
            lost_frames: self.lost_frames.saturating_sub(start.lost_frames),
            unsupported: self.unsupported.saturating_sub(start.unsupported),
        }
    }
}

#[derive(Clone)]
pub struct PacketSender {
    tx: mpsc::Sender<Packet>,
    pub metrics: Arc<Metrics>,
}

impl PacketSender {
    pub fn new(tx: mpsc::Sender<Packet>, metrics: Arc<Metrics>) -> Self {
        Self { tx, metrics }
    }

    /// Захват не блокируется медленным API; потери видны в статистике и дампе.
    pub fn send(&self, packet: Packet) -> Result<(), ()> {
        match self.tx.try_send(packet) {
            Ok(()) => {
                self.metrics.accepted.fetch_add(1, Ordering::Release);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(()),
        }
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    #[test]
    fn full_queue_counts_loss_without_growing_or_stopping_capture() {
        let frame = [
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1, 0x9c, 0x40,
            0x01, 0xbb, 0, 8, 0, 0,
        ];
        let packet = crate::pcap::parse_link(101, &frame).unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        let metrics = Arc::new(Metrics::default());
        let sender = PacketSender::new(tx, metrics.clone());
        for _ in 0..100 {
            assert!(sender.send(packet.clone()).is_ok());
        }
        assert_eq!(rx.len(), 2);
        assert_eq!(metrics.dropped.load(Ordering::Relaxed), 98);
        rx.try_recv().unwrap();
        assert!(sender.send(packet.clone()).is_ok());
        assert_eq!(rx.len(), 2);
        drop(rx);
        assert!(sender.send(packet).is_err());
    }

    #[test]
    fn losses_during_recording_are_counted_from_its_start() {
        let start = Losses {
            dropped: 5,
            lost_frames: 1,
            unsupported: 9,
        };
        let now = Losses {
            dropped: 7,
            lost_frames: 1,
            unsupported: 12,
        };
        assert_eq!(
            now.since(start),
            Losses {
                dropped: 2,
                lost_frames: 0,
                unsupported: 3
            }
        );
        assert_eq!(start.since(now).dropped, 0);
    }
}
