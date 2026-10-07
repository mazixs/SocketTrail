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

pub const QUEUE_CAPACITY: usize = 8192;

#[derive(Default)]
pub struct Metrics {
    pub dropped: AtomicU64,
    pub accepted: AtomicU64,
    pub processed: AtomicU64,
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
}
