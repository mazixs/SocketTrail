//! Признак открытого окна, не зависящий от браузера: страница держит SSE-канал
//! /api/alive, и пока хотя бы один канал открыт, окно живо. Опрос процесса
//! браузера на Windows ненадежен: Edge может остаться в фоне после закрытия окна.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::response::sse::{Event, Sse};
use futures_util::Stream;

#[derive(Default)]
pub struct Alive {
    clients: AtomicUsize,
    seen: AtomicBool,
}

struct Client(Arc<Alive>);

impl Drop for Client {
    fn drop(&mut self) {
        self.0.clients.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Частые пинги нужны не странице, а серверу: разрыв соединения замечается
/// только при следующей записи в него.
pub fn stream(a: Arc<Alive>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    a.clients.fetch_add(1, Ordering::SeqCst);
    a.seen.store(true, Ordering::SeqCst);
    let first = true;
    let s = futures_util::stream::unfold((Client(a), first), |(c, first)| async move {
        if !first {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Some((Ok(Event::default().comment("")), (c, false)))
    });
    Sse::new(s)
}

/// Ждет, пока окно было открыто и все каналы закрыты `grace` секунд подряд.
/// Счет идет тиками, а не часами: после сна системы отсчет начинается заново.
pub async fn wait_closed(a: Arc<Alive>, grace: u32) {
    let mut idle = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if a.seen.load(Ordering::SeqCst) && a.clients.load(Ordering::SeqCst) == 0 {
            idle += 1;
            if idle >= grace {
                return;
            }
        } else {
            idle = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closes_only_after_last_client() {
        let a = Arc::new(Alive::default());
        let w = tokio::spawn(wait_closed(a.clone(), 2));
        let s1 = stream(a.clone());
        let s2 = stream(a.clone());
        drop(s1);
        tokio::time::sleep(Duration::from_millis(3500)).await;
        assert!(!w.is_finished(), "окно еще открыто второй страницей");
        drop(s2);
        tokio::time::timeout(Duration::from_secs(5), w).await.unwrap().unwrap();
    }
}
