use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::event::FileEvent;
use crate::monitor::FileSystemMonitor;

/// Cross-platform file system monitor using the `notify` crate.
///
/// This provides a fallback implementation that works on all major platforms
/// but does not support blocking (pre-access) decisions.
pub struct NotifyMonitor {
    watcher: Option<RecommendedWatcher>,
    tx: mpsc::Sender<FileEvent>,
    rx: mpsc::Receiver<FileEvent>,
    running: Arc<AtomicBool>,
}

impl NotifyMonitor {
    /// Create a new `NotifyMonitor` with a buffered channel of the given capacity.
    pub fn new(channel_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        Self {
            watcher: None,
            tx,
            rx,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Convert a `notify::Event` into one or more `FileEvent` values.
    fn convert_event(event: Event) -> Vec<FileEvent> {
        let mut results = Vec::new();

        for path in event.paths {
            let file_event = match event.kind {
                EventKind::Create(_) => Some(FileEvent::Create { path }),
                EventKind::Modify(_) => Some(FileEvent::Modify { path }),
                EventKind::Remove(_) => Some(FileEvent::Delete { path }),
                EventKind::Access(notify::event::AccessKind::Open(_)) => Some(FileEvent::Open { path, pid: 0 }),
                EventKind::Access(notify::event::AccessKind::Close(notify::event::AccessMode::Write)) => {
                    Some(FileEvent::CloseWrite { path })
                }
                _ => None,
            };

            if let Some(fe) = file_event {
                results.push(fe);
            }
        }

        results
    }
}

#[async_trait]
impl FileSystemMonitor for NotifyMonitor {
    async fn start(&mut self, paths: &[PathBuf]) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            anyhow::bail!("monitor is already running");
        }

        let tx = self.tx.clone();
        let running = self.running.clone();

        let mut watcher = notify::recommended_watcher(move |res: std::result::Result<Event, notify::Error>| {
            if !running.load(Ordering::Relaxed) {
                return;
            }

            match res {
                Ok(event) => {
                    let file_events = Self::convert_event(event);
                    for fe in file_events {
                        // Use try_send to avoid blocking the notify thread.
                        // Events are dropped if the channel is full.
                        let _ = tx.try_send(fe);
                    }
                }
                Err(e) => {
                    tracing::error!("notify watcher error: {e}");
                }
            }
        })
        .context("failed to create notify watcher")?;

        for path in paths {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("failed to watch path: {}", path.display()))?;
        }

        self.running.store(true, Ordering::Release);
        self.watcher = Some(watcher);

        tracing::info!("notify monitor started, watching {} path(s)", paths.len());

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Release);

        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
        }

        tracing::info!("notify monitor stopped");
        Ok(())
    }

    fn event_receiver(&self) -> &mpsc::Receiver<FileEvent> {
        &self.rx
    }

    fn supports_blocking(&self) -> bool {
        false
    }
}

impl Default for NotifyMonitor {
    fn default() -> Self {
        Self::new(4096)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::uninlined_format_args
    )]
    use super::*;
    use std::fs;
    use tokio::time::{Duration, timeout};

    #[test]
    fn test_notify_monitor_new_creates_successfully() {
        let monitor = NotifyMonitor::new(128);
        assert!(monitor.watcher.is_none());
        assert!(!monitor.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_supports_blocking_returns_false() {
        let monitor = NotifyMonitor::new(128);
        assert!(!monitor.supports_blocking());
    }

    #[tokio::test]
    async fn test_start_stop_lifecycle() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let mut monitor = NotifyMonitor::new(128);

        monitor
            .start(&[tmp_dir.path().to_path_buf()])
            .await
            .expect("start failed");
        assert!(monitor.running.load(Ordering::Relaxed));
        assert!(monitor.watcher.is_some());

        monitor.stop().await.expect("stop failed");
        assert!(!monitor.running.load(Ordering::Relaxed));
        assert!(monitor.watcher.is_none());
    }

    #[tokio::test]
    async fn test_start_twice_fails() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let mut monitor = NotifyMonitor::new(128);

        monitor
            .start(&[tmp_dir.path().to_path_buf()])
            .await
            .expect("first start failed");

        let result = monitor.start(&[tmp_dir.path().to_path_buf()]).await;
        assert!(result.is_err());

        monitor.stop().await.expect("stop failed");
    }

    #[tokio::test]
    async fn test_file_creation_generates_event() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let mut monitor = NotifyMonitor::new(128);

        monitor
            .start(&[tmp_dir.path().to_path_buf()])
            .await
            .expect("start failed");

        // Create a file in the watched directory
        let file_path = tmp_dir.path().join("test_file.txt");
        fs::write(&file_path, "hello").expect("failed to write file");

        // Wait for an event with a timeout
        let result = timeout(Duration::from_secs(5), monitor.rx.recv()).await;
        assert!(result.is_ok(), "timed out waiting for file event");
        let event = result.expect("timeout").expect("channel closed");

        // The event path should reference our file
        let event_path = event.path();
        assert!(
            event_path.to_string_lossy().contains("test_file.txt"),
            "event path {:?} does not contain test_file.txt",
            event_path
        );

        monitor.stop().await.expect("stop failed");
    }

    #[test]
    fn test_default_creates_with_4096_capacity() {
        let monitor = NotifyMonitor::default();
        assert!(monitor.watcher.is_none());
        assert!(!monitor.running.load(Ordering::Relaxed));
    }
}
