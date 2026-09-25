#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::event::FileEvent;
use crate::monitor::FileSystemMonitor;

/// macOS file system monitor using FSEvents via the `notify` crate.
///
/// On macOS, `notify::RecommendedWatcher` uses the FSEvents API under the hood,
/// which provides efficient, recursive directory monitoring at the kernel level.
///
/// # Limitations
///
/// - **No PID tracking**: FSEvents does not report which process caused a file
///   system event. PID fields are set to `0` for all events. The macOS Endpoint
///   Security framework (`es_new_client`) would be needed for per-process
///   attribution, but it requires a System Extension entitlement from Apple.
///
/// - **No blocking support**: FSEvents is purely notification-based. It cannot
///   intercept or deny file operations before they complete. The Endpoint
///   Security framework's `ES_ACTION_TYPE_AUTH` events would be needed for that.
///
/// - **Coalesced events**: FSEvents may coalesce multiple rapid changes into a
///   single notification, so individual intermediate states may not be observed.
pub struct MacOSMonitor {
    watcher: Option<RecommendedWatcher>,
    tx: mpsc::Sender<FileEvent>,
    rx: mpsc::Receiver<FileEvent>,
    running: Arc<AtomicBool>,
}

impl MacOSMonitor {
    /// Create a new `MacOSMonitor` with a buffered channel of the given capacity.
    pub fn new(channel_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        Self {
            watcher: None,
            tx,
            rx,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Convert a `notify::Event` into `FileEvent` values.
    ///
    /// FSEvents does not provide PID information, so all PID fields are set to 0.
    fn convert_event(event: Event) -> Vec<FileEvent> {
        let mut results = Vec::new();

        // Handle rename events specially: notify may provide two paths (from, to)
        if matches!(event.kind, EventKind::Modify(notify::event::ModifyKind::Name(_))) {
            if event.paths.len() >= 2 {
                results.push(FileEvent::Rename {
                    from: event.paths[0].clone(),
                    to: event.paths[1].clone(),
                    pid: 0, // FSEvents does not provide PID
                });
                return results;
            }
        }

        for path in event.paths {
            let file_event = match event.kind {
                EventKind::Create(_) => Some(FileEvent::Create { path }),
                EventKind::Modify(_) => Some(FileEvent::Modify { path }),
                EventKind::Remove(_) => Some(FileEvent::Delete { path }),
                EventKind::Access(notify::event::AccessKind::Open(_)) => {
                    // FSEvents does not provide PID; set to 0
                    Some(FileEvent::Open { path, pid: 0 })
                }
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
impl FileSystemMonitor for MacOSMonitor {
    async fn start(&mut self, paths: &[PathBuf]) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            anyhow::bail!("macOS monitor is already running");
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
                        // Use try_send to avoid blocking the FSEvents callback thread.
                        // Events are dropped if the channel is full.
                        let _ = tx.try_send(fe);
                    }
                }
                Err(e) => {
                    tracing::error!("macOS FSEvents watcher error: {e}");
                }
            }
        })
        .context("failed to create macOS FSEvents watcher")?;

        for path in paths {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("failed to watch path: {}", path.display()))?;
        }

        self.running.store(true, Ordering::Release);
        self.watcher = Some(watcher);

        tracing::info!("macOS FSEvents monitor started, watching {} path(s)", paths.len());

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Release);

        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
        }

        tracing::info!("macOS FSEvents monitor stopped");
        Ok(())
    }

    fn event_receiver(&self) -> &mpsc::Receiver<FileEvent> {
        &self.rx
    }

    /// FSEvents does not support blocking/pre-access decisions.
    fn supports_blocking(&self) -> bool {
        false
    }

    /// No-op: FSEvents cannot block or deny file operations.
    fn respond(&self, _event_fd: i32, _allow: bool) {
        // FSEvents is purely notification-based; blocking requires
        // the Endpoint Security framework which needs Apple entitlements.
    }
}

impl Default for MacOSMonitor {
    fn default() -> Self {
        Self::new(4096)
    }
}
