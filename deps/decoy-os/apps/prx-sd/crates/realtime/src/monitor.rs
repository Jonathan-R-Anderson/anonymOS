use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::event::FileEvent;

/// Trait for file system monitors that watch paths and emit file events.
///
/// Implementations must be safe to share across threads (`Send + Sync`).
#[async_trait]
pub trait FileSystemMonitor: Send + Sync {
    /// Start monitoring the given paths for file system events.
    ///
    /// This begins watching the specified directories/files and sending
    /// events through the channel returned by [`event_receiver`].
    async fn start(&mut self, paths: &[PathBuf]) -> Result<()>;

    /// Stop monitoring. No more events will be sent after this returns.
    async fn stop(&mut self) -> Result<()>;

    /// Returns a reference to the receiver end of the event channel.
    ///
    /// Events are sent to this channel as they are captured by the monitor.
    fn event_receiver(&self) -> &mpsc::Receiver<FileEvent>;

    /// Whether this monitor supports blocking (pre-access) decisions.
    ///
    /// If `true`, the monitor can deny file operations before they complete
    /// (e.g., via fanotify permission events on Linux). If `false`, events
    /// are purely informational and the operation has already occurred.
    fn supports_blocking(&self) -> bool;

    /// Send a blocking response for a permission event.
    ///
    /// `event_fd` is the file descriptor from the original permission event.
    /// `allow` controls whether the operation is permitted (`true`) or
    /// denied (`false`).
    ///
    /// Only meaningful when [`supports_blocking`](Self::supports_blocking)
    /// returns `true`.  The default implementation is a no-op.
    fn respond(&self, _event_fd: i32, _allow: bool) {}
}
