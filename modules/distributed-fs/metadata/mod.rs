//! Async metadata layer inspired by AsyncFS.
//!
//! Writes are acknowledged quickly and enqueued.  Reads trigger a flush
//! of pending updates.  This allows multiple clients to share a consistent view
//! of directories with minimal latency.

use std::sync::{Mutex, OnceLock};
use crate::network;

/// Simple buffer for queued metadata updates.
static BUFFER: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

/// Process a write operation by enqueueing it.
pub fn enqueue_write(update: &str) {
    let mut buf = BUFFER.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
    buf.push(update.to_string());
    // In a real system we might notify the network layer.
    network::send(update.as_bytes());
}

/// Flush queued updates when a read occurs.
pub fn flush_on_read() -> Vec<String> {
    let mut buf = BUFFER.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
    let drained: Vec<String> = buf.drain(..).collect();
    drained
}
