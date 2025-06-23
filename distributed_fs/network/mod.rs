//! Networking and coordination layer.
//!
//! Real implementations may use P4-programmable switches to batch metadata
//! updates before they reach the server.  This module acts as a shim so that
//! the server and metadata layer can remain agnostic of whether in-network
//! acceleration is available.

use std::sync::mpsc::{Sender, Receiver, channel, TryRecvError};
use std::sync::{Mutex, OnceLock};

/// Simple in-memory network channel used by the examples.
pub struct Handle {
    tx: Sender<Vec<u8>>,      // Outgoing packets
    rx: Mutex<Receiver<Vec<u8>>>, // Incoming packets
}

static NET: OnceLock<Handle> = OnceLock::new();

/// Initialize networking and return a handle used by other modules.
pub fn init() {
    let (tx, rx) = channel();
    let handle = Handle { tx, rx: Mutex::new(rx) };
    let _ = NET.set(handle);
    println!("network layer initialized");
}

/// Send a packet across the in-memory channel.
pub fn send(data: &[u8]) {
    if let Some(h) = NET.get() {
        let _ = h.tx.send(data.to_vec());
    }
}

/// Try to receive a packet if one is available.
pub fn try_receive() -> Option<Vec<u8>> {
    NET.get().and_then(|h| match h.rx.lock() {
        Ok(ref mut r) => match r.try_recv() {
            Ok(v) => Some(v),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        },
        Err(_) => None,
    })
}
