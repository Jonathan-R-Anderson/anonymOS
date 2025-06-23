//! Client library for interacting with the distributed filesystem.
//!
//! Applications would link against this crate (or the language equivalent) to
//! mount the filesystem or perform RPC operations directly.  Here we merely
//! sketch out the high level structure.

/// Mount the remote filesystem using a FUSE-like interface.
use crate::network;

pub fn mount(addr: &str, mountpoint: &str) {
    // Initialize the network layer so we can communicate with the server.
    network::init();
    println!("mounting {} at {}", addr, mountpoint);
    network::send(format!("mount:{}:{}", addr, mountpoint).as_bytes());
}
