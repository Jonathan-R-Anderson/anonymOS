//! Storage backend abstraction.
//!
//! The real system would provide drivers for local disks, object stores like S3,
//! or other cloud providers.  Each block written by the server is encrypted by
//! the crypto module and stored under a content address.  To keep the skeleton
//! self-contained we mimic a small DHT implementation that replicates blocks
//! across nodes, providing rudimentary redundancy similar to RAID.

pub mod dht;

/// Store an encrypted block.
pub fn store_block(id: &str, data: &[u8]) {
    // In this stub we delegate to the in-memory DHT which replicates the block
    // across multiple nodes for redundancy.
    dht::store_block(id, data);
}

/// Retrieve an encrypted block.
pub fn get_block(id: &str) -> Option<Vec<u8>> {
    dht::get_block(id)
}
