//! Top-level library for the distributed cryptographic filesystem.
//!
//! Re-exports the key submodules so client and server code can depend on a
//! single crate.  Actual logic is deliberately minimal; real functionality would
//! be implemented incrementally.

pub mod client;
pub mod server;
pub mod network;
pub mod crypto;
pub mod metadata;
pub mod storage;
