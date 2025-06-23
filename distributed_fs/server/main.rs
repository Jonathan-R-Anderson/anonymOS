//! Skeleton FS server implemented in Rust.
//!
//! In a full implementation this binary would:
//!  - Initialize the network layer to communicate with programmable switches
//!    for metadata batching (AsyncFS style).
//!  - Set up the storage backend (local disk or cloud) and load cryptographic
//!    keys for the UPSS engine.
//!  - Start a gRPC server based on the definitions in `proto/fs.proto`.
//!  - Handle requests by delegating to the metadata layer, crypto engine and
//!    storage driver.
//!
//! This file is intentionally sparse; the goal is to outline architecture,
//! not provide production-ready code.

use crate::lib::start_server;

fn main() {
    // Start the minimal server used in tests and examples
    start_server();
}
