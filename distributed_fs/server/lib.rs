//! Library portion of the filesystem server.
//!
//! Exposes helpers for starting the gRPC service so that integration tests can
//! spawn an embedded server if desired.

pub fn start_server() {
    // Real implementation would wire up gRPC, storage and crypto layers
    println!("starting server (stub)");
}
