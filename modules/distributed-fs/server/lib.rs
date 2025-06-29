//! Library portion of the filesystem server.
//!
//! Exposes helpers for starting the gRPC service so that integration tests can
//! spawn an embedded server if desired.

use crate::{network, metadata};

/// Start the minimal filesystem server.
pub fn start_server() {
    // Initialize the simple network layer and flush any pending metadata.
    network::init();
    metadata::flush_on_read();
    // Removed debug print
}
