//! Example showing how a client might mount the filesystem and perform basic
//! operations.  This is purely illustrative; it does nothing at runtime.

use distributed_fs::client;

fn main() {
    client::mount("127.0.0.1:50051", "/mnt/dfs");
    // Additional operations would follow here
}
