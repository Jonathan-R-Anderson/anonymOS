use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::dht;

/// Simple network file storage that maps paths to blocks stored in the DHT.
/// This is purely illustrative and not meant for production use.
struct NetFs {
    index: HashMap<String, String>, // path -> block id
    next_id: u64,
}

impl NetFs {
    fn new() -> Self {
        Self { index: HashMap::new(), next_id: 0 }
    }

    fn alloc_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id += 1;
        format!("blk{}", id)
    }
}

static NETFS: OnceLock<Mutex<NetFs>> = OnceLock::new();

fn instance() -> std::sync::MutexGuard<'static, NetFs> {
    NETFS.get_or_init(|| Mutex::new(NetFs::new())).lock().unwrap()
}

/// Write a file to the DHT-backed store.
pub fn write_file(path: &str, data: &[u8]) {
    let mut fs = instance();
    let id = fs.index.entry(path.to_string()).or_insert_with(|| fs.alloc_id());
    dht::store_block(id, data);
}

/// Read a file from the DHT-backed store.
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    let fs = instance();
    fs.index.get(path).and_then(|id| dht::get_block(id))
}
