use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// A very small in-memory DHT implementation used for examples.
/// Data is replicated across multiple nodes to mimic RAID style redundancy.
pub struct Dht {
    nodes: Vec<HashMap<String, Vec<u8>>>,
    redundancy: usize,
}

impl Dht {
    pub fn new(node_count: usize, redundancy: usize) -> Self {
        let mut nodes = Vec::new();
        for _ in 0..node_count {
            nodes.push(HashMap::new());
        }
        Self { nodes, redundancy }
    }

    fn hash(key: &str) -> usize {
        // very naive hash for demonstration
        key.as_bytes().iter().fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(*b as usize))
    }

    pub fn store(&mut self, id: &str, data: &[u8]) {
        for replica in 0..self.redundancy {
            let idx = (Self::hash(id) + replica) % self.nodes.len();
            self.nodes[idx].insert(id.to_string(), data.to_vec());
        }
    }

    pub fn get(&self, id: &str) -> Option<Vec<u8>> {
        for table in &self.nodes {
            if let Some(v) = table.get(id) {
                return Some(v.clone());
            }
        }
        None
    }
}

static DHT: OnceLock<Mutex<Dht>> = OnceLock::new();

fn instance() -> std::sync::MutexGuard<'static, Dht> {
    DHT.get_or_init(|| Mutex::new(Dht::new(4, 2))).lock().unwrap()
}

pub fn init(nodes: usize, redundancy: usize) {
    let mut guard = DHT.get_or_init(|| Mutex::new(Dht::new(nodes, redundancy))).lock().unwrap();
    *guard = Dht::new(nodes, redundancy);
}

pub fn store_block(id: &str, data: &[u8]) {
    let mut dht = instance();
    dht.store(id, data);
}

pub fn get_block(id: &str) -> Option<Vec<u8>> {
    let dht = instance();
    dht.get(id)
}
