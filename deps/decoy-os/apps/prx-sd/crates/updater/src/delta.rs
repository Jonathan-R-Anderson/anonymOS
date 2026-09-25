//! Delta patch encoding and decoding for incremental signature updates.
//!
//! A delta patch describes the difference between two signature database
//! versions: which hashes to add or remove and which YARA rules to change.
//! Patches are serialized with `bincode` and compressed with `zstd`.

use std::io::Read;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A delta patch that transforms a signature database from one version to
/// the next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaPatch {
    /// The target version number after applying this patch.
    pub version: u64,
    /// Timestamp when this patch was created.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// SHA-256 hash entries to add: `(hash_bytes, malware_name)`.
    pub add_hashes: Vec<(Vec<u8>, String)>,
    /// SHA-256 hash entries to remove (by hash bytes).
    pub remove_hashes: Vec<Vec<u8>>,
    /// YARA rule changes included in this patch.
    pub yara_rules: Vec<YaraRuleEntry>,
}

/// A single YARA rule change within a delta patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleEntry {
    /// Rule identifier / filename.
    pub name: String,
    /// Full rule source content.
    pub content: String,
    /// What to do with this rule.
    pub action: RuleAction,
}

/// The action to take for a YARA rule entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// Add a new rule.
    Add,
    /// Remove an existing rule.
    Remove,
    /// Replace an existing rule with updated content.
    Update,
}

/// Maximum decompressed size for delta patches (256 MB).
///
/// Prevents malicious or corrupted compressed data from exhausting memory
/// during decompression.
const MAX_DELTA_DECOMPRESSED_SIZE: u64 = 256 * 1024 * 1024;

/// Decompress a zstd-compressed blob and deserialize it into a `DeltaPatch`.
///
/// Decompression is capped at [`MAX_DELTA_DECOMPRESSED_SIZE`] to prevent
/// memory exhaustion from decompression bombs.
pub fn decode_delta(compressed: &[u8]) -> Result<DeltaPatch> {
    let decoder = zstd::Decoder::new(std::io::Cursor::new(compressed))
        .context("failed to create zstd decoder for delta patch")?;
    let mut limited = decoder.take(MAX_DELTA_DECOMPRESSED_SIZE);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .context("failed to decompress delta patch (zstd)")?;

    let patch: DeltaPatch = bincode::deserialize(&decompressed).context("failed to deserialize delta patch")?;

    Ok(patch)
}

/// Serialize a `DeltaPatch` and compress it with zstd.
///
/// Uses zstd compression level 3 (a good balance of speed and ratio).
pub fn encode_delta(patch: &DeltaPatch) -> Result<Vec<u8>> {
    let serialized = bincode::serialize(patch).context("failed to serialize delta patch")?;

    let compressed = zstd::encode_all(serialized.as_slice(), 3).context("failed to compress delta patch")?;

    Ok(compressed)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_patch() -> DeltaPatch {
        DeltaPatch {
            version: 42,
            timestamp: Utc::now(),
            add_hashes: vec![
                (vec![0xaa; 32], "Win.Trojan.FakeAV-1".to_string()),
                (vec![0xbb; 32], "Linux.Backdoor.Shell-2".to_string()),
            ],
            remove_hashes: vec![vec![0xcc; 32]],
            yara_rules: vec![
                YaraRuleEntry {
                    name: "detect_packer".to_string(),
                    content: "rule detect_packer { condition: true }".to_string(),
                    action: RuleAction::Add,
                },
                YaraRuleEntry {
                    name: "old_rule".to_string(),
                    content: String::new(),
                    action: RuleAction::Remove,
                },
            ],
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = sample_patch();
        let compressed = encode_delta(&original).unwrap();
        let decoded = decode_delta(&compressed).unwrap();

        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.add_hashes.len(), 2);
        assert_eq!(decoded.remove_hashes.len(), 1);
        assert_eq!(decoded.yara_rules.len(), 2);
        assert_eq!(decoded.yara_rules[0].action, RuleAction::Add);
        assert_eq!(decoded.yara_rules[1].action, RuleAction::Remove);
    }

    #[test]
    fn test_compressed_is_smaller() {
        let patch = sample_patch();
        let raw = bincode::serialize(&patch).unwrap();
        let compressed = encode_delta(&patch).unwrap();
        // Compressed should be smaller (or at least not much larger) than raw.
        // For small payloads zstd might add a tiny header, but it should still
        // be in the same ballpark.
        assert!(compressed.len() <= raw.len() + 32);
    }

    #[test]
    fn test_decode_invalid_data() {
        let result = decode_delta(b"this is not zstd data");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_patch() {
        let patch = DeltaPatch {
            version: 1,
            timestamp: Utc::now(),
            add_hashes: vec![],
            remove_hashes: vec![],
            yara_rules: vec![],
        };
        let compressed = encode_delta(&patch).unwrap();
        let decoded = decode_delta(&compressed).unwrap();
        assert_eq!(decoded.version, 1);
        assert!(decoded.add_hashes.is_empty());
        assert!(decoded.remove_hashes.is_empty());
        assert!(decoded.yara_rules.is_empty());
    }
}
