//! Parser for `ClamAV` `.hdb` (MD5 hash) and `.hsb` (SHA-256/SHA-1 hash) signature files.
//!
//! HDB format (one per line):
//! ```text
//! MD5Hash:FileSize:MalwareName
//! ```
//!
//! HSB format (one per line):
//! ```text
//! SHA256Hash:FileSize:MalwareName
//! ```
//!
//! `FileSize` may be `*` (match any size) or a decimal byte count.

use anyhow::{Result, bail};

/// A parsed hash-based signature entry.
#[derive(Debug, Clone)]
pub struct HashSignature {
    /// The hex-encoded hash string (MD5 = 32 chars, SHA-256 = 64 chars).
    pub hash_hex: String,
    /// File size constraint (`None` means any size).
    pub file_size: Option<u64>,
    /// Malware family/variant name.
    pub name: String,
}

/// The kind of hash in a parsed signature set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Md5,
    Sha256,
    Sha1,
}

/// Result of parsing an HDB or HSB file.
#[derive(Debug)]
pub struct HashSignatureSet {
    /// The detected hash kind based on entry lengths.
    pub kind: HashKind,
    /// The parsed entries.
    pub entries: Vec<HashSignature>,
    /// Number of lines that were skipped due to parse errors.
    pub skipped: usize,
}

/// Parse the content of an `.hdb` file (MD5 hash signatures).
pub fn parse_hdb(content: &str) -> Result<HashSignatureSet> {
    parse_hash_file(content, Some(HashKind::Md5))
}

/// Parse the content of an `.hsb` file (SHA-256 or SHA-1 hash signatures).
pub fn parse_hsb(content: &str) -> Result<HashSignatureSet> {
    parse_hash_file(content, None)
}

/// Generic parser for hash-based signature files.
///
/// If `expected_kind` is `None`, the hash kind is inferred from the first
/// valid entry's hash length (32 = MD5, 40 = SHA-1, 64 = SHA-256).
fn parse_hash_file(content: &str, expected_kind: Option<HashKind>) -> Result<HashSignatureSet> {
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    let mut kind = expected_kind;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 {
            skipped += 1;
            continue;
        }

        let Some(hash_hex) = parts.first().map(|s| s.trim()) else {
            skipped += 1;
            continue;
        };
        let Some(size_str) = parts.get(1).map(|s| s.trim()) else {
            skipped += 1;
            continue;
        };
        let Some(name) = parts.get(2).map(|s| s.trim()) else {
            skipped += 1;
            continue;
        };

        // Validate hex characters.
        if !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            skipped += 1;
            continue;
        }

        // Infer kind from first valid entry if not specified.
        if kind.is_none() {
            kind = match hash_hex.len() {
                32 => Some(HashKind::Md5),
                40 => Some(HashKind::Sha1),
                64 => Some(HashKind::Sha256),
                _ => {
                    skipped += 1;
                    continue;
                }
            };
        }

        let file_size = if size_str == "*" {
            None
        } else if let Ok(n) = size_str.parse::<u64>() {
            Some(n)
        } else {
            skipped += 1;
            continue;
        };

        entries.push(HashSignature {
            hash_hex: hash_hex.to_ascii_lowercase(),
            file_size,
            name: name.to_string(),
        });
    }

    let resolved_kind = if let Some(k) = kind {
        k
    } else {
        if entries.is_empty() {
            bail!("no valid hash entries found");
        }
        HashKind::Md5 // fallback
    };

    Ok(HashSignatureSet {
        kind: resolved_kind,
        entries,
        skipped,
    })
}

/// Decode a hex string into raw bytes.
pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let pair = hex.get(i..i + 2)?;
        let byte = u8::from_str_radix(pair, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hdb() {
        let content = "\
# ClamAV HDB file
abc123def456abc123def456abc123de:1024:Win.Trojan.Test-1
aabbccddaabbccddaabbccddaabbccdd:*:Win.Malware.Generic
";
        let result = parse_hdb(content).unwrap();
        assert_eq!(result.kind, HashKind::Md5);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].name, "Win.Trojan.Test-1");
        assert_eq!(result.entries[0].file_size, Some(1024));
        assert_eq!(result.entries[1].file_size, None);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn test_parse_hsb_sha256() {
        let hash = "a".repeat(64);
        let content = format!("{hash}:2048:Win.Ransom.Test-1\n");
        let result = parse_hsb(&content).unwrap();
        assert_eq!(result.kind, HashKind::Sha256);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "Win.Ransom.Test-1");
        assert_eq!(result.entries[0].file_size, Some(2048));
    }

    #[test]
    fn test_skip_malformed_lines() {
        let content = "\
badline
abc123def456abc123def456abc123de:1024:Ok.Sig
too:few
:empty:hash
";
        let result = parse_hdb(content).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(result.skipped >= 2);
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("4d5a"), Some(vec![0x4d, 0x5a]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert!(decode_hex("4d5").is_none());
        assert!(decode_hex("zzzz").is_none());
    }
}
