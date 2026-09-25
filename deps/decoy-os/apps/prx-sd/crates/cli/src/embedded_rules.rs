//! Embedded YARA rules that ship with the binary.
//!
//! These rules are compiled into the `sd` binary via `include_str!` so that
//! basic detection works even before the user downloads the full signature
//! database. Only a small, curated set of high-value rules is embedded to
//! keep binary size reasonable.

use std::path::Path;

use anyhow::{Context, Result};

/// EICAR antivirus test file detection rule.
pub const EICAR_RULE: &str = include_str!("../../../signatures-db/yara/test/eicar.yar");

/// Generic ransomware detection rules.
pub const RANSOMWARE_RULE: &str = include_str!("../../../signatures-db/yara/malware/ransomware.yar");

/// Linux-specific malware detection rules.
pub const LINUX_MALWARE_RULE: &str = include_str!("../../../signatures-db/yara/malware/linux_malware.yar");

/// Cross-platform malware detection rules.
pub const CROSS_PLATFORM_RULE: &str = include_str!("../../../signatures-db/yara/malware/cross_platform.yar");

/// Common packer detection rules.
pub const PACKER_RULE: &str = include_str!("../../../signatures-db/yara/packer/common_packers.yar");

/// Embedded SHA-256 hash blocklist (compiled into binary).
/// Format: `hex_hash` `malware_name` per line.
pub const EMBEDDED_HASHES: &str = include_str!("../../../signatures-db/hashes/sha256_blocklist.txt");

/// Import embedded hashes into the signature database at `signatures_dir`.
/// Skips if the database already has entries (avoids re-importing on every run).
pub fn import_embedded_hashes(signatures_dir: &std::path::Path) -> Result<usize> {
    let db = prx_sd_signatures::SignatureDatabase::open(signatures_dir)
        .context("failed to open signature database for embedded hash import")?;

    // Skip if database already has hashes (user already ran import or update).
    let stats = db.get_stats().context("failed to read database stats")?;
    if stats.hash_count > 0 {
        return Ok(0);
    }

    let mut entries: Vec<(Vec<u8>, String)> = Vec::new();
    for line in EMBEDDED_HASHES.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((hex_str, name_str)) = line.split_once(' ') else {
            continue;
        };
        let hex = hex_str.trim();
        let name = name_str.trim().to_string();
        if let Ok(bytes) = decode_hex(hex) {
            entries.push((bytes, name));
        }
    }

    if entries.is_empty() {
        return Ok(0);
    }

    let count = db.import_hashes(&entries).context("failed to import embedded hashes")?;
    Ok(count)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            let pair = s.get(i..i + 2).ok_or_else(|| anyhow::anyhow!("index out of bounds"))?;
            u8::from_str_radix(pair, 16).map_err(|e| anyhow::anyhow!("{e}"))
        })
        .collect()
}

/// All embedded rules paired with their relative output paths.
const EMBEDDED_RULES: &[(&str, &str)] = &[
    (EICAR_RULE, "test/eicar.yar"),
    (RANSOMWARE_RULE, "malware/ransomware.yar"),
    (LINUX_MALWARE_RULE, "malware/linux_malware.yar"),
    (CROSS_PLATFORM_RULE, "malware/cross_platform.yar"),
    (PACKER_RULE, "packer/common_packers.yar"),
];

/// Write all embedded YARA rules to `yara_dir`, creating subdirectories as
/// needed. Existing files are **not** overwritten, so user modifications or
/// downloaded updates take precedence.
pub fn write_embedded_rules(yara_dir: &Path) -> Result<()> {
    for (content, rel_path) in EMBEDDED_RULES {
        let dest = yara_dir.join(rel_path);

        // Skip if the rule file already exists on disk.
        if dest.exists() {
            continue;
        }

        // Ensure the parent directory exists.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        std::fs::write(&dest, content)
            .with_context(|| format!("failed to write embedded rule to {}", dest.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn embedded_rules_are_non_empty() {
        assert!(!EICAR_RULE.is_empty());
        assert!(!RANSOMWARE_RULE.is_empty());
        assert!(!LINUX_MALWARE_RULE.is_empty());
        assert!(!CROSS_PLATFORM_RULE.is_empty());
        assert!(!PACKER_RULE.is_empty());
    }

    #[test]
    fn write_embedded_rules_creates_files() {
        let tmp = std::env::temp_dir().join("prx-sd-test-embedded");
        let _ = std::fs::remove_dir_all(&tmp);

        write_embedded_rules(&tmp).expect("write_embedded_rules should succeed");

        assert!(tmp.join("test/eicar.yar").exists());
        assert!(tmp.join("malware/ransomware.yar").exists());
        assert!(tmp.join("malware/linux_malware.yar").exists());
        assert!(tmp.join("malware/cross_platform.yar").exists());
        assert!(tmp.join("packer/common_packers.yar").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_embedded_rules_does_not_overwrite() {
        let tmp = std::env::temp_dir().join("prx-sd-test-no-overwrite");
        let _ = std::fs::remove_dir_all(&tmp);

        let eicar_path = tmp.join("test/eicar.yar");
        std::fs::create_dir_all(eicar_path.parent().expect("has parent")).expect("create dir");
        std::fs::write(&eicar_path, "custom rule").expect("write custom");

        write_embedded_rules(&tmp).expect("write_embedded_rules should succeed");

        let content = std::fs::read_to_string(&eicar_path).expect("read");
        assert_eq!(content, "custom rule");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
