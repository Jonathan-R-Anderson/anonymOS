//! Import hash signatures from blocklist files into the signature database.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use colored::Colorize;

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd length hex string"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            let pair = s.get(i..i + 2).ok_or_else(|| anyhow!("index out of bounds"))?;
            u8::from_str_radix(pair, 16).map_err(|e| anyhow!("{e}"))
        })
        .collect()
}

pub fn run(blocklist_path: &Path, data_dir: &Path) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    let db = prx_sd_signatures::SignatureDatabase::open(&sig_dir).context("failed to open signature database")?;

    let content = std::fs::read_to_string(blocklist_path)
        .with_context(|| format!("failed to read {}", blocklist_path.display()))?;

    let mut entries: Vec<(Vec<u8>, String)> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: hex_hash malware_name
        let Some((hex_hash, name_str)) = line.split_once(' ') else {
            eprintln!("{} skipping malformed line: {line}", "warning:".yellow());
            continue;
        };

        let hex_hash = hex_hash.trim();
        let name = name_str.trim().to_string();

        match decode_hex(hex_hash) {
            Ok(hash_bytes) => entries.push((hash_bytes, name)),
            Err(e) => {
                eprintln!("{} invalid hex '{hex_hash}': {e}", "warning:".yellow());
            }
        }
    }

    if entries.is_empty() {
        println!("No valid entries found in {}", blocklist_path.display());
        return Ok(());
    }

    let count = db.import_hashes(&entries)?;
    println!(
        "{} Imported {count} hash entries from {}",
        "success:".green().bold(),
        blocklist_path.display()
    );

    let stats = db.get_stats()?;
    println!("  Database now has {} SHA-256 entries", stats.hash_count);

    Ok(())
}
