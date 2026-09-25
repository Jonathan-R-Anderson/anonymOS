use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use prx_sd_signatures::SignatureDatabase;

use crate::output;

#[allow(clippy::unnecessary_wraps)]
pub fn run(data_dir: &Path) -> Result<()> {
    println!("{}", "PRX-SD Antivirus Engine".cyan().bold());
    println!();

    // Version.
    println!("  {:<22} {}", "Version:".bold(), env!("CARGO_PKG_VERSION"));

    // Data directory.
    println!("  {:<22} {}", "Data directory:".bold(), data_dir.display());

    // Signature database info.
    let sig_dir = data_dir.join("signatures");
    if sig_dir.exists() {
        match SignatureDatabase::open(&sig_dir) {
            Ok(db) => match db.get_stats() {
                Ok(stats) => {
                    println!("  {:<22} {}", "Signature DB version:".bold(), stats.version);
                    println!("  {:<22} {}", "SHA-256 hash count:".bold(), stats.hash_count);
                    println!("  {:<22} {}", "MD5 hash count:".bold(), stats.md5_count);
                    if let Some(ts) = stats.last_update {
                        let dt = chrono::DateTime::from_timestamp(ts, 0)
                            .map_or_else(|| ts.to_string(), |d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                        println!("  {:<22} {}", "Last DB update:".bold(), dt);
                    } else {
                        println!("  {:<22} {}", "Last DB update:".bold(), "never".dimmed());
                    }
                }
                Err(e) => {
                    println!(
                        "  {:<22} {} ({})",
                        "Signature DB:".bold(),
                        "error reading stats".red(),
                        e
                    );
                }
            },
            Err(e) => {
                println!(
                    "  {:<22} {} ({})",
                    "Signature DB:".bold(),
                    "not initialised".yellow(),
                    e
                );
            }
        }
    } else {
        println!("  {:<22} {}", "Signature DB:".bold(), "not found".yellow());
    }

    // YARA rules.
    let yara_dir = data_dir.join("yara");
    if yara_dir.exists() {
        let rule_count = walkdir::WalkDir::new(&yara_dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().is_file() && e.path().extension().is_some_and(|ext| ext == "yar" || ext == "yara"))
            .count();
        println!("  {:<22} {} file(s)", "YARA rules:".bold(), rule_count);
    } else {
        println!("  {:<22} {}", "YARA rules:".bold(), "not found".yellow());
    }

    // Quarantine stats.
    let vault_dir = data_dir.join("quarantine").join("vault");
    if vault_dir.exists() {
        let mut file_count = 0u64;
        let mut total_size = 0u64;

        if let Ok(entries) = std::fs::read_dir(&vault_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                // Count blob files (those without .meta.json extension).
                if path.is_file() && !path.to_string_lossy().ends_with(".meta.json") {
                    file_count += 1;
                    total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }

        println!(
            "  {:<22} {} file(s), {}",
            "Quarantine:".bold(),
            file_count,
            output::format_bytes(total_size)
        );
    } else {
        println!("  {:<22} {}", "Quarantine:".bold(), "empty".dimmed());
    }

    // Platform info.
    println!();
    println!("  {:<22} {}", "OS:".bold(), std::env::consts::OS);
    println!("  {:<22} {}", "Architecture:".bold(), std::env::consts::ARCH);

    Ok(())
}
