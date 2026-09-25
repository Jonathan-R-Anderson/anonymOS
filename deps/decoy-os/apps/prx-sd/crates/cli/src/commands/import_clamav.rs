//! Import `ClamAV` signature files (.cvd, .hdb, .hsb) into the signature database.

use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::Colorize;

pub fn run(paths: &[std::path::PathBuf], data_dir: &Path) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    let db = prx_sd_signatures::SignatureDatabase::open(&sig_dir).context("failed to open signature database")?;

    if paths.is_empty() {
        bail!("no ClamAV signature files specified");
    }

    let mut total_sha256 = 0usize;
    let mut total_md5 = 0usize;
    let mut total_ndb = 0usize;
    let mut total_logic_sigs = 0usize;

    for path in paths {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        println!("Importing {}...", path.display());

        let stats = match ext.as_str() {
            "cvd" | "cld" => prx_sd_signatures::import_cvd(path, &db)
                .with_context(|| format!("failed to import CVD: {}", path.display()))?,
            "hdb" | "hsb" => prx_sd_signatures::import_hash_file(path, &db)
                .with_context(|| format!("failed to import: {}", path.display()))?,
            _ => {
                eprintln!(
                    "{} unsupported file type '{}' for {}",
                    "warning:".yellow(),
                    ext,
                    path.display()
                );
                continue;
            }
        };

        // Print per-file results.
        if stats.cvd_version > 0 {
            println!("  CVD version: {}", stats.cvd_version);
            println!("  Header declares {} signatures", stats.header_sig_count);
        }
        if stats.sha256_imported > 0 {
            println!("  SHA-256 imported: {}", stats.sha256_imported);
        }
        if stats.md5_imported > 0 {
            println!("  MD5 imported: {}", stats.md5_imported);
        }
        if stats.sha1_skipped > 0 {
            println!("  SHA-1 skipped: {} (not supported)", stats.sha1_skipped);
        }
        if stats.ndb_count > 0 {
            println!("  NDB patterns: {} (skipped, requires YARA-X engine)", stats.ndb_count);
        }
        if stats.ldb_count > 0 {
            println!(
                "  LDB logical sigs: {} (skipped, requires YARA-X engine)",
                stats.ldb_count
            );
        }
        if stats.parse_errors > 0 {
            eprintln!(
                "  {} {} lines skipped due to parse errors",
                "warning:".yellow(),
                stats.parse_errors
            );
        }

        total_sha256 += stats.sha256_imported;
        total_md5 += stats.md5_imported;
        total_ndb += stats.ndb_count;
        total_logic_sigs += stats.ldb_count;
    }

    println!();
    println!("{} ClamAV import complete", "success:".green().bold());
    println!("  Total SHA-256 hash entries imported: {total_sha256}");
    println!("  Total MD5 hash entries imported: {total_md5}");
    if total_ndb > 0 || total_logic_sigs > 0 {
        println!("  Pattern signatures found but not imported: {total_ndb} NDB + {total_logic_sigs} LDB");
        println!("  (These will be usable after YARA-X engine integration)");
    }

    let db_stats = db.get_stats()?;
    println!();
    println!("Database totals:");
    println!("  SHA-256 entries: {}", db_stats.hash_count);
    println!("  MD5 entries: {}", db_stats.md5_count);

    Ok(())
}
