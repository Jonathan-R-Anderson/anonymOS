//! CLI handler for the `scan-memory` subcommand.

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use colored::Colorize;

use prx_sd_core::memscan::{self, MemScanResult};
use prx_sd_core::{ScanConfig, ScanEngine, ThreatLevel};

/// Build a `ScanConfig` rooted in the given data directory.
fn build_config(data_dir: &Path) -> ScanConfig {
    ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"))
}

/// Run the memory scan command.
pub fn run(pid: Option<u32>, json: bool, data_dir: &Path) -> Result<()> {
    let config = build_config(data_dir);
    let engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    let start = Instant::now();

    let results: Vec<MemScanResult> = if let Some(pid) = pid {
        eprintln!("Scanning process {pid}...");
        let result = memscan::scan_process(pid, &engine.yara, &engine.signatures)
            .with_context(|| format!("failed to scan PID {pid}"))?;
        vec![result]
    } else {
        eprintln!("Scanning all processes (requires root)...");
        memscan::scan_all_processes(&engine.yara, &engine.signatures)
    };

    #[allow(clippy::cast_possible_truncation)] // Scan duration won't exceed u64::MAX ms.
    let elapsed = start.elapsed().as_millis() as u64;

    if json {
        let out = serde_json::to_string_pretty(&results).context("failed to serialize results")?;
        println!("{out}");
    } else {
        print_results(&results);
        print_summary(&results, elapsed);
    }

    // Exit with non-zero status if any threats were found.
    let has_threats = results.iter().any(|r| r.threat_level != ThreatLevel::Clean);
    if has_threats {
        std::process::exit(1);
    }

    Ok(())
}

/// Print results in human-readable format.
fn print_results(results: &[MemScanResult]) {
    for r in results {
        let level_str = match r.threat_level {
            ThreatLevel::Clean => "CLEAN".green().to_string(),
            ThreatLevel::Suspicious => "SUSPICIOUS".yellow().bold().to_string(),
            ThreatLevel::Malicious => "MALICIOUS".red().bold().to_string(),
        };

        let threat = r.threat_name.as_deref().unwrap_or("-");

        println!(
            "  [{level_str}] PID {} ({}) | {threat} [{} ms]",
            r.pid, r.process_name, r.scan_time_ms,
        );

        for m in &r.matched_regions {
            println!(
                "         0x{:x}-0x{:x} {} -> {}",
                m.region_start,
                m.region_end,
                m.permissions.dimmed(),
                m.rule_name.red(),
            );
        }
    }
}

/// Print a summary of the memory scan.
fn print_summary(results: &[MemScanResult], elapsed_ms: u64) {
    let total = results.len();
    let clean = results.iter().filter(|r| r.threat_level == ThreatLevel::Clean).count();
    let malicious = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .count();
    let suspicious = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Suspicious)
        .count();

    println!();
    println!("{}", "Memory Scan Summary".cyan().bold());
    println!("  Processes scanned: {total}");
    println!("  Clean:             {}", format!("{clean}").green());
    if suspicious > 0 {
        println!("  Suspicious:        {}", format!("{suspicious}").yellow().bold());
    } else {
        println!("  Suspicious:        {suspicious}");
    }
    if malicious > 0 {
        println!("  Malicious:         {}", format!("{malicious}").red().bold());
    } else {
        println!("  Malicious:         {malicious}");
    }
    println!("  Time elapsed:      {elapsed_ms} ms");
}
