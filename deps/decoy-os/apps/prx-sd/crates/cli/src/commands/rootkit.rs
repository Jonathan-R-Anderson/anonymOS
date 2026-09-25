//! CLI handler for the `check-rootkit` subcommand.

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use prx_sd_core::ThreatLevel;
use prx_sd_core::rootkit::{self, RootkitScanResult};

/// Run the rootkit check command.
pub fn run(json: bool, _data_dir: &Path) -> Result<()> {
    eprintln!("Checking for rootkit indicators...");

    let result = rootkit::scan_rootkit();

    if json {
        let out =
            serde_json::to_string_pretty(&result).map_err(|e| anyhow::anyhow!("failed to serialize results: {e}"))?;
        println!("{out}");
    } else {
        print_result(&result);
    }

    // Exit with non-zero status if threats were found.
    if result.threat_level != ThreatLevel::Clean {
        std::process::exit(1);
    }

    Ok(())
}

/// Print rootkit scan results in human-readable format.
fn print_result(result: &RootkitScanResult) {
    let level_str = match result.threat_level {
        ThreatLevel::Clean => "CLEAN".green().bold().to_string(),
        ThreatLevel::Suspicious => "SUSPICIOUS".yellow().bold().to_string(),
        ThreatLevel::Malicious => "MALICIOUS".red().bold().to_string(),
    };

    println!();
    println!("{}", "Rootkit Check Results".cyan().bold());
    println!("  Overall status: [{level_str}]");
    println!("  Scan time:      {} ms", result.scan_time_ms);
    println!();

    // Hidden processes.
    if result.hidden_processes.is_empty() {
        println!("  {} No hidden processes detected", "[OK]".green());
    } else {
        println!(
            "  {} {} hidden process(es) found:",
            "[!!]".red().bold(),
            result.hidden_processes.len()
        );
        for hp in &result.hidden_processes {
            println!("       PID {}: {}", format!("{}", hp.pid).red(), hp.detection_method);
        }
    }

    // Kernel modules.
    if result.suspicious_modules.is_empty() {
        println!("  {} No suspicious kernel modules", "[OK]".green());
    } else {
        println!(
            "  {} {} suspicious module(s):",
            "[!!]".red().bold(),
            result.suspicious_modules.len()
        );
        for sm in &result.suspicious_modules {
            println!("       {}: {}", sm.name.red(), sm.reason);
        }
    }

    // LD_PRELOAD.
    if let Some(ref detail) = result.ld_preload_hijack {
        println!("  {} LD_PRELOAD hijack: {}", "[!!]".yellow().bold(), detail);
    } else {
        println!("  {} No LD_PRELOAD hijacking", "[OK]".green());
    }

    // /proc anomalies.
    if result.proc_anomalies.is_empty() {
        println!("  {} No /proc anomalies", "[OK]".green());
    } else {
        println!(
            "  {} {} /proc anomaly(ies):",
            "[!!]".yellow().bold(),
            result.proc_anomalies.len()
        );
        for pa in &result.proc_anomalies {
            println!("       {}: {}", pa.path, pa.description);
        }
    }

    println!();
}
