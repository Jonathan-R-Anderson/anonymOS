use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use prx_sd_core::{ScanConfig, ScanEngine, ScanResult, ThreatLevel};
use prx_sd_remediation::actions::RemediationEngine;
use prx_sd_remediation::policy::RemediationPolicy;

use crate::output;

/// Build a `ScanConfig` rooted in the given data directory.
fn build_config(data_dir: &Path, threads: Option<usize>, exclude: Vec<String>) -> ScanConfig {
    let mut config = ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"));

    if let Some(t) = threads {
        config = config.with_scan_threads(t);
    }

    config.exclude_paths = exclude;

    // Load VT API key from config.json if present.
    let config_path = data_dir.join("config.json");
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(key) = json.get("vt_api_key").and_then(|v| v.as_str()) {
                    config.vt_api_key = key.to_string();
                }
            }
        }
    }

    config
}

/// Quarantine a single file using the real AES-256-GCM encrypted vault.
fn quarantine_file(path: &Path, threat_name: &str, data_dir: &Path) -> Result<()> {
    let vault_dir = data_dir.join("quarantine");
    let quarantine = prx_sd_quarantine::Quarantine::new(vault_dir).context("failed to open quarantine vault")?;
    let id = quarantine
        .quarantine(path, threat_name)
        .with_context(|| format!("failed to quarantine {}", path.display()))?;
    tracing::info!(id = %id, path = %path.display(), threat = threat_name, "file quarantined");
    Ok(())
}

/// Run remediation for detected threats.
async fn remediate_threats(results: &[ScanResult], data_dir: &Path) -> Result<()> {
    let threats: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious || r.threat_level == ThreatLevel::Suspicious)
        .collect();

    if threats.is_empty() {
        return Ok(());
    }

    // Load policy from config dir, or use defaults.
    let policy_path = data_dir.join("remediation_policy.json");
    let policy = if policy_path.exists() {
        RemediationPolicy::load(&policy_path).unwrap_or_else(|e| {
            eprintln!("  {} failed to load policy: {e}, using defaults", "warning:".yellow());
            RemediationPolicy::default()
        })
    } else {
        RemediationPolicy::default()
    };

    let vault_dir = data_dir.join("quarantine");
    let quarantine =
        Arc::new(prx_sd_quarantine::Quarantine::new(vault_dir).context("failed to open quarantine vault")?);

    let audit_dir = data_dir.join("audit");
    let engine =
        RemediationEngine::new(policy, quarantine, audit_dir).context("failed to initialise remediation engine")?;

    println!("\n{} remediating {} threat(s)...", ">>>".yellow().bold(), threats.len());

    for r in threats {
        let threat_name = r.threat_name.as_deref().unwrap_or("Unknown");
        let threat_level = match r.threat_level {
            ThreatLevel::Malicious => "malicious",
            ThreatLevel::Suspicious => "suspicious",
            ThreatLevel::Clean => "clean",
        };
        let detection_type = r
            .detection_type
            .as_ref()
            .map_or_else(|| "Unknown".to_string(), |d| format!("{d:?}"));

        let actions = engine
            .handle_threat(&r.path, threat_name, threat_level, &detection_type)
            .await;

        // Print remediation results.
        println!("\n  {} {}", "File:".bold(), r.path.display());
        for action_result in &actions {
            let status = if action_result.success {
                "OK".green().bold()
            } else {
                "FAIL".red().bold()
            };
            println!("    [{}] {:?}", status, action_result.action);
            if let Some(err) = &action_result.error {
                eprintln!("      {}", err.as_str().red());
            }
        }
    }

    println!("\n{} remediation complete", "success:".green().bold());

    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    clippy::similar_names,
    clippy::cast_precision_loss
)]
pub async fn run(
    path: PathBuf,
    recursive: bool,
    json_output: bool,
    threads: Option<usize>,
    auto_quarantine: bool,
    remediate: bool,
    exclude: Vec<String>,
    report: Option<PathBuf>,
    data_dir: &Path,
) -> Result<()> {
    let config = build_config(data_dir, threads, exclude);
    let engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    let start = Instant::now();

    let results: Vec<ScanResult> = if path.is_file() {
        // Single-file scan.
        if !json_output {
            println!("{} {}", "Scanning".cyan().bold(), path.display());
        }
        let result = engine.scan_file(&path).await?;
        vec![result]
    } else if path.is_dir() {
        if recursive {
            // Count files first for progress bar.
            let entries: Vec<PathBuf> = WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_type().is_file())
                .map(walkdir::DirEntry::into_path)
                .collect();

            let total = entries.len() as u64;

            if !json_output {
                println!("{} {} ({} files)", "Scanning".cyan().bold(), path.display(), total);
            }

            let pb = if !json_output && total > 0 {
                let pb = ProgressBar::new(total);
                pb.set_style(
                    ProgressStyle::with_template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} | {per_sec} | ETA {eta} | {msg}",
                    ).map_or_else(|_| ProgressStyle::default_bar(), |style| style.progress_chars("#>-")),
                );
                pb.set_message("scanning...");
                Some(pb)
            } else {
                None
            };

            // Use the engine's parallel directory scanner.
            let results = engine.scan_directory(&path);

            if let Some(pb) = &pb {
                pb.finish_and_clear();
            }

            results
        } else {
            // Non-recursive: scan only direct children.
            let entries: Vec<PathBuf> = std::fs::read_dir(&path)?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();

            if !json_output {
                println!(
                    "{} {} ({} files, non-recursive)",
                    "Scanning".cyan().bold(),
                    path.display(),
                    entries.len()
                );
            }

            let mut results = Vec::with_capacity(entries.len());
            for entry in &entries {
                match engine.scan_file(entry).await {
                    Ok(r) => results.push(r),
                    Err(e) => {
                        tracing::error!(path = %entry.display(), error = %e, "scan failed");
                    }
                }
            }
            results
        }
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    };

    #[allow(clippy::cast_possible_truncation)] // Scan duration won't exceed u64::MAX ms.
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Print results.
    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        // Show individual threat/suspicious results.
        for r in &results {
            if r.is_threat() {
                output::print_scan_result(r, true);
            }
        }
        println!();
        output::print_scan_summary(&results, elapsed_ms);

        // Print scan speed statistics.
        if !results.is_empty() {
            let total_bytes: u64 = results
                .iter()
                .map(|r| std::fs::metadata(&r.path).map(|m| m.len()).unwrap_or(0))
                .sum();
            #[allow(clippy::cast_precision_loss)] // Acceptable for display stats.
            let mb = total_bytes as f64 / (1024.0 * 1024.0);
            #[allow(clippy::cast_precision_loss)] // Acceptable for display stats.
            let secs = elapsed_ms as f64 / 1000.0;
            println!(
                "  Speed: {:.1} MB/s ({:.0} files/sec)",
                mb / secs.max(0.001),
                results.len() as f64 / secs.max(0.001)
            );
        }
    }

    // Generate HTML report if requested.
    if let Some(report_path) = &report {
        let html = super::report::generate_html_report(&results, &path.display().to_string(), elapsed_ms);
        super::report::write_report(report_path, &html)?;
        println!("Report saved to {}", report_path.display());
    }

    // Remediation (--remediate) takes precedence over --auto-quarantine
    // since remediation already includes quarantine in its default policy.
    if remediate {
        if let Err(e) = remediate_threats(&results, data_dir).await {
            eprintln!("\n{} remediation error: {e:#}", "Error:".red().bold());
        }
    } else if auto_quarantine {
        let threats: Vec<&ScanResult> = results
            .iter()
            .filter(|r| r.threat_level == ThreatLevel::Malicious)
            .collect();

        if !threats.is_empty() {
            println!(
                "\n{} quarantining {} malicious file(s)...",
                ">>>".yellow().bold(),
                threats.len()
            );
            for r in threats {
                let threat_name = r.threat_name.as_deref().unwrap_or("Unknown");
                match quarantine_file(&r.path, threat_name, data_dir) {
                    Ok(()) => {
                        println!("  {} {}", "Quarantined:".red().bold(), r.path.display());
                    }
                    Err(e) => {
                        eprintln!(
                            "  {} failed to quarantine {}: {}",
                            "Error:".red().bold(),
                            r.path.display(),
                            e
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
