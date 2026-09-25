use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use colored::Colorize;

use prx_sd_core::{ScanConfig, ScanEngine, ScanResult, ThreatLevel};

use crate::output;

/// Maximum number of retries when waiting for a device to be mounted.
const MOUNT_RETRIES: u32 = 3;
/// Delay between mount-check retries.
const MOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Build a `ScanConfig` rooted in the given data directory.
fn build_config(data_dir: &Path) -> ScanConfig {
    let mut config = ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"));

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

/// Parse mount table and return the mount point for the given device path.
///
/// - Linux: reads `/proc/mounts`
/// - macOS: reads `/etc/mtab` or output of `mount`
/// - Windows: not supported via this path (uses drive letters)
fn find_mount_point(device: &str) -> Option<PathBuf> {
    let mount_file = mount_table_path();
    let contents = std::fs::read_to_string(mount_file).ok()?;
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let dev = parts.next()?;
        let mount = parts.next()?;
        if dev == device {
            return Some(PathBuf::from(mount));
        }
    }
    None
}

/// Platform-specific path to the mount table file.
const fn mount_table_path() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "/proc/mounts"
    }
    #[cfg(target_os = "macos")]
    {
        "/etc/mtab"
    }
    // Windows and other platforms: no mount table file
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ""
    }
}

/// Find all mounted USB/removable devices.
///
/// Platform heuristics:
/// - Linux: `/dev/sd*` mounted under `/media`, `/mnt`, `/run/media`
/// - macOS: `/dev/disk*` mounted under `/Volumes`
/// - Windows: stub (returns empty)
fn find_usb_mounts() -> Vec<(String, PathBuf)> {
    let mount_file = mount_table_path();
    let Ok(contents) = std::fs::read_to_string(mount_file) else {
        return Vec::new();
    };

    let mut mounts = Vec::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let Some(dev) = parts.next() else { continue };
        let Some(mount) = parts.next() else { continue };

        if is_removable_device(dev, mount) {
            mounts.push((dev.to_string(), PathBuf::from(mount)));
        }
    }

    mounts
}

/// Platform-specific heuristic to identify removable/USB devices.
fn is_removable_device(dev: &str, mount: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let is_usb_device = dev.starts_with("/dev/sd");
        let is_removable_mount =
            mount.starts_with("/media") || mount.starts_with("/mnt") || mount.starts_with("/run/media");
        is_usb_device && is_removable_mount
    }
    #[cfg(target_os = "macos")]
    {
        let is_disk_device = dev.starts_with("/dev/disk");
        let is_volumes = mount.starts_with("/Volumes");
        // Skip the boot volume
        let is_not_root = mount != "/Volumes/Macintosh HD";
        is_disk_device && is_volumes && is_not_root
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (dev, mount);
        false
    }
}

/// Quarantine a single file using the AES-256-GCM encrypted vault.
fn quarantine_file(path: &Path, threat_name: &str, data_dir: &Path) -> Result<()> {
    let vault_dir = data_dir.join("quarantine");
    let quarantine = prx_sd_quarantine::Quarantine::new(vault_dir).context("failed to open quarantine vault")?;
    let id = quarantine
        .quarantine(path, threat_name)
        .with_context(|| format!("failed to quarantine {}", path.display()))?;
    tracing::info!(id = %id, path = %path.display(), threat = threat_name, "file quarantined");
    Ok(())
}

/// Scan a single mount point and return the scan results.
fn scan_mount(mount_path: &Path, engine: &ScanEngine) -> Vec<ScanResult> {
    println!("\n{} scanning USB mount: {}", ">>>".cyan().bold(), mount_path.display());
    engine.scan_directory(mount_path)
}

/// Entry point for the `sd scan-usb` command.
///
/// When `device` is `Some`, we locate the mount point for that specific device
/// and scan it. When `device` is `None`, we discover all mounted USB devices
/// and scan each one.
pub async fn run(device: Option<&str>, auto_quarantine: bool, data_dir: &Path) -> Result<()> {
    let config = build_config(data_dir);
    let engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    let mounts: Vec<(String, PathBuf)> = if let Some(dev) = device {
        // Try to find where the specified device is mounted, retrying a few
        // times since USB devices may take a moment to be automounted.
        let mut mount_point = find_mount_point(dev);
        if mount_point.is_none() {
            for attempt in 1..=MOUNT_RETRIES {
                println!(
                    "{} device {} not yet mounted, waiting... (attempt {}/{})",
                    "info:".cyan(),
                    dev,
                    attempt,
                    MOUNT_RETRIES,
                );
                tokio::time::sleep(MOUNT_RETRY_DELAY).await;
                mount_point = find_mount_point(dev);
                if mount_point.is_some() {
                    break;
                }
            }
        }

        if let Some(mp) = mount_point {
            vec![(dev.to_string(), mp)]
        } else {
            eprintln!(
                "{} device {} is not mounted after {} retries. Skipping.",
                "warning:".yellow().bold(),
                dev,
                MOUNT_RETRIES,
            );
            return Ok(());
        }
    } else {
        let usb_mounts = find_usb_mounts();
        if usb_mounts.is_empty() {
            println!("{} no mounted USB devices found.", "info:".cyan());
            return Ok(());
        }
        usb_mounts
    };

    println!(
        "{} PRX-SD USB scan: {} device(s) detected",
        ">>>".cyan().bold(),
        mounts.len(),
    );

    for (dev, mount) in &mounts {
        println!("  {} -> {}", dev, mount.display());
    }

    let start = Instant::now();
    let mut all_results: Vec<ScanResult> = Vec::new();

    for (_dev, mount) in &mounts {
        let results = scan_mount(mount, &engine);
        all_results.extend(results);
    }

    #[allow(clippy::cast_possible_truncation)] // Scan duration won't exceed u64::MAX ms.
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Print individual threats.
    for r in &all_results {
        if r.is_threat() {
            output::print_scan_result(r, true);
        }
    }

    println!();
    output::print_scan_summary(&all_results, elapsed_ms);

    // Auto-quarantine malicious files if requested.
    if auto_quarantine {
        let threats: Vec<&ScanResult> = all_results
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
