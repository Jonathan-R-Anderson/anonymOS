use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use prx_sd_signatures::SignatureDatabase;

use crate::output;

/// Read the PID from the PID file.
fn read_pid(data_dir: &Path) -> Option<u32> {
    let pid_path = data_dir.join("prx-sd.pid");
    std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Check whether a process with the given PID is running.
fn is_process_running(pid: u32) -> bool {
    // Check /proc/<pid> on Linux, or use `kill -0` via command on other Unix.
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        // Best-effort: assume not running on unknown platforms.
        let _ = pid;
        false
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn run(data_dir: &Path) -> Result<()> {
    println!("{}", "PRX-SD Daemon Status".cyan().bold());
    println!();

    // Check PID file and process status.
    match read_pid(data_dir) {
        Some(pid) => {
            let running = is_process_running(pid);
            if running {
                println!("  {:<22} {} (PID {})", "Status:".bold(), "RUNNING".green().bold(), pid);

                // Try to get uptime from /proc on Linux.
                #[cfg(target_os = "linux")]
                {
                    let uptime = data_dir
                        .join("prx-sd.pid")
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.elapsed().ok());
                    if let Some(elapsed) = uptime {
                        let secs = elapsed.as_secs();
                        let hours = secs / 3600;
                        let mins = (secs % 3600) / 60;
                        println!("  {:<22} {hours}h {mins}m", "Uptime:".bold());
                    }
                }
            } else {
                println!(
                    "  {:<22} {} (stale PID file, PID {})",
                    "Status:".bold(),
                    "STOPPED".red().bold(),
                    pid
                );
            }
        }
        None => {
            println!("  {:<22} {} (no PID file)", "Status:".bold(), "STOPPED".yellow());
        }
    }

    // Signature database info.
    let sig_dir = data_dir.join("signatures");
    if sig_dir.exists() {
        match SignatureDatabase::open(&sig_dir) {
            Ok(db) => match db.get_stats() {
                Ok(stats) => {
                    println!("  {:<22} v{}", "Signature version:".bold(), stats.version);
                    println!("  {:<22} {}", "Hash signatures:".bold(), stats.hash_count);

                    if let Some(ts) = stats.last_update {
                        let dt = chrono::DateTime::from_timestamp(ts, 0)
                            .map_or_else(|| ts.to_string(), |d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                        println!("  {:<22} {}", "Last update:".bold(), dt);
                    } else {
                        println!("  {:<22} {}", "Last update:".bold(), "never".dimmed());
                    }
                }
                Err(e) => {
                    println!("  {:<22} {} ({})", "Signatures:".bold(), "error reading stats".red(), e);
                }
            },
            Err(e) => {
                println!("  {:<22} {} ({})", "Signatures:".bold(), "not initialised".yellow(), e);
            }
        }
    } else {
        println!("  {:<22} {}", "Signatures:".bold(), "not found".yellow());
    }

    // Quarantine stats.
    let vault_dir = data_dir.join("quarantine").join("vault");
    if vault_dir.exists() {
        let mut file_count = 0u64;
        let mut total_size = 0u64;

        if let Ok(entries) = std::fs::read_dir(&vault_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && !path.to_string_lossy().ends_with(".meta.json") {
                    file_count += 1;
                    total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }

        println!(
            "  {:<22} {} file(s), {}",
            "Threats blocked:".bold(),
            file_count,
            output::format_bytes(total_size)
        );
    } else {
        println!("  {:<22} {}", "Threats blocked:".bold(), "0".dimmed());
    }

    Ok(())
}
