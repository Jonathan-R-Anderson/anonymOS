//! Linux-specific remediation actions.
//!
//! Provides functions for killing processes via signals, cleaning various
//! persistence mechanisms (crontab, systemd, init scripts, shell profiles,
//! `authorized_keys`, `LD_PRELOAD`), and network isolation via iptables.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::PersistenceType;

/// Kill a process by PID using SIGKILL.
pub fn kill_process(pid: u32) -> Result<()> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    #[allow(clippy::cast_possible_wrap)]
    let nix_pid = Pid::from_raw(pid as i32);
    kill(nix_pid, Signal::SIGKILL).with_context(|| format!("failed to kill process {pid}"))?;
    tracing::info!(pid = pid, "killed process via SIGKILL");
    Ok(())
}

/// Find and remove crontab entries referencing the given path.
///
/// Scans both the user crontab (via `crontab -l`) and system crontab files
/// in `/etc/cron.d/`, `/etc/crontab`, and `/var/spool/cron/crontabs/`.
/// Returns a list of removed entries.
#[allow(clippy::excessive_nesting)]
pub fn clean_crontab(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut removed = Vec::new();

    // Clean system crontab files
    let cron_dirs = ["/etc/cron.d", "/var/spool/cron/crontabs"];
    let cron_files = ["/etc/crontab"];

    for cron_file in &cron_files {
        let cron_path = Path::new(cron_file);
        if cron_path.exists() {
            if let Ok(content) = fs::read_to_string(cron_path) {
                let (cleaned, removed_lines) = remove_matching_lines(&content, &path_str);
                if !removed_lines.is_empty() {
                    fs::write(cron_path, cleaned)
                        .with_context(|| format!("failed to write cleaned crontab: {}", cron_path.display()))?;
                    for line in &removed_lines {
                        tracing::info!(file = cron_file, line = line.as_str(), "removed crontab entry");
                    }
                    removed.extend(removed_lines);
                }
            }
        }
    }

    for dir in &cron_dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let file_path = entry.path();
                if !file_path.is_file() {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&file_path) {
                    let (cleaned, removed_lines) = remove_matching_lines(&content, &path_str);
                    if !removed_lines.is_empty() {
                        fs::write(&file_path, cleaned)
                            .with_context(|| format!("failed to write cleaned cron file: {}", file_path.display()))?;
                        for line in &removed_lines {
                            tracing::info!(
                                file = %file_path.display(),
                                line = line.as_str(),
                                "removed cron entry"
                            );
                        }
                        removed.extend(removed_lines);
                    }
                }
            }
        }
    }

    Ok(removed)
}

/// Find and disable systemd services referencing the given path.
///
/// Scans `/etc/systemd/system/` and `/usr/lib/systemd/system/` for `.service`
/// and `.timer` unit files that reference the malicious path.
/// Disables and masks the unit, then removes it.
/// Returns a list of cleaned unit names.
#[allow(clippy::excessive_nesting)]
pub fn clean_systemd_services(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    let systemd_dirs = ["/etc/systemd/system", "/usr/lib/systemd/system"];

    for dir in &systemd_dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let file_path = entry.path();
                let file_name = file_path
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().to_string());

                // Only check .service and .timer files
                let is_service = std::path::Path::new(&file_name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("service"));
                let is_timer = std::path::Path::new(&file_name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"));
                if !is_service && !is_timer {
                    continue;
                }

                if let Ok(content) = fs::read_to_string(&file_path) {
                    if content.contains(path_str.as_ref()) {
                        // Attempt to stop and disable the unit
                        let _ = std::process::Command::new("systemctl")
                            .args(["stop", &file_name])
                            .output();
                        let _ = std::process::Command::new("systemctl")
                            .args(["disable", &file_name])
                            .output();

                        // Remove the unit file
                        if let Err(e) = fs::remove_file(&file_path) {
                            tracing::warn!(
                                file = %file_path.display(),
                                error = %e,
                                "failed to remove systemd unit"
                            );
                        } else {
                            tracing::info!(unit = file_name.as_str(), "removed malicious systemd unit");
                            cleaned.push(file_name);
                        }
                    }
                }
            }
        }
    }

    // Reload systemd if we removed anything
    if !cleaned.is_empty() {
        let _ = std::process::Command::new("systemctl").arg("daemon-reload").output();
    }

    Ok(cleaned)
}

/// Remove malicious entries from init scripts (/etc/rc.local and /etc/init.d/).
///
/// Returns a list of descriptions of what was cleaned.
#[allow(clippy::excessive_nesting)]
pub fn clean_init_scripts(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    // Clean /etc/rc.local
    let rc_local = Path::new("/etc/rc.local");
    if rc_local.exists() {
        if let Ok(content) = fs::read_to_string(rc_local) {
            let (new_content, removed_lines) = remove_matching_lines(&content, &path_str);
            if !removed_lines.is_empty() {
                fs::write(rc_local, new_content).context("failed to write cleaned /etc/rc.local")?;
                for line in &removed_lines {
                    tracing::info!(line = line.as_str(), "removed from /etc/rc.local");
                }
                cleaned.extend(removed_lines);
            }
        }
    }

    // Check /etc/init.d/ for scripts referencing the path
    let init_d = Path::new("/etc/init.d");
    if init_d.exists() {
        if let Ok(entries) = fs::read_dir(init_d) {
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let file_path = entry.path();
                if !file_path.is_file() {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if content.contains(path_str.as_ref()) {
                        // Disable the init script
                        let file_name = file_path
                            .file_name()
                            .map_or_else(String::new, |n| n.to_string_lossy().to_string());
                        let _ = std::process::Command::new("update-rc.d")
                            .args([&file_name, "disable"])
                            .output();
                        if let Err(e) = fs::remove_file(&file_path) {
                            tracing::warn!(
                                file = %file_path.display(),
                                error = %e,
                                "failed to remove init script"
                            );
                        } else {
                            let desc = format!("removed init script: {file_name}");
                            tracing::info!("{desc}");
                            cleaned.push(desc);
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Remove malicious entries from shell profile files.
///
/// Scans `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `/etc/profile`,
/// and /etc/profile.d/*.sh for lines referencing the malicious path.
/// Returns a list of removed entries.
#[allow(clippy::excessive_nesting)]
pub fn clean_shell_profiles(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    // User profile files - check for all users via /etc/passwd
    let profile_files = ["/etc/profile", "/etc/bash.bashrc", "/etc/environment"];

    for pf in &profile_files {
        let pf_path = Path::new(pf);
        if pf_path.exists() {
            if let Ok(content) = fs::read_to_string(pf_path) {
                let (new_content, removed_lines) = remove_matching_lines(&content, &path_str);
                if !removed_lines.is_empty() {
                    fs::write(pf_path, new_content)
                        .with_context(|| format!("failed to write: {}", pf_path.display()))?;
                    for line in &removed_lines {
                        tracing::info!(file = *pf, line = line.as_str(), "removed from shell profile");
                    }
                    cleaned.extend(removed_lines);
                }
            }
        }
    }

    // Check /etc/profile.d/
    let profile_d = Path::new("/etc/profile.d");
    if profile_d.exists() {
        if let Ok(entries) = fs::read_dir(profile_d) {
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let file_path = entry.path();
                if !file_path.is_file() {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if content.contains(path_str.as_ref()) {
                        if let Err(e) = fs::remove_file(&file_path) {
                            tracing::warn!(
                                file = %file_path.display(),
                                error = %e,
                                "failed to remove profile.d script"
                            );
                        } else {
                            let desc = format!("removed profile.d script: {}", file_path.display());
                            tracing::info!("{desc}");
                            cleaned.push(desc);
                        }
                    }
                }
            }
        }
    }

    // Scan home directories
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            let Some(home) = parts.get(5) else {
                continue;
            };
            if home.is_empty() || !Path::new(home).exists() {
                continue;
            }

            let user_files = [".bashrc", ".profile", ".bash_profile", ".zshrc"];
            for uf in &user_files {
                let uf_path = Path::new(home).join(uf);
                if uf_path.exists() {
                    if let Ok(content) = fs::read_to_string(&uf_path) {
                        let (new_content, removed_lines) = remove_matching_lines(&content, &path_str);
                        if !removed_lines.is_empty() {
                            if let Err(e) = fs::write(&uf_path, new_content) {
                                tracing::warn!(
                                    file = %uf_path.display(),
                                    error = %e,
                                    "failed to write cleaned profile"
                                );
                            } else {
                                for rl in &removed_lines {
                                    tracing::info!(
                                        file = %uf_path.display(),
                                        line = rl.as_str(),
                                        "removed from user profile"
                                    );
                                }
                                cleaned.extend(removed_lines);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Remove entries from `~/.ssh/authorized_keys` that match a suspicious pattern.
///
/// This searches all users' `authorized_keys` files for lines containing the
/// given pattern and removes them.
/// Returns a list of removed key descriptions.
#[allow(clippy::excessive_nesting)]
pub fn clean_authorized_keys(suspicious_pattern: &str) -> Result<Vec<String>> {
    let mut cleaned = Vec::new();

    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            let Some(home) = parts.get(5) else {
                continue;
            };
            let ak_path = Path::new(home).join(".ssh/authorized_keys");

            if !ak_path.exists() {
                continue;
            }

            if let Ok(content) = fs::read_to_string(&ak_path) {
                let (new_content, removed_lines) = remove_matching_lines(&content, suspicious_pattern);
                if !removed_lines.is_empty() {
                    if let Err(e) = fs::write(&ak_path, new_content) {
                        tracing::warn!(
                            file = %ak_path.display(),
                            error = %e,
                            "failed to write cleaned authorized_keys"
                        );
                    } else {
                        for rl in &removed_lines {
                            tracing::info!(
                                file = %ak_path.display(),
                                "removed authorized_keys entry: {}",
                                rl
                            );
                        }
                        cleaned.extend(removed_lines);
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Remove `LD_PRELOAD` entries from `/etc/ld.so.preload` that reference the path.
///
/// Returns a list of removed entries.
pub fn clean_ld_preload(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let preload_path = Path::new("/etc/ld.so.preload");

    if !preload_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(preload_path).context("failed to read /etc/ld.so.preload")?;
    let (new_content, removed_lines) = remove_matching_lines(&content, &path_str);

    if !removed_lines.is_empty() {
        fs::write(preload_path, new_content).context("failed to write cleaned /etc/ld.so.preload")?;
        for line in &removed_lines {
            tracing::info!(line = line.as_str(), "removed from /etc/ld.so.preload");
        }
    }

    Ok(removed_lines)
}

/// Network isolation via iptables.
///
/// Saves the current iptables rules to `/tmp/prx-sd-iptables-backup.rules`,
/// then drops all traffic except loopback.
pub fn isolate_network_iptables() -> Result<()> {
    // Save current rules
    let output = std::process::Command::new("iptables-save")
        .output()
        .context("failed to run iptables-save")?;

    if output.status.success() {
        fs::write("/tmp/prx-sd-iptables-backup.rules", &output.stdout).context("failed to save iptables backup")?;
        tracing::info!("saved iptables rules to /tmp/prx-sd-iptables-backup.rules");
    }

    // Flush existing rules
    let _ = std::process::Command::new("iptables").args(["-F"]).output();

    // Allow loopback
    let _ = std::process::Command::new("iptables")
        .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        .output();

    // Allow established connections (so we don't kill current SSH)
    let _ = std::process::Command::new("iptables")
        .args([
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .output();
    let _ = std::process::Command::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .output();

    // Drop everything else
    let _ = std::process::Command::new("iptables")
        .args(["-P", "INPUT", "DROP"])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-P", "OUTPUT", "DROP"])
        .output();
    let _ = std::process::Command::new("iptables")
        .args(["-P", "FORWARD", "DROP"])
        .output();

    tracing::info!("network isolated via iptables");
    Ok(())
}

/// Restore network rules from the backup saved during isolation.
pub fn restore_network_iptables() -> Result<()> {
    let backup_path = Path::new("/tmp/prx-sd-iptables-backup.rules");

    if backup_path.exists() {
        let rules = fs::read_to_string(backup_path).context("failed to read iptables backup")?;
        let mut child = std::process::Command::new("iptables-restore")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("failed to run iptables-restore")?;

        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            stdin
                .write_all(rules.as_bytes())
                .context("failed to write to iptables-restore stdin")?;
        }

        let status = child.wait().context("failed to wait for iptables-restore")?;
        if !status.success() {
            anyhow::bail!("iptables-restore exited with status: {status}");
        }

        fs::remove_file(backup_path).ok();
        tracing::info!("network restored from iptables backup");
    } else {
        // No backup, just flush and set ACCEPT policy
        let _ = std::process::Command::new("iptables").args(["-F"]).output();
        let _ = std::process::Command::new("iptables")
            .args(["-P", "INPUT", "ACCEPT"])
            .output();
        let _ = std::process::Command::new("iptables")
            .args(["-P", "OUTPUT", "ACCEPT"])
            .output();
        let _ = std::process::Command::new("iptables")
            .args(["-P", "FORWARD", "ACCEPT"])
            .output();
        tracing::info!("network restored to default ACCEPT policy (no backup found)");
    }

    Ok(())
}

/// Scan all Linux persistence mechanisms for references to the given path.
///
/// Returns a list of `(PersistenceType, detail)` tuples for each match found.
#[allow(clippy::excessive_nesting)]
pub fn scan_all_persistence(path: &Path) -> Vec<(PersistenceType, String)> {
    let path_str = path.to_string_lossy();
    let mut findings = Vec::new();

    // Crontab entries
    let cron_locations = ["/etc/crontab", "/var/spool/cron/crontabs", "/etc/cron.d"];
    for loc in &cron_locations {
        let loc_path = Path::new(loc);
        if loc_path.is_file() {
            if let Ok(content) = fs::read_to_string(loc_path) {
                if content.contains(path_str.as_ref()) {
                    findings.push((PersistenceType::Crontab, format!("found in {loc}")));
                }
            }
        } else if loc_path.is_dir() {
            if let Ok(entries) = fs::read_dir(loc_path) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if content.contains(path_str.as_ref()) {
                            findings.push((PersistenceType::CronJob, format!("found in {}", entry.path().display())));
                        }
                    }
                }
            }
        }
    }

    // Systemd services and timers
    let systemd_dirs = ["/etc/systemd/system", "/usr/lib/systemd/system"];
    for dir in &systemd_dirs {
        let dir_path = Path::new(dir);
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let ep = entry.path();
                if let Ok(content) = fs::read_to_string(&ep) {
                    if content.contains(path_str.as_ref()) {
                        let is_timer = ep.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("timer"));
                        let ptype = if is_timer {
                            PersistenceType::SystemdTimer
                        } else {
                            PersistenceType::SystemdService
                        };
                        findings.push((ptype, format!("found in {}", ep.display())));
                    }
                }
            }
        }
    }

    // Shell profiles
    let shell_files = ["/etc/profile", "/etc/bash.bashrc"];
    for sf in &shell_files {
        let sf_path = Path::new(sf);
        if let Ok(content) = fs::read_to_string(sf_path) {
            if content.contains(path_str.as_ref()) {
                findings.push((PersistenceType::ShellRc, format!("found in {sf}")));
            }
        }
    }

    // Init scripts
    let rc_local = Path::new("/etc/rc.local");
    if let Ok(content) = fs::read_to_string(rc_local) {
        if content.contains(path_str.as_ref()) {
            findings.push((PersistenceType::InitScript, "found in /etc/rc.local".to_string()));
        }
    }

    // LD_PRELOAD
    let ld_preload = Path::new("/etc/ld.so.preload");
    if let Ok(content) = fs::read_to_string(ld_preload) {
        if content.contains(path_str.as_ref()) {
            findings.push((PersistenceType::LdPreload, "found in /etc/ld.so.preload".to_string()));
        }
    }

    findings
}

/// Remove lines from text that contain the given pattern.
/// Returns the cleaned text and a list of removed lines.
fn remove_matching_lines(content: &str, pattern: &str) -> (String, Vec<String>) {
    let mut kept = Vec::new();
    let mut removed = Vec::new();

    for line in content.lines() {
        if line.contains(pattern) {
            removed.push(line.to_string());
        } else {
            kept.push(line);
        }
    }

    let mut result = kept.join("\n");
    // Preserve trailing newline if original had one
    if content.ends_with('\n') {
        result.push('\n');
    }

    (result, removed)
}
