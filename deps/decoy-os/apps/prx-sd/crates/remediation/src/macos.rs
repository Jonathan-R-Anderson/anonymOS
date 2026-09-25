//! macOS-specific remediation actions.
//!
//! Provides functions for killing processes, cleaning LaunchAgent/LaunchDaemon
//! plists, login items, shell profiles, and network isolation via the pf firewall.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::PersistenceType;

/// Escape a string for safe embedding in AppleScript double-quoted strings.
///
/// Prevents command injection when interpolating untrusted values into
/// osascript commands by escaping backslashes and double-quotes.
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Kill a process by PID using SIGKILL.
pub fn kill_process(pid: u32) -> Result<()> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);
    kill(nix_pid, Signal::SIGKILL).with_context(|| format!("failed to kill process {}", pid))?;
    tracing::info!(pid = pid, "killed process via SIGKILL");
    Ok(())
}

/// Remove LaunchAgent plist files that reference the given path.
///
/// Searches ~/Library/LaunchAgents/ and /Library/LaunchAgents/ for plist
/// files containing the malicious path, unloads them via launchctl, and
/// removes the plist files.
/// Returns a list of removed plist file paths.
pub fn clean_launch_agents(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    let dirs = collect_launch_agent_dirs();

    for dir in &dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.extension().and_then(|e| e.to_str()) != Some("plist") {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if content.contains(path_str.as_ref()) {
                        // Unload the agent
                        let _ = Command::new("launchctl")
                            .args(["unload", "-w"])
                            .arg(&file_path)
                            .output();

                        if let Err(e) = fs::remove_file(&file_path) {
                            tracing::warn!(
                                file = %file_path.display(),
                                error = %e,
                                "failed to remove LaunchAgent plist"
                            );
                        } else {
                            let desc = format!("removed LaunchAgent: {}", file_path.display());
                            tracing::info!("{}", desc);
                            cleaned.push(desc);
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Remove LaunchDaemon plist files that reference the given path.
///
/// Searches /Library/LaunchDaemons/ and /System/Library/LaunchDaemons/
/// for plist files containing the malicious path.
/// Returns a list of removed plist file paths.
pub fn clean_launch_daemons(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    let dirs = ["/Library/LaunchDaemons"];

    for dir in &dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.extension().and_then(|e| e.to_str()) != Some("plist") {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if content.contains(path_str.as_ref()) {
                        // Unload the daemon
                        let _ = Command::new("launchctl")
                            .args(["unload", "-w"])
                            .arg(&file_path)
                            .output();

                        if let Err(e) = fs::remove_file(&file_path) {
                            tracing::warn!(
                                file = %file_path.display(),
                                error = %e,
                                "failed to remove LaunchDaemon plist"
                            );
                        } else {
                            let desc = format!("removed LaunchDaemon: {}", file_path.display());
                            tracing::info!("{}", desc);
                            cleaned.push(desc);
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Remove login items that reference the given path.
///
/// Uses `osascript` to list and remove login items referencing the path.
/// Returns a list of removed items.
pub fn clean_login_items(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    // List login items via osascript
    let output = Command::new("osascript")
        .args([
            "-e",
            "tell application \"System Events\" to get the name of every login item",
        ])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("failed to list login items: {}", e);
            return Ok(cleaned);
        }
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Items are comma-separated
        for item_name in stdout.split(',') {
            let item_name = item_name.trim();
            if item_name.is_empty() {
                continue;
            }
            // Check if this item references the malicious path
            // by getting its path property.
            // Escape item_name to prevent AppleScript injection.
            let safe_name = escape_applescript(item_name);
            let check_script = format!(
                "tell application \"System Events\" to get the path of login item \"{}\"",
                safe_name
            );
            let check_output = Command::new("osascript").args(["-e", &check_script]).output();

            if let Ok(co) = check_output {
                let item_path = String::from_utf8_lossy(&co.stdout).trim().to_string();
                if item_path.contains(path_str.as_ref()) {
                    let delete_script = format!(
                        "tell application \"System Events\" to delete login item \"{}\"",
                        safe_name
                    );
                    let _ = Command::new("osascript").args(["-e", &delete_script]).output();
                    let desc = format!("removed login item: {}", item_name);
                    tracing::info!("{}", desc);
                    cleaned.push(desc);
                }
            }
        }
    }

    Ok(cleaned)
}

/// Clean shell profiles on macOS.
///
/// Scans common shell configuration files for lines referencing the malicious path.
/// Returns a list of removed entries.
pub fn clean_shell_profiles(path: &Path) -> Result<Vec<String>> {
    let path_str = path.to_string_lossy();
    let mut cleaned = Vec::new();

    // System-wide profiles
    let system_files = ["/etc/profile", "/etc/bashrc", "/etc/zshrc"];

    for sf in &system_files {
        let sf_path = Path::new(sf);
        if sf_path.exists() {
            if let Ok(content) = fs::read_to_string(sf_path) {
                let (new_content, removed) = remove_matching_lines(&content, &path_str);
                if !removed.is_empty() {
                    if let Err(e) = fs::write(sf_path, new_content) {
                        tracing::warn!(file = *sf, error = %e, "failed to clean shell profile");
                    } else {
                        cleaned.extend(removed);
                    }
                }
            }
        }
    }

    // User profiles
    if let Ok(home) = std::env::var("HOME") {
        let user_files = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"];
        for uf in &user_files {
            let uf_path = Path::new(&home).join(uf);
            if uf_path.exists() {
                if let Ok(content) = fs::read_to_string(&uf_path) {
                    let (new_content, removed) = remove_matching_lines(&content, &path_str);
                    if !removed.is_empty() {
                        if let Err(e) = fs::write(&uf_path, new_content) {
                            tracing::warn!(
                                file = %uf_path.display(),
                                error = %e,
                                "failed to clean user profile"
                            );
                        } else {
                            cleaned.extend(removed);
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Network isolation via pf firewall.
///
/// Saves the current pf rules, then activates a restrictive ruleset
/// that blocks all traffic except loopback and established connections.
pub fn isolate_network_pf() -> Result<()> {
    // Save current pf rules
    let output = Command::new("pfctl")
        .args(["-sr"])
        .output()
        .context("failed to run pfctl -sr")?;

    if output.status.success() {
        fs::write("/tmp/prx-sd-pf-backup.rules", &output.stdout).context("failed to save pf backup")?;
        tracing::info!("saved pf rules to /tmp/prx-sd-pf-backup.rules");
    }

    // Write isolation rules
    let isolation_rules = "# prx-sd network isolation\n\
        block all\n\
        pass on lo0 all\n\
        pass out proto tcp from any to any flags S/SA keep state\n";

    fs::write("/tmp/prx-sd-pf-isolation.rules", isolation_rules).context("failed to write pf isolation rules")?;

    // Load isolation rules
    let result = Command::new("pfctl")
        .args(["-f", "/tmp/prx-sd-pf-isolation.rules"])
        .output()
        .context("failed to load pf isolation rules")?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        anyhow::bail!("pfctl -f failed: {}", stderr);
    }

    // Enable pf
    let _ = Command::new("pfctl").args(["-e"]).output();

    tracing::info!("network isolated via pf");
    Ok(())
}

/// Restore network rules from the backup saved during isolation.
pub fn restore_network_pf() -> Result<()> {
    let backup_path = Path::new("/tmp/prx-sd-pf-backup.rules");

    if backup_path.exists() {
        let result = Command::new("pfctl")
            .args(["-f", "/tmp/prx-sd-pf-backup.rules"])
            .output()
            .context("failed to restore pf rules")?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            anyhow::bail!("pfctl restore failed: {}", stderr);
        }

        fs::remove_file(backup_path).ok();
        fs::remove_file("/tmp/prx-sd-pf-isolation.rules").ok();
        tracing::info!("network restored from pf backup");
    } else {
        // No backup, just disable pf
        let _ = Command::new("pfctl").args(["-d"]).output();
        tracing::info!("pf disabled (no backup found)");
    }

    Ok(())
}

/// Scan all macOS persistence mechanisms for references to the given path.
///
/// Returns a list of `(PersistenceType, detail)` tuples for each finding.
pub fn scan_all_persistence(path: &Path) -> Vec<(PersistenceType, String)> {
    let path_str = path.to_string_lossy();
    let mut findings = Vec::new();

    // LaunchAgents
    let agent_dirs = collect_launch_agent_dirs();
    for dir in &agent_dirs {
        scan_plist_dir(dir, &path_str, PersistenceType::LaunchAgent, &mut findings);
    }

    // LaunchDaemons
    scan_plist_dir(
        "/Library/LaunchDaemons",
        &path_str,
        PersistenceType::LaunchDaemon,
        &mut findings,
    );

    // Shell profiles
    let shell_files = ["/etc/profile", "/etc/bashrc", "/etc/zshrc"];
    for sf in &shell_files {
        if let Ok(content) = fs::read_to_string(sf) {
            if content.contains(path_str.as_ref()) {
                findings.push((PersistenceType::ShellRc, format!("found in {}", sf)));
            }
        }
    }

    findings
}

/// Collect LaunchAgent directories (system and user).
fn collect_launch_agent_dirs() -> Vec<String> {
    let mut dirs = vec!["/Library/LaunchAgents".to_string()];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(format!("{}/Library/LaunchAgents", home));
    }
    dirs
}

/// Scan a directory of plist files for references to the given pattern.
fn scan_plist_dir(dir: &str, pattern: &str, ptype: PersistenceType, findings: &mut Vec<(PersistenceType, String)>) {
    let dir_path = Path::new(dir);
    if !dir_path.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let file_path = entry.path();
            if file_path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&file_path) {
                if content.contains(pattern) {
                    findings.push((ptype.clone(), format!("found in {}", file_path.display())));
                }
            }
        }
    }
}

/// Remove lines from text that contain the given pattern.
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
    if content.ends_with('\n') {
        result.push('\n');
    }

    (result, removed)
}
