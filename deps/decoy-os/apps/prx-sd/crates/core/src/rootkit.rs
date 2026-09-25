//! Rootkit detection module (Linux only).
//!
//! Performs integrity checks to detect kernel-level and user-level rootkits:
//! - Hidden process detection (compare `/proc` enumeration with syscall results)
//! - Kernel module integrity (check `/proc/modules` for unknown modules)
//! - Suspicious `/proc` entries
//! - `LD_PRELOAD` hijacking
//! - Syscall table integrity (indirect check)

#[cfg(not(target_os = "linux"))]
compile_error!("rootkit module is Linux-only");

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::result::ThreatLevel;

/// Result of a full rootkit scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitScanResult {
    /// Processes detected as hidden (exist via syscall but not visible in `/proc`).
    pub hidden_processes: Vec<HiddenProcess>,
    /// Kernel modules flagged as suspicious.
    pub suspicious_modules: Vec<SuspiciousModule>,
    /// `LD_PRELOAD` hijacking indicator, if detected.
    pub ld_preload_hijack: Option<String>,
    /// Anomalies detected in `/proc` filesystem entries.
    pub proc_anomalies: Vec<ProcAnomaly>,
    /// Overall threat level derived from all findings.
    pub threat_level: ThreatLevel,
    /// Human-readable summary of each finding.
    pub findings: Vec<String>,
    /// Wall-clock time spent on the scan, in milliseconds.
    pub scan_time_ms: u64,
}

/// A process that appears to be hidden from `/proc` enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenProcess {
    /// The numeric process ID.
    pub pid: u32,
    /// How the hidden process was detected.
    pub detection_method: String,
}

/// A kernel module flagged as suspicious.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousModule {
    /// Module name as reported in `/proc/modules`.
    pub name: String,
    /// Why this module was flagged.
    pub reason: String,
}

/// An anomaly detected in the `/proc` filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcAnomaly {
    /// Filesystem path where the anomaly was observed.
    pub path: String,
    /// Description of the anomaly.
    pub description: String,
}

/// Suspicious keywords that indicate a rootkit-like kernel module name.
const SUSPICIOUS_MODULE_KEYWORDS: &[&str] = &[
    "rootkit",
    "backdoor",
    "hide",
    "stealth",
    "invisible",
    "diamorphine",
    "reptile",
    "suterusu",
    "knark",
    "adore",
];

/// Perform a full rootkit scan and return aggregated results.
#[allow(clippy::cast_possible_truncation)] // Scan durations will never exceed u64::MAX ms
pub fn scan_rootkit() -> RootkitScanResult {
    let start = std::time::Instant::now();
    let mut findings = Vec::new();

    let hidden_processes = detect_hidden_processes();
    for hp in &hidden_processes {
        findings.push(format!(
            "Hidden process PID {} detected via {}",
            hp.pid, hp.detection_method
        ));
    }

    let suspicious_modules = check_kernel_modules();
    for sm in &suspicious_modules {
        findings.push(format!("Suspicious kernel module '{}': {}", sm.name, sm.reason));
    }

    let ld_preload_hijack = check_ld_preload();
    if let Some(ref detail) = ld_preload_hijack {
        findings.push(format!("LD_PRELOAD hijack detected: {detail}"));
    }

    let proc_anomalies = check_proc_anomalies();
    for pa in &proc_anomalies {
        findings.push(format!("{}: {}", pa.path, pa.description));
    }

    // Determine overall threat level.
    let threat_level = aggregate_threat_level(
        &hidden_processes,
        &suspicious_modules,
        ld_preload_hijack.as_ref(),
        &proc_anomalies,
    );

    let scan_time_ms = start.elapsed().as_millis() as u64;

    RootkitScanResult {
        hidden_processes,
        suspicious_modules,
        ld_preload_hijack,
        proc_anomalies,
        threat_level,
        findings,
        scan_time_ms,
    }
}

/// Detect hidden processes by comparing `/proc` enumeration with `kill(pid, 0)` probing.
///
/// A process that responds to `kill(pid, 0)` but has no corresponding `/proc/{pid}`
/// directory is potentially hidden by a rootkit.
fn detect_hidden_processes() -> Vec<HiddenProcess> {
    let mut hidden = Vec::new();

    // Read max PID from /proc/sys/kernel/pid_max (default 32768 or 4194304).
    let max_pid = read_max_pid().unwrap_or(32768);
    // Cap the scan range to avoid excessive iteration.
    let scan_limit = max_pid.min(65536);

    // Collect PIDs visible in /proc.
    let Ok(visible_pids) = list_proc_pids() else {
        return hidden;
    };

    // For each PID in range, check if it exists via kill(0) but is missing from /proc.
    for pid in 1..=scan_limit {
        // Skip PIDs that are visible in /proc.
        if visible_pids.contains(&pid) {
            continue;
        }

        // Check if the process exists via kill(pid, 0).
        // SAFETY: kill with signal 0 does not send a signal; it only checks existence.
        // The cast to i32 is safe because pid_max is capped at 65536.
        #[allow(clippy::cast_possible_wrap)]
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            // Process exists but is not visible in /proc.
            let proc_path = format!("/proc/{pid}");
            if !Path::new(&proc_path).exists() {
                hidden.push(HiddenProcess {
                    pid,
                    detection_method: "kill(pid,0) succeeded but /proc entry missing".to_string(),
                });
            }
        }
    }

    hidden
}

/// Read the maximum PID value from the kernel.
fn read_max_pid() -> Option<u32> {
    let content = fs::read_to_string("/proc/sys/kernel/pid_max").ok()?;
    content.trim().parse().ok()
}

/// List all numeric (PID) entries in `/proc`.
fn list_proc_pids() -> std::io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    Ok(pids)
}

/// Check kernel modules for suspicious characteristics.
fn check_kernel_modules() -> Vec<SuspiciousModule> {
    let mut suspicious = Vec::new();

    // Parse /proc/modules.
    let Ok(modules_content) = fs::read_to_string("/proc/modules") else {
        return suspicious;
    };

    for line in modules_content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(module_name) = fields.first() else {
            continue;
        };

        // Check for suspicious keywords in module name.
        let lower_name = module_name.to_lowercase();
        for keyword in SUSPICIOUS_MODULE_KEYWORDS {
            if lower_name.contains(keyword) {
                suspicious.push(SuspiciousModule {
                    name: (*module_name).to_string(),
                    reason: format!("module name contains suspicious keyword '{keyword}'"),
                });
                break;
            }
        }

        // Check taint flags: [OE] means out-of-tree + unsigned.
        // The taint column is typically the last field in /proc/modules.
        if let Some(taint_field) = fields.last() {
            if taint_field.contains('O') && taint_field.contains('E') {
                // Only flag if not already flagged by keyword.
                let already_flagged = suspicious.iter().any(|s| s.name == *module_name);
                if !already_flagged {
                    suspicious.push(SuspiciousModule {
                        name: (*module_name).to_string(),
                        reason: "module is out-of-tree and unsigned (taint flags OE)".to_string(),
                    });
                }
            }
        }
    }

    // Check kernel taint status.
    if let Ok(taint_str) = fs::read_to_string("/proc/sys/kernel/tainted") {
        if let Ok(taint_val) = taint_str.trim().parse::<u64>() {
            if taint_val != 0 {
                suspicious.push(SuspiciousModule {
                    name: "<kernel>".to_string(),
                    reason: format!("kernel is tainted (value {taint_val}), may indicate unsigned/out-of-tree modules"),
                });
            }
        }
    }

    suspicious
}

/// Check for `LD_PRELOAD` hijacking indicators.
fn check_ld_preload() -> Option<String> {
    // 1. Check /etc/ld.so.preload.
    if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Some(format!("/etc/ld.so.preload contains: {trimmed}"));
        }
    }

    // 2. Check LD_PRELOAD environment variable.
    if let Ok(val) = std::env::var("LD_PRELOAD") {
        if !val.is_empty() {
            return Some(format!("LD_PRELOAD environment variable set: {val}"));
        }
    }

    // 3. Check /proc/self/maps for suspicious preloaded libraries.
    if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let lower = line.to_lowercase();
            if lower.contains("preload") || lower.contains("inject") || lower.contains("hook") {
                return Some(format!("suspicious library in process maps: {line}"));
            }
        }
    }

    None
}

/// Detect anomalies in the `/proc` filesystem that may indicate rootkit activity.
fn check_proc_anomalies() -> Vec<ProcAnomaly> {
    let mut anomalies = Vec::new();

    // 1. Check if /proc/net/tcp is readable (rootkits may hide connections).
    if fs::read_to_string("/proc/net/tcp").is_err() {
        anomalies.push(ProcAnomaly {
            path: "/proc/net/tcp".to_string(),
            description: "unable to read /proc/net/tcp — network connections may be hidden".to_string(),
        });
    }

    // 2. Check /proc/kallsyms — if empty or inaccessible, may indicate rootkit.
    match fs::read_to_string("/proc/kallsyms") {
        Ok(content) => {
            // On systems with kptr_restrict, all addresses will be zeroed out,
            // but the file should still have content.
            if content.trim().is_empty() {
                anomalies.push(ProcAnomaly {
                    path: "/proc/kallsyms".to_string(),
                    description: "kernel symbol table is empty — possible rootkit manipulation".to_string(),
                });
            }
        }
        Err(_) => {
            anomalies.push(ProcAnomaly {
                path: "/proc/kallsyms".to_string(),
                description: "unable to read kernel symbol table".to_string(),
            });
        }
    }

    // 3. Check for deleted but running binaries in /proc/*/exe.
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            // Only check numeric (PID) directories.
            if name_str.parse::<u32>().is_err() {
                continue;
            }
            let exe_path = format!("/proc/{name_str}/exe");
            if let Ok(target) = fs::read_link(&exe_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("(deleted)") {
                    anomalies.push(ProcAnomaly {
                        path: exe_path,
                        description: format!("process running from deleted binary: {target_str}"),
                    });
                }
            }
        }
    }

    // 4. Check /proc/sys/kernel/modules_disabled.
    if let Ok(val) = fs::read_to_string("/proc/sys/kernel/modules_disabled") {
        if val.trim() == "0" {
            // modules_disabled=0 means new modules can still be loaded.
            // This is normal on most systems but noteworthy in a hardened environment.
            // We only flag this as informational — not suspicious on its own.
        }
    }

    anomalies
}

/// Determine the overall threat level based on all findings.
fn aggregate_threat_level(
    hidden_processes: &[HiddenProcess],
    suspicious_modules: &[SuspiciousModule],
    ld_preload: Option<&String>,
    proc_anomalies: &[ProcAnomaly],
) -> ThreatLevel {
    // Hidden processes are a strong rootkit indicator.
    if !hidden_processes.is_empty() {
        return ThreatLevel::Malicious;
    }

    // Modules with rootkit-like names are a strong indicator.
    let has_rootkit_module = suspicious_modules.iter().any(|m| {
        let lower = m.name.to_lowercase();
        SUSPICIOUS_MODULE_KEYWORDS.iter().any(|kw| lower.contains(kw))
    });
    if has_rootkit_module {
        return ThreatLevel::Malicious;
    }

    // LD_PRELOAD hijack or proc anomalies are suspicious.
    if ld_preload.is_some() || !proc_anomalies.is_empty() {
        return ThreatLevel::Suspicious;
    }

    // Tainted kernel alone is suspicious (but not malicious).
    if !suspicious_modules.is_empty() {
        return ThreatLevel::Suspicious;
    }

    ThreatLevel::Clean
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    /// Parse `/proc/modules` content into a list of (name, `taint_flags`) pairs.
    fn parse_proc_modules(content: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                continue;
            }
            let name = fields[0].to_string();
            let taint = fields.last().unwrap_or(&"").to_string();
            result.push((name, taint));
        }
        result
    }
    use super::*;

    #[test]
    fn test_parse_proc_modules_basic() {
        let content = "ext4 786432 1 - Live 0xffffffffc0800000 (E)\n\
                        btrfs 1650688 1 - Live 0xffffffffc0600000\n\
                        rootkit_mod 4096 0 - Live 0xffffffffc0500000 (OE)";

        let modules = parse_proc_modules(content);
        assert_eq!(modules.len(), 3);
        assert_eq!(modules[0].0, "ext4");
        assert_eq!(modules[0].1, "(E)");
        assert_eq!(modules[2].0, "rootkit_mod");
        assert_eq!(modules[2].1, "(OE)");
    }

    #[test]
    fn test_parse_proc_modules_empty() {
        let modules = parse_proc_modules("");
        assert!(modules.is_empty());
    }

    #[test]
    fn test_ld_preload_detection_env_var() {
        // Save and restore LD_PRELOAD.
        let original = std::env::var("LD_PRELOAD").ok();

        std::env::set_var("LD_PRELOAD", "/tmp/evil.so");
        let result = check_ld_preload();
        assert!(result.is_some());
        let msg = result.expect("expected Some");
        assert!(msg.contains("/tmp/evil.so"));

        // Restore.
        match original {
            Some(v) => std::env::set_var("LD_PRELOAD", v),
            None => std::env::remove_var("LD_PRELOAD"),
        }
    }

    #[test]
    fn test_aggregate_threat_level_clean() {
        let level = aggregate_threat_level(&[], &[], None, &[]);
        assert_eq!(level, ThreatLevel::Clean);
    }

    #[test]
    fn test_aggregate_threat_level_hidden_process() {
        let hidden = vec![HiddenProcess {
            pid: 1234,
            detection_method: "test".to_string(),
        }];
        let level = aggregate_threat_level(&hidden, &[], None, &[]);
        assert_eq!(level, ThreatLevel::Malicious);
    }

    #[test]
    fn test_aggregate_threat_level_rootkit_module() {
        let modules = vec![SuspiciousModule {
            name: "diamorphine".to_string(),
            reason: "contains suspicious keyword".to_string(),
        }];
        let level = aggregate_threat_level(&[], &modules, None, &[]);
        assert_eq!(level, ThreatLevel::Malicious);
    }

    #[test]
    fn test_aggregate_threat_level_ld_preload() {
        let preload = "LD_PRELOAD=/tmp/evil.so".to_string();
        let level = aggregate_threat_level(&[], &[], Some(&preload), &[]);
        assert_eq!(level, ThreatLevel::Suspicious);
    }

    #[test]
    fn test_aggregate_threat_level_proc_anomaly() {
        let anomalies = vec![ProcAnomaly {
            path: "/proc/kallsyms".to_string(),
            description: "empty".to_string(),
        }];
        let level = aggregate_threat_level(&[], &[], None, &anomalies);
        assert_eq!(level, ThreatLevel::Suspicious);
    }

    #[test]
    fn test_aggregate_threat_level_tainted_kernel() {
        let modules = vec![SuspiciousModule {
            name: "<kernel>".to_string(),
            reason: "kernel is tainted".to_string(),
        }];
        let level = aggregate_threat_level(&[], &modules, None, &[]);
        assert_eq!(level, ThreatLevel::Suspicious);
    }
}
