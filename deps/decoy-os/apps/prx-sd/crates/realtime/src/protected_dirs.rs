//! Protected directory enforcement.
//!
//! Prevents unauthorized processes from modifying security-sensitive paths
//! such as `~/.ssh`, `/etc/shadow`, `/etc/systemd`, etc. Uses a whitelist
//! of allowed process names/paths.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Configuration for protected directory enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedDirsConfig {
    /// Directories to protect from unauthorized modification.
    pub protected_paths: Vec<PathBuf>,
    /// Process names (from /proc/pid/comm) allowed to modify protected dirs.
    pub allowed_processes: HashSet<String>,
    /// Full binary paths allowed to modify protected dirs.
    pub allowed_binaries: HashSet<PathBuf>,
    /// Whether enforcement is active.
    pub enabled: bool,
}

/// Platform-specific default protected paths.
fn default_protected_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![
            // SSH keys and config
            PathBuf::from("/root/.ssh"),
            PathBuf::from("/home"), // will match /home/*/.ssh via starts_with
            // System authentication
            PathBuf::from("/etc/shadow"),
            PathBuf::from("/etc/passwd"),
            PathBuf::from("/etc/sudoers"),
            PathBuf::from("/etc/sudoers.d"),
            // Systemd services
            PathBuf::from("/etc/systemd"),
            PathBuf::from("/usr/lib/systemd"),
            // Cron
            PathBuf::from("/etc/cron.d"),
            PathBuf::from("/etc/crontab"),
            PathBuf::from("/var/spool/cron"),
            // Init scripts
            PathBuf::from("/etc/init.d"),
            PathBuf::from("/etc/rc.local"),
            // PAM
            PathBuf::from("/etc/pam.d"),
            // DNS
            PathBuf::from("/etc/resolv.conf"),
            // Hosts
            PathBuf::from("/etc/hosts"),
            // LD preload
            PathBuf::from("/etc/ld.so.preload"),
            PathBuf::from("/etc/ld.so.conf"),
            PathBuf::from("/etc/ld.so.conf.d"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/Users"), // match /Users/*/.ssh
            PathBuf::from("/var/root/.ssh"),
            PathBuf::from("/etc/passwd"),
            PathBuf::from("/etc/sudoers"),
            PathBuf::from("/etc/sudoers.d"),
            PathBuf::from("/etc/pam.d"),
            PathBuf::from("/etc/hosts"),
            PathBuf::from("/etc/resolv.conf"),
            PathBuf::from("/Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchDaemons"),
            PathBuf::from("/System/Library/LaunchAgents"),
            PathBuf::from("/System/Library/LaunchDaemons"),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
            PathBuf::from(r"C:\Windows\System32\config"),
        ]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        vec![PathBuf::from("/etc/hosts"), PathBuf::from("/etc/passwd")]
    }
}

impl Default for ProtectedDirsConfig {
    fn default() -> Self {
        Self {
            protected_paths: default_protected_paths(),
            allowed_processes: HashSet::from([
                "sshd".to_string(),
                "ssh-keygen".to_string(),
                "systemctl".to_string(),
                "systemd".to_string(),
                "useradd".to_string(),
                "usermod".to_string(),
                "passwd".to_string(),
                "chpasswd".to_string(),
                "crontab".to_string(),
                "visudo".to_string(),
                "apt".to_string(),
                "dpkg".to_string(),
                "yum".to_string(),
                "dnf".to_string(),
                "pacman".to_string(),
                "vim".to_string(),
                "nano".to_string(),
                "vi".to_string(),
                "sd".to_string(),
            ]),
            allowed_binaries: HashSet::new(),
            enabled: true,
        }
    }
}

/// Verdict from checking a file modification against protected dirs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionVerdict {
    /// Path is not protected or process is allowed.
    Allowed,
    /// Path is protected and process is NOT in the whitelist.
    Blocked {
        path: PathBuf,
        pid: u32,
        process_name: String,
        reason: String,
    },
}

/// Enforces protection rules on security-sensitive directories.
pub struct ProtectedDirsEnforcer {
    config: ProtectedDirsConfig,
}

impl ProtectedDirsEnforcer {
    /// Create a new enforcer with the given config.
    pub const fn new(config: ProtectedDirsConfig) -> Self {
        Self { config }
    }

    /// Check if a file modification should be allowed.
    ///
    /// `path` is the file being modified. `pid` is the process making the change.
    /// Returns `Blocked` if the path is protected and the process is not whitelisted.
    pub fn check_access(&self, path: &Path, pid: u32) -> ProtectionVerdict {
        if !self.config.enabled {
            return ProtectionVerdict::Allowed;
        }

        // Check if path is under a protected directory.
        let is_protected = self
            .config
            .protected_paths
            .iter()
            .any(|protected| path.starts_with(protected));

        if !is_protected {
            return ProtectionVerdict::Allowed;
        }

        // Check SSH-specific: only protect .ssh subdirectories, not all of /home or /Users
        let path_str = path.to_string_lossy();
        let is_ssh_path = path_str.contains("/.ssh/") || path_str.ends_with("/.ssh");
        let is_home_path = path.starts_with("/home") || path.starts_with("/Users");

        // /home (Linux) and /Users (macOS) are in protected_paths as a catch-all for .ssh —
        // only block if it's actually .ssh
        if is_home_path && !is_ssh_path {
            return ProtectionVerdict::Allowed;
        }

        // Get process info.
        let process_name = process_name_from_pid(pid);

        // Check process name whitelist.
        if self.config.allowed_processes.contains(&process_name) {
            return ProtectionVerdict::Allowed;
        }

        // Check binary path whitelist.
        let binary_path = process_binary_from_pid(pid);
        if let Some(bin) = &binary_path {
            if self.config.allowed_binaries.contains(bin) {
                return ProtectionVerdict::Allowed;
            }
        }

        let matched_dir = self
            .config
            .protected_paths
            .iter()
            .find(|p| path.starts_with(p))
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        ProtectionVerdict::Blocked {
            path: path.to_path_buf(),
            pid,
            process_name: process_name.clone(),
            reason: format!(
                "process '{}' (pid {}) attempted to modify protected path {} (under {})",
                process_name,
                pid,
                path.display(),
                matched_dir
            ),
        }
    }

    /// Add a process name to the whitelist.
    pub fn allow_process(&mut self, name: &str) {
        self.config.allowed_processes.insert(name.to_string());
    }

    /// Add a binary path to the whitelist.
    pub fn allow_binary(&mut self, path: PathBuf) {
        self.config.allowed_binaries.insert(path);
    }

    /// Check if a specific path is protected.
    pub fn is_protected(&self, path: &Path) -> bool {
        if !self.config.enabled {
            return false;
        }
        let path_str = path.to_string_lossy();
        self.config.protected_paths.iter().any(|protected| {
            if path.starts_with(protected) {
                // Special case for /home (Linux) and /Users (macOS) — only .ssh
                if protected == Path::new("/home") || protected == Path::new("/Users") {
                    path_str.contains("/.ssh/") || path_str.ends_with("/.ssh")
                } else {
                    true
                }
            } else {
                false
            }
        })
    }
}

/// Read process name from the OS.
///
/// - Linux: reads `/proc/{pid}/comm`
/// - macOS: reads `/proc/{pid}/comm` (procfs compatibility) or falls back
/// - Windows/other: returns `"pid:{pid}"` placeholder
fn process_name_from_pid(pid: u32) -> String {
    // Try /proc first (Linux, some macOS setups with procfs)
    if let Ok(name) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        return name.trim().to_string();
    }

    // macOS fallback: use ps command
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }

    format!("pid:{pid}")
}

/// Read process binary path from the OS.
///
/// - Linux: reads `/proc/{pid}/exe` symlink
/// - macOS: falls back to `ps` command
/// - Windows/other: returns `None`
fn process_binary_from_pid(pid: u32) -> Option<PathBuf> {
    // Try /proc first (Linux)
    if let Ok(path) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        return Some(path);
    }

    // macOS fallback
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ProtectedDirsConfig {
        ProtectedDirsConfig {
            protected_paths: vec![
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/systemd"),
                PathBuf::from("/home"),
            ],
            allowed_processes: HashSet::from(["systemctl".to_string(), "passwd".to_string()]),
            allowed_binaries: HashSet::new(),
            enabled: true,
        }
    }

    #[test]
    fn test_unprotected_path_allowed() {
        let enforcer = ProtectedDirsEnforcer::new(test_config());
        let verdict = enforcer.check_access(Path::new("/tmp/file.txt"), 1234);
        assert_eq!(verdict, ProtectionVerdict::Allowed);
    }

    #[test]
    fn test_home_non_ssh_allowed() {
        let enforcer = ProtectedDirsEnforcer::new(test_config());
        let verdict = enforcer.check_access(Path::new("/home/user/documents/file.txt"), 1234);
        assert_eq!(verdict, ProtectionVerdict::Allowed);
    }

    #[test]
    fn test_home_ssh_blocked_for_unknown_process() {
        let enforcer = ProtectedDirsEnforcer::new(test_config());
        // PID 99999 likely doesn't exist, so process_name will be "pid:99999"
        let verdict = enforcer.check_access(Path::new("/home/user/.ssh/authorized_keys"), 99999);
        assert!(matches!(verdict, ProtectionVerdict::Blocked { .. }));
    }

    #[test]
    fn test_disabled_allows_all() {
        let mut config = test_config();
        config.enabled = false;
        let enforcer = ProtectedDirsEnforcer::new(config);
        let verdict = enforcer.check_access(Path::new("/etc/shadow"), 99999);
        assert_eq!(verdict, ProtectionVerdict::Allowed);
    }

    #[test]
    fn test_is_protected() {
        let enforcer = ProtectedDirsEnforcer::new(test_config());
        assert!(enforcer.is_protected(Path::new("/etc/shadow")));
        assert!(enforcer.is_protected(Path::new("/etc/systemd/system/foo.service")));
        assert!(enforcer.is_protected(Path::new("/home/user/.ssh/id_rsa")));
        assert!(!enforcer.is_protected(Path::new("/home/user/file.txt")));
        assert!(!enforcer.is_protected(Path::new("/tmp/file")));
    }

    #[test]
    fn test_allow_process() {
        let mut enforcer = ProtectedDirsEnforcer::new(test_config());
        enforcer.allow_process("my_tool");
        // Can't easily test with real PIDs, but the insertion should work.
        assert!(enforcer.config.allowed_processes.contains("my_tool"));
    }
}
