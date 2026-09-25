//! Cross-platform process utilities for remediation.
//!
//! Provides functions for finding processes that have a specific file open,
//! with platform-specific implementations under the hood.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Information about a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
}

/// Find all processes that have the given file path open.
///
/// On Linux, this reads `/proc/*/fd/` symlinks and `/proc/*/maps`.
/// On macOS, this invokes the `lsof` command.
/// On Windows, this is a stub that returns an empty list.
pub fn find_processes_using_file(path: &Path) -> Result<Vec<ProcessInfo>> {
    #[cfg(target_os = "linux")]
    {
        find_processes_linux(path)
    }
    #[cfg(target_os = "macos")]
    {
        find_processes_macos(path)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = path;
        Ok(Vec::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = path;
        Ok(Vec::new())
    }
}

/// Linux implementation: scan `/proc/*/fd/` and `/proc/*/maps` for references to the file.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn find_processes_linux(path: &Path) -> Result<Vec<ProcessInfo>> {
    use std::fs;

    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let target_str = target.to_string_lossy();
    let mut results: Vec<ProcessInfo> = Vec::new();
    let mut seen_pids = std::collections::HashSet::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("failed to read /proc: {e}");
            return Ok(Vec::new());
        }
    };

    for entry in proc_dir {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        // Check /proc/<pid>/fd/ for symlinks pointing to the target file.
        let fd_dir = format!("/proc/{pid}/fd");
        let mut found = false;

        if let Ok(fds) = fs::read_dir(&fd_dir) {
            for fd_entry in fds {
                let Ok(fd_entry) = fd_entry else {
                    continue;
                };
                if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                    if link_target == target {
                        found = true;
                        break;
                    }
                }
            }
        }

        // Check /proc/<pid>/maps for memory-mapped references.
        if !found {
            let maps_path = format!("/proc/{pid}/maps");
            if let Ok(maps_content) = fs::read_to_string(&maps_path) {
                if maps_content.contains(target_str.as_ref()) {
                    found = true;
                }
            }
        }

        if found && seen_pids.insert(pid) {
            let proc_name = fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .to_string();
            let status_content = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let user = status_content
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("unknown")
                .to_string();

            results.push(ProcessInfo {
                pid,
                name: proc_name,
                cmdline,
                user,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_info_struct_creation() {
        let info = ProcessInfo {
            pid: 12345,
            name: "test_process".to_string(),
            cmdline: "/usr/bin/test_process --flag".to_string(),
            user: "root".to_string(),
        };
        assert_eq!(info.pid, 12345);
        assert_eq!(info.name, "test_process");
        assert_eq!(info.cmdline, "/usr/bin/test_process --flag");
        assert_eq!(info.user, "root");
    }

    #[test]
    fn process_info_clone() {
        let info = ProcessInfo {
            pid: 999,
            name: "daemon".to_string(),
            cmdline: "/usr/sbin/daemon".to_string(),
            user: "nobody".to_string(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.pid, info.pid);
        assert_eq!(cloned.name, info.name);
        assert_eq!(cloned.cmdline, info.cmdline);
        assert_eq!(cloned.user, info.user);
    }

    #[test]
    fn process_info_serialization_roundtrip() {
        let info = ProcessInfo {
            pid: 42,
            name: "evil".to_string(),
            cmdline: "./evil --payload".to_string(),
            user: "attacker".to_string(),
        };
        let json = serde_json::to_string(&info).expect("serialize");
        let deserialized: ProcessInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.pid, info.pid);
        assert_eq!(deserialized.name, info.name);
        assert_eq!(deserialized.cmdline, info.cmdline);
        assert_eq!(deserialized.user, info.user);
    }

    #[test]
    fn find_processes_using_nonexistent_file_returns_empty() {
        let result = find_processes_using_file(Path::new("/nonexistent/file/that/does/not/exist.bin"));
        // Should not error, just return empty (or possibly empty on this platform)
        assert!(result.is_ok());
        assert!(result.expect("result").is_empty());
    }
}

/// macOS implementation: use `lsof` to find processes using the file.
#[cfg(target_os = "macos")]
fn find_processes_macos(path: &Path) -> Result<Vec<ProcessInfo>> {
    use std::process::Command;

    let output = Command::new("lsof").arg("-t").arg("-F").arg("pcun").arg(path).output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("failed to run lsof: {}", e);
            return Ok(Vec::new());
        }
    };

    if !output.status.success() {
        // lsof returns non-zero when no processes found
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();
    let mut current_pid: Option<u32> = None;
    let mut current_name = String::new();
    let mut current_user = String::new();
    let mut current_cmdline = String::new();

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let (prefix, value) = line.split_at(1);
        match prefix {
            "p" => {
                // Flush previous entry
                if let Some(pid) = current_pid {
                    results.push(ProcessInfo {
                        pid,
                        name: std::mem::take(&mut current_name),
                        cmdline: std::mem::take(&mut current_cmdline),
                        user: std::mem::take(&mut current_user),
                    });
                }
                current_pid = value.parse().ok();
            }
            "c" => {
                current_name = value.to_string();
                current_cmdline = value.to_string();
            }
            "u" => {
                current_user = value.to_string();
            }
            _ => {}
        }
    }

    // Flush last entry
    if let Some(pid) = current_pid {
        results.push(ProcessInfo {
            pid,
            name: current_name,
            cmdline: current_cmdline,
            user: current_user,
        });
    }

    Ok(results)
}
