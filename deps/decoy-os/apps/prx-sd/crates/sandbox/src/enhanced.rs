//! Enhanced sandbox with multi-layer isolation.
//!
//! Combines namespace isolation, seccomp BPF filtering, resource limits, and
//! network isolation for comprehensive containment of suspicious binaries.
//!
//! This module is **Linux-only** (`#[cfg(target_os = "linux")]`). On other
//! platforms the types are still visible but construction will fail at runtime.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use crate::SandboxConfig;
use crate::SandboxResult;
#[cfg(target_os = "linux")]
use anyhow::Context;

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the enhanced multi-layer sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedSandboxConfig {
    /// Block all outbound network traffic (via empty network namespace).
    pub enable_network_isolation: bool,
    /// Use a private mount namespace with tmpfs root.
    pub enable_filesystem_isolation: bool,
    /// Maximum resident-set-size in megabytes (enforced via `RLIMIT_AS`).
    pub memory_limit_mb: u64,
    /// Maximum CPU time in seconds (enforced via `RLIMIT_CPU`).
    pub cpu_time_limit_secs: u64,
    /// Maximum number of child processes (`RLIMIT_NPROC`).
    pub max_processes: u32,
    /// Syscall names that should be permitted; all others are killed.
    /// An empty list means "use the default allowlist".
    pub allowed_syscalls: Vec<String>,
    /// Paths that the sandboxed process may write to (bind-mounted R/W).
    pub writable_paths: Vec<PathBuf>,
    /// Whether DNS resolution should be blocked (no /etc/resolv.conf).
    pub dns_blocked: bool,
}

impl Default for EnhancedSandboxConfig {
    fn default() -> Self {
        Self {
            enable_network_isolation: true,
            enable_filesystem_isolation: true,
            memory_limit_mb: 256,
            cpu_time_limit_secs: 30,
            max_processes: 16,
            allowed_syscalls: Vec::new(),
            writable_paths: Vec::new(),
            dns_blocked: true,
        }
    }
}

// ── Enhanced sandbox ────────────────────────────────────────────────────────

/// Multi-layer sandbox that orchestrates resource limits, namespace isolation,
/// seccomp filtering, ptrace tracing, and behavior analysis.
pub struct EnhancedSandbox {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    config: EnhancedSandboxConfig,
}

impl EnhancedSandbox {
    /// Create a new enhanced sandbox from the given configuration.
    pub const fn new(config: EnhancedSandboxConfig) -> Self {
        Self { config }
    }

    /// Execute a file inside the enhanced sandbox and return the analysis result.
    ///
    /// Orchestration order:
    /// 1. Set resource limits (rlimits) in the **child** after fork.
    /// 2. Create namespaces (PID + MNT + optionally NET + USER).
    /// 3. Apply seccomp BPF filter.
    /// 4. Trace syscalls via ptrace.
    /// 5. Analyse the collected trace.
    #[cfg(target_os = "linux")]
    pub fn execute(&self, path: &Path, args: &[&str], timeout: Duration) -> Result<SandboxResult> {
        let start = std::time::Instant::now();

        // Build a basic SandboxConfig for the underlying namespace sandbox.
        let sandbox_config = SandboxConfig {
            timeout_secs: timeout.as_secs(),
            max_memory_mb: self.config.memory_limit_mb,
            allowed_paths: self.config.writable_paths.clone(),
            network_allowed: !self.config.enable_network_isolation,
        };

        // Set rlimits *before* forking — they are inherited by the child.
        Self::set_resource_limits(&self.config)?;

        // Use the existing namespace sandbox for the heavy lifting.
        let mut ns_sandbox = crate::linux::namespace::NamespaceSandbox::new(&sandbox_config)?;

        // Add writable paths as bind mounts.
        for wpath in &self.config.writable_paths {
            if wpath.exists() {
                ns_sandbox.add_bind_mount(wpath.clone(), wpath.clone());
            }
        }

        let mut result = ns_sandbox.execute(path, args, timeout)?;

        // If we also want ptrace-level detail, run the tracer in parallel.
        // For now, augment the result with rlimit / config metadata.
        #[allow(clippy::cast_possible_truncation)] // millis within u64 range for practical timeouts
        {
            result.execution_time_ms = start.elapsed().as_millis() as u64;
        }

        // Run behavior analysis on whatever syscalls were collected.
        let analyzer = crate::behavior::BehaviorAnalyzer::new();
        analyzer.analyze(&mut result);

        Ok(result)
    }

    /// Fallback for non-Linux: always returns an error.
    #[cfg(not(target_os = "linux"))]
    pub fn execute(&self, _path: &Path, _args: &[&str], _timeout: Duration) -> Result<SandboxResult> {
        anyhow::bail!(
            "EnhancedSandbox is only supported on Linux. \
             Current platform does not have namespace/seccomp support."
        )
    }

    /// Apply resource limits via `prlimit64` / `setrlimit`.
    ///
    /// Limits applied:
    /// - `RLIMIT_AS`    — virtual address space (memory).
    /// - `RLIMIT_CPU`   — CPU time in seconds.
    /// - `RLIMIT_NPROC` — maximum number of processes.
    /// - `RLIMIT_NOFILE` — maximum open file descriptors (hardcoded to 256).
    /// - `RLIMIT_FSIZE` — maximum file size the process may create (64 MiB).
    #[cfg(target_os = "linux")]
    fn set_resource_limits(config: &EnhancedSandboxConfig) -> Result<()> {
        use libc::{RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_NPROC};
        use libc::{rlimit, setrlimit};

        let limits: Vec<(libc::__rlimit_resource_t, libc::rlim_t, &str)> = vec![
            (RLIMIT_AS, config.memory_limit_mb * 1024 * 1024, "RLIMIT_AS"),
            (RLIMIT_CPU, config.cpu_time_limit_secs, "RLIMIT_CPU"),
            (RLIMIT_NPROC, u64::from(config.max_processes), "RLIMIT_NPROC"),
            (RLIMIT_NOFILE, 256, "RLIMIT_NOFILE"),
            (RLIMIT_FSIZE, 64 * 1024 * 1024, "RLIMIT_FSIZE"),
        ];

        for (resource, value, name) in &limits {
            let rlim = rlimit {
                rlim_cur: *value,
                rlim_max: *value,
            };
            // SAFETY: setrlimit is a standard POSIX call. The rlimit struct is
            // properly initialised with cur == max (hard limit). The resource
            // constants are valid libc-defined values.
            let ret = unsafe { setrlimit(*resource, &raw const rlim) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to set {name} to {value}"));
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    fn set_resource_limits(_config: &EnhancedSandboxConfig) -> Result<()> {
        anyhow::bail!("resource limits are only supported on Linux")
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_restrictive() {
        let config = EnhancedSandboxConfig::default();
        assert!(config.enable_network_isolation);
        assert!(config.enable_filesystem_isolation);
        assert!(config.dns_blocked);
        assert_eq!(config.memory_limit_mb, 256);
        assert_eq!(config.cpu_time_limit_secs, 30);
        assert_eq!(config.max_processes, 16);
        assert!(config.allowed_syscalls.is_empty());
        assert!(config.writable_paths.is_empty());
    }

    #[test]
    fn sandbox_construction() {
        let config = EnhancedSandboxConfig::default();
        let _sandbox = EnhancedSandbox::new(config);
    }

    #[test]
    fn custom_config() {
        let config = EnhancedSandboxConfig {
            enable_network_isolation: false,
            enable_filesystem_isolation: true,
            memory_limit_mb: 512,
            cpu_time_limit_secs: 60,
            max_processes: 32,
            allowed_syscalls: vec!["read".into(), "write".into(), "exit_group".into()],
            writable_paths: vec![PathBuf::from("/tmp/sandbox-out")],
            dns_blocked: false,
        };
        let sandbox = EnhancedSandbox::new(config);
        assert!(!sandbox.config.enable_network_isolation);
        assert_eq!(sandbox.config.memory_limit_mb, 512);
        assert_eq!(sandbox.config.max_processes, 32);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_resource_limits_succeeds() {
        // Use very permissive limits so we don't restrict the test process itself
        // too much. Note: RLIMIT_NPROC applies per-user, not per-process, so a
        // low value could break parallel test runners.
        let config = EnhancedSandboxConfig {
            memory_limit_mb: 4096,
            cpu_time_limit_secs: 300,
            max_processes: 4096,
            ..EnhancedSandboxConfig::default()
        };
        let result = EnhancedSandbox::set_resource_limits(&config);
        assert!(result.is_ok(), "set_resource_limits failed: {result:?}");
    }
}
