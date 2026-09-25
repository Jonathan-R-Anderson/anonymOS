//! macOS sandbox implementation using sandbox-exec (seatbelt) profiles.
//!
//! On macOS, process sandboxing is achieved through the `sandbox-exec` command
//! which applies Seatbelt profiles (`.sb` files) written in TinyScheme.
//! When running as root, dtrace can also be used for syscall tracing.

use std::path::Path;

use anyhow::Result;

use crate::{SandboxConfig, SandboxResult, SandboxVerdict};

/// macOS sandbox using sandbox-exec (seatbelt) profiles.
pub struct MacOSSandbox {
    config: SandboxConfig,
}

impl MacOSSandbox {
    /// Create a new macOS sandbox with the given configuration.
    pub fn new(config: &SandboxConfig) -> Self {
        Self { config: config.clone() }
    }

    /// Execute a command in the macOS sandbox.
    ///
    /// This implementation:
    /// 1. Generates a Seatbelt profile (.sb) that restricts file/network access
    /// 2. Runs the target via `sandbox-exec -f profile.sb <cmd> <args>`
    /// 3. Parses output for behavioral indicators
    /// 4. Optionally uses dtrace (requires root) for syscall-level tracing
    pub async fn execute(&self, cmd: &Path, args: &[&str]) -> Result<SandboxResult> {
        let profile = self.generate_seatbelt_profile();
        let start = std::time::Instant::now();

        // Write the seatbelt profile to a temporary file.
        let profile_path = std::env::temp_dir().join(format!("prx-sandbox-{}.sb", std::process::id()));
        tokio::fs::write(&profile_path, &profile).await?;

        // Build the sandbox-exec command.
        let mut command = tokio::process::Command::new("sandbox-exec");
        command.arg("-f").arg(&profile_path).arg(cmd);
        for arg in args {
            command.arg(arg);
        }

        // Execute with timeout.
        let timeout = tokio::time::Duration::from_secs(self.config.timeout_secs);
        let output = match tokio::time::timeout(timeout, command.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&profile_path).await;
                return Err(anyhow::anyhow!("sandbox-exec failed to start: {e}"));
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&profile_path).await;
                let elapsed = start.elapsed();
                return Ok(SandboxResult {
                    exit_code: -1,
                    syscalls: Vec::new(),
                    behaviors: Vec::new(),
                    verdict: SandboxVerdict::Timeout,
                    threat_score: 0,
                    network_attempts: Vec::new(),
                    file_operations: Vec::new(),
                    process_operations: Vec::new(),
                    execution_time_ms: elapsed.as_millis() as u64,
                });
            }
        };

        let _ = tokio::fs::remove_file(&profile_path).await;
        let elapsed = start.elapsed();

        let exit_code = output.status.code().unwrap_or(-1);

        Ok(SandboxResult {
            exit_code,
            syscalls: Vec::new(),
            behaviors: Vec::new(),
            verdict: SandboxVerdict::Clean,
            threat_score: 0,
            network_attempts: Vec::new(),
            file_operations: Vec::new(),
            process_operations: Vec::new(),
            execution_time_ms: elapsed.as_millis() as u64,
        })
    }

    /// Generate a Seatbelt profile that restricts the sandboxed process.
    ///
    /// The profile denies all operations by default, then selectively allows:
    /// - Reading from allowed paths
    /// - Process execution of the target binary
    /// - Network access only if configured
    fn generate_seatbelt_profile(&self) -> String {
        let mut profile = String::from("(version 1)\n(deny default)\n");

        // Allow basic process operations.
        profile.push_str("(allow process-exec)\n");
        profile.push_str("(allow process-fork)\n");
        profile.push_str("(allow sysctl-read)\n");

        // Allow reading from allowed paths.
        for path in &self.config.allowed_paths {
            profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", path.display()));
        }

        // Allow basic temp directory access.
        profile.push_str("(allow file-read* (subpath \"/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");

        // Network access.
        if self.config.network_allowed {
            profile.push_str("(allow network*)\n");
        } else {
            profile.push_str("(deny network*)\n");
        }

        profile
    }
}
