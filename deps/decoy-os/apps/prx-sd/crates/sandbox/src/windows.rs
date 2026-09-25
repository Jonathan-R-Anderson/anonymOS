//! Windows sandbox implementation using Job Objects and Restricted Tokens.
//!
//! This module provides the structure for Windows-based sandboxing. The full
//! implementation is planned but not yet available. When complete, it will use:
//!
//! - **Job Objects**: CPU, memory, and process count limits
//! - **Restricted Tokens**: Remove admin privileges and dangerous rights
//! - **ETW (Event Tracing for Windows)**: Syscall-level monitoring

use std::path::Path;

use anyhow::Result;

use crate::{SandboxConfig, SandboxResult};

/// Windows sandbox using Job Objects and Restricted Tokens.
pub struct WindowsSandbox {
    #[allow(dead_code)]
    config: SandboxConfig,
}

impl WindowsSandbox {
    /// Create a new Windows sandbox with the given configuration.
    pub fn new(config: &SandboxConfig) -> Self {
        Self { config: config.clone() }
    }

    /// Execute a command in the Windows sandbox.
    ///
    /// Currently returns an error as the Windows implementation is not yet
    /// complete. The planned implementation will:
    /// 1. `CreateRestrictedToken` (remove admin, dangerous privileges)
    /// 2. `CreateJobObject` with limits (CPU, memory, process count)
    /// 3. `CreateProcessAsUser` with the restricted token inside the job
    /// 4. Monitor via ETW (Event Tracing for Windows) for syscall tracing
    /// 5. Wait with timeout, then collect results
    pub async fn execute(&self, _cmd: &Path, _args: &[&str]) -> Result<SandboxResult> {
        anyhow::bail!(
            "Windows sandbox is not yet implemented. \
             Planned: Job Objects + Restricted Tokens + ETW tracing"
        )
    }
}
