//! Linux-specific sandbox implementation.
//!
//! Combines multiple Linux security mechanisms:
//! - **Seccomp BPF**: System call filtering
//! - **Landlock LSM**: File system access restriction
//! - **Ptrace**: System call tracing for behavioral analysis
//! - **Namespaces**: Process, mount, network, and user isolation

pub mod landlock;
pub mod namespace;
pub mod seccomp;
pub mod tracer;

pub use landlock::LandlockSandbox;
pub use seccomp::SeccompFilter;
pub use tracer::{PtraceTracer, SyscallEvent};

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::{
    FileOpType, FileOperation, NetworkAttempt, ProcessOpType, ProcessOperation, SandboxConfig, SandboxResult,
    SandboxVerdict,
};

/// Execute a file in the Linux sandbox with ptrace-based syscall tracing.
///
/// This is the primary Linux execution path. It:
/// 1. Forks a child process.
/// 2. In the child: applies seccomp BPF filters and Landlock rules, then exec's the target.
/// 3. In the parent: traces all system calls via ptrace until the child exits or timeout.
/// 4. Converts raw syscall events into structured operation records.
pub fn execute(config: &SandboxConfig, path: &Path, args: &[&str]) -> Result<SandboxResult> {
    let timeout = Duration::from_secs(config.timeout_secs);
    let start = std::time::Instant::now();

    // Trace the child process.
    let syscalls = PtraceTracer::trace_child(path, args, timeout)?;

    let elapsed = start.elapsed();

    // Analyze the syscall trace into structured operations.
    let mut file_operations = Vec::new();
    let mut network_attempts = Vec::new();
    let mut process_operations = Vec::new();
    let mut exit_code: i32 = -1;
    let mut saw_exit = false;

    for event in &syscalls {
        match event.name.as_str() {
            // File read operations.
            "open" | "openat" => {
                file_operations.push(FileOperation {
                    op: FileOpType::Read,
                    path: format!("<fd from {}>", event.name),
                    blocked: false,
                });
            }
            // File creation.
            "creat" | "mkdir" => {
                file_operations.push(FileOperation {
                    op: FileOpType::Create,
                    path: format!("<created via {}>", event.name),
                    blocked: false,
                });
            }
            // File deletion.
            "unlink" | "rmdir" => {
                file_operations.push(FileOperation {
                    op: FileOpType::Delete,
                    path: format!("<deleted via {}>", event.name),
                    blocked: false,
                });
            }
            // File rename (could be overwrite).
            "rename" => {
                file_operations.push(FileOperation {
                    op: FileOpType::Write,
                    path: format!("<renamed via {}>", event.name),
                    blocked: false,
                });
            }
            // Permission changes.
            "chmod" | "chown" => {
                file_operations.push(FileOperation {
                    op: FileOpType::Chmod,
                    path: format!("<{}>", event.name),
                    blocked: false,
                });
            }
            // Network operations.
            "socket" => {
                network_attempts.push(NetworkAttempt {
                    address: String::new(),
                    port: 0,
                    protocol: "unknown".into(),
                    blocked: !config.network_allowed,
                });
            }
            "connect" => {
                network_attempts.push(NetworkAttempt {
                    address: "unknown".into(),
                    port: 0,
                    protocol: "tcp".into(),
                    blocked: !config.network_allowed,
                });
            }
            // Process operations.
            "fork" | "vfork" | "clone" => {
                process_operations.push(ProcessOperation {
                    op: ProcessOpType::Fork,
                    target: event.name.clone(),
                });
            }
            "execve" => {
                process_operations.push(ProcessOperation {
                    op: ProcessOpType::Exec,
                    target: "unknown".into(),
                });
            }
            "kill" => {
                process_operations.push(ProcessOperation {
                    op: ProcessOpType::Kill,
                    target: "signal via kill()".to_string(),
                });
            }
            "ptrace" => {
                process_operations.push(ProcessOperation {
                    op: ProcessOpType::Ptrace,
                    target: "ptrace syscall".into(),
                });
            }
            // Process exit.
            "exit" | "exit_group" => {
                saw_exit = true;
                #[allow(clippy::cast_possible_truncation)] // exit codes are i32 by convention
                {
                    exit_code = event.return_value as i32;
                }
            }
            _ => {}
        }
    }

    if !saw_exit {
        exit_code = -1;
    }

    Ok(SandboxResult {
        exit_code,
        syscalls,
        behaviors: Vec::new(),
        verdict: SandboxVerdict::Clean,
        threat_score: 0,
        network_attempts,
        file_operations,
        process_operations,
        #[allow(clippy::cast_possible_truncation)] // millis within u64 range for practical timeouts
        execution_time_ms: elapsed.as_millis() as u64,
    })
}
