// This crate uses unsafe for Linux syscalls (seccomp-bpf, clone, ptrace,
// landlock, setrlimit). All unsafe blocks have SAFETY comments.
#![allow(unsafe_code)]

//! Sandbox execution environment for the prx-sd antivirus engine.
//!
//! Provides multi-platform behavioral analysis of suspicious files by
//! executing them in a restricted environment with system call tracing
//! and behavior-based threat detection.
//!
//! ## Platform support
//!
//! - **Linux**: Full support via seccomp BPF, Landlock LSM, ptrace tracing,
//!   and namespace isolation (PID, MNT, NET, USER).
//! - **macOS**: Sandbox-exec (Seatbelt) profiles with optional dtrace tracing.
//! - **Windows**: Planned support via Job Objects, Restricted Tokens, and ETW.
//!
//! ## Architecture
//!
//! The [`Sandbox`] struct provides a platform-agnostic interface. Internally it
//! delegates to the appropriate platform module. After execution, the
//! [`BehaviorAnalyzer`](behavior::BehaviorAnalyzer) evaluates the collected
//! operations against a set of threat detection rules to produce a verdict.

pub mod anti_sandbox;
pub mod behavior;
pub mod enhanced;
pub mod yara_gen;

pub use yara_gen::{GeneratedRule, generate_rules};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::{LandlockSandbox, PtraceTracer, SeccompFilter, SyscallEvent};

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::behavior::BehaviorAnalyzer;

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the sandbox execution environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum execution time in seconds before the process is killed.
    pub timeout_secs: u64,
    /// Maximum memory usage in megabytes (enforced via rlimits).
    pub max_memory_mb: u64,
    /// Paths the sandboxed process is allowed to access.
    pub allowed_paths: Vec<PathBuf>,
    /// Whether network access is permitted.
    pub network_allowed: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_memory_mb: 256,
            allowed_paths: Vec::new(),
            network_allowed: false,
        }
    }
}

// ── Threat categories ───────────────────────────────────────────────────────

/// Categories of threats detected by behavior analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    /// Reverse shell: network connection + shell execution.
    ReverseShell,
    /// Data exfiltration: reading files and sending over network.
    DataExfiltration,
    /// Credential theft: accessing password files, SSH keys, etc.
    CredentialTheft,
    /// Persistence: writing to cron, systemd, `LaunchAgents`, etc.
    Persistence,
    /// Privilege escalation: setuid, capability changes.
    PrivilegeEscalation,
    /// Lateral movement: SSH/SCP to other hosts, port scanning.
    LateralMovement,
    /// Crypto mining: connecting to mining pools.
    CryptoMining,
    /// Ransomware: mass file read + encrypt + delete pattern.
    Ransomware,
    /// Anti-analysis: debugger detection, VM detection, timing evasion.
    AntiAnalysis,
    /// Dropper: write executable + chmod + exec.
    Dropper,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReverseShell => write!(f, "reverse_shell"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::CredentialTheft => write!(f, "credential_theft"),
            Self::Persistence => write!(f, "persistence"),
            Self::PrivilegeEscalation => write!(f, "privilege_escalation"),
            Self::LateralMovement => write!(f, "lateral_movement"),
            Self::CryptoMining => write!(f, "crypto_mining"),
            Self::Ransomware => write!(f, "ransomware"),
            Self::AntiAnalysis => write!(f, "anti_analysis"),
            Self::Dropper => write!(f, "dropper"),
        }
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// Result of executing a file in the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    /// Exit code of the sandboxed process (-1 if killed by signal or unknown).
    pub exit_code: i32,
    /// Raw system call events traced during execution (Linux only; empty on other platforms).
    #[cfg(target_os = "linux")]
    pub syscalls: Vec<SyscallEvent>,
    /// Raw system call events (empty on non-Linux platforms).
    #[cfg(not(target_os = "linux"))]
    pub syscalls: Vec<SyscallEventStub>,
    /// Behavior findings from the analysis engine.
    pub behaviors: Vec<BehaviorFinding>,
    /// Overall verdict.
    pub verdict: SandboxVerdict,
    /// Threat score from 0 (clean) to 100 (definitely malicious).
    pub threat_score: u32,
    /// Network connection attempts observed.
    pub network_attempts: Vec<NetworkAttempt>,
    /// File system operations observed.
    pub file_operations: Vec<FileOperation>,
    /// Process operations observed (fork, exec, kill, ptrace).
    pub process_operations: Vec<ProcessOperation>,
    /// Total execution time in milliseconds.
    pub execution_time_ms: u64,
}

/// Stub syscall event for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEventStub {
    /// The system call number.
    pub number: u64,
    /// Human-readable name of the system call.
    pub name: String,
    /// Return value of the system call.
    pub return_value: i64,
    /// Timestamp in nanoseconds since the trace started.
    pub timestamp_ns: u64,
}

/// A suspicious behavior detected during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFinding {
    /// Name of the detection rule that matched.
    pub rule_name: String,
    /// Category of the threat.
    pub category: ThreatCategory,
    /// Score contribution of this finding.
    pub score: u32,
    /// Human-readable description of the finding.
    pub description: String,
}

/// Overall verdict from sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxVerdict {
    /// No threats detected.
    Clean,
    /// Some suspicious activity detected but not definitively malicious.
    Suspicious {
        /// Reasons for suspicion.
        reasons: Vec<String>,
    },
    /// Malicious behavior detected with high confidence.
    Malicious {
        /// Evidence of malicious behavior.
        reasons: Vec<String>,
    },
    /// Execution timed out.
    Timeout,
    /// An error occurred during analysis.
    Error(String),
}

// ── Operation types ─────────────────────────────────────────────────────────

/// A network connection attempt observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAttempt {
    /// Target address (IP or hostname).
    pub address: String,
    /// Target port.
    pub port: u16,
    /// Protocol (tcp, udp, etc.).
    pub protocol: String,
    /// Whether the connection was blocked by the sandbox.
    pub blocked: bool,
}

/// A file system operation observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    /// Type of file operation.
    pub op: FileOpType,
    /// Path that was operated on.
    pub path: String,
    /// Whether the operation was blocked by the sandbox.
    pub blocked: bool,
}

/// Types of file operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileOpType {
    /// File was opened for reading.
    Read,
    /// File was written to.
    Write,
    /// File was created.
    Create,
    /// File was deleted.
    Delete,
    /// File was executed.
    Execute,
    /// File permissions were changed (chmod/chown).
    Chmod,
}

/// A process operation observed during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperation {
    /// Type of process operation.
    pub op: ProcessOpType,
    /// Target of the operation (process name, PID, etc.).
    pub target: String,
}

/// Types of process operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessOpType {
    /// Process fork/clone.
    Fork,
    /// Process exec (new program).
    Exec,
    /// Signal sent to another process.
    Kill,
    /// Ptrace operation.
    Ptrace,
}

// ── Sandbox ─────────────────────────────────────────────────────────────────

/// Platform-agnostic sandbox for executing and analyzing suspicious files.
///
/// Delegates to the appropriate platform implementation and runs the
/// behavior analysis engine on the results.
pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    /// Create a new sandbox with the given configuration.
    pub const fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Execute a file in the sandbox and analyze its behavior.
    ///
    /// This method:
    /// 1. Delegates to the platform-specific sandbox implementation.
    /// 2. Runs the behavior analysis engine on the raw results.
    /// 3. Returns a `SandboxResult` with syscalls, structured operations,
    ///    behavior findings, and a final threat verdict.
    pub async fn execute(&self, path: &Path, args: &[&str]) -> Result<SandboxResult> {
        let mut result = self.platform_execute(path, args).await?;

        // Run behavior analysis on the collected data.
        let analyzer = BehaviorAnalyzer::new();
        analyzer.analyze(&mut result);

        Ok(result)
    }

    /// Platform-specific execution dispatch.
    async fn platform_execute(&self, path: &Path, args: &[&str]) -> Result<SandboxResult> {
        #[cfg(target_os = "linux")]
        {
            // Linux: use ptrace-based tracing (runs synchronously in a blocking task).
            let config = self.config.clone();
            let path = path.to_path_buf();
            let args: Vec<String> = args.iter().map(ToString::to_string).collect();

            let result = tokio::task::spawn_blocking(move || {
                let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
                linux::execute(&config, &path, &arg_refs)
            })
            .await
            .map_err(|e| anyhow::anyhow!("sandbox task join error: {e}"))??;

            Ok(result)
        }

        #[cfg(target_os = "macos")]
        {
            let sandbox = macos::MacOSSandbox::new(&self.config);
            sandbox.execute(path, args).await
        }

        #[cfg(target_os = "windows")]
        {
            let sandbox = windows::WindowsSandbox::new(&self.config);
            sandbox.execute(path, args).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = (path, args);
            anyhow::bail!(
                "sandbox execution is not supported on this platform. \
                 Supported platforms: Linux, macOS, Windows (planned)."
            )
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::uninlined_format_args)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default_values() {
        let config = SandboxConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_memory_mb, 256);
        assert!(config.allowed_paths.is_empty());
        assert!(!config.network_allowed);
    }

    #[test]
    fn test_sandbox_config_custom_values() {
        let config = SandboxConfig {
            timeout_secs: 60,
            max_memory_mb: 512,
            allowed_paths: vec![PathBuf::from("/tmp")],
            network_allowed: true,
        };
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.allowed_paths.len(), 1);
        assert!(config.network_allowed);
    }

    #[test]
    fn test_sandbox_verdict_serialization_roundtrip_clean() {
        let verdict = SandboxVerdict::Clean;
        let json = serde_json::to_string(&verdict).expect("serialize failed");
        let deserialized: SandboxVerdict = serde_json::from_str(&json).expect("deserialize failed");
        assert!(matches!(deserialized, SandboxVerdict::Clean));
    }

    #[test]
    fn test_sandbox_verdict_serialization_roundtrip_suspicious() {
        let verdict = SandboxVerdict::Suspicious {
            reasons: vec!["anti-analysis detected".into()],
        };
        let json = serde_json::to_string(&verdict).expect("serialize failed");
        let deserialized: SandboxVerdict = serde_json::from_str(&json).expect("deserialize failed");
        match deserialized {
            SandboxVerdict::Suspicious { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0], "anti-analysis detected");
            }
            other => panic!("expected Suspicious, got {:?}", other),
        }
    }

    #[test]
    fn test_sandbox_verdict_serialization_roundtrip_malicious() {
        let verdict = SandboxVerdict::Malicious {
            reasons: vec!["reverse shell".into(), "credential theft".into()],
        };
        let json = serde_json::to_string(&verdict).expect("serialize failed");
        let deserialized: SandboxVerdict = serde_json::from_str(&json).expect("deserialize failed");
        match deserialized {
            SandboxVerdict::Malicious { reasons } => {
                assert_eq!(reasons.len(), 2);
            }
            other => panic!("expected Malicious, got {:?}", other),
        }
    }

    #[test]
    fn test_sandbox_verdict_serialization_roundtrip_timeout() {
        let verdict = SandboxVerdict::Timeout;
        let json = serde_json::to_string(&verdict).expect("serialize failed");
        let deserialized: SandboxVerdict = serde_json::from_str(&json).expect("deserialize failed");
        assert!(matches!(deserialized, SandboxVerdict::Timeout));
    }

    #[test]
    fn test_sandbox_verdict_serialization_roundtrip_error() {
        let verdict = SandboxVerdict::Error("something went wrong".into());
        let json = serde_json::to_string(&verdict).expect("serialize failed");
        let deserialized: SandboxVerdict = serde_json::from_str(&json).expect("deserialize failed");
        match deserialized {
            SandboxVerdict::Error(msg) => assert_eq!(msg, "something went wrong"),
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_behavior_finding_creation() {
        let finding = BehaviorFinding {
            rule_name: "Reverse Shell".into(),
            category: ThreatCategory::ReverseShell,
            score: 90,
            description: "Detected reverse shell pattern".into(),
        };
        assert_eq!(finding.rule_name, "Reverse Shell");
        assert_eq!(finding.category, ThreatCategory::ReverseShell);
        assert_eq!(finding.score, 90);
        assert_eq!(finding.description, "Detected reverse shell pattern");
    }

    #[test]
    fn test_sandbox_result_creation() {
        let result = SandboxResult {
            exit_code: 0,
            syscalls: Vec::new(),
            behaviors: vec![BehaviorFinding {
                rule_name: "Test Rule".into(),
                category: ThreatCategory::CryptoMining,
                score: 70,
                description: "test".into(),
            }],
            verdict: SandboxVerdict::Malicious {
                reasons: vec!["crypto mining".into()],
            },
            threat_score: 70,
            network_attempts: vec![NetworkAttempt {
                address: "pool.example.com".into(),
                port: 3333,
                protocol: "tcp".into(),
                blocked: false,
            }],
            file_operations: vec![FileOperation {
                op: FileOpType::Read,
                path: "/etc/passwd".into(),
                blocked: false,
            }],
            process_operations: vec![ProcessOperation {
                op: ProcessOpType::Exec,
                target: "/bin/sh".into(),
            }],
            execution_time_ms: 500,
        };

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.behaviors.len(), 1);
        assert_eq!(result.threat_score, 70);
        assert_eq!(result.network_attempts.len(), 1);
        assert_eq!(result.file_operations.len(), 1);
        assert_eq!(result.process_operations.len(), 1);
        assert_eq!(result.execution_time_ms, 500);
        assert!(matches!(result.verdict, SandboxVerdict::Malicious { .. }));
    }

    #[test]
    fn test_threat_category_display() {
        assert_eq!(ThreatCategory::ReverseShell.to_string(), "reverse_shell");
        assert_eq!(ThreatCategory::DataExfiltration.to_string(), "data_exfiltration");
        assert_eq!(ThreatCategory::CredentialTheft.to_string(), "credential_theft");
        assert_eq!(ThreatCategory::Persistence.to_string(), "persistence");
        assert_eq!(ThreatCategory::PrivilegeEscalation.to_string(), "privilege_escalation");
        assert_eq!(ThreatCategory::LateralMovement.to_string(), "lateral_movement");
        assert_eq!(ThreatCategory::CryptoMining.to_string(), "crypto_mining");
        assert_eq!(ThreatCategory::Ransomware.to_string(), "ransomware");
        assert_eq!(ThreatCategory::AntiAnalysis.to_string(), "anti_analysis");
        assert_eq!(ThreatCategory::Dropper.to_string(), "dropper");
    }

    #[test]
    fn test_file_op_type_variants() {
        assert_eq!(FileOpType::Read, FileOpType::Read);
        assert_ne!(FileOpType::Read, FileOpType::Write);
        assert_ne!(FileOpType::Create, FileOpType::Delete);
        assert_ne!(FileOpType::Execute, FileOpType::Chmod);
    }

    #[test]
    fn test_process_op_type_variants() {
        assert_eq!(ProcessOpType::Fork, ProcessOpType::Fork);
        assert_ne!(ProcessOpType::Fork, ProcessOpType::Exec);
        assert_ne!(ProcessOpType::Kill, ProcessOpType::Ptrace);
    }
}
