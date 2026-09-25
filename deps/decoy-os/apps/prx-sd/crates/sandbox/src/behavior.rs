//! Behavior analysis engine for threat detection.
//!
//! This module is the "brain" of the sandbox: it converts raw syscall traces
//! and structured operation records into threat verdicts. It uses a rule-based
//! approach where each rule matches specific behavioral patterns associated
//! with known threat categories.
//!
//! The analyzer is fully cross-platform -- it operates on the abstract
//! `SandboxResult` structures rather than platform-specific syscall data.

use crate::{BehaviorFinding, FileOpType, ProcessOpType, SandboxResult, SandboxVerdict, ThreatCategory};

// ── Behavior Rule ───────────────────────────────────────────────────────────

/// Identifies which behavior rule to apply.
///
/// Using an enum instead of `Box<dyn Fn>` so that `BehaviorRule` is `Send + Sync`.
#[derive(Debug, Clone, Copy)]
enum RuleMatcher {
    ReverseShell,
    CredentialTheft,
    Ransomware,
    CryptoMiner,
    PersistenceInstall,
    Dropper,
    AntiAnalysis,
    DataExfiltration,
    PrivilegeEscalation,
    LateralMovement,
}

/// A single behavior detection rule.
#[derive(Debug, Clone)]
pub struct BehaviorRule {
    /// Human-readable name of the rule.
    pub name: String,
    /// Threat category this rule detects.
    pub category: ThreatCategory,
    /// Score contribution if matched (0-100).
    pub score: u32,
    /// Which matching function to use.
    matcher: RuleMatcher,
}

impl BehaviorRule {
    /// Evaluate this rule against a sandbox result.
    fn matches(&self, result: &SandboxResult) -> bool {
        match self.matcher {
            RuleMatcher::ReverseShell => match_reverse_shell(result),
            RuleMatcher::CredentialTheft => match_credential_theft(result),
            RuleMatcher::Ransomware => match_ransomware(result),
            RuleMatcher::CryptoMiner => match_crypto_miner(result),
            RuleMatcher::PersistenceInstall => match_persistence_install(result),
            RuleMatcher::Dropper => match_dropper(result),
            RuleMatcher::AntiAnalysis => match_anti_analysis(result),
            RuleMatcher::DataExfiltration => match_data_exfiltration(result),
            RuleMatcher::PrivilegeEscalation => match_privilege_escalation(result),
            RuleMatcher::LateralMovement => match_lateral_movement(result),
        }
    }
}

// ── Rule matchers ───────────────────────────────────────────────────────────

/// Pattern: `socket()` + `connect(external_ip)` + `dup2(stdin/stdout)` + `execve(/bin/sh|/bin/bash)`
///
/// A reverse shell typically opens a network connection and then duplicates
/// the socket fd to stdin/stdout before spawning a shell. We detect the
/// combination of outbound network + shell execution.
fn match_reverse_shell(result: &SandboxResult) -> bool {
    let has_outbound_connect = result
        .network_attempts
        .iter()
        .any(|n| n.port > 0 || !n.address.is_empty());

    let has_shell_exec = result.process_operations.iter().any(|p| {
        matches!(p.op, ProcessOpType::Exec)
            && (p.target.contains("/bin/sh")
                || p.target.contains("/bin/bash")
                || p.target.contains("/bin/zsh")
                || p.target.contains("/bin/ash")
                || p.target.contains("cmd.exe")
                || p.target.contains("powershell"))
    });

    // Also check raw syscall trace for dup2 (fd redirection) which is the
    // hallmark of binding a socket to stdin/stdout.
    let has_dup2 = result.syscalls.iter().any(|s| s.name == "dup2");

    has_outbound_connect && has_shell_exec && has_dup2
}

/// Pattern: open/read of sensitive credential files.
///
/// Detects access to password databases, SSH keys, browser credential stores,
/// cloud credential files, and other sensitive authentication material.
fn match_credential_theft(result: &SandboxResult) -> bool {
    const SENSITIVE_PATHS: &[&str] = &[
        "/etc/shadow",
        "/etc/passwd",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".ssh/id_dsa",
        ".ssh/authorized_keys",
        ".ssh/known_hosts",
        "Login Data",  // Chrome passwords
        "logins.json", // Firefox passwords
        "key3.db",     // Firefox key store
        "key4.db",     // Firefox key store
        ".aws/credentials",
        ".config/gcloud",
        ".kube/config",
        ".docker/config.json",
        ".gnupg/",
        ".netrc",
        "/etc/krb5.keytab",
        "wallet.dat", // cryptocurrency wallets
    ];

    result
        .file_operations
        .iter()
        .any(|f| matches!(f.op, FileOpType::Read) && SENSITIVE_PATHS.iter().any(|sensitive| f.path.contains(sensitive)))
}

/// Pattern: mass file enumeration + read + write (new extension) + delete original.
///
/// Ransomware typically enumerates files in user directories, reads them,
/// writes an encrypted copy (often with a new extension), and deletes
/// the original. We detect a high ratio of read + write + delete operations.
fn match_ransomware(result: &SandboxResult) -> bool {
    let read_count = result
        .file_operations
        .iter()
        .filter(|f| matches!(f.op, FileOpType::Read))
        .count();

    let write_count = result
        .file_operations
        .iter()
        .filter(|f| matches!(f.op, FileOpType::Write | FileOpType::Create))
        .count();

    let delete_count = result
        .file_operations
        .iter()
        .filter(|f| matches!(f.op, FileOpType::Delete))
        .count();

    // Ransomware pattern: lots of reads followed by writes and deletes.
    // Minimum thresholds to reduce false positives.
    read_count >= 10 && write_count >= 10 && delete_count >= 5
}

/// Pattern: connect to stratum mining pool addresses/ports.
///
/// Crypto miners connect to mining pools using the stratum protocol
/// (typically on ports 3333, 4444, 5555, 8888, 14444, or 45700).
/// We also check for common pool hostnames in network addresses.
fn match_crypto_miner(result: &SandboxResult) -> bool {
    const MINING_PORTS: &[u16] = &[3333, 4444, 5555, 8888, 14444, 14433, 45700, 9999];
    const MINING_KEYWORDS: &[&str] = &[
        "stratum",
        "pool.",
        "mining.",
        "xmr.",
        "monero",
        "nicehash",
        "nanopool",
        "f2pool",
        "ethermine",
        "hashvault",
        "minexmr",
    ];

    result.network_attempts.iter().any(|n| {
        let port_match = MINING_PORTS.contains(&n.port);
        let addr_match = MINING_KEYWORDS.iter().any(|kw| n.address.to_lowercase().contains(kw));
        port_match || addr_match
    })
}

/// Pattern: write to persistence locations (crontab, systemd, `LaunchAgent`, etc.).
///
/// Malware establishes persistence by writing to system locations that
/// are automatically executed on boot or login.
fn match_persistence_install(result: &SandboxResult) -> bool {
    const PERSISTENCE_PATHS: &[&str] = &[
        "/etc/cron",
        "/var/spool/cron",
        "crontab",
        "/etc/systemd/system/",
        "/usr/lib/systemd/system/",
        "/.config/systemd/user/",
        "/etc/init.d/",
        "/etc/rc.local",
        "Library/LaunchAgents/",
        "Library/LaunchDaemons/",
        "/Library/LaunchAgents/",
        "/Library/LaunchDaemons/",
        "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/",
        "/etc/xdg/autostart/",
        "/.config/autostart/",
        "/.bashrc",
        "/.bash_profile",
        "/.profile",
        "/.zshrc",
    ];

    result.file_operations.iter().any(|f| {
        matches!(f.op, FileOpType::Write | FileOpType::Create) && PERSISTENCE_PATHS.iter().any(|pp| f.path.contains(pp))
    })
}

/// Pattern: write file + chmod +x + execve.
///
/// Droppers download or extract a payload, write it to disk, make it
/// executable, and then run it. We detect this sequence of operations.
fn match_dropper(result: &SandboxResult) -> bool {
    let has_file_write = result
        .file_operations
        .iter()
        .any(|f| matches!(f.op, FileOpType::Write | FileOpType::Create));

    let has_chmod = result.file_operations.iter().any(|f| matches!(f.op, FileOpType::Chmod));

    // Also check for direct chmod syscall or file-execute operations.
    let has_exec_file = result
        .file_operations
        .iter()
        .any(|f| matches!(f.op, FileOpType::Execute));

    let has_exec_process = result
        .process_operations
        .iter()
        .any(|p| matches!(p.op, ProcessOpType::Exec));

    has_file_write && (has_chmod || has_exec_file) && has_exec_process
}

/// Pattern: ptrace(TRACEME) on self, /proc/self checks, excessive sleep.
///
/// Anti-analysis techniques include:
/// - Calling `ptrace(PTRACE_TRACEME)` to detect debuggers
/// - Reading /proc/self/status for `TracerPid`
/// - Timing-based checks (excessive sleep/gettimeofday calls)
/// - VM detection via CPUID or /proc/cpuinfo
fn match_anti_analysis(result: &SandboxResult) -> bool {
    // Check for ptrace self-trace (anti-debug).
    let has_ptrace_self = result
        .process_operations
        .iter()
        .any(|p| matches!(p.op, ProcessOpType::Ptrace));

    // Check for /proc/self reads (debugger/VM detection).
    let has_proc_self_read = result.file_operations.iter().any(|f| {
        matches!(f.op, FileOpType::Read)
            && (f.path.contains("/proc/self/status")
                || f.path.contains("/proc/self/maps")
                || f.path.contains("/proc/self/exe")
                || f.path.contains("/sys/class/dmi")
                || f.path.contains("/proc/cpuinfo")
                || f.path.contains("/proc/version"))
    });

    // Check for excessive nanosleep calls (sandbox evasion via timing).
    let sleep_count = result
        .syscalls
        .iter()
        .filter(|s| s.name == "nanosleep" || s.name == "clock_nanosleep")
        .count();

    // Check for excessive gettimeofday calls (timing checks).
    let timing_count = result
        .syscalls
        .iter()
        .filter(|s| s.name == "gettimeofday" || s.name == "clock_gettime")
        .count();

    has_ptrace_self || has_proc_self_read || sleep_count >= 5 || timing_count >= 20
}

/// Pattern: read sensitive files + establish network connection + send data.
///
/// Data exfiltration involves reading files of interest and then sending
/// their contents over the network. We detect the combination of file reads
/// followed by network sends.
fn match_data_exfiltration(result: &SandboxResult) -> bool {
    let has_file_reads = result
        .file_operations
        .iter()
        .filter(|f| matches!(f.op, FileOpType::Read))
        .count()
        >= 3;

    let has_network_send = result
        .network_attempts
        .iter()
        .any(|n| n.port > 0 || !n.address.is_empty());

    // Also check for sendto/write-to-socket syscalls after file reads.
    let has_send_syscall = result
        .syscalls
        .iter()
        .any(|s| s.name == "sendto" || s.name == "sendmsg" || s.name == "send");

    has_file_reads && (has_network_send || has_send_syscall)
}

/// Pattern: setuid(0), capability changes, SUID bit manipulation.
///
/// Privilege escalation attempts include calling setuid/setgid to gain
/// root privileges, modifying capabilities, or creating SUID binaries.
fn match_privilege_escalation(result: &SandboxResult) -> bool {
    // Check for setuid/setgid/setresuid syscalls.
    let has_setuid = result.syscalls.iter().any(|s| {
        s.name == "setuid"
            || s.name == "setgid"
            || s.name == "setresuid"
            || s.name == "setresgid"
            || s.name == "setreuid"
            || s.name == "setregid"
    });

    // Check for SUID/SGID file creation (chmod with setuid bit).
    let has_suid_create = result
        .file_operations
        .iter()
        .any(|f| matches!(f.op, FileOpType::Chmod) && f.path.contains("suid"));

    has_setuid || has_suid_create
}

/// Pattern: SSH to other hosts, network scanning behavior.
///
/// Lateral movement involves connecting to other hosts on the internal
/// network, typically via SSH, or scanning for open ports to find new targets.
fn match_lateral_movement(result: &SandboxResult) -> bool {
    // Check for SSH client execution.
    let has_ssh_exec = result.process_operations.iter().any(|p| {
        matches!(p.op, ProcessOpType::Exec)
            && (p.target.contains("ssh")
                || p.target.contains("scp")
                || p.target.contains("rsync")
                || p.target.contains("psexec")
                || p.target.contains("wmic")
                || p.target.contains("net use"))
    });

    // Check for SSH port connections (port 22).
    let has_ssh_connect = result.network_attempts.iter().any(|n| n.port == 22);

    // Check for port scanning behavior: many connections to different ports.
    let unique_ports: std::collections::HashSet<u16> = result
        .network_attempts
        .iter()
        .filter(|n| n.port > 0)
        .map(|n| n.port)
        .collect();
    let is_port_scanning = unique_ports.len() >= 10;

    // Check for connections to many different addresses (host scanning).
    let unique_addrs: std::collections::HashSet<&str> = result
        .network_attempts
        .iter()
        .filter(|n| !n.address.is_empty())
        .map(|n| n.address.as_str())
        .collect();
    let is_host_scanning = unique_addrs.len() >= 5;

    has_ssh_exec || has_ssh_connect || is_port_scanning || is_host_scanning
}

// ── Behavior Analyzer ───────────────────────────────────────────────────────

/// The behavior analysis engine.
///
/// Evaluates a set of behavior detection rules against sandbox execution
/// results and produces a threat verdict with a confidence score.
pub struct BehaviorAnalyzer {
    rules: Vec<BehaviorRule>,
}

impl BehaviorAnalyzer {
    /// Create a new behavior analyzer with all built-in detection rules.
    pub fn new() -> Self {
        let rules = vec![
            BehaviorRule {
                name: "Reverse Shell".into(),
                category: ThreatCategory::ReverseShell,
                score: 90,
                matcher: RuleMatcher::ReverseShell,
            },
            BehaviorRule {
                name: "Credential Theft".into(),
                category: ThreatCategory::CredentialTheft,
                score: 85,
                matcher: RuleMatcher::CredentialTheft,
            },
            BehaviorRule {
                name: "Ransomware".into(),
                category: ThreatCategory::Ransomware,
                score: 95,
                matcher: RuleMatcher::Ransomware,
            },
            BehaviorRule {
                name: "Crypto Miner".into(),
                category: ThreatCategory::CryptoMining,
                score: 70,
                matcher: RuleMatcher::CryptoMiner,
            },
            BehaviorRule {
                name: "Persistence Install".into(),
                category: ThreatCategory::Persistence,
                score: 75,
                matcher: RuleMatcher::PersistenceInstall,
            },
            BehaviorRule {
                name: "Dropper".into(),
                category: ThreatCategory::Dropper,
                score: 80,
                matcher: RuleMatcher::Dropper,
            },
            BehaviorRule {
                name: "Anti-Analysis".into(),
                category: ThreatCategory::AntiAnalysis,
                score: 40,
                matcher: RuleMatcher::AntiAnalysis,
            },
            BehaviorRule {
                name: "Data Exfiltration".into(),
                category: ThreatCategory::DataExfiltration,
                score: 85,
                matcher: RuleMatcher::DataExfiltration,
            },
            BehaviorRule {
                name: "Privilege Escalation".into(),
                category: ThreatCategory::PrivilegeEscalation,
                score: 90,
                matcher: RuleMatcher::PrivilegeEscalation,
            },
            BehaviorRule {
                name: "Lateral Movement".into(),
                category: ThreatCategory::LateralMovement,
                score: 80,
                matcher: RuleMatcher::LateralMovement,
            },
        ];

        Self { rules }
    }

    /// Analyze a sandbox result and update it with threat findings.
    ///
    /// Evaluates all behavior rules against the result, accumulates scores,
    /// and sets the final verdict based on the total threat score:
    /// - 0-29: Clean
    /// - 30-69: Suspicious
    /// - 70+: Malicious
    pub fn analyze(&self, result: &mut SandboxResult) {
        let mut total_score: u32 = 0;
        let mut reasons = Vec::new();

        for rule in &self.rules {
            if rule.matches(result) {
                total_score = total_score.saturating_add(rule.score);
                let reason = format!("[{}] {}", rule.category, rule.name);
                reasons.push(reason);
                result.behaviors.push(BehaviorFinding {
                    rule_name: rule.name.clone(),
                    category: rule.category.clone(),
                    score: rule.score,
                    description: format!("Detected {} behavior pattern (category: {})", rule.name, rule.category),
                });
            }
        }

        result.threat_score = total_score.min(100);
        result.verdict = match total_score {
            0..=29 => SandboxVerdict::Clean,
            30..=69 => SandboxVerdict::Suspicious { reasons },
            _ => SandboxVerdict::Malicious { reasons },
        };
    }
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileOperation, NetworkAttempt};

    fn empty_result() -> SandboxResult {
        SandboxResult {
            exit_code: 0,
            syscalls: Vec::new(),
            behaviors: Vec::new(),
            verdict: SandboxVerdict::Clean,
            threat_score: 0,
            network_attempts: Vec::new(),
            file_operations: Vec::new(),
            process_operations: Vec::new(),
            execution_time_ms: 100,
        }
    }

    #[test]
    fn test_clean_result() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();
        analyzer.analyze(&mut result);

        assert_eq!(result.threat_score, 0);
        assert!(matches!(result.verdict, SandboxVerdict::Clean));
        assert!(result.behaviors.is_empty());
    }

    #[test]
    fn test_credential_theft_detection() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();
        result.file_operations.push(FileOperation {
            op: FileOpType::Read,
            path: "/etc/shadow".into(),
            blocked: false,
        });

        analyzer.analyze(&mut result);

        assert!(result.threat_score >= 70);
        assert!(result.behaviors.iter().any(|b| b.rule_name == "Credential Theft"));
    }

    #[test]
    fn test_lateral_movement_ssh() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();
        result.network_attempts.push(NetworkAttempt {
            address: "192.168.1.100".into(),
            port: 22,
            protocol: "tcp".into(),
            blocked: false,
        });

        analyzer.analyze(&mut result);

        assert!(result.behaviors.iter().any(|b| b.rule_name == "Lateral Movement"));
    }

    #[test]
    fn test_crypto_miner_detection() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();
        result.network_attempts.push(NetworkAttempt {
            address: "pool.minexmr.com".into(),
            port: 4444,
            protocol: "tcp".into(),
            blocked: false,
        });

        analyzer.analyze(&mut result);

        assert!(result.behaviors.iter().any(|b| b.rule_name == "Crypto Miner"));
    }

    #[test]
    fn test_behavior_analyzer_creation() {
        let analyzer = BehaviorAnalyzer::new();
        assert_eq!(analyzer.rules.len(), 10);
    }

    #[test]
    fn test_behavior_analyzer_default() {
        let analyzer = BehaviorAnalyzer::default();
        assert_eq!(analyzer.rules.len(), 10);
    }

    #[test]
    fn test_empty_operations_returns_clean() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();
        analyzer.analyze(&mut result);

        assert_eq!(result.threat_score, 0);
        assert!(matches!(result.verdict, SandboxVerdict::Clean));
        assert!(result.behaviors.is_empty());
    }

    #[test]
    fn test_suspicious_operations_returns_findings() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();

        // Anti-analysis: ptrace self-trace gives score 40 -> Suspicious range
        result.process_operations.push(crate::ProcessOperation {
            op: crate::ProcessOpType::Ptrace,
            target: "self".into(),
        });

        analyzer.analyze(&mut result);

        assert!(result.threat_score >= 30);
        assert!(result.threat_score < 70);
        assert!(matches!(result.verdict, SandboxVerdict::Suspicious { .. }));
        assert!(result.behaviors.iter().any(|b| b.rule_name == "Anti-Analysis"));
    }

    #[test]
    fn test_reverse_shell_pattern() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();

        // Network connect
        result.network_attempts.push(NetworkAttempt {
            address: "10.0.0.1".into(),
            port: 4444,
            protocol: "tcp".into(),
            blocked: false,
        });

        // Shell exec
        result.process_operations.push(crate::ProcessOperation {
            op: crate::ProcessOpType::Exec,
            target: "/bin/sh".into(),
        });

        // dup2 syscall in trace
        #[cfg(target_os = "linux")]
        result.syscalls.push(crate::SyscallEvent {
            number: 33,
            name: "dup2".into(),
            return_value: 0,
            timestamp_ns: 1000,
        });

        #[cfg(not(target_os = "linux"))]
        result.syscalls.push(crate::SyscallEventStub {
            number: 33,
            name: "dup2".into(),
            return_value: 0,
            timestamp_ns: 1000,
        });

        analyzer.analyze(&mut result);

        assert!(result.behaviors.iter().any(|b| b.rule_name == "Reverse Shell"));
        assert!(result.threat_score >= 70);
        assert!(matches!(result.verdict, SandboxVerdict::Malicious { .. }));
    }

    #[test]
    fn test_threat_score_capped_at_100() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();

        // Trigger multiple high-score rules to exceed 100

        // Credential theft (85)
        result.file_operations.push(FileOperation {
            op: FileOpType::Read,
            path: "/etc/shadow".into(),
            blocked: false,
        });

        // Lateral movement via SSH (80)
        result.network_attempts.push(NetworkAttempt {
            address: "192.168.1.50".into(),
            port: 22,
            protocol: "tcp".into(),
            blocked: false,
        });

        analyzer.analyze(&mut result);

        assert!(result.threat_score <= 100);
    }

    #[test]
    fn test_persistence_install_detection() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();

        result.file_operations.push(FileOperation {
            op: FileOpType::Write,
            path: "/etc/cron.d/backdoor".into(),
            blocked: false,
        });

        analyzer.analyze(&mut result);

        assert!(result.behaviors.iter().any(|b| b.rule_name == "Persistence Install"));
    }

    #[test]
    fn test_privilege_escalation_detection() {
        let analyzer = BehaviorAnalyzer::new();
        let mut result = empty_result();

        #[cfg(target_os = "linux")]
        result.syscalls.push(crate::SyscallEvent {
            number: 105,
            name: "setuid".into(),
            return_value: 0,
            timestamp_ns: 500,
        });

        #[cfg(not(target_os = "linux"))]
        result.syscalls.push(crate::SyscallEventStub {
            number: 105,
            name: "setuid".into(),
            return_value: 0,
            timestamp_ns: 500,
        });

        analyzer.analyze(&mut result);

        assert!(result.behaviors.iter().any(|b| b.rule_name == "Privilege Escalation"));
    }
}
