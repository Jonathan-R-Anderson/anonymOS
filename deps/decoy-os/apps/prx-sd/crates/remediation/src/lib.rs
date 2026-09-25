//! Remediation crate for the prx-sd antivirus engine.
//!
//! Handles all post-detection threat response actions including quarantine,
//! process termination, persistence cleaning, network isolation, and audit
//! logging. Provides platform-specific implementations for Linux, macOS,
//! and Windows.

pub mod actions;
pub mod audit;
pub mod common;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod policy;
#[cfg(target_os = "windows")]
pub mod windows;

use serde::{Deserialize, Serialize};

/// What action was taken on a threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationAction {
    /// Only logged, no action taken.
    ReportOnly,
    /// File moved to encrypted quarantine.
    Quarantined { quarantine_id: String },
    /// File access blocked (realtime).
    Blocked,
    /// Malicious process killed.
    ProcessKilled { pid: u32, name: String },
    /// Persistence entry removed.
    PersistenceCleaned {
        persistence_type: PersistenceType,
        detail: String,
    },
    /// File permanently deleted.
    Deleted,
    /// Network isolated (iptables/pf).
    NetworkIsolated,
    /// Hash added to local blocklist.
    AddedToBlocklist,
    /// Whitelisted (false positive).
    Whitelisted,
}

/// Type of persistence mechanism found and cleaned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceType {
    // Linux
    Crontab,
    SystemdService,
    SystemdTimer,
    BashProfile,
    InitScript,
    AuthorizedKeys,
    LdPreload,
    // macOS
    LaunchAgent,
    LaunchDaemon,
    LoginItem,
    // Windows
    RegistryRun,
    ScheduledTask,
    Service,
    StartupFolder,
    // Cross-platform
    CronJob,
    ShellRc,
}

/// Result of a remediation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub action: RemediationAction,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub requires_reboot: bool,
}

impl RemediationResult {
    /// Create a successful remediation result.
    pub fn success(action: RemediationAction) -> Self {
        Self {
            action,
            success: true,
            error: None,
            timestamp: chrono::Utc::now(),
            requires_reboot: false,
        }
    }

    /// Create a failed remediation result.
    pub fn failure(action: RemediationAction, error: String) -> Self {
        Self {
            action,
            success: false,
            error: Some(error),
            timestamp: chrono::Utc::now(),
            requires_reboot: false,
        }
    }
}

/// Full audit record for one threat handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAuditRecord {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub file_path: String,
    pub threat_name: String,
    pub threat_level: String,
    pub detection_type: String,
    pub actions_taken: Vec<RemediationResult>,
    pub platform: String,
    pub hostname: String,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn remediation_result_success_creates_correct_struct() {
        let result = RemediationResult::success(RemediationAction::Blocked);
        assert!(result.success);
        assert!(result.error.is_none());
        assert!(!result.requires_reboot);
        assert!(matches!(result.action, RemediationAction::Blocked));
    }

    #[test]
    fn remediation_result_failure_has_error_field_set() {
        let result = RemediationResult::failure(RemediationAction::Deleted, "permission denied".to_string());
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("permission denied"));
        assert!(!result.requires_reboot);
        assert!(matches!(result.action, RemediationAction::Deleted));
    }

    #[test]
    fn remediation_result_success_with_quarantined_variant() {
        let result = RemediationResult::success(RemediationAction::Quarantined {
            quarantine_id: "abc-123".to_string(),
        });
        assert!(result.success);
        if let RemediationAction::Quarantined { quarantine_id } = &result.action {
            assert_eq!(quarantine_id, "abc-123");
        } else {
            panic!("expected Quarantined variant");
        }
    }

    #[test]
    fn remediation_result_success_with_process_killed_variant() {
        let result = RemediationResult::success(RemediationAction::ProcessKilled {
            pid: 42,
            name: "evil_proc".to_string(),
        });
        assert!(result.success);
        if let RemediationAction::ProcessKilled { pid, name } = &result.action {
            assert_eq!(*pid, 42);
            assert_eq!(name, "evil_proc");
        } else {
            panic!("expected ProcessKilled variant");
        }
    }

    #[test]
    fn threat_audit_record_serialization_roundtrip() {
        let record = ThreatAuditRecord {
            id: "test-id-001".to_string(),
            timestamp: chrono::Utc::now(),
            file_path: "/tmp/malware.exe".to_string(),
            threat_name: "Trojan.GenericKD".to_string(),
            threat_level: "malicious".to_string(),
            detection_type: "yara".to_string(),
            actions_taken: vec![
                RemediationResult::success(RemediationAction::Quarantined {
                    quarantine_id: "q-1".to_string(),
                }),
                RemediationResult::failure(
                    RemediationAction::ProcessKilled {
                        pid: 100,
                        name: "malproc".to_string(),
                    },
                    "no such process".to_string(),
                ),
            ],
            platform: "linux".to_string(),
            hostname: "testhost".to_string(),
        };

        let json = serde_json::to_string(&record).expect("serialize");
        let deserialized: ThreatAuditRecord = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.id, record.id);
        assert_eq!(deserialized.file_path, record.file_path);
        assert_eq!(deserialized.threat_name, record.threat_name);
        assert_eq!(deserialized.threat_level, record.threat_level);
        assert_eq!(deserialized.detection_type, record.detection_type);
        assert_eq!(deserialized.platform, record.platform);
        assert_eq!(deserialized.hostname, record.hostname);
        assert_eq!(deserialized.actions_taken.len(), 2);
        assert!(deserialized.actions_taken[0].success);
        assert!(!deserialized.actions_taken[1].success);
        assert_eq!(deserialized.actions_taken[1].error.as_deref(), Some("no such process"));
    }

    #[test]
    fn persistence_type_variants_serialize() {
        let types = vec![
            PersistenceType::Crontab,
            PersistenceType::SystemdService,
            PersistenceType::LaunchAgent,
            PersistenceType::RegistryRun,
            PersistenceType::ShellRc,
        ];
        for pt in &types {
            let json = serde_json::to_string(pt).expect("serialize");
            let deserialized: PersistenceType = serde_json::from_str(&json).expect("deserialize");
            // Just verify roundtrip doesn't fail
            let json2 = serde_json::to_string(&deserialized).expect("re-serialize");
            assert_eq!(json, json2);
        }
    }
}
