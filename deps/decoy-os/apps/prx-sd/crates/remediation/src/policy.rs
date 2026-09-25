//! Configurable auto-response policy for threat remediation.
//!
//! Defines what actions are taken automatically when threats of various
//! severity levels are detected, along with whitelisting support.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Defines what to do automatically when threats are detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct RemediationPolicy {
    /// What to do for Malicious detections.
    pub on_malicious: Vec<ActionType>,
    /// What to do for Suspicious detections.
    pub on_suspicious: Vec<ActionType>,
    /// Whitelisted SHA-256 hashes (never act on these).
    pub whitelist_hashes: Vec<String>,
    /// Whitelisted paths (never act on files here).
    pub whitelist_paths: Vec<String>,
    /// Whether to kill processes using malicious files.
    pub kill_processes: bool,
    /// Whether to clean persistence mechanisms.
    pub clean_persistence: bool,
    /// Whether to isolate network on critical threats.
    pub network_isolation: bool,
    /// Log all actions to audit log.
    pub audit_logging: bool,
}

/// Type of remediation action in a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Report,
    Quarantine,
    Block,
    KillProcess,
    CleanPersistence,
    Delete,
    NetworkIsolate,
    AddToBlocklist,
}

impl Default for RemediationPolicy {
    fn default() -> Self {
        Self {
            on_malicious: vec![
                ActionType::KillProcess,
                ActionType::Quarantine,
                ActionType::CleanPersistence,
                ActionType::AddToBlocklist,
            ],
            on_suspicious: vec![ActionType::Report],
            whitelist_hashes: vec![],
            whitelist_paths: vec![],
            kill_processes: true,
            clean_persistence: true,
            network_isolation: false,
            audit_logging: true,
        }
    }
}

impl RemediationPolicy {
    /// Load a remediation policy from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("failed to read policy file: {}", path.display()))?;
        let policy: Self = serde_json::from_str(&data).context("failed to parse remediation policy JSON")?;
        Ok(policy)
    }

    /// Save the remediation policy to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("failed to serialize remediation policy")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create parent directory: {}", parent.display()))?;
        }
        std::fs::write(path, json).with_context(|| format!("failed to write policy file: {}", path.display()))?;
        Ok(())
    }

    /// Check if a file is whitelisted by path or hash.
    pub fn is_whitelisted(&self, path: &Path, hash: Option<&str>) -> bool {
        let path_str = path.to_string_lossy();

        // Check path whitelist
        for wp in &self.whitelist_paths {
            if path_str.starts_with(wp.as_str()) {
                return true;
            }
        }

        // Check hash whitelist
        if let Some(h) = hash {
            let h_lower = h.to_lowercase();
            for wh in &self.whitelist_hashes {
                if wh.to_lowercase() == h_lower {
                    return true;
                }
            }
        }

        false
    }

    /// Get the list of actions configured for a given threat level string.
    pub fn actions_for_threat_level(&self, level: &str) -> &[ActionType] {
        match level.to_lowercase().as_str() {
            "malicious" => &self.on_malicious,
            "suspicious" => &self.on_suspicious,
            _ => &[],
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn default_has_expected_malicious_actions() {
        let policy = RemediationPolicy::default();
        assert_eq!(policy.on_malicious.len(), 4);
        assert!(matches!(policy.on_malicious[0], ActionType::KillProcess));
        assert!(matches!(policy.on_malicious[1], ActionType::Quarantine));
        assert!(matches!(policy.on_malicious[2], ActionType::CleanPersistence));
        assert!(matches!(policy.on_malicious[3], ActionType::AddToBlocklist));
    }

    #[test]
    fn default_has_expected_suspicious_actions() {
        let policy = RemediationPolicy::default();
        assert_eq!(policy.on_suspicious.len(), 1);
        assert!(matches!(policy.on_suspicious[0], ActionType::Report));
    }

    #[test]
    fn default_flags_are_correct() {
        let policy = RemediationPolicy::default();
        assert!(policy.kill_processes);
        assert!(policy.clean_persistence);
        assert!(!policy.network_isolation);
        assert!(policy.audit_logging);
        assert!(policy.whitelist_hashes.is_empty());
        assert!(policy.whitelist_paths.is_empty());
    }

    #[test]
    fn load_save_roundtrip() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("policy.json");

        let original = RemediationPolicy {
            on_malicious: vec![ActionType::Quarantine, ActionType::Delete],
            on_suspicious: vec![ActionType::Report, ActionType::Block],
            whitelist_hashes: vec!["abc123".to_string()],
            whitelist_paths: vec!["/safe/dir".to_string()],
            kill_processes: false,
            clean_persistence: true,
            network_isolation: true,
            audit_logging: false,
        };

        original.save(&path).expect("save policy");
        let loaded = RemediationPolicy::load(&path).expect("load policy");

        assert_eq!(loaded.on_malicious.len(), original.on_malicious.len());
        assert_eq!(loaded.on_suspicious.len(), original.on_suspicious.len());
        assert_eq!(loaded.whitelist_hashes, original.whitelist_hashes);
        assert_eq!(loaded.whitelist_paths, original.whitelist_paths);
        assert_eq!(loaded.kill_processes, original.kill_processes);
        assert_eq!(loaded.clean_persistence, original.clean_persistence);
        assert_eq!(loaded.network_isolation, original.network_isolation);
        assert_eq!(loaded.audit_logging, original.audit_logging);
    }

    #[test]
    fn is_whitelisted_by_path() {
        let policy = RemediationPolicy {
            whitelist_paths: vec!["/safe/dir".to_string()],
            ..RemediationPolicy::default()
        };

        assert!(policy.is_whitelisted(Path::new("/safe/dir/file.exe"), None));
        assert!(!policy.is_whitelisted(Path::new("/other/file.exe"), None));
    }

    #[test]
    fn is_whitelisted_by_hash() {
        let policy = RemediationPolicy {
            whitelist_hashes: vec!["AABBCCDD1122334455667788".to_string()],
            ..RemediationPolicy::default()
        };

        // Case-insensitive match
        assert!(policy.is_whitelisted(Path::new("/any/file"), Some("aabbccdd1122334455667788"),));
        assert!(!policy.is_whitelisted(Path::new("/any/file"), Some("0000000000000000"),));
        // No hash provided
        assert!(!policy.is_whitelisted(Path::new("/any/file"), None));
    }

    #[test]
    fn actions_for_malicious_returns_on_malicious() {
        let policy = RemediationPolicy::default();
        let actions = policy.actions_for_threat_level("malicious");
        assert_eq!(actions.len(), policy.on_malicious.len());
    }

    #[test]
    fn actions_for_suspicious_returns_on_suspicious() {
        let policy = RemediationPolicy::default();
        let actions = policy.actions_for_threat_level("suspicious");
        assert_eq!(actions.len(), policy.on_suspicious.len());
    }

    #[test]
    fn actions_for_unknown_returns_empty() {
        let policy = RemediationPolicy::default();
        let actions = policy.actions_for_threat_level("unknown");
        assert!(actions.is_empty());

        let actions = policy.actions_for_threat_level("clean");
        assert!(actions.is_empty());
    }

    #[test]
    fn actions_for_threat_level_is_case_insensitive() {
        let policy = RemediationPolicy::default();
        let actions = policy.actions_for_threat_level("MALICIOUS");
        assert_eq!(actions.len(), policy.on_malicious.len());

        let actions = policy.actions_for_threat_level("Suspicious");
        assert_eq!(actions.len(), policy.on_suspicious.len());
    }

    #[test]
    fn malformed_json_returns_error() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "this is not json {{{").expect("write bad json");

        let result = RemediationPolicy::load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let result = RemediationPolicy::load(Path::new("/nonexistent/path/policy.json"));
        assert!(result.is_err());
    }
}
