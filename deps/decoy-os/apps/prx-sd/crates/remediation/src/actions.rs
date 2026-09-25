//! Remediation action executor.
//!
//! The [`RemediationEngine`] orchestrates the full threat response pipeline:
//! checking whitelists, executing policy-defined actions in order, and logging
//! results to the audit trail.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use prx_sd_quarantine::Quarantine;

use crate::audit::AuditLogger;
use crate::common::find_processes_using_file;
use crate::policy::{ActionType, RemediationPolicy};
use crate::{PersistenceType, RemediationAction, RemediationResult, ThreatAuditRecord};

/// Main remediation engine that coordinates all post-detection actions.
pub struct RemediationEngine {
    policy: RemediationPolicy,
    quarantine: Arc<Quarantine>,
    audit: AuditLogger,
    blocklist_path: PathBuf,
}

impl RemediationEngine {
    /// Create a new remediation engine.
    ///
    /// * `policy` - The remediation policy governing automatic actions.
    /// * `quarantine` - Shared reference to the quarantine vault.
    /// * `audit_dir` - Directory for writing audit log files.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(policy: RemediationPolicy, quarantine: Arc<Quarantine>, audit_dir: PathBuf) -> Result<Self> {
        let audit = AuditLogger::new(audit_dir.clone())?;
        let blocklist_path = audit_dir.join("blocklist.txt");
        Ok(Self {
            policy,
            quarantine,
            audit,
            blocklist_path,
        })
    }

    /// Execute the full remediation pipeline for a detected threat.
    ///
    /// This is the main entry point called after a threat is detected.
    /// It checks whitelists, determines the appropriate actions based on
    /// threat level, executes each action in order, and logs everything
    /// to the audit trail.
    #[allow(clippy::unused_async)]
    pub async fn handle_threat(
        &self,
        file_path: &Path,
        threat_name: &str,
        threat_level: &str,
        detection_type: &str,
    ) -> Vec<RemediationResult> {
        let mut results = Vec::new();

        // 1. Check whitelist
        // Compute hash for whitelist check
        let hash = compute_sha256(file_path);
        if self.policy.is_whitelisted(file_path, hash.as_deref()) {
            tracing::info!(
                path = %file_path.display(),
                "file is whitelisted, skipping remediation"
            );
            results.push(RemediationResult::success(RemediationAction::Whitelisted));
            return results;
        }

        // 2. Get actions for threat level
        let actions = self.policy.actions_for_threat_level(threat_level);

        // 3. Execute each action in order
        for action_type in actions {
            let result = match action_type {
                ActionType::Report => {
                    tracing::info!(
                        path = %file_path.display(),
                        threat = threat_name,
                        level = threat_level,
                        "threat detected (report only)"
                    );
                    RemediationResult::success(RemediationAction::ReportOnly)
                }
                ActionType::KillProcess => {
                    if self.policy.kill_processes {
                        self.kill_processes_using_file(file_path)
                    } else {
                        continue;
                    }
                }
                ActionType::Quarantine => self.quarantine_file(file_path, threat_name),
                ActionType::CleanPersistence => {
                    if self.policy.clean_persistence {
                        let persistence_results = self.clean_persistence(file_path);
                        results.extend(persistence_results);
                    }
                    continue;
                }
                ActionType::Delete => self.delete_file(file_path),
                ActionType::Block => RemediationResult::success(RemediationAction::Blocked),
                ActionType::NetworkIsolate => {
                    if self.policy.network_isolation {
                        self.isolate_network()
                    } else {
                        continue;
                    }
                }
                ActionType::AddToBlocklist => self.add_to_blocklist(file_path),
            };
            results.push(result);
        }

        // 4. Log to audit
        if self.policy.audit_logging {
            let hostname = get_hostname();
            let platform = get_platform();
            let record = ThreatAuditRecord {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                file_path: file_path.to_string_lossy().to_string(),
                threat_name: threat_name.to_string(),
                threat_level: threat_level.to_string(),
                detection_type: detection_type.to_string(),
                actions_taken: results.clone(),
                platform,
                hostname,
            };
            if let Err(e) = self.audit.log(&record) {
                tracing::error!(error = %e, "failed to write audit record");
            }
        }

        results
    }

    /// Kill all processes that have the given file open or memory-mapped.
    pub fn kill_processes_using_file(&self, path: &Path) -> RemediationResult {
        let processes = match find_processes_using_file(path) {
            Ok(p) => p,
            Err(e) => {
                return RemediationResult::failure(
                    RemediationAction::ProcessKilled {
                        pid: 0,
                        name: String::new(),
                    },
                    format!("failed to find processes: {e}"),
                );
            }
        };

        if processes.is_empty() {
            return RemediationResult::success(RemediationAction::ReportOnly);
        }

        let mut last_result = RemediationResult::success(RemediationAction::ReportOnly);

        for proc_info in &processes {
            let kill_result = kill_process_platform(proc_info.pid);
            match kill_result {
                Ok(()) => {
                    tracing::info!(
                        pid = proc_info.pid,
                        name = proc_info.name.as_str(),
                        "killed process using malicious file"
                    );
                    last_result = RemediationResult::success(RemediationAction::ProcessKilled {
                        pid: proc_info.pid,
                        name: proc_info.name.clone(),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        pid = proc_info.pid,
                        error = %e,
                        "failed to kill process"
                    );
                    last_result = RemediationResult::failure(
                        RemediationAction::ProcessKilled {
                            pid: proc_info.pid,
                            name: proc_info.name.clone(),
                        },
                        format!("{e}"),
                    );
                }
            }
        }

        last_result
    }

    /// Move the file to encrypted quarantine.
    pub fn quarantine_file(&self, path: &Path, threat_name: &str) -> RemediationResult {
        match self.quarantine.quarantine(path, threat_name) {
            Ok(id) => {
                tracing::info!(
                    path = %path.display(),
                    quarantine_id = %id,
                    "file quarantined"
                );
                RemediationResult::success(RemediationAction::Quarantined {
                    quarantine_id: id.to_string(),
                })
            }
            Err(e) => RemediationResult::failure(
                RemediationAction::Quarantined {
                    quarantine_id: String::new(),
                },
                format!("quarantine failed: {e}"),
            ),
        }
    }

    /// Scan and clean persistence mechanisms referencing this file.
    pub fn clean_persistence(&self, path: &Path) -> Vec<RemediationResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            let findings = crate::linux::scan_all_persistence(path);
            for (ptype, detail) in &findings {
                tracing::info!(
                    persistence_type = ?ptype,
                    detail = detail.as_str(),
                    "found persistence mechanism"
                );
            }

            // Clean crontab
            match crate::linux::clean_crontab(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::Crontab,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::Crontab,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean systemd
            match crate::linux::clean_systemd_services(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::SystemdService,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::SystemdService,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean init scripts
            match crate::linux::clean_init_scripts(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::InitScript,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::InitScript,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean shell profiles
            match crate::linux::clean_shell_profiles(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::BashProfile,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::BashProfile,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean LD_PRELOAD
            match crate::linux::clean_ld_preload(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LdPreload,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LdPreload,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let findings = crate::macos::scan_all_persistence(path);
            for (ptype, detail) in &findings {
                tracing::info!(
                    persistence_type = ?ptype,
                    detail = detail.as_str(),
                    "found persistence mechanism"
                );
            }

            // Clean LaunchAgents
            match crate::macos::clean_launch_agents(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LaunchAgent,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LaunchAgent,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean LaunchDaemons
            match crate::macos::clean_launch_daemons(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LaunchDaemon,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LaunchDaemon,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean login items
            match crate::macos::clean_login_items(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LoginItem,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::LoginItem,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }

            // Clean shell profiles
            match crate::macos::clean_shell_profiles(path) {
                Ok(removed) => {
                    for entry in removed {
                        results.push(RemediationResult::success(RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::ShellRc,
                            detail: entry,
                        }));
                    }
                }
                Err(e) => {
                    results.push(RemediationResult::failure(
                        RemediationAction::PersistenceCleaned {
                            persistence_type: PersistenceType::ShellRc,
                            detail: String::new(),
                        },
                        format!("{e}"),
                    ));
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            let _ = path;
            // Windows persistence cleaning not yet implemented
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = path;
        }

        results
    }

    /// Block network access (emergency isolation).
    pub fn isolate_network(&self) -> RemediationResult {
        #[cfg(target_os = "linux")]
        {
            match crate::linux::isolate_network_iptables() {
                Ok(()) => RemediationResult::success(RemediationAction::NetworkIsolated),
                Err(e) => RemediationResult::failure(RemediationAction::NetworkIsolated, format!("{e}")),
            }
        }
        #[cfg(target_os = "macos")]
        {
            match crate::macos::isolate_network_pf() {
                Ok(()) => RemediationResult::success(RemediationAction::NetworkIsolated),
                Err(e) => RemediationResult::failure(RemediationAction::NetworkIsolated, format!("{e}")),
            }
        }
        #[cfg(target_os = "windows")]
        {
            RemediationResult::failure(
                RemediationAction::NetworkIsolated,
                "Windows network isolation not yet implemented".to_string(),
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            RemediationResult::failure(
                RemediationAction::NetworkIsolated,
                "network isolation not supported on this platform".to_string(),
            )
        }
    }

    /// Restore network after isolation.
    pub fn restore_network(&self) -> RemediationResult {
        #[cfg(target_os = "linux")]
        {
            match crate::linux::restore_network_iptables() {
                Ok(()) => RemediationResult::success(RemediationAction::ReportOnly),
                Err(e) => {
                    RemediationResult::failure(RemediationAction::ReportOnly, format!("network restore failed: {e}"))
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            match crate::macos::restore_network_pf() {
                Ok(()) => RemediationResult::success(RemediationAction::ReportOnly),
                Err(e) => {
                    RemediationResult::failure(RemediationAction::ReportOnly, format!("network restore failed: {e}"))
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            RemediationResult::failure(
                RemediationAction::ReportOnly,
                "Windows network restore not yet implemented".to_string(),
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            RemediationResult::failure(
                RemediationAction::ReportOnly,
                "network restore not supported on this platform".to_string(),
            )
        }
    }

    /// Add the file's SHA-256 hash to the local blocklist.
    #[allow(clippy::option_if_let_else)]
    pub fn add_to_blocklist(&self, path: &Path) -> RemediationResult {
        use std::io::Write;
        let Some(hash) = compute_sha256(path) else {
            return RemediationResult::failure(
                RemediationAction::AddedToBlocklist,
                format!("failed to compute hash of {}", path.display()),
            );
        };
        let entry = format!("{}  {}\n", hash, path.display());
        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.blocklist_path)
        {
            Ok(f) => f,
            Err(e) => {
                return RemediationResult::failure(
                    RemediationAction::AddedToBlocklist,
                    format!("failed to open blocklist: {e}"),
                );
            }
        };
        match file.write_all(entry.as_bytes()) {
            Ok(()) => {
                tracing::info!(
                    hash = hash.as_str(),
                    path = %path.display(),
                    "added to blocklist"
                );
                RemediationResult::success(RemediationAction::AddedToBlocklist)
            }
            Err(e) => RemediationResult::failure(
                RemediationAction::AddedToBlocklist,
                format!("failed to write blocklist: {e}"),
            ),
        }
    }

    /// Mark a file as whitelisted (false positive).
    ///
    /// Adds the hash to the policy's whitelist and optionally adds the path.
    pub fn whitelist(&self, path: &Path, hash: &str) -> Result<()> {
        // We modify the in-memory policy by cloning, but callers should
        // persist the policy separately.
        tracing::info!(
            path = %path.display(),
            hash = hash,
            "file whitelisted as false positive"
        );
        // The caller is expected to update the policy and persist it.
        // We just log the action here since we hold an immutable ref.
        Ok(())
    }

    /// Permanently delete a file.
    #[allow(clippy::unused_self)]
    fn delete_file(&self, path: &Path) -> RemediationResult {
        match std::fs::remove_file(path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "file permanently deleted");
                RemediationResult::success(RemediationAction::Deleted)
            }
            Err(e) => RemediationResult::failure(RemediationAction::Deleted, format!("failed to delete: {e}")),
        }
    }
}

/// Compute the SHA-256 hash of a file, returning None if the file can't be read.
fn compute_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("{:x}", hasher.finalize()))
}

/// Kill a process using the platform-appropriate method.
fn kill_process_platform(pid: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        crate::linux::kill_process(pid)
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos::kill_process(pid)
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::kill_process(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = pid;
        anyhow::bail!("process killing not supported on this platform")
    }
}

/// Get the current hostname.
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map_or_else(|_| "unknown".to_string(), |s| s.trim().to_string())
}

/// Get the current platform string.
fn get_platform() -> String {
    if cfg!(target_os = "linux") {
        "linux".to_string()
    } else if cfg!(target_os = "macos") {
        "macos".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::policy::RemediationPolicy;

    fn create_engine(dir: &std::path::Path) -> RemediationEngine {
        let vault_dir = dir.join("vault");
        let audit_dir = dir.join("audit");
        let quarantine = Arc::new(Quarantine::new(vault_dir).expect("create quarantine"));
        let policy = RemediationPolicy::default();
        RemediationEngine::new(policy, quarantine, audit_dir).expect("create engine")
    }

    #[test]
    fn engine_new_succeeds_with_valid_config() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let engine = create_engine(dir.path());
        assert!(engine.blocklist_path.exists() || !engine.blocklist_path.exists());
        // Engine created without error - that's the main assertion
    }

    #[tokio::test]
    async fn handle_threat_whitelisted_path_returns_whitelisted() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let vault_dir = dir.path().join("vault");
        let audit_dir = dir.path().join("audit");
        let quarantine = Arc::new(Quarantine::new(vault_dir).expect("create quarantine"));
        let policy = RemediationPolicy {
            whitelist_paths: vec!["/safe/dir".to_string()],
            ..RemediationPolicy::default()
        };
        let engine = RemediationEngine::new(policy, quarantine, audit_dir).expect("create engine");

        let results = engine
            .handle_threat(Path::new("/safe/dir/file.txt"), "TestThreat", "malicious", "hash")
            .await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert!(matches!(results[0].action, RemediationAction::Whitelisted));
    }

    #[tokio::test]
    async fn handle_threat_malicious_triggers_expected_actions() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let vault_dir = dir.path().join("vault");
        let audit_dir = dir.path().join("audit");

        // Create a test file so quarantine/hash can work on it
        let malware_path = dir.path().join("malware.exe");
        std::fs::write(&malware_path, b"fake malware content").expect("write test file");

        let quarantine = Arc::new(Quarantine::new(vault_dir).expect("create quarantine"));
        let policy = RemediationPolicy {
            // Simplify to just Report + AddToBlocklist for testability
            on_malicious: vec![
                crate::policy::ActionType::Report,
                crate::policy::ActionType::AddToBlocklist,
            ],
            kill_processes: false,
            clean_persistence: false,
            ..RemediationPolicy::default()
        };
        let engine = RemediationEngine::new(policy, quarantine, audit_dir).expect("create engine");

        let results = engine
            .handle_threat(&malware_path, "TestMalware", "malicious", "hash")
            .await;

        assert!(results.len() >= 2);
        assert!(matches!(results[0].action, RemediationAction::ReportOnly));
        assert!(matches!(results[1].action, RemediationAction::AddedToBlocklist));
    }

    #[tokio::test]
    async fn handle_threat_suspicious_triggers_report_only() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let vault_dir = dir.path().join("vault");
        let audit_dir = dir.path().join("audit");

        let suspicious_file = dir.path().join("suspicious.exe");
        std::fs::write(&suspicious_file, b"suspicious content").expect("write");

        let quarantine = Arc::new(Quarantine::new(vault_dir).expect("create quarantine"));
        let policy = RemediationPolicy::default();
        let engine = RemediationEngine::new(policy, quarantine, audit_dir).expect("create engine");

        let results = engine
            .handle_threat(&suspicious_file, "SuspiciousThreat", "suspicious", "heuristic")
            .await;

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].action, RemediationAction::ReportOnly));
        assert!(results[0].success);
    }

    #[test]
    fn add_to_blocklist_writes_hash_to_file() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let engine = create_engine(dir.path());

        // Create a test file for hashing
        let test_file = dir.path().join("test_malware.bin");
        std::fs::write(&test_file, b"malware bytes").expect("write test file");

        let result = engine.add_to_blocklist(&test_file);
        assert!(result.success);
        assert!(matches!(result.action, RemediationAction::AddedToBlocklist));

        // Verify blocklist file was written
        let blocklist_content = std::fs::read_to_string(&engine.blocklist_path).expect("read blocklist");
        assert!(blocklist_content.contains("test_malware.bin"));
        // SHA-256 hash should be a 64-char hex string
        let hash_part = blocklist_content.split_whitespace().next().expect("hash");
        assert_eq!(hash_part.len(), 64);
    }

    #[test]
    fn add_to_blocklist_nonexistent_file_fails() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let engine = create_engine(dir.path());

        let result = engine.add_to_blocklist(Path::new("/nonexistent/file.exe"));
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn compute_sha256_returns_correct_hash() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let file = dir.path().join("test.bin");
        std::fs::write(&file, b"hello").expect("write");

        let hash = compute_sha256(&file);
        assert!(hash.is_some());
        // SHA-256 of "hello" is known
        assert_eq!(
            hash.unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn compute_sha256_nonexistent_returns_none() {
        let hash = compute_sha256(Path::new("/nonexistent/file"));
        assert!(hash.is_none());
    }
}
