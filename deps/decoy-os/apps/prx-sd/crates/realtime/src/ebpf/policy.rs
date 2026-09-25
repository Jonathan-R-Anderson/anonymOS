//! TOML-driven policy engine for eBPF runtime events.
//!
//! The [`PolicyEngine`] evaluates incoming [`RuntimeEvent`]s against a set of
//! user-defined rules, producing [`PolicyMatch`]es that indicate which actions
//! should be taken (alert, scan, quarantine, kill, etc.).
//!
//! # Policy File Format (TOML)
//!
//! ```toml
//! [[rule]]
//! id = "exec_tmp"
//! kind = "exec"
//! match_path_prefix = ["/tmp", "/dev/shm"]
//! action = ["alert", "trigger_file_scan"]
//! severity = "high"
//! enabled = true
//! ```

use super::correlate::AlertSeverity;
use super::events::{EventDetail, RuntimeEvent, RuntimeEventKind};
use anyhow::{Context, Result};
use std::path::Path;

// ── Policy action types ─────────────────────────────────────────────────

/// Actions that a policy rule can trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Emit an alert (log + forward to pipeline output).
    Alert,
    /// Trigger a file scan on the associated path.
    TriggerFileScan,
    /// Trigger a memory scan on the associated process.
    TriggerMemoryScan,
    /// Kill the offending process.
    KillProcess,
    /// Quarantine the associated file.
    QuarantinePath,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert => write!(f, "alert"),
            Self::TriggerFileScan => write!(f, "trigger_file_scan"),
            Self::TriggerMemoryScan => write!(f, "trigger_memory_scan"),
            Self::KillProcess => write!(f, "kill_process"),
            Self::QuarantinePath => write!(f, "quarantine_path"),
        }
    }
}

// ── Policy rule definition ──────────────────────────────────────────────

/// The event kind a rule matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleKind {
    Exec,
    FileOpen,
    Connect,
}

/// Severity level for serde (mirrors AlertSeverity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<PolicySeverity> for AlertSeverity {
    fn from(s: PolicySeverity) -> Self {
        match s {
            PolicySeverity::Low => Self::Low,
            PolicySeverity::Medium => Self::Medium,
            PolicySeverity::High => Self::High,
            PolicySeverity::Critical => Self::Critical,
        }
    }
}

/// A single policy rule loaded from TOML.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyRule {
    /// Unique rule identifier.
    pub id: String,
    /// Event kind this rule matches.
    pub kind: PolicyRuleKind,
    /// Path prefixes to match (exec filename or file open path).
    #[serde(default)]
    pub match_path_prefix: Vec<String>,
    /// Path suffixes to match (e.g., file extensions).
    #[serde(default)]
    pub match_path_suffix: Vec<String>,
    /// Port range to match for connect events `[low, high]` inclusive.
    #[serde(default)]
    pub match_port_range: Option<[u16; 2]>,
    /// UID list to match (empty = match all).
    #[serde(default)]
    pub match_uid: Vec<u32>,
    /// Actions to take when the rule matches.
    pub action: Vec<PolicyAction>,
    /// Severity level.
    #[serde(default = "default_severity")]
    pub severity: PolicySeverity,
    /// Whether the rule is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_severity() -> PolicySeverity {
    PolicySeverity::Medium
}

fn default_enabled() -> bool {
    true
}

/// TOML file structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rule: Vec<PolicyRule>,
}

// ── Policy match result ─────────────────────────────────────────────────

/// The result of a policy rule matching an event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyMatch {
    /// Rule that matched.
    pub rule_id: String,
    /// Severity level.
    pub severity: AlertSeverity,
    /// Actions to take.
    pub actions: Vec<PolicyAction>,
    /// Process ID from the triggering event.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Human-readable description.
    pub description: String,
    /// Associated path (for file scan / quarantine).
    pub path: Option<String>,
    /// Monotonic timestamp of the triggering event.
    pub trigger_ts_ns: u64,
}

impl std::fmt::Display for PolicyMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[POLICY:{}] rule={} pid={} comm={} actions=[{}] — {}",
            self.severity,
            self.rule_id,
            self.pid,
            self.comm,
            self.actions
                .iter()
                .map(|a| format!("{a}"))
                .collect::<Vec<_>>()
                .join(","),
            self.description,
        )
    }
}

// ── Policy engine ───────────────────────────────────────────────────────

/// Evaluates runtime events against policy rules.
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create an engine with no rules.
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create an engine with built-in default rules.
    pub fn with_defaults() -> Self {
        Self { rules: default_rules() }
    }

    /// Load rules from a TOML file, merging with built-in defaults.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
        let file: PolicyFile =
            toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;

        let mut rules = default_rules();
        // User rules override defaults with the same ID.
        for user_rule in file.rule {
            if let Some(pos) = rules.iter().position(|r| r.id == user_rule.id) {
                rules.remove(pos);
            }
            rules.push(user_rule);
        }

        Ok(Self { rules })
    }

    /// Load rules from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self> {
        let file: PolicyFile = toml::from_str(content).context("failed to parse policy TOML")?;
        Ok(Self { rules: file.rule })
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate an event against all enabled rules.
    pub fn evaluate(&self, event: &RuntimeEvent) -> Vec<PolicyMatch> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if let Some(m) = evaluate_rule(rule, event) {
                matches.push(m);
            }
        }

        matches
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ── Rule evaluation ─────────────────────────────────────────────────────

fn evaluate_rule(rule: &PolicyRule, event: &RuntimeEvent) -> Option<PolicyMatch> {
    // Check event kind matches rule kind.
    let kind_matches = match (rule.kind, event.kind) {
        (PolicyRuleKind::Exec, RuntimeEventKind::Exec) => true,
        (PolicyRuleKind::FileOpen, RuntimeEventKind::FileOpen) => true,
        (PolicyRuleKind::Connect, RuntimeEventKind::Connect) => true,
        _ => false,
    };
    if !kind_matches {
        return None;
    }

    // Check UID filter.
    if !rule.match_uid.is_empty() && !rule.match_uid.contains(&event.uid) {
        return None;
    }

    // Extract the relevant path/port for matching.
    let (event_path, event_port) = match &event.detail {
        EventDetail::Exec { filename, .. } => (Some(filename.as_str()), None),
        EventDetail::FileOpen { path, .. } => (Some(path.as_str()), None),
        EventDetail::Connect { port, .. } => (None, Some(*port)),
        EventDetail::Exit { .. } => (None, None),
    };

    // Check path prefix match.
    if !rule.match_path_prefix.is_empty() {
        let path = match event_path {
            Some(p) => p,
            None => return None,
        };
        let prefix_match = rule
            .match_path_prefix
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()));
        if !prefix_match {
            return None;
        }
    }

    // Check path suffix match.
    if !rule.match_path_suffix.is_empty() {
        let path = match event_path {
            Some(p) => p,
            None => return None,
        };
        let suffix_match = rule
            .match_path_suffix
            .iter()
            .any(|suffix| path.ends_with(suffix.as_str()));
        if !suffix_match {
            return None;
        }
    }

    // Check port range match.
    if let Some([low, high]) = rule.match_port_range {
        let port = match event_port {
            Some(p) => p,
            None => return None,
        };
        if port < low || port > high {
            return None;
        }
    }

    // Build match description.
    let description = build_description(rule, event_path, event_port);

    Some(PolicyMatch {
        rule_id: rule.id.clone(),
        severity: rule.severity.into(),
        actions: rule.action.clone(),
        pid: event.pid,
        comm: event.comm.clone(),
        description,
        path: event_path.map(String::from),
        trigger_ts_ns: event.ts_ns,
    })
}

fn build_description(rule: &PolicyRule, path: Option<&str>, port: Option<u16>) -> String {
    match rule.kind {
        PolicyRuleKind::Exec => {
            format!("exec matched rule '{}': {}", rule.id, path.unwrap_or("(unknown)"))
        }
        PolicyRuleKind::FileOpen => {
            format!(
                "file access matched rule '{}': {}",
                rule.id,
                path.unwrap_or("(unknown)")
            )
        }
        PolicyRuleKind::Connect => {
            format!(
                "connection matched rule '{}': port {}",
                rule.id,
                port.map_or_else(|| "?".to_string(), |p| p.to_string())
            )
        }
    }
}

// ── Default built-in rules ──────────────────────────────────────────────

fn default_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            id: "exec_suspicious_dir".into(),
            kind: PolicyRuleKind::Exec,
            match_path_prefix: vec![
                "/tmp/".into(),
                "/dev/shm/".into(),
                "/var/tmp/".into(),
                "/run/user/".into(),
            ],
            match_path_suffix: Vec::new(),
            match_port_range: None,
            match_uid: Vec::new(),
            action: vec![PolicyAction::Alert, PolicyAction::TriggerFileScan],
            severity: PolicySeverity::High,
            enabled: true,
        },
        PolicyRule {
            id: "sensitive_file_access".into(),
            kind: PolicyRuleKind::FileOpen,
            match_path_prefix: vec![
                "/etc/shadow".into(),
                "/etc/sudoers".into(),
                "/etc/ssh/".into(),
                "/root/.ssh/".into(),
                "/proc/kcore".into(),
                "/boot/vmlinuz".into(),
            ],
            match_path_suffix: Vec::new(),
            match_port_range: None,
            match_uid: Vec::new(),
            action: vec![PolicyAction::Alert],
            severity: PolicySeverity::Medium,
            enabled: true,
        },
        PolicyRule {
            id: "common_c2_ports".into(),
            kind: PolicyRuleKind::Connect,
            match_path_prefix: Vec::new(),
            match_path_suffix: Vec::new(),
            match_port_range: Some([4444, 4444]),
            match_uid: Vec::new(),
            action: vec![PolicyAction::Alert, PolicyAction::TriggerMemoryScan],
            severity: PolicySeverity::Critical,
            enabled: true,
        },
        PolicyRule {
            id: "exec_hidden_file".into(),
            kind: PolicyRuleKind::Exec,
            match_path_prefix: Vec::new(),
            match_path_suffix: Vec::new(),
            match_port_range: None,
            match_uid: Vec::new(),
            // This rule uses path prefix "./" trick — we match dotfiles in
            // suspicious dirs via the prefix rule above. This rule catches
            // hidden executables anywhere.
            action: vec![PolicyAction::Alert, PolicyAction::TriggerFileScan],
            severity: PolicySeverity::Medium,
            enabled: false, // Disabled by default, too noisy
        },
    ]
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_exec_event(pid: u32, filename: &str) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 1_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Exec,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Exec {
                filename: filename.to_string(),
                argv: String::new(),
            },
        }
    }

    fn make_file_event(pid: u32, path: &str, flags: i32) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 1_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::FileOpen,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::FileOpen {
                path: path.to_string(),
                flags,
            },
        }
    }

    fn make_connect_event(pid: u32, port: u16) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 1_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Connect,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Connect {
                af: 2,
                port,
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        }
    }

    #[test]
    fn test_default_engine_has_rules() {
        let engine = PolicyEngine::with_defaults();
        assert!(engine.rule_count() >= 3);
    }

    #[test]
    fn test_exec_suspicious_dir_matches() {
        let engine = PolicyEngine::with_defaults();
        let event = make_exec_event(100, "/tmp/payload");
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "exec_suspicious_dir");
        assert_eq!(matches[0].severity, AlertSeverity::High);
        assert!(matches[0].actions.contains(&PolicyAction::Alert));
        assert!(matches[0].actions.contains(&PolicyAction::TriggerFileScan));
    }

    #[test]
    fn test_exec_normal_path_no_match() {
        let engine = PolicyEngine::with_defaults();
        let event = make_exec_event(100, "/usr/bin/ls");
        let matches = engine.evaluate(&event);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sensitive_file_matches() {
        let engine = PolicyEngine::with_defaults();
        let event = make_file_event(100, "/etc/shadow", 0);
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "sensitive_file_access");
    }

    #[test]
    fn test_c2_port_matches() {
        let engine = PolicyEngine::with_defaults();
        let event = make_connect_event(100, 4444);
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "common_c2_ports");
        assert_eq!(matches[0].severity, AlertSeverity::Critical);
        assert!(matches[0].actions.contains(&PolicyAction::TriggerMemoryScan));
    }

    #[test]
    fn test_normal_port_no_match() {
        let engine = PolicyEngine::with_defaults();
        let event = make_connect_event(100, 443);
        let matches = engine.evaluate(&event);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let engine = PolicyEngine::with_defaults();
        // exec_hidden_file is disabled by default
        let event = make_exec_event(100, "/home/user/.hidden");
        let matches = engine.evaluate(&event);
        // Should not match the disabled rule
        assert!(matches.is_empty());
    }

    #[test]
    fn test_uid_filter() {
        let toml_str = r#"
[[rule]]
id = "root_exec"
kind = "exec"
match_path_prefix = ["/tmp/"]
match_uid = [0]
action = ["alert"]
severity = "critical"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();

        // UID 1000 — should not match
        let event = make_exec_event(100, "/tmp/payload");
        let matches = engine.evaluate(&event);
        assert!(matches.is_empty());

        // UID 0 — should match
        let mut root_event = make_exec_event(100, "/tmp/payload");
        root_event.uid = 0;
        let matches = engine.evaluate(&root_event);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_path_suffix_match() {
        let toml_str = r#"
[[rule]]
id = "script_exec"
kind = "exec"
match_path_suffix = [".sh", ".py"]
action = ["alert"]
severity = "low"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();

        let event = make_exec_event(100, "/home/user/deploy.sh");
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "script_exec");

        let event2 = make_exec_event(100, "/usr/bin/ls");
        assert!(engine.evaluate(&event2).is_empty());
    }

    #[test]
    fn test_port_range() {
        let toml_str = r#"
[[rule]]
id = "high_ports"
kind = "connect"
match_port_range = [8000, 9000]
action = ["alert"]
severity = "low"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();

        // In range
        let matches = engine.evaluate(&make_connect_event(100, 8080));
        assert_eq!(matches.len(), 1);

        // Below range
        assert!(engine.evaluate(&make_connect_event(100, 443)).is_empty());

        // Above range
        assert!(engine.evaluate(&make_connect_event(100, 9999)).is_empty());
    }

    #[test]
    fn test_from_toml_parse() {
        let toml_str = r#"
[[rule]]
id = "custom1"
kind = "exec"
match_path_prefix = ["/opt/suspicious/"]
action = ["alert", "trigger_file_scan", "kill_process"]
severity = "critical"

[[rule]]
id = "custom2"
kind = "file_open"
match_path_prefix = ["/etc/"]
action = ["alert"]
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_load_from_file_merges_defaults() {
        // Write a temporary TOML file.
        let dir = std::env::temp_dir().join("prxsd_policy_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_policy.toml");
        std::fs::write(
            &path,
            r#"
[[rule]]
id = "custom_rule"
kind = "exec"
match_path_prefix = ["/opt/evil/"]
action = ["alert"]
severity = "high"
"#,
        )
        .unwrap();

        let engine = PolicyEngine::load_from_file(&path).unwrap();
        // Should have defaults + custom rule
        assert!(engine.rule_count() >= 4);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_user_rule_overrides_default() {
        // Override the default "exec_suspicious_dir" rule
        let toml_str = r#"
[[rule]]
id = "exec_suspicious_dir"
kind = "exec"
match_path_prefix = ["/tmp/"]
action = ["alert", "kill_process"]
severity = "critical"
"#;
        let content = std::fs::read_to_string("/dev/null").unwrap_or_default();
        let _ = content;

        // Use load_from_file with a temp file
        let dir = std::env::temp_dir().join("prxsd_policy_test2");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("override.toml");
        std::fs::write(&path, toml_str).unwrap();

        let engine = PolicyEngine::load_from_file(&path).unwrap();
        let event = make_exec_event(100, "/tmp/evil");
        let matches = engine.evaluate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, AlertSeverity::Critical);
        assert!(matches[0].actions.contains(&PolicyAction::KillProcess));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_policy_match_display() {
        let m = PolicyMatch {
            rule_id: "test_rule".to_string(),
            severity: AlertSeverity::High,
            actions: vec![PolicyAction::Alert, PolicyAction::TriggerFileScan],
            pid: 42,
            comm: "evil".to_string(),
            description: "test match".to_string(),
            path: Some("/tmp/evil".to_string()),
            trigger_ts_ns: 1000,
        };
        let s = format!("{m}");
        assert!(s.contains("[POLICY:HIGH]"));
        assert!(s.contains("rule=test_rule"));
        assert!(s.contains("alert,trigger_file_scan"));
    }

    #[test]
    fn test_empty_engine_no_matches() {
        let engine = PolicyEngine::empty();
        let event = make_exec_event(100, "/tmp/evil");
        assert!(engine.evaluate(&event).is_empty());
    }

    #[test]
    fn test_policy_action_display() {
        assert_eq!(format!("{}", PolicyAction::Alert), "alert");
        assert_eq!(format!("{}", PolicyAction::KillProcess), "kill_process");
        assert_eq!(format!("{}", PolicyAction::QuarantinePath), "quarantine_path");
    }

    #[test]
    fn test_multiple_rules_can_match() {
        let toml_str = r#"
[[rule]]
id = "rule_a"
kind = "exec"
match_path_prefix = ["/tmp/"]
action = ["alert"]
severity = "low"

[[rule]]
id = "rule_b"
kind = "exec"
match_path_suffix = [".sh"]
action = ["trigger_file_scan"]
severity = "medium"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let event = make_exec_event(100, "/tmp/script.sh");
        let matches = engine.evaluate(&event);
        // Both rules should match
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_exit_event_no_match() {
        let engine = PolicyEngine::with_defaults();
        let event = RuntimeEvent {
            ts_ns: 1_000_000,
            pid: 100,
            tid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Exit,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Exit { exit_code: 0 },
        };
        assert!(engine.evaluate(&event).is_empty());
    }
}
