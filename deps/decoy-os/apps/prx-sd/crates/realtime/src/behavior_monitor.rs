//! Process behavior monitoring via `/proc` and audit log parsing.
//!
//! This module provides a userspace behavior monitor that tracks process
//! activity (execve, connect, open syscalls) without requiring eBPF. It
//! uses two data sources:
//!
//! 1. **`/proc` polling** — scans `/proc/{pid}/fd`, `/proc/{pid}/net/tcp`,
//!    and `/proc/{pid}/status` for live process state.
//! 2. **Audit log parsing** — reads `/var/log/audit/audit.log` for
//!    historical syscall events.
//!
//! Each process accumulates a [`ProcessBehaviorScore`] based on observed
//! behaviors, and a [`BehaviorVerdict`] is returned per-process.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration for the behavior monitor.
#[derive(Debug, Clone)]
pub struct BehaviorConfig {
    /// Polling interval in milliseconds.
    pub poll_interval_ms: u64,
    /// Score threshold above which a process is considered suspicious.
    pub score_threshold_suspicious: u32,
    /// Score threshold above which a process is considered malicious.
    pub score_threshold_malicious: u32,
    /// Paths considered sensitive (access to these increases the score).
    pub sensitive_paths: Vec<String>,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1000,
            score_threshold_suspicious: 30,
            score_threshold_malicious: 60,
            sensitive_paths: vec![
                "/etc/shadow".into(),
                "/etc/passwd".into(),
                "/etc/sudoers".into(),
                "/root/.ssh".into(),
                "/home".into(), // .ssh dirs under /home
                "/etc/crontab".into(),
                "/var/spool/cron".into(),
            ],
        }
    }
}

/// Per-process behavior counters and cumulative score.
#[derive(Debug, Clone)]
pub struct ProcessBehaviorScore {
    /// Process ID.
    pub pid: u32,
    /// Process name (best effort from `/proc/{pid}/comm`).
    pub process_name: String,
    /// Number of child processes spawned (observed via `/proc/{pid}/task` or audit).
    pub exec_count: u32,
    /// Number of network connections (observed via `/proc/{pid}/net/tcp`).
    pub connect_count: u32,
    /// Number of writable file descriptors (proxy for file writes).
    pub file_write_count: u32,
    /// Number of accesses to sensitive paths.
    pub sensitive_access: u32,
    /// Aggregate threat score.
    pub total_score: u32,
}

impl ProcessBehaviorScore {
    const fn new(pid: u32, process_name: String) -> Self {
        Self {
            pid,
            process_name,
            exec_count: 0,
            connect_count: 0,
            file_write_count: 0,
            sensitive_access: 0,
            total_score: 0,
        }
    }

    /// Recalculate the total score from counters.
    const fn recalculate(&mut self) {
        // Weights: exec=5, connect=3, file_write=1, sensitive=10
        self.total_score = self
            .exec_count
            .saturating_mul(5)
            .saturating_add(self.connect_count.saturating_mul(3))
            .saturating_add(self.file_write_count)
            .saturating_add(self.sensitive_access.saturating_mul(10));
    }
}

/// Verdict for a single process based on observed behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorVerdict {
    /// No suspicious behavior detected.
    Clean,
    /// Some indicators observed; warrants further investigation.
    Suspicious {
        pid: u32,
        process_name: String,
        score: u32,
        reasons: Vec<String>,
    },
    /// Strong indicators of malicious activity.
    Malicious {
        pid: u32,
        process_name: String,
        score: u32,
        reasons: Vec<String>,
    },
}

/// A parsed network connection from `/proc/{pid}/net/tcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnection {
    /// Local address in dotted-quad notation.
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address in dotted-quad notation.
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
    /// TCP state (e.g. `1` = ESTABLISHED).
    pub state: u8,
}

/// A single event parsed from the Linux audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The audit event type (e.g. `SYSCALL`, `EXECVE`, `PATH`).
    pub event_type: String,
    /// Timestamp (seconds since epoch, as string).
    pub timestamp: String,
    /// Process ID that generated the event.
    pub pid: u32,
    /// Syscall name or number, if applicable.
    pub syscall: String,
    /// Executable path, if available.
    pub exe: String,
    /// Additional key=value fields from the log line.
    pub fields: HashMap<String, String>,
}

// ── BehaviorMonitor ──────────────────────────────────────────────────────────

/// Userspace process behavior monitor.
///
/// Tracks per-process scores using `/proc` inspection and optional audit
/// log parsing. Call [`scan_all_processes`] to sweep all running processes,
/// or [`poll_process_behavior`] for a single PID.
pub struct BehaviorMonitor {
    process_scores: HashMap<u32, ProcessBehaviorScore>,
    config: BehaviorConfig,
}

impl BehaviorMonitor {
    /// Create a new monitor with the given configuration.
    pub fn new(config: BehaviorConfig) -> Self {
        Self {
            process_scores: HashMap::new(),
            config,
        }
    }

    /// Return the current configuration.
    pub const fn config(&self) -> &BehaviorConfig {
        &self.config
    }

    /// Return the current score map (for inspection / tests).
    pub const fn scores(&self) -> &HashMap<u32, ProcessBehaviorScore> {
        &self.process_scores
    }

    /// Poll a single process and return a verdict.
    ///
    /// Reads `/proc/{pid}/fd`, `/proc/{pid}/net/tcp`, and
    /// `/proc/{pid}/status` to update the process score.
    pub fn poll_process_behavior(&mut self, pid: u32) -> BehaviorVerdict {
        let name = process_name_for_pid(pid);

        let entry = self
            .process_scores
            .entry(pid)
            .or_insert_with(|| ProcessBehaviorScore::new(pid, name.clone()));

        // Update process name if it was a placeholder.
        if entry.process_name.starts_with("pid:") && !name.starts_with("pid:") {
            entry.process_name = name;
        }

        // 1. Network connections
        let connections = check_network_connections(pid);
        #[allow(clippy::cast_possible_truncation)] // connection count won't exceed u32::MAX
        {
            entry.connect_count = connections.len() as u32;
        }

        // 2. Children (exec proxy)
        entry.exec_count = count_children(pid);

        // 3. File descriptors — check for writes and sensitive access
        let (write_count, sensitive_count) = check_fd_activity(pid, &self.config.sensitive_paths);
        entry.file_write_count = write_count;
        entry.sensitive_access = sensitive_count;

        // 4. Recalculate and emit verdict
        entry.recalculate();

        self.verdict_for(pid)
    }

    /// Scan all running processes (by iterating numeric entries in `/proc`).
    pub fn scan_all_processes(&mut self) -> Vec<BehaviorVerdict> {
        let pids = list_pids();
        let mut results = Vec::new();
        for pid in pids {
            let verdict = self.poll_process_behavior(pid);
            if !matches!(verdict, BehaviorVerdict::Clean) {
                results.push(verdict);
            }
        }
        results
    }

    /// Build a verdict from the current score for `pid`.
    fn verdict_for(&self, pid: u32) -> BehaviorVerdict {
        let Some(entry) = self.process_scores.get(&pid) else {
            return BehaviorVerdict::Clean;
        };

        let mut reasons = Vec::new();
        if entry.exec_count > 0 {
            reasons.push(format!("spawned {} child processes", entry.exec_count));
        }
        if entry.connect_count > 0 {
            reasons.push(format!("{} active network connections", entry.connect_count));
        }
        if entry.file_write_count > 0 {
            reasons.push(format!("{} writable file descriptors", entry.file_write_count));
        }
        if entry.sensitive_access > 0 {
            reasons.push(format!("{} accesses to sensitive paths", entry.sensitive_access));
        }

        if entry.total_score >= self.config.score_threshold_malicious {
            BehaviorVerdict::Malicious {
                pid: entry.pid,
                process_name: entry.process_name.clone(),
                score: entry.total_score,
                reasons,
            }
        } else if entry.total_score >= self.config.score_threshold_suspicious {
            BehaviorVerdict::Suspicious {
                pid: entry.pid,
                process_name: entry.process_name.clone(),
                score: entry.total_score,
                reasons,
            }
        } else {
            BehaviorVerdict::Clean
        }
    }
}

// ── /proc helpers ─────────────────────────────────────────────────────────────

/// Best-effort process name from `/proc/{pid}/comm`.
fn process_name_for_pid(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm")).map_or_else(|_| format!("pid:{pid}"), |s| s.trim().to_string())
}

/// List all numeric PID entries in `/proc`.
fn list_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
        .collect()
}

/// Count child threads/tasks of a process via `/proc/{pid}/task`.
fn count_children(pid: u32) -> u32 {
    let task_dir = format!("/proc/{pid}/task");
    fs::read_dir(task_dir).map_or(0, |entries| {
        let count = entries.filter_map(std::result::Result::ok).count();
        // Subtract 1 for the main thread; saturate to avoid underflow.
        // Task count is bounded by OS limits, well within u32 range.
        #[allow(clippy::cast_possible_truncation)]
        let count_u32 = count as u32;
        count_u32.saturating_sub(1)
    })
}

/// Inspect `/proc/{pid}/fd` for:
/// - writable file descriptors (`write_count`)
/// - links pointing to sensitive paths (`sensitive_count`)
///
/// Returns `(file_write_count, sensitive_access_count)`.
fn check_fd_activity(pid: u32, sensitive_paths: &[String]) -> (u32, u32) {
    let fd_dir = format!("/proc/{pid}/fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return (0, 0);
    };

    let mut write_count: u32 = 0;
    let mut sensitive_count: u32 = 0;

    for entry in entries.filter_map(std::result::Result::ok) {
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };

        let Some(link_str) = link.to_str() else {
            continue;
        };

        // Skip stdin/stdout/stderr and special fds
        if link_str.starts_with("pipe:")
            || link_str.starts_with("socket:")
            || link_str.starts_with("anon_inode:")
            || link_str == "/dev/null"
            || link_str == "/dev/pts/0"
        {
            continue;
        }

        // Count regular file fds (proxy for file writes)
        write_count = write_count.saturating_add(1);

        // Check if linked path is sensitive
        for sp in sensitive_paths {
            if link_str.starts_with(sp.as_str()) {
                sensitive_count = sensitive_count.saturating_add(1);
                break;
            }
        }
    }

    (write_count, sensitive_count)
}

/// Parse `/proc/{pid}/net/tcp` to extract active TCP connections.
///
/// Each line (after the header) has the format:
/// ```text
///   sl  local_address rem_address   st ...
///    0: 0100007F:1F90 00000000:0000 0A ...
/// ```
pub fn check_network_connections(pid: u32) -> Vec<NetworkConnection> {
    let tcp_path = format!("/proc/{pid}/net/tcp");
    parse_proc_net_tcp(&tcp_path)
}

/// Parse a `/proc/*/net/tcp` file at the given path.
fn parse_proc_net_tcp(path: &str) -> Vec<NetworkConnection> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };

    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        // skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        // fields[1] = local_address:port, fields[2] = rem_address:port, fields[3] = state
        let (Some(&local_field), Some(&remote_field), Some(&state_field)) =
            (fields.get(1), fields.get(2), fields.get(3))
        else {
            continue;
        };
        if let (Some(local), Some(remote), Some(state)) = (
            parse_hex_addr(local_field),
            parse_hex_addr(remote_field),
            parse_hex_state(state_field),
        ) {
            connections.push(NetworkConnection {
                local_addr: local.0,
                local_port: local.1,
                remote_addr: remote.0,
                remote_port: remote.1,
                state,
            });
        }
    }

    connections
}

/// Parse a hex address:port pair like `0100007F:1F90`.
#[allow(clippy::many_single_char_names)] // octet names a.b.c.d match IP notation
fn parse_hex_addr(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    // Bounds-checked access for the two-element split result.
    let addr_u32 = u32::from_str_radix(parts.first()?, 16).ok()?;
    let port = u16::from_str_radix(parts.get(1)?, 16).ok()?;

    // /proc/net/tcp stores addresses in little-endian byte order on little-endian systems.
    let a = (addr_u32 & 0xFF) as u8;
    let b = ((addr_u32 >> 8) & 0xFF) as u8;
    let c = ((addr_u32 >> 16) & 0xFF) as u8;
    let d = ((addr_u32 >> 24) & 0xFF) as u8;

    Some((format!("{a}.{b}.{c}.{d}"), port))
}

/// Parse a hex TCP state string like `0A` → 10.
fn parse_hex_state(s: &str) -> Option<u8> {
    u8::from_str_radix(s, 16).ok()
}

// ── Audit log parsing ─────────────────────────────────────────────────────────

/// Parse audit log events from the given file path.
///
/// Expected format (one event per line):
/// ```text
/// type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 ... pid=1234 exe="/usr/bin/curl"
/// ```
///
/// Returns an empty vector if the file cannot be read.
pub fn parse_audit_events(log_path: &Path) -> Vec<AuditEvent> {
    let Ok(content) = fs::read_to_string(log_path) else {
        return Vec::new();
    };

    let mut events = Vec::new();

    for line in content.lines() {
        if let Some(event) = parse_single_audit_line(line) {
            events.push(event);
        }
    }

    events
}

/// Parse a single audit log line into an [`AuditEvent`].
fn parse_single_audit_line(line: &str) -> Option<AuditEvent> {
    // Extract event type: "type=SYSCALL ..."
    let event_type = extract_field(line, "type=")?;

    // Extract timestamp from "msg=audit(TIMESTAMP:SERIAL):"
    let timestamp = extract_audit_timestamp(line);

    // Extract common fields
    let pid_str = extract_field(line, "pid=").unwrap_or_default();
    let pid: u32 = pid_str.parse().ok().unwrap_or(0);

    let syscall = extract_field(line, "syscall=").unwrap_or_default();
    let exe = extract_field(line, "exe=")
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_default();

    // Collect all key=value pairs
    let mut fields = HashMap::new();
    for token in line.split_whitespace() {
        if let Some(idx) = token.find('=') {
            let key = &token[..idx];
            let val = &token[idx + 1..];
            fields.insert(key.to_string(), val.trim_matches('"').to_string());
        }
    }

    Some(AuditEvent {
        event_type,
        timestamp,
        pid,
        syscall,
        exe,
        fields,
    })
}

/// Extract the value after `key=` up to the next whitespace.
///
/// Matches only when `key` appears at the start of a token (preceded by
/// whitespace or line start) to avoid partial matches like `ppid=` when
/// searching for `pid=`.
fn extract_field(line: &str, key: &str) -> Option<String> {
    // Search for occurrences of `key` that are preceded by whitespace or at position 0.
    let mut search_from = 0;
    loop {
        let pos = line[search_from..].find(key)?;
        let abs_pos = search_from + pos;

        // Ensure it's a whole-token match (at start or preceded by whitespace / ':' / '(').
        let is_token_start = abs_pos == 0
            || line
                .as_bytes()
                .get(abs_pos.wrapping_sub(1))
                .is_some_and(|&b| b == b' ' || b == b'\t' || b == b':' || b == b'(');

        if is_token_start {
            let value_start = abs_pos + key.len();
            let rest = &line[value_start..];

            // Value may be quoted
            return rest.strip_prefix('"').map_or_else(
                || {
                    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                    Some(rest[..end].to_string())
                },
                |stripped| {
                    let end = stripped.find('"').unwrap_or(stripped.len());
                    Some(stripped[..end].to_string())
                },
            );
        }

        // Skip past this occurrence and keep searching
        search_from = abs_pos + key.len();
        if search_from >= line.len() {
            return None;
        }
    }
}

/// Extract timestamp from `msg=audit(TIMESTAMP:SERIAL):`.
fn extract_audit_timestamp(line: &str) -> String {
    let marker = "msg=audit(";
    if let Some(start) = line.find(marker) {
        let rest = &line[start + marker.len()..];
        if let Some(end) = rest.find(':') {
            return rest[..end].to_string();
        }
    }
    String::new()
}

/// Check if a path resolves to a sensitive file by examining `/proc/{pid}/fd`.
pub fn check_sensitive_file_access(pid: u32, sensitive_paths: &[String]) -> Vec<String> {
    let fd_dir = format!("/proc/{pid}/fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return Vec::new();
    };

    let mut accessed = Vec::new();

    for entry in entries.filter_map(std::result::Result::ok) {
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };

        let Some(link_str_ref) = link.to_str() else {
            continue;
        };
        let link_str = link_str_ref.to_string();

        for sp in sensitive_paths {
            if link_str.starts_with(sp.as_str()) {
                accessed.push(link_str.clone());
                break;
            }
        }
    }

    accessed
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_thresholds() {
        let cfg = BehaviorConfig::default();
        assert_eq!(cfg.score_threshold_suspicious, 30);
        assert_eq!(cfg.score_threshold_malicious, 60);
        assert!(cfg.poll_interval_ms > 0);
        assert!(!cfg.sensitive_paths.is_empty());
    }

    #[test]
    fn process_behavior_score_recalculate() {
        let mut score = ProcessBehaviorScore::new(1, "test".into());
        score.exec_count = 2; // 2 * 5 = 10
        score.connect_count = 3; // 3 * 3 = 9
        score.file_write_count = 4; // 4 * 1 = 4
        score.sensitive_access = 1; // 1 * 10 = 10
        score.recalculate();
        assert_eq!(score.total_score, 33); // 10 + 9 + 4 + 10
    }

    #[test]
    fn verdict_clean_when_below_threshold() {
        let config = BehaviorConfig {
            score_threshold_suspicious: 50,
            score_threshold_malicious: 100,
            ..BehaviorConfig::default()
        };
        let mut monitor = BehaviorMonitor::new(config);

        // Insert a low-scoring process manually
        let mut ps = ProcessBehaviorScore::new(1, "clean_proc".into());
        ps.exec_count = 1;
        ps.recalculate(); // score = 5
        monitor.process_scores.insert(1, ps);

        let verdict = monitor.verdict_for(1);
        assert!(matches!(verdict, BehaviorVerdict::Clean));
    }

    #[test]
    fn verdict_suspicious_when_above_threshold() {
        let config = BehaviorConfig {
            score_threshold_suspicious: 10,
            score_threshold_malicious: 100,
            ..BehaviorConfig::default()
        };
        let mut monitor = BehaviorMonitor::new(config);

        let mut ps = ProcessBehaviorScore::new(42, "medium_proc".into());
        ps.exec_count = 3; // 15
        ps.connect_count = 2; // 6
        ps.recalculate(); // 21 >= 10
        monitor.process_scores.insert(42, ps);

        let verdict = monitor.verdict_for(42);
        assert!(
            matches!(verdict, BehaviorVerdict::Suspicious { score: 21, .. }),
            "expected Suspicious with score 21, got {verdict:?}"
        );
    }

    #[test]
    fn verdict_malicious_when_above_malicious_threshold() {
        let config = BehaviorConfig {
            score_threshold_suspicious: 10,
            score_threshold_malicious: 30,
            ..BehaviorConfig::default()
        };
        let mut monitor = BehaviorMonitor::new(config);

        let mut ps = ProcessBehaviorScore::new(99, "bad_proc".into());
        ps.exec_count = 4; // 20
        ps.sensitive_access = 2; // 20
        ps.recalculate(); // 40 >= 30
        monitor.process_scores.insert(99, ps);

        let verdict = monitor.verdict_for(99);
        assert!(
            matches!(verdict, BehaviorVerdict::Malicious { score: 40, .. }),
            "expected Malicious with score 40, got {verdict:?}"
        );
    }

    #[test]
    fn verdict_for_unknown_pid_is_clean() {
        let monitor = BehaviorMonitor::new(BehaviorConfig::default());
        assert!(matches!(monitor.verdict_for(999_999), BehaviorVerdict::Clean));
    }

    #[test]
    fn parse_hex_addr_loopback() {
        let result = parse_hex_addr("0100007F:1F90");
        assert_eq!(result, Some(("127.0.0.1".to_string(), 8080)));
    }

    #[test]
    fn parse_hex_addr_any() {
        let result = parse_hex_addr("00000000:0050");
        assert_eq!(result, Some(("0.0.0.0".to_string(), 80)));
    }

    #[test]
    fn parse_hex_addr_invalid() {
        assert!(parse_hex_addr("not_valid").is_none());
        assert!(parse_hex_addr("ZZZZ:1234").is_none());
    }

    #[test]
    fn parse_hex_state_valid() {
        assert_eq!(parse_hex_state("0A"), Some(10)); // LISTEN
        assert_eq!(parse_hex_state("01"), Some(1)); // ESTABLISHED
    }

    #[test]
    fn parse_proc_net_tcp_sample() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0101A8C0:C350 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0";

        let dir = tempfile::tempdir().expect("tempdir");
        let tcp_file = dir.path().join("tcp");
        {
            let mut f = fs::File::create(&tcp_file).expect("create");
            f.write_all(sample.as_bytes()).expect("write");
        }

        let path_str = tcp_file.to_str().expect("to_str");
        let conns = parse_proc_net_tcp(path_str);
        assert_eq!(conns.len(), 2);

        assert_eq!(conns[0].local_addr, "127.0.0.1");
        assert_eq!(conns[0].local_port, 8080);
        assert_eq!(conns[0].state, 0x0A); // LISTEN

        assert_eq!(conns[1].local_addr, "127.0.0.1");
        assert_eq!(conns[1].local_port, 80);
        assert_eq!(conns[1].remote_addr, "192.168.1.1");
        assert_eq!(conns[1].remote_port, 50000);
        assert_eq!(conns[1].state, 0x01); // ESTABLISHED
    }

    #[test]
    fn parse_audit_events_sample() {
        let sample = r#"type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key=(null)
type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="curl" a1="-s" a2="http://evil.example.com"
type=SYSCALL msg=audit(1700000001.456:789): arch=c000003e syscall=42 success=yes exit=0 pid=5678 comm="nc" exe="/usr/bin/nc" key=(null)
"#;

        let dir = tempfile::tempdir().expect("tempdir");
        let log_file = dir.path().join("audit.log");
        fs::write(&log_file, sample).expect("write");

        let events = parse_audit_events(&log_file);
        assert_eq!(events.len(), 3);

        assert_eq!(events[0].event_type, "SYSCALL");
        assert_eq!(events[0].timestamp, "1700000000.123");
        assert_eq!(events[0].pid, 1234);
        assert_eq!(events[0].syscall, "59");
        assert_eq!(events[0].exe, "/usr/bin/curl");

        assert_eq!(events[1].event_type, "EXECVE");
        assert_eq!(events[2].pid, 5678);
        assert_eq!(events[2].exe, "/usr/bin/nc");
    }

    #[test]
    fn parse_audit_events_missing_file() {
        let events = parse_audit_events(Path::new("/nonexistent/audit.log"));
        assert!(events.is_empty());
    }

    #[test]
    fn extract_field_basic() {
        let line = r#"type=SYSCALL pid=1234 exe="/usr/bin/curl""#;
        assert_eq!(extract_field(line, "type="), Some("SYSCALL".into()));
        assert_eq!(extract_field(line, "pid="), Some("1234".into()));
        assert_eq!(extract_field(line, "exe="), Some("/usr/bin/curl".into()));
        assert_eq!(extract_field(line, "missing="), None);
    }

    #[test]
    fn extract_audit_timestamp_basic() {
        let line = "type=SYSCALL msg=audit(1700000000.123:456): rest";
        assert_eq!(extract_audit_timestamp(line), "1700000000.123");
    }

    #[test]
    fn extract_audit_timestamp_missing() {
        assert_eq!(extract_audit_timestamp("no timestamp here"), "");
    }

    #[test]
    fn list_pids_returns_some() {
        // On any Linux system /proc should contain at least PID 1.
        let pids = list_pids();
        assert!(!pids.is_empty(), "expected at least one PID in /proc");
        assert!(pids.contains(&1), "expected PID 1 in the list");
    }

    #[test]
    fn monitor_new_has_empty_scores() {
        let monitor = BehaviorMonitor::new(BehaviorConfig::default());
        assert!(monitor.scores().is_empty());
    }

    #[test]
    fn reasons_populated_correctly() {
        let config = BehaviorConfig {
            score_threshold_suspicious: 1,
            score_threshold_malicious: 1000,
            ..BehaviorConfig::default()
        };
        let mut monitor = BehaviorMonitor::new(config);

        let mut ps = ProcessBehaviorScore::new(10, "proc".into());
        ps.exec_count = 1;
        ps.connect_count = 2;
        ps.sensitive_access = 1;
        ps.recalculate();
        monitor.process_scores.insert(10, ps);

        if let BehaviorVerdict::Suspicious { reasons, .. } = monitor.verdict_for(10) {
            assert!(reasons.iter().any(|r| r.contains("child processes")));
            assert!(reasons.iter().any(|r| r.contains("network connections")));
            assert!(reasons.iter().any(|r| r.contains("sensitive paths")));
        } else {
            panic!("expected Suspicious verdict");
        }
    }
}
