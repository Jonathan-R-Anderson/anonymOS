//! Time-window event correlation engine for eBPF runtime events.
//!
//! The [`Correlator`] inspects each incoming [`RuntimeEvent`] against the
//! [`ProcessCache`] and produces [`CorrelationAlert`]s when suspicious
//! multi-event patterns are detected.
//!
//! # Correlation Rules
//!
//! | Rule | Window | Trigger |
//! |------|--------|---------|
//! | `ExecThenConnect` | 30 s | Process exec → outbound connect |
//! | `DropAndExec` | 10 min | File written → then executed |
//! | `RansomwareBurst` | 60 s | Many file writes from one PID |
//! | `SensitiveAccess` | 60 s | Access to multiple sensitive paths |

use super::events::{EventDetail, RuntimeEvent, RuntimeEventKind};
use super::state::{ProcessCache, ProcessKey};
use std::time::{Duration, Instant};

// ── Configuration ────────────────────────────────────────────────────────

/// Time window for exec → connect correlation.
const EXEC_CONNECT_WINDOW: Duration = Duration::from_secs(30);

/// Time window for file-drop → exec correlation.
const DROP_EXEC_WINDOW: Duration = Duration::from_secs(600);

/// Sliding window for ransomware burst detection.
const RANSOMWARE_WINDOW: Duration = Duration::from_secs(60);

/// Threshold of file writes within the window to trigger ransomware alert.
/// Must be <= `MAX_RECENT_FILES` (32) since the cache caps stored entries.
const RANSOMWARE_THRESHOLD: usize = 25;

/// Time window for sensitive path access correlation.
const SENSITIVE_ACCESS_WINDOW: Duration = Duration::from_secs(60);

/// Minimum distinct sensitive paths within window to trigger alert.
const SENSITIVE_ACCESS_THRESHOLD: usize = 3;

/// Paths considered sensitive for access correlation.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/",
    "/root/.ssh/",
    "/proc/kcore",
    "/proc/kallsyms",
    "/sys/kernel/",
    "/boot/vmlinuz",
    "/boot/initrd",
];

/// Paths considered suspicious for exec origin.
const SUSPICIOUS_EXEC_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];

// ── Alert types ──────────────────────────────────────────────────────────

/// Severity level for correlation alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A correlation alert produced when suspicious multi-event patterns
/// are detected.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CorrelationAlert {
    /// Alert rule that fired.
    pub rule: AlertRule,
    /// Severity level.
    pub severity: AlertSeverity,
    /// Human-readable description.
    pub description: String,
    /// Process ID that triggered the alert.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Monotonic timestamp of the triggering event (ns).
    pub trigger_ts_ns: u64,
}

impl std::fmt::Display for CorrelationAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ALERT:{}] {} pid={} comm={} — {}",
            self.severity, self.rule, self.pid, self.comm, self.description
        )
    }
}

/// Correlation rule identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum AlertRule {
    /// Newly exec'd process made outbound connection within window.
    ExecThenConnect,
    /// File was written and then executed from a suspicious location.
    DropAndExec,
    /// Burst of file writes suggesting ransomware activity.
    RansomwareBurst,
    /// Multiple sensitive file accesses from one process.
    SensitiveAccess,
}

impl std::fmt::Display for AlertRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecThenConnect => write!(f, "exec_then_connect"),
            Self::DropAndExec => write!(f, "drop_and_exec"),
            Self::RansomwareBurst => write!(f, "ransomware_burst"),
            Self::SensitiveAccess => write!(f, "sensitive_access"),
        }
    }
}

// ── Correlator ───────────────────────────────────────────────────────────

/// Stateless correlation engine that checks each event against the
/// process cache and returns zero or more alerts.
pub struct Correlator {
    cache: ProcessCache,
}

impl Correlator {
    /// Create a new correlator backed by the given process cache.
    pub fn new(cache: ProcessCache) -> Self {
        Self { cache }
    }

    /// Check an incoming event for correlation patterns.
    ///
    /// This should be called **after** `ProcessCache::on_event()` has
    /// updated the state, so the correlator sees the latest data.
    pub fn check(&self, event: &RuntimeEvent) -> Vec<CorrelationAlert> {
        let mut alerts = Vec::new();

        match event.kind {
            RuntimeEventKind::Connect => {
                self.check_exec_then_connect(event, &mut alerts);
            }
            RuntimeEventKind::Exec => {
                self.check_drop_and_exec(event, &mut alerts);
            }
            RuntimeEventKind::FileOpen => {
                self.check_ransomware_burst(event, &mut alerts);
                self.check_sensitive_access(event, &mut alerts);
            }
            RuntimeEventKind::Exit => {}
        }

        alerts
    }

    /// Rule: exec → connect within 30 seconds.
    ///
    /// If a process was recently exec'd and is now making an outbound
    /// connection, that's potentially suspicious (dropper phoning home).
    fn check_exec_then_connect(&self, event: &RuntimeEvent, alerts: &mut Vec<CorrelationAlert>) {
        let key = ProcessKey {
            pid: event.pid,
            mnt_ns: event.mnt_ns,
        };

        let Some(state) = self.cache.get(&key) else {
            return;
        };

        let Some(exec_path) = &state.exec_path else {
            return;
        };

        // Only alert if exec was from a suspicious directory.
        let from_suspicious = SUSPICIOUS_EXEC_DIRS.iter().any(|dir| exec_path.starts_with(dir));

        if !from_suspicious {
            return;
        }

        // Check time window using wall-clock from state.
        let now = Instant::now();
        if now.duration_since(state.created_at) > EXEC_CONNECT_WINDOW {
            return;
        }

        let (port, addr) = match &event.detail {
            EventDetail::Connect { port, addr, .. } => (*port, *addr),
            _ => return,
        };

        alerts.push(CorrelationAlert {
            rule: AlertRule::ExecThenConnect,
            severity: AlertSeverity::High,
            description: format!(
                "Process from {exec_path} connected to {addr}:{port} within {}s of exec",
                EXEC_CONNECT_WINDOW.as_secs()
            ),
            pid: event.pid,
            comm: event.comm.clone(),
            trigger_ts_ns: event.ts_ns,
        });
    }

    /// Rule: file drop → exec from suspicious location.
    ///
    /// If a file was recently written (seen as FileOpen with write flags)
    /// and now being exec'd from /tmp, /dev/shm, etc.
    fn check_drop_and_exec(&self, event: &RuntimeEvent, alerts: &mut Vec<CorrelationAlert>) {
        let exec_path = match &event.detail {
            EventDetail::Exec { filename, .. } => filename,
            _ => return,
        };

        // Only check if exec is from a suspicious directory.
        let from_suspicious = SUSPICIOUS_EXEC_DIRS.iter().any(|dir| exec_path.starts_with(dir));

        if !from_suspicious {
            return;
        }

        // Search all active processes for a recent file write to this path.
        let now = Instant::now();
        let exec_path_clone = exec_path.clone();
        let mut found_writer = None;

        self.cache.for_each_active(|_key, state| {
            if found_writer.is_some() {
                return;
            }
            for fa in &state.recent_files {
                if fa.path == exec_path_clone
                    && now.duration_since(fa.wall) <= DROP_EXEC_WINDOW
                    && is_write_flags(fa.flags)
                {
                    found_writer = Some((state.pid, state.comm.clone()));
                    return;
                }
            }
        });

        if let Some((writer_pid, writer_comm)) = found_writer {
            alerts.push(CorrelationAlert {
                rule: AlertRule::DropAndExec,
                severity: AlertSeverity::Critical,
                description: format!(
                    "File {exec_path} was written by {writer_comm}(pid={writer_pid}) \
                     and exec'd within {}min",
                    DROP_EXEC_WINDOW.as_secs() / 60
                ),
                pid: event.pid,
                comm: event.comm.clone(),
                trigger_ts_ns: event.ts_ns,
            });
        }
    }

    /// Rule: burst of file writes suggesting ransomware.
    fn check_ransomware_burst(&self, event: &RuntimeEvent, alerts: &mut Vec<CorrelationAlert>) {
        let key = ProcessKey {
            pid: event.pid,
            mnt_ns: event.mnt_ns,
        };

        let Some(state) = self.cache.get(&key) else {
            return;
        };

        // Only consider write operations.
        let write_flag = match &event.detail {
            EventDetail::FileOpen { flags, .. } => is_write_flags(*flags),
            _ => false,
        };

        if !write_flag {
            return;
        }

        // Count recent writes within the ransomware window.
        let now = Instant::now();
        let recent_writes = state
            .recent_files
            .iter()
            .filter(|fa| is_write_flags(fa.flags) && now.duration_since(fa.wall) <= RANSOMWARE_WINDOW)
            .count();

        if recent_writes >= RANSOMWARE_THRESHOLD {
            alerts.push(CorrelationAlert {
                rule: AlertRule::RansomwareBurst,
                severity: AlertSeverity::Critical,
                description: format!(
                    "{recent_writes} file writes in {}s (threshold: {RANSOMWARE_THRESHOLD})",
                    RANSOMWARE_WINDOW.as_secs()
                ),
                pid: event.pid,
                comm: event.comm.clone(),
                trigger_ts_ns: event.ts_ns,
            });
        }
    }

    /// Rule: multiple sensitive file accesses from one process.
    fn check_sensitive_access(&self, event: &RuntimeEvent, alerts: &mut Vec<CorrelationAlert>) {
        let current_path = match &event.detail {
            EventDetail::FileOpen { path, .. } => path,
            _ => return,
        };

        // Check if the current access is to a sensitive path.
        if !is_sensitive_path(current_path) {
            return;
        }

        let key = ProcessKey {
            pid: event.pid,
            mnt_ns: event.mnt_ns,
        };

        let Some(state) = self.cache.get(&key) else {
            return;
        };

        // Count distinct sensitive paths accessed within window.
        let now = Instant::now();
        let mut sensitive_paths: Vec<&str> = Vec::new();
        for fa in &state.recent_files {
            if now.duration_since(fa.wall) <= SENSITIVE_ACCESS_WINDOW && is_sensitive_path(&fa.path) {
                if !sensitive_paths.iter().any(|&p| p == fa.path) {
                    sensitive_paths.push(&fa.path);
                }
            }
        }

        if sensitive_paths.len() >= SENSITIVE_ACCESS_THRESHOLD {
            alerts.push(CorrelationAlert {
                rule: AlertRule::SensitiveAccess,
                severity: AlertSeverity::High,
                description: format!(
                    "{} distinct sensitive paths accessed in {}s: {}",
                    sensitive_paths.len(),
                    SENSITIVE_ACCESS_WINDOW.as_secs(),
                    sensitive_paths.iter().take(5).copied().collect::<Vec<_>>().join(", ")
                ),
                pid: event.pid,
                comm: event.comm.clone(),
                trigger_ts_ns: event.ts_ns,
            });
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Check if open flags indicate a write operation.
/// O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0x40, O_TRUNC = 0x200
fn is_write_flags(flags: i32) -> bool {
    let access_mode = flags & 0x3; // O_ACCMODE
    let has_creat = flags & 0x40 != 0;
    let has_trunc = flags & 0x200 != 0;
    access_mode == 1 || access_mode == 2 || has_creat || has_trunc
}

/// Check if a path matches any sensitive path prefix.
fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.iter().any(|&prefix| path.starts_with(prefix))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::super::events::RuntimeEventKind;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_event(pid: u32, mnt_ns: u64, kind: RuntimeEventKind, detail: EventDetail) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 1_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind,
            cgroup_id: 1,
            mnt_ns,
            pid_ns: 1,
            comm: "test".to_string(),
            detail,
        }
    }

    #[test]
    fn test_write_flags_detection() {
        assert!(is_write_flags(1)); // O_WRONLY
        assert!(is_write_flags(2)); // O_RDWR
        assert!(is_write_flags(0x42)); // O_RDWR | O_CREAT
        assert!(is_write_flags(0x241)); // O_WRONLY | O_CREAT | O_TRUNC
        assert!(!is_write_flags(0)); // O_RDONLY
    }

    #[test]
    fn test_sensitive_path() {
        assert!(is_sensitive_path("/etc/shadow"));
        assert!(is_sensitive_path("/etc/ssh/sshd_config"));
        assert!(is_sensitive_path("/proc/kcore"));
        assert!(!is_sensitive_path("/home/user/document.txt"));
        assert!(!is_sensitive_path("/tmp/test"));
    }

    #[test]
    fn test_exec_then_connect_triggers() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Exec from /tmp.
        let exec_event = make_event(
            100,
            1,
            RuntimeEventKind::Exec,
            EventDetail::Exec {
                filename: "/tmp/malware".to_string(),
                argv: String::new(),
            },
        );
        cache.on_event(&exec_event);

        // Connect shortly after.
        let connect_event = make_event(
            100,
            1,
            RuntimeEventKind::Connect,
            EventDetail::Connect {
                af: 2,
                port: 4444,
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        );
        cache.on_event(&connect_event);

        let alerts = correlator.check(&connect_event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::ExecThenConnect);
        assert_eq!(alerts[0].severity, AlertSeverity::High);
    }

    #[test]
    fn test_exec_then_connect_no_trigger_from_normal_path() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Exec from /usr/bin — normal.
        let exec_event = make_event(
            100,
            1,
            RuntimeEventKind::Exec,
            EventDetail::Exec {
                filename: "/usr/bin/curl".to_string(),
                argv: String::new(),
            },
        );
        cache.on_event(&exec_event);

        let connect_event = make_event(
            100,
            1,
            RuntimeEventKind::Connect,
            EventDetail::Connect {
                af: 2,
                port: 443,
                addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            },
        );
        cache.on_event(&connect_event);

        let alerts = correlator.check(&connect_event);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_sensitive_access_triggers() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Access several sensitive files.
        let paths = ["/etc/shadow", "/etc/passwd", "/etc/sudoers"];
        let mut last_event = None;
        for path in &paths {
            let event = make_event(
                200,
                1,
                RuntimeEventKind::FileOpen,
                EventDetail::FileOpen {
                    path: (*path).to_string(),
                    flags: 0, // O_RDONLY
                },
            );
            cache.on_event(&event);
            last_event = Some(event);
        }

        let alerts = correlator.check(&last_event.unwrap());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::SensitiveAccess);
    }

    #[test]
    fn test_no_alert_for_single_sensitive_access() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        let event = make_event(
            200,
            1,
            RuntimeEventKind::FileOpen,
            EventDetail::FileOpen {
                path: "/etc/shadow".to_string(),
                flags: 0,
            },
        );
        cache.on_event(&event);

        let alerts = correlator.check(&event);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_ransomware_burst_below_threshold() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Only 5 writes — well below threshold (25).
        let mut last_event = None;
        for i in 0u32..5 {
            let event = RuntimeEvent {
                ts_ns: u64::from(i) * 1000,
                pid: 300,
                tid: 300,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                kind: RuntimeEventKind::FileOpen,
                cgroup_id: 1,
                mnt_ns: 1,
                pid_ns: 1,
                comm: "test".to_string(),
                detail: EventDetail::FileOpen {
                    path: format!("/home/user/doc{i}.encrypted"),
                    flags: 0x241, // O_WRONLY | O_CREAT | O_TRUNC
                },
            };
            cache.on_event(&event);
            last_event = Some(event);
        }

        let alerts = correlator.check(&last_event.unwrap());
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_ransomware_burst_triggers() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Push 30 write events — above threshold of 25.
        let mut last_event = None;
        for i in 0u32..30 {
            let event = RuntimeEvent {
                ts_ns: u64::from(i) * 1000,
                pid: 500,
                tid: 500,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                kind: RuntimeEventKind::FileOpen,
                cgroup_id: 1,
                mnt_ns: 1,
                pid_ns: 1,
                comm: "ransom".to_string(),
                detail: EventDetail::FileOpen {
                    path: format!("/home/user/doc{i}.encrypted"),
                    flags: 0x241, // O_WRONLY | O_CREAT | O_TRUNC
                },
            };
            cache.on_event(&event);
            last_event = Some(event);
        }

        let alerts = correlator.check(&last_event.unwrap());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::RansomwareBurst);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_drop_and_exec_triggers() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Process 100 writes a file to /tmp.
        let write_event = RuntimeEvent {
            ts_ns: 1_000_000,
            pid: 100,
            tid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::FileOpen,
            cgroup_id: 1,
            mnt_ns: 1,
            pid_ns: 1,
            comm: "dropper".to_string(),
            detail: EventDetail::FileOpen {
                path: "/tmp/payload".to_string(),
                flags: 0x241, // O_WRONLY | O_CREAT | O_TRUNC
            },
        };
        cache.on_event(&write_event);

        // Process 200 exec's the dropped file.
        let exec_event = make_event(
            200,
            1,
            RuntimeEventKind::Exec,
            EventDetail::Exec {
                filename: "/tmp/payload".to_string(),
                argv: String::new(),
            },
        );
        cache.on_event(&exec_event);

        let alerts = correlator.check(&exec_event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::DropAndExec);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_drop_and_exec_no_trigger_normal_path() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // Exec from /usr/bin — not suspicious, should not trigger.
        let exec_event = make_event(
            200,
            1,
            RuntimeEventKind::Exec,
            EventDetail::Exec {
                filename: "/usr/bin/ls".to_string(),
                argv: String::new(),
            },
        );
        cache.on_event(&exec_event);

        let alerts = correlator.check(&exec_event);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_exit_event_no_alert() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        let event = make_event(100, 1, RuntimeEventKind::Exit, EventDetail::Exit { exit_code: 0 });
        cache.on_event(&event);

        let alerts = correlator.check(&event);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_file_open_readonly_no_ransomware() {
        let cache = ProcessCache::new();
        let correlator = Correlator::new(cache.handle());

        // 60 O_RDONLY opens — should NOT trigger ransomware.
        let mut last_event = None;
        for i in 0u32..60 {
            let event = RuntimeEvent {
                ts_ns: u64::from(i) * 1000,
                pid: 400,
                tid: 400,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                kind: RuntimeEventKind::FileOpen,
                cgroup_id: 1,
                mnt_ns: 1,
                pid_ns: 1,
                comm: "reader".to_string(),
                detail: EventDetail::FileOpen {
                    path: format!("/home/user/file{i}"),
                    flags: 0, // O_RDONLY
                },
            };
            cache.on_event(&event);
            last_event = Some(event);
        }

        let alerts = correlator.check(&last_event.unwrap());
        // No ransomware alert because all reads, not writes.
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_alert_display_and_severity() {
        let alert = CorrelationAlert {
            rule: AlertRule::ExecThenConnect,
            severity: AlertSeverity::High,
            description: "test alert".to_string(),
            pid: 42,
            comm: "evil".to_string(),
            trigger_ts_ns: 1000,
        };
        let s = format!("{alert}");
        assert!(s.contains("[ALERT:HIGH]"));
        assert!(s.contains("exec_then_connect"));
        assert!(s.contains("pid=42"));
        assert!(s.contains("evil"));

        // Test all severity Display variants.
        assert_eq!(format!("{}", AlertSeverity::Low), "LOW");
        assert_eq!(format!("{}", AlertSeverity::Medium), "MEDIUM");
        assert_eq!(format!("{}", AlertSeverity::Critical), "CRITICAL");
    }

    #[test]
    fn test_alert_rule_display() {
        assert_eq!(format!("{}", AlertRule::ExecThenConnect), "exec_then_connect");
        assert_eq!(format!("{}", AlertRule::DropAndExec), "drop_and_exec");
        assert_eq!(format!("{}", AlertRule::RansomwareBurst), "ransomware_burst");
        assert_eq!(format!("{}", AlertRule::SensitiveAccess), "sensitive_access");
    }
}
