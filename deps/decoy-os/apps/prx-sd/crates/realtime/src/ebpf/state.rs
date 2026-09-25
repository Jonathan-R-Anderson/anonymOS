//! Process state cache for eBPF runtime event correlation.
//!
//! [`ProcessCache`] maintains a mapping from process identity to accumulated
//! state, allowing the correlation engine to reason about sequences of events
//! from the same process (e.g. "exec then connect within 30 seconds").
//!
//! The cache uses a composite key `(pid, mnt_ns)` to guard against PID reuse
//! across mount namespaces and uses `parking_lot::RwLock` per project rules.

use super::events::{EventDetail, RuntimeEvent};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default TTL for exited processes before eviction.
const EXITED_TTL: Duration = Duration::from_secs(60);

/// Default TTL for idle processes (no events received).
const IDLE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of recent file accesses to track per process.
const MAX_RECENT_FILES: usize = 32;

/// Maximum number of recent network targets to track per process.
const MAX_RECENT_TARGETS: usize = 16;

/// Composite key that uniquely identifies a process, guarding against
/// PID reuse by including the mount namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub mnt_ns: u64,
}

/// Accumulated state for a single process.
#[derive(Debug, Clone)]
pub struct ProcessState {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User ID.
    pub uid: u32,
    /// Command name (comm field, max 16 bytes).
    pub comm: String,
    /// Mount namespace.
    pub mnt_ns: u64,
    /// PID namespace.
    pub pid_ns: u64,
    /// Cgroup ID.
    pub cgroup_id: u64,
    /// First exec filename observed for this process.
    pub exec_path: Option<String>,
    /// Timestamp (monotonic ns) of the first exec event.
    pub exec_ts_ns: Option<u64>,
    /// Recent file accesses (path, flags, monotonic_ns).
    /// Uses `VecDeque` for O(1) front eviction when cap is reached.
    pub recent_files: VecDeque<FileAccess>,
    /// Recent network connection targets.
    /// Uses `VecDeque` for O(1) front eviction when cap is reached.
    pub recent_targets: VecDeque<NetworkTarget>,
    /// Whether the process has exited.
    pub exited: bool,
    /// Exit code (if exited).
    pub exit_code: Option<i32>,
    /// Wall-clock instant when this entry was created.
    pub created_at: Instant,
    /// Wall-clock instant of the last event update.
    pub last_seen: Instant,
}

/// A recorded file access event.
#[derive(Debug, Clone)]
pub struct FileAccess {
    pub path: String,
    pub flags: i32,
    pub ts_ns: u64,
    pub wall: Instant,
}

/// A recorded network connection target.
#[derive(Debug, Clone)]
pub struct NetworkTarget {
    pub addr: IpAddr,
    pub port: u16,
    pub af: u32,
    pub ts_ns: u64,
    pub wall: Instant,
}

/// Thread-safe process state cache.
pub struct ProcessCache {
    inner: Arc<RwLock<HashMap<ProcessKey, ProcessState>>>,
}

impl ProcessCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a clone-able handle to the same underlying cache.
    pub fn handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Update the cache with a new runtime event.
    ///
    /// Creates a new entry if the process is not yet tracked, or updates
    /// the existing entry with event-specific data.
    pub fn on_event(&self, event: &RuntimeEvent) {
        let key = ProcessKey {
            pid: event.pid,
            mnt_ns: event.mnt_ns,
        };
        let now = Instant::now();

        let mut map = self.inner.write();
        let state = map.entry(key).or_insert_with(|| ProcessState {
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            comm: event.comm.clone(),
            mnt_ns: event.mnt_ns,
            pid_ns: event.pid_ns,
            cgroup_id: event.cgroup_id,
            exec_path: None,
            exec_ts_ns: None,
            recent_files: VecDeque::new(),
            recent_targets: VecDeque::new(),
            exited: false,
            exit_code: None,
            created_at: now,
            last_seen: now,
        });

        state.last_seen = now;
        if state.comm != event.comm {
            state.comm = event.comm.clone();
        }

        match &event.detail {
            EventDetail::Exec { filename, .. } => {
                if state.exec_path.is_none() {
                    state.exec_path = Some(filename.clone());
                    state.exec_ts_ns = Some(event.ts_ns);
                }
            }
            EventDetail::FileOpen { path, flags } => {
                if state.recent_files.len() >= MAX_RECENT_FILES {
                    state.recent_files.pop_front();
                }
                state.recent_files.push_back(FileAccess {
                    path: path.clone(),
                    flags: *flags,
                    ts_ns: event.ts_ns,
                    wall: now,
                });
            }
            EventDetail::Connect { af, port, addr } => {
                if state.recent_targets.len() >= MAX_RECENT_TARGETS {
                    state.recent_targets.pop_front();
                }
                state.recent_targets.push_back(NetworkTarget {
                    addr: *addr,
                    port: *port,
                    af: *af,
                    ts_ns: event.ts_ns,
                    wall: now,
                });
            }
            EventDetail::Exit { exit_code } => {
                state.exited = true;
                state.exit_code = Some(*exit_code);
            }
        }
    }

    /// Look up a process by key. Returns a clone of the state.
    pub fn get(&self, key: &ProcessKey) -> Option<ProcessState> {
        let map = self.inner.read();
        map.get(key).cloned()
    }

    /// Look up a process by PID alone (first match). Useful when mnt_ns
    /// is not available from the caller. Returns a clone of the state.
    pub fn get_by_pid(&self, pid: u32) -> Option<ProcessState> {
        let map = self.inner.read();
        map.values().find(|s| s.pid == pid && !s.exited).cloned()
    }

    /// Return the current number of tracked processes.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Evict stale entries:
    /// - Exited processes older than `EXITED_TTL`
    /// - Idle processes (no events) older than `IDLE_TTL`
    ///
    /// Returns the number of evicted entries.
    pub fn evict_stale(&self) -> usize {
        let now = Instant::now();
        let mut map = self.inner.write();
        let before = map.len();
        map.retain(|_key, state| {
            if state.exited && now.duration_since(state.last_seen) > EXITED_TTL {
                return false;
            }
            if now.duration_since(state.last_seen) > IDLE_TTL {
                return false;
            }
            true
        });
        before - map.len()
    }

    /// Iterate over all processes that have a non-None exec_path and are
    /// not yet exited. Calls the closure with each matching state.
    pub fn for_each_active<F>(&self, mut f: F)
    where
        F: FnMut(&ProcessKey, &ProcessState),
    {
        let map = self.inner.read();
        for (key, state) in map.iter() {
            if !state.exited {
                f(key, state);
            }
        }
    }
}

impl Default for ProcessCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::super::events::RuntimeEventKind;
    use super::*;
    use std::net::Ipv4Addr;

    fn make_exec_event(pid: u32, mnt_ns: u64, filename: &str) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 1_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Exec,
            cgroup_id: 1,
            mnt_ns,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Exec {
                filename: filename.to_string(),
                argv: String::new(),
            },
        }
    }

    fn make_connect_event(pid: u32, mnt_ns: u64, port: u16) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 2_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Connect,
            cgroup_id: 1,
            mnt_ns,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Connect {
                af: 2,
                port,
                addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            },
        }
    }

    fn make_exit_event(pid: u32, mnt_ns: u64) -> RuntimeEvent {
        RuntimeEvent {
            ts_ns: 3_000_000,
            pid,
            tid: pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            kind: RuntimeEventKind::Exit,
            cgroup_id: 1,
            mnt_ns,
            pid_ns: 1,
            comm: "test".to_string(),
            detail: EventDetail::Exit { exit_code: 0 },
        }
    }

    #[test]
    fn test_exec_creates_entry() {
        let cache = ProcessCache::new();
        let event = make_exec_event(100, 1, "/usr/bin/curl");
        cache.on_event(&event);

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let state = cache.get(&key);
        assert!(state.is_some());
        let s = state.unwrap();
        assert_eq!(s.exec_path.as_deref(), Some("/usr/bin/curl"));
        assert!(!s.exited);
    }

    #[test]
    fn test_connect_appends_target() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/usr/bin/curl"));
        cache.on_event(&make_connect_event(100, 1, 443));

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let s = cache.get(&key).unwrap();
        assert_eq!(s.recent_targets.len(), 1);
        assert_eq!(s.recent_targets[0].port, 443);
    }

    #[test]
    fn test_exit_marks_exited() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));
        cache.on_event(&make_exit_event(100, 1));

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let s = cache.get(&key).unwrap();
        assert!(s.exited);
        assert_eq!(s.exit_code, Some(0));
    }

    #[test]
    fn test_pid_reuse_with_different_mnt_ns() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/a"));
        cache.on_event(&make_exec_event(100, 2, "/bin/b"));

        assert_eq!(cache.len(), 2);

        let a = cache.get(&ProcessKey { pid: 100, mnt_ns: 1 }).unwrap();
        let b = cache.get(&ProcessKey { pid: 100, mnt_ns: 2 }).unwrap();
        assert_eq!(a.exec_path.as_deref(), Some("/bin/a"));
        assert_eq!(b.exec_path.as_deref(), Some("/bin/b"));
    }

    #[test]
    fn test_recent_files_cap() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));

        for i in 0u32..40 {
            let event = RuntimeEvent {
                ts_ns: u64::from(i) * 1000,
                pid: 100,
                tid: 100,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                kind: RuntimeEventKind::FileOpen,
                cgroup_id: 1,
                mnt_ns: 1,
                pid_ns: 1,
                comm: "sh".to_string(),
                detail: EventDetail::FileOpen {
                    path: format!("/tmp/file{i}"),
                    flags: 0,
                },
            };
            cache.on_event(&event);
        }

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let s = cache.get(&key).unwrap();
        assert_eq!(s.recent_files.len(), MAX_RECENT_FILES);
    }

    #[test]
    fn test_evict_exited() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));
        cache.on_event(&make_exit_event(100, 1));

        // Immediately after exit, should still be present.
        assert_eq!(cache.len(), 1);

        // Cannot test real TTL expiry in a unit test without sleeping,
        // but we verify the method runs without error.
        let evicted = cache.evict_stale();
        // Exited < EXITED_TTL ago, so not evicted yet.
        assert_eq!(evicted, 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_get_by_pid() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));
        cache.on_event(&make_exec_event(200, 1, "/bin/bash"));

        let found = cache.get_by_pid(100);
        assert!(found.is_some());
        assert_eq!(found.unwrap().pid, 100);

        assert!(cache.get_by_pid(999).is_none());
    }

    #[test]
    fn test_get_by_pid_skips_exited() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));
        cache.on_event(&make_exit_event(100, 1));

        // get_by_pid should skip exited processes.
        assert!(cache.get_by_pid(100).is_none());
    }

    #[test]
    fn test_handle_shares_state() {
        let cache = ProcessCache::new();
        let handle = cache.handle();

        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));
        // handle should see the same entry.
        assert_eq!(handle.len(), 1);
        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        assert!(handle.get(&key).is_some());
    }

    #[test]
    fn test_for_each_active_skips_exited() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/a"));
        cache.on_event(&make_exec_event(200, 1, "/bin/b"));
        cache.on_event(&make_exit_event(100, 1));

        let mut active_pids = Vec::new();
        cache.for_each_active(|_key, state| {
            active_pids.push(state.pid);
        });

        assert_eq!(active_pids.len(), 1);
        assert_eq!(active_pids[0], 200);
    }

    #[test]
    fn test_is_empty_and_len() {
        let cache = ProcessCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_recent_targets_cap() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));

        // Add 20 connect events — should cap at MAX_RECENT_TARGETS (16).
        for i in 0u32..20 {
            let event = RuntimeEvent {
                ts_ns: u64::from(i) * 1000,
                pid: 100,
                tid: 100,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                kind: RuntimeEventKind::Connect,
                cgroup_id: 1,
                mnt_ns: 1,
                pid_ns: 1,
                comm: "sh".to_string(),
                detail: EventDetail::Connect {
                    af: 2,
                    port: 1000 + (i as u16),
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                },
            };
            cache.on_event(&event);
        }

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let s = cache.get(&key).unwrap();
        assert_eq!(s.recent_targets.len(), MAX_RECENT_TARGETS);
    }

    #[test]
    fn test_exec_does_not_overwrite_first() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/first"));
        cache.on_event(&make_exec_event(100, 1, "/bin/second"));

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let s = cache.get(&key).unwrap();
        // First exec path is preserved.
        assert_eq!(s.exec_path.as_deref(), Some("/bin/first"));
    }

    #[test]
    fn test_comm_updates_on_each_event() {
        let cache = ProcessCache::new();
        cache.on_event(&make_exec_event(100, 1, "/bin/sh"));

        let mut event = make_connect_event(100, 1, 80);
        event.comm = "curl".to_string();
        cache.on_event(&event);

        let key = ProcessKey { pid: 100, mnt_ns: 1 };
        let s = cache.get(&key).unwrap();
        assert_eq!(s.comm, "curl");
    }
}
