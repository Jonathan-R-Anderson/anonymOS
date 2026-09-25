//! Ransomware behaviour detection module.
//!
//! Monitors file-system events for patterns characteristic of ransomware:
//! - Rapid bulk file modifications by a single process.
//! - Mass rename operations to known ransomware extensions.
//! - Suspicious extension changes on many files in a short time window.
//!
//! The detector is purely in-process — it receives [`FileEvent`]s from
//! the monitor layer, maintains per-PID sliding-window counters, and
//! emits a [`RansomwareVerdict`] for each event.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::event::FileEvent;

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration knobs for the ransomware detector.
#[derive(Debug, Clone)]
pub struct RansomwareConfig {
    /// Sliding window duration for counting operations.
    pub window_secs: u64,
    /// File-modification count inside the window that triggers an alert.
    pub modification_threshold: u32,
    /// Rename-operation count inside the window that triggers an alert.
    pub rename_threshold: u32,
    /// File extensions commonly appended by ransomware families.
    pub ransomware_extensions: Vec<String>,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            window_secs: 10,
            modification_threshold: 20,
            rename_threshold: 10,
            ransomware_extensions: vec![
                ".encrypted".into(),
                ".locked".into(),
                ".crypto".into(),
                ".crypt".into(),
                ".enc".into(),
                ".locky".into(),
                ".cerber".into(),
                ".zepto".into(),
                ".thor".into(),
                ".aaa".into(),
                ".abc".into(),
                ".zzz".into(),
                ".micro".into(),
                ".vvv".into(),
                ".ecc".into(),
                ".ezz".into(),
                ".exx".into(),
                ".xyz".into(),
                ".xxx".into(),
                ".ttt".into(),
                ".mp3".into(), // TeslaCrypt
                ".fun".into(),
                ".gws".into(),
                ".btc".into(),
                ".ctb".into(),
                ".ctbl".into(),
                ".crinf".into(),
                ".r5a".into(),
                ".XRNT".into(),
                ".XTBL".into(),
            ],
        }
    }
}

/// Verdict returned after analysing a single file event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RansomwareVerdict {
    /// No ransomware indicators detected.
    Clean,
    /// Some indicators detected but below the definitive threshold.
    Suspicious {
        pid: u32,
        process_name: String,
        reason: String,
        score: u32,
    },
    /// Strong ransomware behaviour detected — recommend killing the process.
    RansomwareDetected {
        pid: u32,
        process_name: String,
        reason: String,
    },
}

// ── Internal bookkeeping ──────────────────────────────────────────────────────

struct ProcessActivity {
    pid: u32,
    process_name: String,
    modifications: VecDeque<Instant>,
    renames: VecDeque<Instant>,
    suspicious_extensions: u32,
}

impl ProcessActivity {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            process_name: process_name_from_pid(pid),
            modifications: VecDeque::new(),
            renames: VecDeque::new(),
            suspicious_extensions: 0,
        }
    }

    /// Remove timestamps older than `window` from both deques.
    fn prune(&mut self, window: Duration, now: Instant) {
        let cutoff = now.checked_sub(window).unwrap_or(now);
        while self.modifications.front().is_some_and(|&t| t < cutoff) {
            self.modifications.pop_front();
        }
        while self.renames.front().is_some_and(|&t| t < cutoff) {
            self.renames.pop_front();
        }
    }
}

// ── Detector ──────────────────────────────────────────────────────────────────

/// Stateful detector that tracks per-process file-system activity and flags
/// ransomware-like patterns.
pub struct RansomwareDetector {
    process_activity: HashMap<u32, ProcessActivity>,
    config: RansomwareConfig,
}

impl RansomwareDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: RansomwareConfig) -> Self {
        Self {
            process_activity: HashMap::new(),
            config,
        }
    }

    /// Process a single file-system event and return a verdict.
    pub fn on_file_event(&mut self, event: &FileEvent) -> RansomwareVerdict {
        self.on_file_event_at(event, Instant::now())
    }

    /// Internal implementation that accepts an explicit `now` for testability.
    fn on_file_event_at(&mut self, event: &FileEvent, now: Instant) -> RansomwareVerdict {
        let pid = match event.pid() {
            Some(p) if p > 0 => p,
            _ => {
                // For file modification events without PID attribution
                // (e.g., from notify-based monitors), track under a sentinel
                // PID so modifications are still counted for path-based detection.
                match event {
                    FileEvent::Modify { .. } | FileEvent::CloseWrite { .. } => u32::MAX,
                    _ => return RansomwareVerdict::Clean,
                }
            }
        };

        let window = Duration::from_secs(self.config.window_secs);

        // Check ransomware extension before borrowing process_activity mutably.
        let is_ransomware_ext = if let FileEvent::Rename { to, .. } = event {
            Self::has_ransomware_extension_in(&self.config.ransomware_extensions, to)
        } else {
            false
        };

        let activity = self
            .process_activity
            .entry(pid)
            .or_insert_with(|| ProcessActivity::new(pid));

        activity.prune(window, now);

        match event {
            FileEvent::Modify { .. } | FileEvent::CloseWrite { .. } => {
                activity.modifications.push_back(now);
            }
            FileEvent::Rename { .. } => {
                activity.renames.push_back(now);
                if is_ransomware_ext {
                    activity.suspicious_extensions += 1;
                }
            }
            _ => return RansomwareVerdict::Clean,
        }

        self.evaluate(pid)
    }

    /// Evaluate current counters for a given PID and return a verdict.
    pub fn check_process(&self, pid: u32) -> RansomwareVerdict {
        let Some(activity) = self.process_activity.get(&pid) else {
            return RansomwareVerdict::Clean;
        };

        // VecDeque lengths are bounded by event rates, well within u32 range.
        #[allow(clippy::cast_possible_truncation)]
        let mod_count = activity.modifications.len() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let ren_count = activity.renames.len() as u32;
        let ext_count = activity.suspicious_extensions;

        // Definitive: both thresholds exceeded OR many ransomware extensions.
        if (mod_count >= self.config.modification_threshold && ren_count >= self.config.rename_threshold)
            || ext_count >= self.config.rename_threshold
        {
            return RansomwareVerdict::RansomwareDetected {
                pid: activity.pid,
                process_name: activity.process_name.clone(),
                reason: format!(
                    "modifications={mod_count}, renames={ren_count}, \
                     ransomware_extensions={ext_count} in {}s window",
                    self.config.window_secs,
                ),
            };
        }

        // Suspicious: either threshold reached individually.
        if mod_count >= self.config.modification_threshold
            || ren_count >= self.config.rename_threshold
            || ext_count >= self.config.rename_threshold / 2
        {
            let score = (mod_count * 2) + (ren_count * 3) + (ext_count * 5);
            return RansomwareVerdict::Suspicious {
                pid: activity.pid,
                process_name: activity.process_name.clone(),
                reason: format!(
                    "modifications={mod_count}, renames={ren_count}, \
                     ransomware_extensions={ext_count} in {}s window",
                    self.config.window_secs,
                ),
                score,
            };
        }

        RansomwareVerdict::Clean
    }

    // ── helpers ───────────────────────────────────────────────────────────

    fn evaluate(&self, pid: u32) -> RansomwareVerdict {
        self.check_process(pid)
    }

    fn has_ransomware_extension_in(extensions: &[String], path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let lower = name.to_ascii_lowercase();
        extensions.iter().any(|ext| lower.ends_with(&ext.to_ascii_lowercase()))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Best-effort process name lookup.
///
/// - Linux: reads `/proc/{pid}/comm`
/// - macOS: falls back to `ps -p {pid} -o comm=`
/// - Other: returns `"pid:{pid}"`
fn process_name_from_pid(pid: u32) -> String {
    // Try /proc first (Linux, some macOS with procfs)
    if let Ok(name) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        return name.trim().to_string();
    }

    // macOS fallback
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }

    format!("pid:{pid}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn make_rename_ransomware(pid: u32, idx: u32) -> FileEvent {
        FileEvent::Rename {
            from: PathBuf::from(format!("/home/user/doc{idx}.pdf")),
            to: PathBuf::from(format!("/home/user/doc{idx}.pdf.encrypted")),
            pid,
        }
    }

    fn make_rename_clean(pid: u32, idx: u32) -> FileEvent {
        FileEvent::Rename {
            from: PathBuf::from(format!("/tmp/file{idx}.tmp")),
            to: PathBuf::from(format!("/tmp/file{idx}.dat")),
            pid,
        }
    }

    #[test]
    fn clean_activity_returns_clean() {
        let mut det = RansomwareDetector::new(RansomwareConfig::default());
        let now = Instant::now();

        // A handful of renames — well below threshold.
        for i in 0..3 {
            let v = det.on_file_event_at(&make_rename_clean(42, i), now);
            assert_eq!(v, RansomwareVerdict::Clean);
        }
    }

    #[test]
    fn rapid_renames_trigger_detection() {
        let config = RansomwareConfig {
            rename_threshold: 5,
            modification_threshold: 100, // high so it won't trigger
            ..RansomwareConfig::default()
        };
        let mut det = RansomwareDetector::new(config);
        let now = Instant::now();

        let mut last = RansomwareVerdict::Clean;
        for i in 0..6 {
            last = det.on_file_event_at(&make_rename_clean(99, i), now);
        }

        // Should be at least suspicious (renames >= threshold).
        assert!(
            matches!(last, RansomwareVerdict::Suspicious { .. }),
            "expected Suspicious, got {last:?}"
        );
    }

    #[test]
    fn ransomware_extensions_trigger_detection() {
        let config = RansomwareConfig {
            rename_threshold: 10,
            modification_threshold: 20,
            ..RansomwareConfig::default()
        };
        let mut det = RansomwareDetector::new(config);
        let now = Instant::now();

        // Feed enough ransomware-extension renames to hit ext_count >= rename_threshold.
        let mut last = RansomwareVerdict::Clean;
        for i in 0..10 {
            last = det.on_file_event_at(&make_rename_ransomware(7, i), now);
        }

        assert!(
            matches!(last, RansomwareVerdict::RansomwareDetected { .. }),
            "expected RansomwareDetected, got {last:?}"
        );
    }

    #[test]
    fn window_expiry_prunes_old_events() {
        let config = RansomwareConfig {
            window_secs: 2,
            rename_threshold: 5,
            modification_threshold: 100,
            ..RansomwareConfig::default()
        };
        let mut det = RansomwareDetector::new(config);

        let t0 = Instant::now();

        // Add 4 renames at t0.
        for i in 0..4 {
            det.on_file_event_at(&make_rename_clean(50, i), t0);
        }

        // Jump forward past the window.
        let t1 = t0 + Duration::from_secs(3);

        // Add 2 more renames at t1 — the old 4 should be pruned.
        for i in 10..12 {
            let v = det.on_file_event_at(&make_rename_clean(50, i), t1);
            assert_eq!(v, RansomwareVerdict::Clean);
        }

        // Total within window should be 2, well below threshold of 5.
        assert_eq!(det.check_process(50), RansomwareVerdict::Clean);
    }

    #[test]
    fn events_without_pid_track_modifications() {
        let config = RansomwareConfig {
            modification_threshold: 3,
            ..RansomwareConfig::default()
        };
        let mut det = RansomwareDetector::new(config);
        let now = Instant::now();

        // Modify events without PID should still be tracked.
        for i in 0..3 {
            det.on_file_event_at(
                &FileEvent::Modify {
                    path: PathBuf::from(format!("/tmp/file{i}")),
                },
                now,
            );
        }
        // The sentinel PID bucket should have 3 modifications.
        let v = det.check_process(u32::MAX);
        assert!(
            matches!(v, RansomwareVerdict::Suspicious { .. }),
            "expected Suspicious from tracked modifications, got {v:?}"
        );
    }

    #[test]
    fn events_without_pid_create_delete_are_ignored() {
        let mut det = RansomwareDetector::new(RansomwareConfig::default());
        let v = det.on_file_event(&FileEvent::Create {
            path: PathBuf::from("/tmp/y"),
        });
        assert_eq!(v, RansomwareVerdict::Clean);

        let v = det.on_file_event(&FileEvent::Delete {
            path: PathBuf::from("/tmp/z"),
        });
        assert_eq!(v, RansomwareVerdict::Clean);
    }

    #[test]
    fn check_process_unknown_pid_is_clean() {
        let det = RansomwareDetector::new(RansomwareConfig::default());
        assert_eq!(det.check_process(99999), RansomwareVerdict::Clean);
    }
}
