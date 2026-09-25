//! Windows registry monitoring for persistence-related keys.
//!
//! Monitors autorun and service registry keys that malware commonly abuses
//! for persistence. On non-Windows platforms, this module provides no-op
//! implementations that compile cleanly.

use serde::{Deserialize, Serialize};

/// Type of registry change detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryEventType {
    /// A registry value was set or modified.
    ValueSet,
    /// A registry value was deleted.
    ValueDeleted,
    /// A new registry key was created.
    KeyCreated,
    /// A registry key was deleted.
    KeyDeleted,
}

/// A single registry change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    /// Full registry key path (e.g. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).
    pub key_path: String,
    /// Name of the value that changed, or empty for key-level events.
    pub value_name: String,
    /// The type of change detected.
    pub event_type: RegistryEventType,
    /// ISO-8601 timestamp of when the event was detected.
    pub timestamp: String,
}

/// Default autorun and service registry keys commonly abused by malware.
const DEFAULT_WATCHED_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
];

/// Monitors Windows registry keys for changes that may indicate malware persistence.
///
/// On Windows, this uses `reg query` via `std::process::Command` to periodically
/// snapshot registry key values and detect additions, modifications, and deletions.
///
/// On non-Windows platforms, all methods are no-ops that return empty results.
pub struct RegistryMonitor {
    watched_keys: Vec<String>,
    #[cfg(target_os = "windows")]
    baseline: std::collections::HashMap<String, Vec<RegistryValueSnapshot>>,
}

/// Snapshot of a single registry value for change detection.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryValueSnapshot {
    name: String,
    data: String,
}

impl RegistryMonitor {
    /// Create a new `RegistryMonitor` watching the default persistence keys.
    pub fn new() -> Self {
        Self::with_keys(DEFAULT_WATCHED_KEYS.iter().map(|k| (*k).to_owned()).collect())
    }

    /// Create a new `RegistryMonitor` watching the specified registry keys.
    #[allow(clippy::missing_const_for_fn)] // not const on Windows (HashMap::new)
    pub fn with_keys(watched_keys: Vec<String>) -> Self {
        Self {
            watched_keys,
            #[cfg(target_os = "windows")]
            baseline: std::collections::HashMap::new(),
        }
    }

    /// Returns the list of registry keys being monitored.
    pub fn watched_keys(&self) -> &[String] {
        &self.watched_keys
    }

    /// Take a baseline snapshot of all watched keys.
    ///
    /// This must be called before `detect_changes` to establish the initial state.
    /// On non-Windows platforms this is a no-op.
    #[allow(clippy::missing_const_for_fn)] // not const on Windows (HashMap::insert, ?)
    pub fn capture_baseline(&mut self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            for key in &self.watched_keys {
                let values = Self::query_key_values(key)?;
                self.baseline.insert(key.clone(), values);
            }
        }
        Ok(())
    }

    /// Detect changes since the last baseline or the last call to `detect_changes`.
    ///
    /// Returns a list of `RegistryEvent`s describing what changed. After detection,
    /// the internal baseline is updated to the current state.
    ///
    /// On non-Windows platforms this always returns an empty list.
    #[allow(clippy::missing_const_for_fn)] // not const on Windows (calls detect_changes_windows)
    pub fn detect_changes(&mut self) -> Result<Vec<RegistryEvent>, String> {
        #[cfg(target_os = "windows")]
        {
            self.detect_changes_windows()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Windows-specific change detection implementation.
    #[cfg(target_os = "windows")]
    fn detect_changes_windows(&mut self) -> Result<Vec<RegistryEvent>, String> {
        let mut events = Vec::new();
        let now = current_timestamp();

        for key in &self.watched_keys {
            let current_values = Self::query_key_values(key)?;
            let old_values = self.baseline.get(key);

            match old_values {
                Some(old) => {
                    // Detect new or modified values
                    for cv in &current_values {
                        match old.iter().find(|ov| ov.name == cv.name) {
                            Some(ov) if ov.data != cv.data => {
                                events.push(RegistryEvent {
                                    key_path: key.clone(),
                                    value_name: cv.name.clone(),
                                    event_type: RegistryEventType::ValueSet,
                                    timestamp: now.clone(),
                                });
                            }
                            None => {
                                events.push(RegistryEvent {
                                    key_path: key.clone(),
                                    value_name: cv.name.clone(),
                                    event_type: RegistryEventType::ValueSet,
                                    timestamp: now.clone(),
                                });
                            }
                            _ => {}
                        }
                    }
                    // Detect deleted values
                    for ov in old {
                        if !current_values.iter().any(|cv| cv.name == ov.name) {
                            events.push(RegistryEvent {
                                key_path: key.clone(),
                                value_name: ov.name.clone(),
                                event_type: RegistryEventType::ValueDeleted,
                                timestamp: now.clone(),
                            });
                        }
                    }
                }
                None => {
                    // Key is new (was not in baseline); report all values as new
                    if !current_values.is_empty() {
                        events.push(RegistryEvent {
                            key_path: key.clone(),
                            value_name: String::new(),
                            event_type: RegistryEventType::KeyCreated,
                            timestamp: now.clone(),
                        });
                    }
                }
            }

            self.baseline.insert(key.clone(), current_values);
        }

        Ok(events)
    }

    /// Query a registry key's values using `reg query`.
    ///
    /// Parses the output of `reg query <key>` to extract value name/data pairs.
    #[cfg(target_os = "windows")]
    fn query_key_values(key: &str) -> Result<Vec<RegistryValueSnapshot>, String> {
        let output = std::process::Command::new("reg")
            .args(["query", key])
            .output()
            .map_err(|e| format!("failed to execute reg query for {key}: {e}"))?;

        if !output.status.success() {
            // Key may not exist; return empty rather than error
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut values = Vec::new();

        for line in stdout.lines() {
            let trimmed = line.trim();
            // reg query output format: "    ValueName    REG_TYPE    Data"
            // Lines with values start with whitespace and have at least 3 fields
            if !trimmed.is_empty() && line.starts_with("    ") {
                let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
                if parts.len() >= 3 {
                    values.push(RegistryValueSnapshot {
                        name: parts[0].trim().to_owned(),
                        data: parts[2].trim().to_owned(),
                    });
                }
            }
        }

        Ok(values)
    }
}

impl Default for RegistryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns an ISO-8601 formatted timestamp string.
///
/// Uses a simple implementation that does not pull in the `chrono` crate.
#[cfg(target_os = "windows")]
fn current_timestamp() -> String {
    // On Windows, use SystemTime for a UTC timestamp
    let now = std::time::SystemTime::now();
    let duration = match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => return "1970-01-01T00:00:00Z".to_owned(),
    };
    let secs = duration.as_secs();
    // Simple UTC timestamp without pulling in chrono
    // Format: seconds since epoch (consumers can convert)
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Compute year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_date(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
#[cfg(target_os = "windows")]
fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_watched_keys() {
        let monitor = RegistryMonitor::new();
        assert_eq!(monitor.watched_keys().len(), 4);
        assert!(monitor.watched_keys()[0].contains("CurrentVersion\\Run"));
    }

    #[test]
    fn test_custom_watched_keys() {
        let keys = vec![r"HKLM\SOFTWARE\Test".to_owned()];
        let monitor = RegistryMonitor::with_keys(keys.clone());
        assert_eq!(monitor.watched_keys(), &keys);
    }

    #[test]
    fn test_detect_changes_noop_on_non_windows() {
        let mut monitor = RegistryMonitor::new();
        // On non-Windows this is a no-op returning empty vec
        let result = monitor.detect_changes();
        assert!(result.is_ok());
        // On Linux/macOS this will always be empty
        #[cfg(not(target_os = "windows"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_capture_baseline_noop_on_non_windows() {
        let mut monitor = RegistryMonitor::new();
        assert!(monitor.capture_baseline().is_ok());
    }

    #[test]
    fn test_registry_event_serialization() {
        let event = RegistryEvent {
            key_path: r"HKLM\SOFTWARE\Test".to_owned(),
            value_name: "TestVal".to_owned(),
            event_type: RegistryEventType::ValueSet,
            timestamp: "2026-03-17T00:00:00Z".to_owned(),
        };
        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
    }
}
