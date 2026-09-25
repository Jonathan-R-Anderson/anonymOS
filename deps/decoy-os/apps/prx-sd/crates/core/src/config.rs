use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the scan engine.
///
/// Sensible defaults are provided via [`Default`]; individual fields can be
/// overridden after construction or loaded from a config file via serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum file size (bytes) to scan. Files larger than this are skipped.
    /// Default: 100 MiB.
    pub max_file_size: u64,

    /// Number of worker threads for parallel directory scans.
    /// Default: number of logical CPUs.
    pub scan_threads: usize,

    /// Per-file timeout in milliseconds. If a single file takes longer than
    /// this the scan is aborted for that file and it is reported as an error.
    /// Default: 30 000 ms (30 s).
    pub timeout_per_file_ms: u64,

    /// Glob patterns or absolute paths to exclude from scanning.
    pub exclude_paths: Vec<String>,

    /// Whether to recurse into archive files (ZIP, tar.gz, 7z, etc.).
    /// Default: `true`.
    pub scan_archives: bool,

    /// Maximum nesting depth when recursing into archives.
    /// Default: 3.
    pub max_archive_depth: u32,

    /// Minimum heuristic score (0-100) required to flag a file as suspicious.
    /// Default: 60.
    pub heuristic_threshold: u32,

    /// Directory containing signature database files.
    pub signatures_dir: PathBuf,

    /// Directory containing compiled YARA rule files (`.yar` / `.yara`).
    pub yara_rules_dir: PathBuf,

    /// Directory where quarantined files are stored.
    pub quarantine_dir: PathBuf,

    /// `VirusTotal` API key for cloud hash lookups. Empty string disables VT.
    #[serde(default)]
    pub vt_api_key: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        let num_cpus = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(4);

        Self {
            max_file_size: 100 * 1024 * 1024, // 100 MiB
            scan_threads: num_cpus,
            timeout_per_file_ms: 30_000,
            exclude_paths: Vec::new(),
            scan_archives: true,
            max_archive_depth: 3,
            heuristic_threshold: 60,
            signatures_dir: PathBuf::from("/var/lib/prx-sd/signatures"),
            yara_rules_dir: PathBuf::from("/var/lib/prx-sd/yara"),
            quarantine_dir: PathBuf::from("/var/lib/prx-sd/quarantine"),
            vt_api_key: String::new(),
        }
    }
}

impl ScanConfig {
    /// Create a config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style setter for `max_file_size`.
    #[must_use]
    pub const fn with_max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Builder-style setter for `scan_threads`.
    #[must_use]
    pub const fn with_scan_threads(mut self, n: usize) -> Self {
        self.scan_threads = n;
        self
    }

    /// Builder-style setter for `timeout_per_file_ms`.
    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_per_file_ms = ms;
        self
    }

    /// Builder-style setter for `heuristic_threshold`.
    #[must_use]
    pub const fn with_heuristic_threshold(mut self, threshold: u32) -> Self {
        self.heuristic_threshold = threshold;
        self
    }

    /// Builder-style setter for `signatures_dir`.
    #[must_use]
    pub fn with_signatures_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.signatures_dir = dir.into();
        self
    }

    /// Builder-style setter for `yara_rules_dir`.
    #[must_use]
    pub fn with_yara_rules_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.yara_rules_dir = dir.into();
        self
    }

    /// Builder-style setter for `quarantine_dir`.
    #[must_use]
    pub fn with_quarantine_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.quarantine_dir = dir.into();
        self
    }

    /// Returns `true` if `path` matches any exclude pattern.
    pub fn is_excluded(&self, path: &std::path::Path) -> bool {
        let path_str = path.to_string_lossy();
        self.exclude_paths.iter().any(|pattern| {
            // Support simple glob-style matching: if the pattern contains '*'
            // we do a basic wildcard check, otherwise we check prefix/contains.
            if pattern.contains('*') {
                glob_match(pattern, &path_str)
            } else {
                path_str.contains(pattern.as_str())
            }
        })
    }
}

/// Minimal glob matcher supporting `*` (any chars) and `?` (single char).
/// This is intentionally simple; for production use consider the `glob` crate.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
        0,
        0,
        0,
    )
}

#[allow(clippy::indexing_slicing)] // pi/ti are always bounds-checked before indexing
fn glob_match_inner(pattern: &[char], text: &[char], pi: usize, ti: usize, depth: usize) -> bool {
    // Guard against pathological patterns (e.g. "****...****") that would
    // otherwise cause exponential recursion / stack overflow.
    const MAX_DEPTH: usize = 100;
    if depth > MAX_DEPTH {
        return false;
    }
    if pi == pattern.len() {
        return ti == text.len();
    }
    if pattern[pi] == '*' {
        // '*' matches zero or more characters.
        // Try matching zero chars, then one, two, ...
        for skip in 0..=(text.len() - ti) {
            if glob_match_inner(pattern, text, pi + 1, ti + skip, depth + 1) {
                return true;
            }
        }
        false
    } else if ti < text.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
        glob_match_inner(pattern, text, pi + 1, ti + 1, depth + 1)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.max_file_size, 100 * 1024 * 1024);
        assert_eq!(cfg.timeout_per_file_ms, 30_000);
        assert!(cfg.scan_archives);
        assert_eq!(cfg.max_archive_depth, 3);
        assert_eq!(cfg.heuristic_threshold, 60);
    }

    #[test]
    fn exclude_simple() {
        let cfg = ScanConfig {
            exclude_paths: vec!["/proc".into(), "*.log".into()],
            ..Default::default()
        };
        assert!(cfg.is_excluded(std::path::Path::new("/proc/1/maps")));
        assert!(cfg.is_excluded(std::path::Path::new("/var/log/app.log")));
        assert!(!cfg.is_excluded(std::path::Path::new("/home/user/file.txt")));
    }

    #[test]
    fn builder_chain() {
        let cfg = ScanConfig::new()
            .with_max_file_size(50 * 1024 * 1024)
            .with_scan_threads(2)
            .with_heuristic_threshold(80);
        assert_eq!(cfg.max_file_size, 50 * 1024 * 1024);
        assert_eq!(cfg.scan_threads, 2);
        assert_eq!(cfg.heuristic_threshold, 80);
    }
}
