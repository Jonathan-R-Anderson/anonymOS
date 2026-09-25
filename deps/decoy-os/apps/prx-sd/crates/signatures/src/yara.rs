//! YARA-X integration for rule-based malware detection.
//!
//! Uses the `yara-x` crate (a pure-Rust YARA implementation) to compile
//! and scan binary data against YARA rules. Rules are loaded from `.yar`
//! and `.yara` files in a given directory.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tracing::instrument;
use walkdir::WalkDir;

/// A match result from a YARA scan.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// The rule identifier that matched.
    pub name: String,
    /// The namespace of the matched rule (typically the file it came from).
    pub namespace: String,
    /// Tags attached to the matched rule.
    pub tags: Vec<String>,
}

/// YARA rule scanning engine backed by `yara-x`.
///
/// Compiles all `.yar`/`.yara` rule files from a directory into an optimized
/// rule set and scans binary data against them.
pub struct YaraEngine {
    /// Number of rule files that were successfully compiled.
    rule_count: usize,
    /// Compiled YARA-X rules, shared via `Arc` so the engine is cheaply cloneable.
    compiled_rules: Option<Arc<yara_x::Rules>>,
}

impl YaraEngine {
    /// Load and compile all `.yar`/`.yara` rule files from `rules_dir` (recursively).
    ///
    /// Rules that fail to compile are logged and skipped — a single bad rule
    /// does not prevent the rest from loading.
    #[instrument(skip_all, fields(rules_dir = %rules_dir.display()))]
    pub fn load_rules(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.is_dir() {
            anyhow::bail!("YARA rules directory does not exist: {}", rules_dir.display());
        }

        let mut compiler = yara_x::Compiler::new();
        let mut count = 0usize;
        let mut errors = 0usize;

        for entry in WalkDir::new(rules_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            // Use entry.file_type() (lstat) rather than path.is_file() (stat)
            // to avoid following symlinks that could escape the rules directory.
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path_is_symlink() {
                tracing::debug!(path = %path.display(), "skipping symlinked YARA rule file");
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
            if ext != "yar" && ext != "yara" && ext != "rule" {
                continue;
            }

            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(path = %path.display(), "failed to read YARA rule: {e}");
                    errors += 1;
                    continue;
                }
            };

            // Use filename stem as namespace to avoid rule name collisions.
            let namespace = path.file_stem().and_then(|s| s.to_str()).unwrap_or("default");

            compiler.new_namespace(namespace);

            if let Err(e) = compiler.add_source(source.as_str()) {
                tracing::warn!(
                    path = %path.display(),
                    "YARA compilation error (skipping): {e}"
                );
                errors += 1;
                continue;
            }

            tracing::debug!(path = %path.display(), "compiled YARA rule file");
            count += 1;
        }

        let compiled_rules = if count > 0 {
            let rules = compiler.build();
            Some(Arc::new(rules))
        } else {
            None
        };

        if errors > 0 {
            tracing::warn!(errors, "some YARA rule files failed to compile");
        }
        tracing::info!(compiled = count, skipped = errors, "YARA-X engine ready");

        Ok(Self {
            rule_count: count,
            compiled_rules,
        })
    }

    /// Scan binary data against all loaded YARA rules.
    ///
    /// Returns a list of `YaraMatch` for each rule that matched.
    #[instrument(skip_all, fields(data_len = data.len(), rules = self.rule_count))]
    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        let Some(rules) = &self.compiled_rules else {
            return Vec::new();
        };

        let mut scanner = yara_x::Scanner::new(rules);
        let results = match scanner.scan(data) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("YARA-X scan error: {e}");
                return Vec::new();
            }
        };

        results
            .matching_rules()
            .map(|rule| YaraMatch {
                name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            })
            .collect()
    }

    /// Return the number of successfully compiled YARA rule files.
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_load_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let engine = YaraEngine::load_rules(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let result = YaraEngine::load_rules(Path::new("/nonexistent/yara/rules"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_with_yar_files() {
        let dir = tempfile::tempdir().unwrap();

        let rule_content = r#"
rule TestRule : tag1 tag2 {
    meta:
        description = "Test rule"
    strings:
        $s1 = "malicious_string"
    condition:
        $s1
}
"#;
        std::fs::write(dir.path().join("test.yar"), rule_content).unwrap();
        std::fs::write(dir.path().join("another.yara"), rule_content).unwrap();
        // Non-YARA file should be ignored.
        std::fs::write(dir.path().join("readme.txt"), "not a rule").unwrap();

        let engine = YaraEngine::load_rules(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_scan_returns_empty_for_clean_data() {
        let dir = tempfile::tempdir().unwrap();
        let engine = YaraEngine::load_rules(dir.path()).unwrap();
        let matches = engine.scan(b"some binary data");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_detects_matching_rule() {
        let dir = tempfile::tempdir().unwrap();

        let rule_content = r#"
rule TestMalware : test {
    meta:
        description = "Detects test malware string"
    strings:
        $evil = "EVIL_PAYLOAD_MARKER"
    condition:
        $evil
}
"#;
        std::fs::write(dir.path().join("test.yar"), rule_content).unwrap();

        let engine = YaraEngine::load_rules(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 1);

        // Should NOT match clean data.
        let matches = engine.scan(b"this is clean data");
        assert!(matches.is_empty());

        // Should match data containing the marker.
        let matches = engine.scan(b"prefix EVIL_PAYLOAD_MARKER suffix");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "TestMalware");
        assert_eq!(matches[0].tags, vec!["test"]);
    }

    #[test]
    fn test_bad_rule_skipped_gracefully() {
        let dir = tempfile::tempdir().unwrap();

        // Valid rule.
        let good_rule = r#"
rule GoodRule {
    strings:
        $s = "good"
    condition:
        $s
}
"#;
        // Invalid YARA syntax.
        let bad_rule = "this is not a valid yara rule {{{";

        std::fs::write(dir.path().join("good.yar"), good_rule).unwrap();
        std::fs::write(dir.path().join("bad.yar"), bad_rule).unwrap();

        let engine = YaraEngine::load_rules(dir.path()).unwrap();
        // Only the good rule should compile successfully.
        assert_eq!(engine.rule_count(), 1);

        let matches = engine.scan(b"this contains good marker");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "GoodRule");
    }
}
