use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use rayon::prelude::*;
use tracing::{debug, error, warn};
use walkdir::WalkDir;

use crate::engine::ScanEngine;
use crate::magic;
use crate::result::{DetectionType, ScanResult, ThreatLevel};
use crate::virustotal::VtVerdict;

impl ScanEngine {
    /// Scan a single file through the full detection pipeline.
    ///
    /// Pipeline order:
    /// 1. Read file & check size limits
    /// 2. Hash lookup (fast-path: known malware => early return)
    /// 3. Magic-byte file-type detection
    /// 4. Format-specific parsing via `prx_sd_parsers`
    /// 5. Parallel YARA rule matching + heuristic scoring
    /// 6. Aggregate results
    pub async fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let start = Instant::now();
        let path = path.to_path_buf();

        // -- Pre-checks -----------------------------------------------------------
        if self.config.is_excluded(&path) {
            debug!(path = %path.display(), "skipping excluded path");
            return Ok(ScanResult::clean(&path, 0));
        }

        let metadata = fs::metadata(&path).with_context(|| format!("cannot stat {}", path.display()))?;

        if metadata.len() > self.config.max_file_size {
            debug!(
                path = %path.display(),
                size = metadata.len(),
                limit = self.config.max_file_size,
                "skipping oversized file"
            );
            return Ok(ScanResult::clean(&path, elapsed_ms(&start)));
        }

        let data = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;

        let mut result = self.scan_data_inner(&data, &path, &start)?;

        // If no local detection and VT is configured, try cloud lookup.
        if result.threat_level == ThreatLevel::Clean {
            if let Some(vt) = &self.vt_client {
                let hash_bytes = prx_sd_signatures::hash::sha256_hash(&data);
                let sha256_hex = hash_bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
                    let _ = write!(acc, "{b:02x}");
                    acc
                });
                match vt.lookup_sha256(&sha256_hex).await {
                    Ok(VtVerdict::Malicious {
                        threat_name,
                        detections,
                        total,
                    }) => {
                        debug!(
                            path = %path.display(),
                            threat = %threat_name,
                            "{detections}/{total} VT detections"
                        );
                        result = ScanResult::detected(
                            &path,
                            ThreatLevel::Malicious,
                            DetectionType::Hash,
                            format!("VT:{threat_name}"),
                            vec![format!(
                                "VirusTotal: {detections}/{total} engines detected as {threat_name}"
                            )],
                            elapsed_ms(&start),
                        );
                    }
                    Ok(VtVerdict::RateLimited) => {
                        debug!(path = %path.display(), "VT rate-limited, skipping");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(path = %path.display(), "VT lookup error: {e}");
                    }
                }
            }
        }

        Ok(result)
    }

    /// Scan a raw byte buffer (used by the real-time file monitor).
    ///
    /// `source` is an arbitrary label recorded in the result path field.
    pub fn scan_bytes(&self, data: &[u8], source: &str) -> ScanResult {
        let start = Instant::now();
        let path = Path::new(source).to_path_buf();

        match self.scan_data_inner(data, &path, &start) {
            Ok(result) => result,
            Err(err) => {
                error!(source = source, error = %err, "scan_bytes failed");
                let mut r = ScanResult::clean(&path, elapsed_ms(&start));
                r.details.push(format!("scan error: {err}"));
                r
            }
        }
    }

    /// Recursively scan every file under `dir`, returning results for all files
    /// (including clean ones).
    ///
    /// Uses `walkdir` for traversal and `rayon` for parallel scanning.
    pub fn scan_directory(&self, dir: &Path) -> Vec<ScanResult> {
        let entries: Vec<_> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter(|e| !self.config.is_excluded(e.path()))
            .collect();

        debug!(count = entries.len(), dir = %dir.display(), "scanning directory");

        // Build a custom thread pool with the configured parallelism.
        let pool = match rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.scan_threads)
            .build()
        {
            Ok(pool) => pool,
            Err(e) => {
                warn!(error = %e, "failed to build custom rayon pool, using default thread count");
                match rayon::ThreadPoolBuilder::new().build() {
                    Ok(pool) => pool,
                    Err(e2) => {
                        error!(
                            error = %e2,
                            "failed to build even a default rayon pool"
                        );
                        // Return error results for all entries instead of panicking.
                        return entries
                            .iter()
                            .map(|entry| {
                                let mut r = ScanResult::clean(entry.path(), 0);
                                r.details
                                    .push(format!("scan error: failed to create thread pool: {e2}"));
                                r
                            })
                            .collect();
                    }
                }
            }
        };

        pool.install(|| {
            entries
                .par_iter()
                .map(|entry| {
                    let path = entry.path();
                    let start = Instant::now();

                    match self.scan_file_sync(path) {
                        Ok(result) => result,
                        Err(err) => {
                            error!(path = %path.display(), error = %err, "scan failed");
                            let mut r = ScanResult::clean(path, elapsed_ms(&start));
                            r.details.push(format!("scan error: {err}"));
                            r
                        }
                    }
                })
                .collect()
        })
    }

    // ---- internal helpers -------------------------------------------------------

    /// Synchronous version of `scan_file` used inside the rayon thread pool
    /// (avoids the need for a tokio runtime on every rayon worker).
    fn scan_file_sync(&self, path: &Path) -> Result<ScanResult> {
        let start = Instant::now();

        let metadata = fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;

        if metadata.len() > self.config.max_file_size {
            return Ok(ScanResult::clean(path, elapsed_ms(&start)));
        }

        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;

        self.scan_data_inner(&data, path, &start)
    }

    /// Core scanning logic shared by all entry points.
    fn scan_data_inner(&self, data: &[u8], path: &Path, start: &Instant) -> Result<ScanResult> {
        let mut sub_results: Vec<ScanResult> = Vec::with_capacity(3);

        // -- 1. Hash lookup (fast path) -------------------------------------------
        if let Some(threat_name) = self.signatures.hash_lookup(data)? {
            debug!(path = %path.display(), threat = %threat_name, "hash match");
            return Ok(ScanResult::detected(
                path,
                ThreatLevel::Malicious,
                DetectionType::Hash,
                &threat_name,
                vec![format!("hash match: {threat_name}")],
                elapsed_ms(start),
            ));
        }

        // -- 2. File-type detection -----------------------------------------------
        let file_type = magic::detect_magic(data);
        debug!(path = %path.display(), file_type = %file_type, "detected type");

        // -- 3. Format-specific parsing -------------------------------------------
        let parsed = prx_sd_parsers::parse(data, file_type_to_parser(file_type));
        let parsed_ref = parsed.as_ref().ok();

        // -- 4a. YARA matching ----------------------------------------------------
        {
            let yara_start = Instant::now();
            let matches = self.yara.scan(data);
            if !matches.is_empty() {
                let names: Vec<String> = matches.iter().map(|m| m.name.clone()).collect();
                let threat = names.first().cloned().unwrap_or_default();
                let details: Vec<String> = names.iter().map(|n| format!("yara rule: {n}")).collect();
                sub_results.push(ScanResult::detected(
                    path,
                    ThreatLevel::Malicious,
                    DetectionType::YaraRule,
                    threat,
                    details,
                    elapsed_ms(&yara_start),
                ));
            }
        }

        // -- 4b. Heuristic scoring ------------------------------------------------
        {
            let heur_start = Instant::now();
            // Build a minimal ParsedFile::Unparsed if parsing failed
            let default_parsed = prx_sd_parsers::ParsedFile::Unparsed {
                file_type: prx_sd_parsers::FileType::Unknown,
                size: data.len(),
            };
            let parsed_file = parsed_ref.unwrap_or(&default_parsed);
            let heur_result = self.heuristic.analyze(data, parsed_file);

            let level = ThreatLevel::from_score(heur_result.score);
            if level != ThreatLevel::Clean {
                let details: Vec<String> = heur_result.findings.iter().map(|f| format!("heuristic: {f}")).collect();
                sub_results.push(ScanResult::detected(
                    path,
                    level,
                    DetectionType::Heuristic,
                    format!("Heuristic.Score.{}", heur_result.score),
                    details,
                    elapsed_ms(&heur_start),
                ));
            }
        }

        // -- 5. Aggregate ---------------------------------------------------------
        if sub_results.is_empty() {
            Ok(ScanResult::clean(path, elapsed_ms(start)))
        } else {
            let mut agg = ScanResult::aggregate(path, &sub_results);
            agg.scan_time_ms = elapsed_ms(start);
            Ok(agg)
        }
    }
}

/// Map our magic-based `FileType` to the parser crate's `FileType` enum.
const fn file_type_to_parser(ft: magic::FileType) -> prx_sd_parsers::FileType {
    match ft {
        magic::FileType::PE => prx_sd_parsers::FileType::PE,
        magic::FileType::ELF => prx_sd_parsers::FileType::ELF,
        magic::FileType::MachO => prx_sd_parsers::FileType::MachO,
        magic::FileType::PDF => prx_sd_parsers::FileType::PDF,
        magic::FileType::Zip => prx_sd_parsers::FileType::Zip,
        magic::FileType::Gzip => prx_sd_parsers::FileType::Gzip,
        magic::FileType::Tar => prx_sd_parsers::FileType::Tar,
        magic::FileType::Office => prx_sd_parsers::FileType::OfficeLegacy,
        magic::FileType::Script => prx_sd_parsers::FileType::Script,
        magic::FileType::SevenZip => prx_sd_parsers::FileType::SevenZip,
        magic::FileType::Unknown => prx_sd_parsers::FileType::Unknown,
    }
}

/// Milliseconds elapsed since `start`.
#[allow(clippy::cast_possible_truncation)] // Scan durations will never exceed u64::MAX ms
fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::ScanEngine;
    use crate::result::ThreatLevel;

    /// Create a minimal `ScanEngine` backed by a temporary directory.
    fn setup_test_engine() -> (tempfile::TempDir, ScanEngine) {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        let config = ScanConfig::default()
            .with_signatures_dir(sig_dir)
            .with_yara_rules_dir(yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"));
        let engine = ScanEngine::new(config).expect("engine init");
        (dir, engine)
    }

    #[tokio::test]
    async fn scan_file_clean_text() {
        let (dir, engine) = setup_test_engine();
        let file = dir.path().join("clean.txt");
        std::fs::write(&file, "Hello, this is a perfectly safe file.").expect("write");

        let result = engine.scan_file(&file).await.expect("scan");
        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(!result.is_threat());
        assert!(result.detection_type.is_none());
    }

    #[tokio::test]
    async fn scan_file_with_known_hash_returns_malicious() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        // Insert a known hash into the signature database.
        let malware_data = b"this_is_fake_malware_payload_for_testing";
        let hash = prx_sd_signatures::hash::sha256_hash(malware_data);
        let db = prx_sd_signatures::SignatureDatabase::open(&sig_dir).expect("db open");
        db.import_hashes(&[(hash, "Test.Malware.FakePayload".to_string())])
            .expect("import");
        drop(db);

        let config = ScanConfig::default()
            .with_signatures_dir(&sig_dir)
            .with_yara_rules_dir(&yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"));
        let engine = ScanEngine::new(config).expect("engine init");

        let file = dir.path().join("malware.bin");
        std::fs::write(&file, malware_data).expect("write");

        let result = engine.scan_file(&file).await.expect("scan");
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_threat());
        assert_eq!(result.detection_type, Some(DetectionType::Hash));
        assert!(
            result
                .threat_name
                .as_deref()
                .unwrap_or("")
                .contains("Test.Malware.FakePayload")
        );
    }

    #[test]
    fn scan_bytes_returns_clean_for_benign_data() {
        let (_dir, engine) = setup_test_engine();
        let result = engine.scan_bytes(b"just some normal bytes", "test_source");
        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(!result.is_threat());
    }

    #[test]
    fn scan_bytes_with_known_hash_returns_malicious() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        let malware_data = b"scan_bytes_malware_test_data_unique";
        let hash = prx_sd_signatures::hash::sha256_hash(malware_data);
        let db = prx_sd_signatures::SignatureDatabase::open(&sig_dir).expect("db open");
        db.import_hashes(&[(hash, "Test.Trojan.ByteScan".to_string())])
            .expect("import");
        drop(db);

        let config = ScanConfig::default()
            .with_signatures_dir(&sig_dir)
            .with_yara_rules_dir(&yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"));
        let engine = ScanEngine::new(config).expect("engine init");

        let result = engine.scan_bytes(malware_data, "in_memory_test");
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_threat());
    }

    #[test]
    fn scan_directory_with_mixed_files() {
        let (dir, engine) = setup_test_engine();

        let scan_dir = dir.path().join("scan_target");
        std::fs::create_dir_all(&scan_dir).expect("create scan dir");

        // Create several clean files.
        std::fs::write(scan_dir.join("file1.txt"), "clean content one").expect("write");
        std::fs::write(scan_dir.join("file2.txt"), "clean content two").expect("write");
        std::fs::write(scan_dir.join("file3.txt"), "clean content three").expect("write");

        let results = engine.scan_directory(&scan_dir);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(r.threat_level, ThreatLevel::Clean);
        }
    }

    #[tokio::test]
    async fn scan_file_excluded_path_returns_clean() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        let mut config = ScanConfig::default()
            .with_signatures_dir(&sig_dir)
            .with_yara_rules_dir(&yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"));
        config.exclude_paths = vec!["/excluded_dir".to_string()];
        let engine = ScanEngine::new(config).expect("engine init");

        // Create a file that matches the exclusion pattern.
        let excluded_dir = dir.path().join("excluded_dir");
        std::fs::create_dir_all(&excluded_dir).expect("create excluded dir");
        let file = excluded_dir.join("test.bin");
        std::fs::write(&file, "does not matter").expect("write");

        // The config excludes paths containing "/excluded_dir", but the actual
        // tempdir path will be something like /tmp/xxx/excluded_dir/test.bin,
        // which contains "excluded_dir" and should match.
        let result = engine.scan_file(&file).await.expect("scan");
        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(result.details.is_empty());
    }

    #[tokio::test]
    async fn scan_file_oversized_returns_clean() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        let config = ScanConfig::default()
            .with_signatures_dir(&sig_dir)
            .with_yara_rules_dir(&yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"))
            .with_max_file_size(10); // 10 bytes max
        let engine = ScanEngine::new(config).expect("engine init");

        let file = dir.path().join("big.bin");
        std::fs::write(&file, "this content is longer than ten bytes").expect("write");

        let result = engine.scan_file(&file).await.expect("scan");
        assert_eq!(result.threat_level, ThreatLevel::Clean);
    }

    #[tokio::test]
    async fn scan_file_nonexistent_returns_error() {
        let (_dir, engine) = setup_test_engine();
        let result = engine.scan_file(Path::new("/tmp/nonexistent_file_abc123xyz")).await;
        assert!(result.is_err());
    }

    #[test]
    fn scan_directory_excludes_paths() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        let mut config = ScanConfig::default()
            .with_signatures_dir(&sig_dir)
            .with_yara_rules_dir(&yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"));
        config.exclude_paths = vec!["skip_me".to_string()];
        let engine = ScanEngine::new(config).expect("engine init");

        let scan_dir = dir.path().join("scandir");
        let skip_dir = scan_dir.join("skip_me");
        std::fs::create_dir_all(&skip_dir).expect("create skip dir");
        std::fs::write(scan_dir.join("included.txt"), "include").expect("write");
        std::fs::write(skip_dir.join("excluded.txt"), "exclude").expect("write");

        let results = engine.scan_directory(&scan_dir);
        // Only the included file should be scanned.
        assert_eq!(results.len(), 1);
        assert!(results[0].path.to_string_lossy().contains("included.txt"));
    }

    #[test]
    fn scan_directory_respects_max_file_size() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("create yara dir");

        let config = ScanConfig::default()
            .with_signatures_dir(&sig_dir)
            .with_yara_rules_dir(&yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"))
            .with_max_file_size(5); // Very small limit
        let engine = ScanEngine::new(config).expect("engine init");

        let scan_dir = dir.path().join("scan_target");
        std::fs::create_dir_all(&scan_dir).expect("create scan dir");
        std::fs::write(scan_dir.join("small.txt"), "hi").expect("write"); // 2 bytes, under limit
        std::fs::write(scan_dir.join("big.txt"), "this is way too long").expect("write"); // over limit

        let results = engine.scan_directory(&scan_dir);
        // Both files should appear in results (oversized ones just get Clean).
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.threat_level, ThreatLevel::Clean);
        }
    }

    #[test]
    fn elapsed_ms_returns_nonzero_after_delay() {
        let start = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let ms = elapsed_ms(&start);
        assert!(ms >= 1, "expected at least 1ms elapsed, got {ms}");
    }
}
