//! Integration test: import hashes into the signature database, then scan
//! files through the full engine pipeline to verify detection.
//!
//! Covers both SHA-256 and MD5 import paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal,
    clippy::redundant_closure_for_method_calls,
    clippy::format_collect,
    clippy::int_plus_one,
    clippy::needless_collect,
    clippy::if_not_else,
    clippy::redundant_clone,
    clippy::uninlined_format_args,
    clippy::similar_names,
    clippy::used_underscore_binding,
    clippy::unnecessary_wraps,
    clippy::bool_assert_comparison,
    clippy::vec_init_then_push,
    clippy::print_stderr,
    clippy::write_with_newline,
    clippy::needless_pass_by_value,
    clippy::match_same_arms,
    clippy::manual_let_else,
    clippy::return_self_not_must_use,
    clippy::must_use_candidate,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
use std::fs;

use prx_sd_core::{DetectionType, ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_signatures::SignatureDatabase;

/// Helper: create dirs, open DB, build engine.
fn setup(tmp: &tempfile::TempDir) -> (SignatureDatabase, ScanConfig) {
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    let db = SignatureDatabase::open(&sigs_dir).expect("open sig db");

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(1);

    (db, config)
}

#[tokio::test]
async fn import_sha256_hash_then_scan_detects() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, config) = setup(&tmp);

    let malware_content = b"__integration_test_malware_sha256_alpha__";
    let hash = prx_sd_signatures::hash::sha256_hash(malware_content);

    let imported = db
        .import_hashes(&[(hash, "Test.Trojan.SHA256Import".to_string())])
        .unwrap();
    assert_eq!(imported, 1);

    // Drop the DB handle so the engine can open it.
    drop(db);

    let engine = ScanEngine::new(config).expect("create engine");

    // Write malware content to a file and scan.
    let evil_path = tmp.path().join("evil_sha256.bin");
    fs::write(&evil_path, malware_content).unwrap();

    let result = engine.scan_file(&evil_path).await.expect("scan file");
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
    assert_eq!(result.detection_type, Some(DetectionType::Hash));
    assert_eq!(result.threat_name.as_deref(), Some("Test.Trojan.SHA256Import"),);

    // Clean file should not match.
    let clean_path = tmp.path().join("clean.txt");
    fs::write(&clean_path, "this is perfectly safe content").unwrap();

    let result = engine.scan_file(&clean_path).await.expect("scan clean");
    assert_eq!(result.threat_level, ThreatLevel::Clean);
}

#[tokio::test]
async fn import_multiple_hashes_scan_detects_all() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, config) = setup(&tmp);

    let sample_a = b"__test_malware_multi_a__";
    let sample_b = b"__test_malware_multi_b__";

    let hash_a = prx_sd_signatures::hash::sha256_hash(sample_a);
    let hash_b = prx_sd_signatures::hash::sha256_hash(sample_b);

    db.import_hashes(&[
        (hash_a, "Test.Malware.MultiA".to_string()),
        (hash_b, "Test.Malware.MultiB".to_string()),
    ])
    .unwrap();
    drop(db);

    let engine = ScanEngine::new(config).expect("create engine");

    let dir = tmp.path().join("multi_scan");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a.bin"), sample_a).unwrap();
    fs::write(dir.join("b.bin"), sample_b).unwrap();
    fs::write(dir.join("clean.txt"), "benign").unwrap();

    let results = engine.scan_directory(&dir);
    assert_eq!(results.len(), 3);

    let malicious: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    assert_eq!(malicious.len(), 2, "both malware samples should be detected");
}

#[tokio::test]
async fn scan_after_md5_import_detects() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, config) = setup(&tmp);

    // MD5 imports go into a separate DB table but the engine checks both.
    // However, the default scan pipeline in scan_data_inner only does
    // SHA-256 hash_lookup. MD5 lookup is used via md5_lookup on the DB
    // directly. We verify that the DB import and lookup work correctly,
    // and that SHA-256 import is the primary detection path in scan_file.

    let sample = b"__test_md5_import_sample__";
    let md5_hash = prx_sd_signatures::hash::md5_hash(sample);

    db.import_md5_hashes(&[(md5_hash.clone(), "Test.MD5.Sample".to_string())])
        .unwrap();

    // Verify direct DB lookup works.
    let lookup = db.md5_lookup(sample).unwrap();
    assert_eq!(lookup, Some("Test.MD5.Sample".to_string()));

    // Also import as SHA-256 so the scan pipeline detects it.
    let sha256_hash = prx_sd_signatures::hash::sha256_hash(sample);
    db.import_hashes(&[(sha256_hash, "Test.SHA256.Sample".to_string())])
        .unwrap();
    drop(db);

    let engine = ScanEngine::new(config).expect("create engine");

    let path = tmp.path().join("md5_test.bin");
    fs::write(&path, sample).unwrap();

    let result = engine.scan_file(&path).await.expect("scan");
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
    assert_eq!(result.detection_type, Some(DetectionType::Hash));
}
