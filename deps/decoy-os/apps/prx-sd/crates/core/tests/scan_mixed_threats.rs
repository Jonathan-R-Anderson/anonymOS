//! Integration test: scanning a directory with a mix of clean, hash-matched,
//! and YARA-matched files.
//!
//! Exercises the full detection pipeline with multiple detection methods active
//! simultaneously and verifies correct aggregation.

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

/// Deterministic content strings whose SHA-256 hashes we import into the DB.
const HASH_MALWARE: &[u8] = b"__prx_sd_mixed_test_hash_malware__";
const YARA_TRIGGER: &[u8] = b"payload MIXED_YARA_EVIL_MARKER end";

/// Set up an engine with both hash signatures and a YARA rule active.
fn setup_mixed_engine(tmp: &tempfile::TempDir) -> ScanEngine {
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Import a SHA-256 hash.
    let db = SignatureDatabase::open(&sigs_dir).expect("open db");
    let hash = prx_sd_signatures::hash::sha256_hash(HASH_MALWARE);
    db.import_hashes(&[(hash, "Mixed.Hash.Malware".to_string())]).unwrap();
    drop(db);

    // Write a YARA rule matching "MIXED_YARA_EVIL_MARKER".
    fs::write(
        yara_dir.join("mixed_test.yar"),
        r#"
rule MixedTestEvil {
    strings:
        $marker = "MIXED_YARA_EVIL_MARKER"
    condition:
        $marker
}
"#,
    )
    .unwrap();

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(2);

    ScanEngine::new(config).expect("create engine")
}

#[test]
fn directory_with_mixed_threat_types() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_mixed_engine(&tmp);

    let scan_dir = tmp.path().join("mixed_scan");
    fs::create_dir_all(&scan_dir).unwrap();

    // Clean files.
    fs::write(scan_dir.join("clean_1.txt"), "normal text file").unwrap();
    fs::write(scan_dir.join("clean_2.txt"), "another safe file").unwrap();
    fs::write(scan_dir.join("clean_3.log"), "log entry 2026-01-01").unwrap();

    // Hash-matched malware file.
    fs::write(scan_dir.join("hash_evil.bin"), HASH_MALWARE).unwrap();

    // YARA-matched malware file.
    fs::write(scan_dir.join("yara_evil.bin"), YARA_TRIGGER).unwrap();

    let results = engine.scan_directory(&scan_dir);
    assert_eq!(results.len(), 5, "should scan all 5 files");

    // Verify hash-detected file.
    let hash_result = results
        .iter()
        .find(|r| r.path.to_string_lossy().contains("hash_evil.bin"))
        .expect("hash_evil.bin should be in results");
    assert_eq!(hash_result.threat_level, ThreatLevel::Malicious);
    assert_eq!(hash_result.detection_type, Some(DetectionType::Hash));
    assert!(
        hash_result
            .threat_name
            .as_deref()
            .unwrap_or("")
            .contains("Mixed.Hash.Malware"),
    );

    // Verify YARA-detected file.
    let yara_result = results
        .iter()
        .find(|r| r.path.to_string_lossy().contains("yara_evil.bin"))
        .expect("yara_evil.bin should be in results");
    assert_eq!(yara_result.threat_level, ThreatLevel::Malicious);
    assert_eq!(yara_result.detection_type, Some(DetectionType::YaraRule));
    assert!(
        yara_result
            .threat_name
            .as_deref()
            .unwrap_or("")
            .contains("MixedTestEvil"),
    );

    // Verify clean files.
    let clean_results: Vec<_> = results
        .iter()
        .filter(|r| {
            let name = r.path.to_string_lossy();
            name.contains("clean_1") || name.contains("clean_2") || name.contains("clean_3")
        })
        .collect();
    assert_eq!(clean_results.len(), 3);
    for r in &clean_results {
        assert_eq!(
            r.threat_level,
            ThreatLevel::Clean,
            "clean file {:?} should be Clean",
            r.path
        );
    }
}

#[tokio::test]
async fn file_matching_both_hash_and_yara_is_malicious() {
    let tmp = tempfile::tempdir().unwrap();

    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Content that will match both hash and YARA.
    let dual_content = b"dual_match_content MIXED_YARA_EVIL_MARKER";

    let db = SignatureDatabase::open(&sigs_dir).expect("open db");
    let hash = prx_sd_signatures::hash::sha256_hash(dual_content);
    db.import_hashes(&[(hash, "Dual.Hash.Match".to_string())]).unwrap();
    drop(db);

    fs::write(
        yara_dir.join("dual_test.yar"),
        r#"
rule DualTestEvil {
    strings:
        $m = "MIXED_YARA_EVIL_MARKER"
    condition:
        $m
}
"#,
    )
    .unwrap();

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(1);

    let engine = ScanEngine::new(config).expect("create engine");

    let path = tmp.path().join("dual.bin");
    fs::write(&path, dual_content).unwrap();

    let result = engine.scan_file(&path).await.expect("scan");

    // Hash is checked first and returns early, so detection_type should be Hash.
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
    assert_eq!(
        result.detection_type,
        Some(DetectionType::Hash),
        "hash match should take priority (fast-path early return)"
    );
}

#[test]
fn empty_directory_returns_no_results() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_mixed_engine(&tmp);

    let empty_dir = tmp.path().join("empty");
    fs::create_dir_all(&empty_dir).unwrap();

    let results = engine.scan_directory(&empty_dir);
    assert!(results.is_empty());
}

#[test]
fn nested_directory_mixed_threats() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_mixed_engine(&tmp);

    let root = tmp.path().join("nested_root");
    let sub_a = root.join("subdir_a");
    let sub_b = root.join("subdir_b").join("deep");

    fs::create_dir_all(&sub_a).unwrap();
    fs::create_dir_all(&sub_b).unwrap();

    fs::write(root.join("clean.txt"), "root clean").unwrap();
    fs::write(sub_a.join("hash_evil.bin"), HASH_MALWARE).unwrap();
    fs::write(sub_b.join("yara_evil.bin"), YARA_TRIGGER).unwrap();
    fs::write(sub_b.join("also_clean.txt"), "deep clean file").unwrap();

    let results = engine.scan_directory(&root);
    assert_eq!(results.len(), 4, "should recurse into all subdirs");

    let malicious: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    assert_eq!(malicious.len(), 2, "should detect both malicious files");

    let clean: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Clean)
        .collect();
    assert!(clean.len() >= 2, "at least 2 clean files expected");
}
