//! Integration test: YARA rule detection through the full scan engine pipeline.
//!
//! Verifies that custom YARA rules loaded from disk are evaluated during
//! `scan_file` and `scan_bytes`, correctly flagging matching content as
//! Malicious while leaving non-matching content Clean.

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

/// Build a `ScanEngine` whose YARA rules directory contains a single rule
/// that matches the string `"EVIL_TEST_MARKER_XYZ"`.
fn setup_engine_with_yara_rule() -> (tempfile::TempDir, ScanEngine) {
    let tmp = tempfile::tempdir().expect("create temp dir");

    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Initialise the signature DB (empty -- we rely on YARA only).
    let _db = SignatureDatabase::open(&sigs_dir).expect("open sig db");

    // Write a YARA rule that matches "EVIL_TEST_MARKER_XYZ".
    fs::write(
        yara_dir.join("test_rule.yar"),
        r#"
rule TestEvil {
    meta:
        description = "Detects test marker for integration tests"
    strings:
        $s = "EVIL_TEST_MARKER_XYZ"
    condition:
        $s
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
    (tmp, engine)
}

#[tokio::test]
async fn yara_rule_detects_matching_content() {
    let (tmp, engine) = setup_engine_with_yara_rule();

    // -- Clean file: no YARA match expected -----------------------------------
    let clean = tmp.path().join("clean.bin");
    fs::write(&clean, "nothing suspicious here").unwrap();
    let result = engine.scan_file(&clean).await.expect("scan clean file");
    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "clean file should not trigger YARA rule"
    );

    // -- Malicious file: should trigger YARA rule -----------------------------
    let evil = tmp.path().join("evil.bin");
    fs::write(&evil, "prefix EVIL_TEST_MARKER_XYZ suffix").unwrap();
    let result = engine.scan_file(&evil).await.expect("scan evil file");
    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "file containing YARA marker should be Malicious"
    );
    assert_eq!(
        result.detection_type,
        Some(DetectionType::YaraRule),
        "detection should be via YaraRule"
    );
    assert!(
        result.threat_name.as_deref().unwrap_or("").contains("TestEvil"),
        "threat name should reference the YARA rule, got {:?}",
        result.threat_name
    );
}

#[test]
fn yara_rule_detects_via_scan_bytes() {
    let (_tmp, engine) = setup_engine_with_yara_rule();

    let result = engine.scan_bytes(b"some preamble EVIL_TEST_MARKER_XYZ trailing data", "in-memory");
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
    assert_eq!(result.detection_type, Some(DetectionType::YaraRule));
    assert!(result.threat_name.as_deref().unwrap_or("").contains("TestEvil"),);
}

#[test]
fn clean_bytes_not_matched_by_yara() {
    let (_tmp, engine) = setup_engine_with_yara_rule();

    let result = engine.scan_bytes(b"completely benign content", "clean-buf");
    assert_eq!(result.threat_level, ThreatLevel::Clean);
    assert!(result.detection_type.is_none() || result.detection_type != Some(DetectionType::YaraRule));
}

#[test]
fn yara_directory_scan_mixed_files() {
    let (tmp, engine) = setup_engine_with_yara_rule();

    let scan_dir = tmp.path().join("scan_target");
    fs::create_dir_all(&scan_dir).unwrap();

    fs::write(scan_dir.join("clean_1.txt"), "hello world").unwrap();
    fs::write(scan_dir.join("clean_2.txt"), "nothing here").unwrap();
    fs::write(scan_dir.join("evil.bin"), "payload EVIL_TEST_MARKER_XYZ end").unwrap();

    let results = engine.scan_directory(&scan_dir);
    assert_eq!(results.len(), 3, "should scan all 3 files");

    let malicious: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    assert_eq!(malicious.len(), 1, "exactly one file should be flagged as Malicious");
    assert!(malicious[0].path.to_string_lossy().contains("evil.bin"),);
}
