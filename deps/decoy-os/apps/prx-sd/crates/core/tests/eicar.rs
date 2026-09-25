//! Integration tests for EICAR test-file detection.
//!
//! The EICAR test string is a standard antivirus test payload that every
//! conforming AV product should detect.  We verify that our hash-based
//! detection pipeline correctly identifies the EICAR string and that clean
//! files pass without false positives.

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

/// The canonical EICAR test string.
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Helper: set up temp dirs, import the EICAR SHA-256 hash into a fresh
/// signature database, and return a ready-to-use `ScanEngine`.
fn setup_engine_with_eicar() -> (tempfile::TempDir, ScanEngine) {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Import EICAR hash into the signature database.
    let db = SignatureDatabase::open(&sigs_dir).expect("failed to open sig db");
    let eicar_hash = prx_sd_signatures::hash::sha256_hash(EICAR);
    db.import_hashes(&[(eicar_hash, "EICAR-Test-File".to_string())])
        .expect("failed to import EICAR hash");

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(1);

    let engine = ScanEngine::new(config).expect("failed to create scan engine");

    (tmp, engine)
}

/// Helper: set up an engine with no malicious hashes imported (clean DB).
fn setup_clean_engine() -> (tempfile::TempDir, ScanEngine) {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Open the database to initialise it, but do not import anything.
    let _db = SignatureDatabase::open(&sigs_dir).expect("failed to open sig db");

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(1);

    let engine = ScanEngine::new(config).expect("failed to create scan engine");
    (tmp, engine)
}

#[tokio::test]
async fn test_eicar_hash_detection() {
    let (tmp, engine) = setup_engine_with_eicar();

    // Write EICAR string to a temp file.
    let eicar_path = tmp.path().join("eicar.com");
    fs::write(&eicar_path, EICAR).unwrap();

    let result = engine.scan_file(&eicar_path).await.expect("scan failed");

    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "EICAR file should be detected as Malicious"
    );
    assert_eq!(
        result.detection_type,
        Some(DetectionType::Hash),
        "EICAR should be detected via hash lookup"
    );
    assert!(
        result.threat_name.as_deref() == Some("EICAR-Test-File"),
        "threat name should be 'EICAR-Test-File', got {:?}",
        result.threat_name
    );
    assert!(result.is_threat());
}

#[tokio::test]
async fn test_clean_file_passes() {
    let (tmp, engine) = setup_engine_with_eicar();

    let clean_path = tmp.path().join("clean.txt");
    fs::write(&clean_path, b"This is a perfectly benign text file.").unwrap();

    let result = engine.scan_file(&clean_path).await.expect("scan failed");

    assert_eq!(result.threat_level, ThreatLevel::Clean, "benign file should be Clean");
    assert!(!result.is_threat());
}

#[test]
fn test_eicar_in_scan_bytes() {
    let (_tmp, engine) = setup_engine_with_eicar();

    let result = engine.scan_bytes(EICAR, "eicar-in-memory");

    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "EICAR bytes should be detected as Malicious"
    );
    assert_eq!(result.detection_type, Some(DetectionType::Hash));
    assert!(result.is_threat());
}

#[test]
fn test_clean_bytes_pass() {
    let (_tmp, engine) = setup_clean_engine();

    let result = engine.scan_bytes(b"just some harmless bytes", "clean-buffer");

    assert_eq!(result.threat_level, ThreatLevel::Clean);
    assert!(!result.is_threat());
}

#[test]
fn test_eicar_not_detected_without_hash_import() {
    let (_tmp, engine) = setup_clean_engine();

    // Without importing the EICAR hash, the engine should not flag it via
    // hash lookup.  It might still score via heuristics, but the EICAR string
    // is short ASCII text so heuristics should not trigger either.
    let result = engine.scan_bytes(EICAR, "eicar-no-import");

    // We only assert that the detection type is NOT Hash -- the overall
    // threat level depends on heuristic scoring which may vary.
    assert_ne!(
        result.detection_type,
        Some(DetectionType::Hash),
        "EICAR should not be detected via hash when not imported"
    );
}
