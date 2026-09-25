//! Integration tests for directory scanning.
//!
//! These tests exercise `ScanEngine::scan_directory`, verifying correct
//! traversal, exclusion filtering, file-size limits, and mixed-threat
//! detection within a directory tree.

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

use prx_sd_core::{ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_signatures::SignatureDatabase;

/// Deterministic "malicious" content strings whose hashes we import into the DB.
const MALWARE_A: &[u8] = b"__prx_sd_test_malware_sample_alpha__";
const MALWARE_B: &[u8] = b"__prx_sd_test_malware_sample_bravo__";

/// Build a `ScanEngine` with the given malicious byte patterns pre-imported.
fn setup_engine(tmp: &tempfile::TempDir, malicious_samples: &[(&[u8], &str)]) -> ScanEngine {
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    let db = SignatureDatabase::open(&sigs_dir).expect("open sig db");
    let entries: Vec<(Vec<u8>, String)> = malicious_samples
        .iter()
        .map(|(data, name)| (prx_sd_signatures::hash::sha256_hash(data), name.to_string()))
        .collect();
    db.import_hashes(&entries).expect("import hashes");

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(2);

    ScanEngine::new(config).expect("create engine")
}

#[test]
fn test_scan_directory_mixed() {
    let tmp = tempfile::tempdir().unwrap();

    let engine = setup_engine(
        &tmp,
        &[(MALWARE_A, "Test.Malware.Alpha"), (MALWARE_B, "Test.Malware.Bravo")],
    );

    // Create a scan target directory with 5 clean + 2 malicious files.
    let target_dir = tmp.path().join("scan_target");
    fs::create_dir_all(&target_dir).unwrap();

    for i in 0..5 {
        fs::write(
            target_dir.join(format!("clean_{i}.txt")),
            format!("benign content #{i}"),
        )
        .unwrap();
    }
    fs::write(target_dir.join("evil_a.bin"), MALWARE_A).unwrap();
    fs::write(target_dir.join("evil_b.bin"), MALWARE_B).unwrap();

    let results = engine.scan_directory(&target_dir);

    assert_eq!(results.len(), 7, "should scan all 7 files");

    let malicious: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    let clean: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Clean)
        .collect();

    assert_eq!(malicious.len(), 2, "should detect exactly 2 malicious files");
    // The remaining files should be clean (heuristics should not trigger on
    // simple ASCII).  If heuristics mark them as Suspicious we still accept
    // that -- the key assertion is that the two malicious files are found.
    assert!(
        clean.len() >= 4,
        "at least 4 files should be clean, got {}",
        clean.len()
    );
}

#[test]
fn test_scan_empty_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_engine(&tmp, &[]);

    let target = tmp.path().join("empty_dir");
    fs::create_dir_all(&target).unwrap();

    let results = engine.scan_directory(&target);
    assert!(results.is_empty(), "empty dir should yield 0 results");
}

#[test]
fn test_scan_respects_exclude_paths() {
    let tmp = tempfile::tempdir().unwrap();

    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    let _db = SignatureDatabase::open(&sigs_dir).unwrap();

    let mut config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(1);

    config.exclude_paths = vec!["excluded_subdir".to_string()];

    let engine = ScanEngine::new(config).expect("create engine");

    // Build directory tree:
    //   scan_target/
    //     included.txt
    //     excluded_subdir/
    //       hidden.txt
    let target = tmp.path().join("scan_target");
    let excluded = target.join("excluded_subdir");
    fs::create_dir_all(&excluded).unwrap();

    fs::write(target.join("included.txt"), b"visible file").unwrap();
    fs::write(excluded.join("hidden.txt"), b"hidden file").unwrap();

    let results = engine.scan_directory(&target);

    assert_eq!(results.len(), 1, "only 1 file should be scanned");
    assert!(
        results[0].path.to_string_lossy().contains("included.txt"),
        "the scanned file should be included.txt"
    );
}

#[test]
fn test_scan_respects_max_file_size() {
    let tmp = tempfile::tempdir().unwrap();

    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    // Import the hash for our "malware" content so it would normally be
    // detected as Malicious.
    let db = SignatureDatabase::open(&sigs_dir).unwrap();
    let big_malware = vec![0xAB; 2048]; // 2 KB of repeated bytes
    let hash = prx_sd_signatures::hash::sha256_hash(&big_malware);
    db.import_hashes(&[(hash, "Test.OversizedMalware".to_string())])
        .unwrap();

    // Set max_file_size to 1 KB so the 2 KB file is skipped.
    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_max_file_size(1024)
        .with_scan_threads(1);

    let engine = ScanEngine::new(config).expect("create engine");

    let target = tmp.path().join("scan_target");
    fs::create_dir_all(&target).unwrap();

    // Write the oversized "malware" file.
    fs::write(target.join("big_evil.bin"), &big_malware).unwrap();
    // Write a small clean file.
    fs::write(target.join("small_clean.txt"), b"hello").unwrap();

    let results = engine.scan_directory(&target);

    assert_eq!(results.len(), 2, "both files should appear in results");

    let big_result = results
        .iter()
        .find(|r| r.path.to_string_lossy().contains("big_evil.bin"))
        .expect("big_evil.bin should be in results");

    assert_eq!(
        big_result.threat_level,
        ThreatLevel::Clean,
        "oversized file should be returned as Clean (skipped)"
    );
}

#[test]
fn test_scan_directory_with_nested_subdirs() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_engine(&tmp, &[(MALWARE_A, "Test.Nested")]);

    // Build nested structure.
    let target = tmp.path().join("nested");
    let sub1 = target.join("a").join("b");
    let sub2 = target.join("c");
    fs::create_dir_all(&sub1).unwrap();
    fs::create_dir_all(&sub2).unwrap();

    fs::write(target.join("root.txt"), b"root file").unwrap();
    fs::write(sub1.join("deep.txt"), b"deep file").unwrap();
    fs::write(sub2.join("evil.bin"), MALWARE_A).unwrap();

    let results = engine.scan_directory(&target);

    assert_eq!(results.len(), 3, "should recurse into subdirs");

    let malicious: Vec<_> = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    assert_eq!(malicious.len(), 1);
}
