//! Integration test: heuristic detection through the full scan engine.
//!
//! Verifies that files with suspicious characteristics trigger heuristic
//! scoring. Note: high entropy ALONE is no longer sufficient — the engine
//! requires corroborating indicators to avoid false positives on legitimate
//! compressed/encrypted files.

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

/// Build a `ScanEngine` with empty signatures and no YARA rules.
fn setup_heuristic_only_engine(tmp: &tempfile::TempDir, threshold: u32) -> ScanEngine {
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    let _db = SignatureDatabase::open(&sigs_dir).expect("open sig db");

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_heuristic_threshold(threshold)
        .with_scan_threads(1);

    ScanEngine::new(config).expect("create engine")
}

/// Generate pseudo-random high-entropy data.
fn generate_high_entropy_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
    for _ in 0..size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push((state & 0xFF) as u8);
    }
    data
}

/// Create a synthetic PE with high entropy + suspicious APIs (should trigger).
fn make_suspicious_pe(apis: &[&str], high_entropy: bool) -> Vec<u8> {
    let mut pe = vec![0u8; 8192];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[0x88..0x8C].copy_from_slice(&0u32.to_le_bytes()); // zero timestamp
    pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // OptionalHeader size
    pe[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes()); // characteristics
    pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
    // Section header at 0x188
    pe[0x188..0x190].copy_from_slice(b".text\x00\x00\x00");
    pe[0x1C4..0x1C8].copy_from_slice(&0xE0000020u32.to_le_bytes()); // R+W+X
    // Write APIs
    let mut off = 0x200;
    for api in apis {
        let bytes = api.as_bytes();
        pe[off..off + bytes.len()].copy_from_slice(bytes);
        off += bytes.len() + 1;
    }
    // Fill with entropy if requested
    if high_entropy {
        let mut state: u64 = 0xCAFE;
        for item in pe.iter_mut().take(8000).skip(off) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *item = (state & 0xFF) as u8;
        }
    }
    pe
}

#[tokio::test]
async fn pe_with_injection_apis_triggers_heuristic() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_heuristic_only_engine(&tmp, 60);

    let pe = make_suspicious_pe(
        &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "cmd.exe"],
        true,
    );
    let path = tmp.path().join("injector.exe");
    fs::write(&path, &pe).unwrap();

    let result = engine.scan_file(&path).await.expect("scan");
    assert!(
        result.threat_level >= ThreatLevel::Suspicious,
        "PE with injection APIs should be flagged, got {:?}: {:?}",
        result.threat_level,
        result.details
    );
}

#[tokio::test]
async fn high_entropy_alone_is_not_flagged() {
    // Principle: entropy alone should NOT trigger detection.
    // This prevents false positives on compressed archives, crypto libs, etc.
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_heuristic_only_engine(&tmp, 60);

    let data = generate_high_entropy_data(4096);
    let path = tmp.path().join("random.bin");
    fs::write(&path, &data).unwrap();

    let result = engine.scan_file(&path).await.expect("scan");
    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "high entropy alone should NOT trigger (avoids FP on compressed files)"
    );
}

#[tokio::test]
async fn low_entropy_text_file_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_heuristic_only_engine(&tmp, 60);

    let path = tmp.path().join("readme.txt");
    fs::write(&path, "This is a normal readme file with typical text content.").unwrap();

    let result = engine.scan_file(&path).await.expect("scan");
    assert_eq!(result.threat_level, ThreatLevel::Clean);
}

#[test]
fn high_entropy_bytes_alone_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_heuristic_only_engine(&tmp, 60);

    let data = generate_high_entropy_data(8192);
    let result = engine.scan_bytes(&data, "entropy-test");
    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "high-entropy bytes alone should be Clean"
    );
}

#[test]
fn uniform_bytes_are_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_heuristic_only_engine(&tmp, 60);

    let data = vec![0u8; 1024];
    let result = engine.scan_bytes(&data, "zeros");
    assert_eq!(result.threat_level, ThreatLevel::Clean);
}

#[test]
fn pe_bytes_with_multiple_apis_flagged() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = setup_heuristic_only_engine(&tmp, 60);

    let pe = make_suspicious_pe(
        &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "InternetOpenA",
            "URLDownloadToFile",
        ],
        true,
    );
    let result = engine.scan_bytes(&pe, "suspicious-pe");
    assert!(
        result.is_threat(),
        "PE with 5 suspicious APIs should be flagged, got {:?}",
        result.threat_level
    );
    assert_eq!(result.detection_type, Some(DetectionType::Heuristic));
}
