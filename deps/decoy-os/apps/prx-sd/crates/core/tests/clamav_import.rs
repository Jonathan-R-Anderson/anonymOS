//! Integration test: ClamAV CVD import followed by scan detection.
//!
//! Builds a synthetic CVD file (512-byte header + tar.gz containing an `.hdb`
//! file with MD5 hashes), imports it via `import_cvd_bytes`, then verifies
//! that the imported hashes are queryable and that the engine detects files
//! whose hashes match.

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
    clippy::cast_possible_wrap,
    clippy::format_push_string
)]
use std::fs;

use prx_sd_core::{DetectionType, ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_signatures::{SignatureDatabase, import_cvd_bytes};

/// Build a minimal CVD byte blob with a single `.hdb` (MD5) entry.
///
/// Returns `(cvd_bytes, md5_hex, sig_name)` where `md5_hex` is the hex-encoded
/// MD5 hash embedded in the HDB file.
fn build_synthetic_cvd(samples: &[(&[u8], &str)]) -> (Vec<u8>, Vec<(String, String)>) {
    // Compute MD5 hex strings for each sample.
    let entries: Vec<(String, String)> = samples
        .iter()
        .map(|(data, name)| {
            let md5_hex = prx_sd_signatures::hash::md5_hash(data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            (md5_hex, name.to_string())
        })
        .collect();

    // Build HDB content: "md5_hex:filesize:name" (filesize = * means any).
    let mut hdb_content = String::new();
    for (md5_hex, name) in &entries {
        hdb_content.push_str(&format!("{md5_hex}:*:{name}\n"));
    }

    // Build a tar.gz containing the .hdb file.
    let mut tar_buf = Vec::new();
    {
        let gz = flate2::write::GzEncoder::new(&mut tar_buf, flate2::Compression::fast());
        let mut tar_builder = tar::Builder::new(gz);

        let data = hdb_content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_path("test.hdb").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, data).unwrap();
        tar_builder.finish().unwrap();
    }

    // Build the 512-byte CVD header.
    let header_str = format!(
        "ClamAV-VDB:01 Jan 2026:500:{}:90:md5placeholder:builder:0",
        entries.len()
    );
    let mut cvd_data = vec![0u8; 512];
    let header_bytes = header_str.as_bytes();
    cvd_data[..header_bytes.len()].copy_from_slice(header_bytes);
    cvd_data.extend_from_slice(&tar_buf);

    (cvd_data, entries)
}

#[test]
fn import_synthetic_cvd_then_lookup_detects() {
    let tmp = tempfile::tempdir().unwrap();
    let sigs_dir = tmp.path().join("signatures");
    fs::create_dir_all(&sigs_dir).unwrap();

    let db = SignatureDatabase::open(&sigs_dir).expect("open db");

    let sample_a = b"cvd_test_malware_content_alpha";
    let sample_b = b"cvd_test_malware_content_bravo";

    let (cvd_bytes, _entries) =
        build_synthetic_cvd(&[(sample_a, "ClamAV.Test.Alpha"), (sample_b, "ClamAV.Test.Bravo")]);

    let stats = import_cvd_bytes(&cvd_bytes, &db).expect("import CVD");
    assert_eq!(stats.md5_imported, 2, "should import 2 MD5 entries");
    assert_eq!(stats.cvd_version, 500);

    // Verify direct MD5 lookups.
    let result_a = db.md5_lookup(sample_a).unwrap();
    assert_eq!(result_a, Some("ClamAV.Test.Alpha".to_string()));

    let result_b = db.md5_lookup(sample_b).unwrap();
    assert_eq!(result_b, Some("ClamAV.Test.Bravo".to_string()));

    // Unknown content should not match.
    assert!(db.md5_lookup(b"something else entirely").unwrap().is_none());

    // Verify DB stats reflect the imports.
    let db_stats = db.get_stats().unwrap();
    assert_eq!(db_stats.md5_count, 2);
    assert!(db_stats.last_update.is_some());
}

#[tokio::test]
async fn import_cvd_then_scan_with_sha256_fallback() {
    // The scan engine uses SHA-256 hash_lookup as its primary detection path.
    // ClamAV HDB files contain MD5 hashes, which are stored in the MD5 table.
    // To test the full flow: import CVD (MD5), also import SHA-256, then scan.
    let tmp = tempfile::tempdir().unwrap();
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let quarantine_dir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&quarantine_dir).unwrap();

    let db = SignatureDatabase::open(&sigs_dir).expect("open db");

    let malware_data = b"cvd_integration_test_malware_payload";

    // Import via CVD (MD5 path).
    let (cvd_bytes, _entries) = build_synthetic_cvd(&[(malware_data, "ClamAV.Test.Payload")]);
    let stats = import_cvd_bytes(&cvd_bytes, &db).expect("import CVD");
    assert_eq!(stats.md5_imported, 1);

    // Also import as SHA-256 so scan_file detects via hash_lookup.
    let sha256 = prx_sd_signatures::hash::sha256_hash(malware_data);
    db.import_hashes(&[(sha256, "ClamAV.Test.Payload".to_string())])
        .unwrap();

    drop(db);

    let config = ScanConfig::new()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&quarantine_dir)
        .with_scan_threads(1);

    let engine = ScanEngine::new(config).expect("create engine");

    let evil_path = tmp.path().join("cvd_evil.bin");
    fs::write(&evil_path, malware_data).unwrap();

    let result = engine.scan_file(&evil_path).await.expect("scan");
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
    assert_eq!(result.detection_type, Some(DetectionType::Hash));
    assert!(
        result
            .threat_name
            .as_deref()
            .unwrap_or("")
            .contains("ClamAV.Test.Payload"),
    );
}

#[test]
fn import_cvd_with_hsb_sha256_entries() {
    // Test importing HSB (SHA-256 hash) entries via CVD format.
    let tmp = tempfile::tempdir().unwrap();
    let sigs_dir = tmp.path().join("signatures");
    fs::create_dir_all(&sigs_dir).unwrap();

    let db = SignatureDatabase::open(&sigs_dir).expect("open db");

    let sample = b"hsb_sha256_test_content";
    let sha256_hex: String = prx_sd_signatures::hash::sha256_hash(sample)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Build a CVD with an .hsb file instead of .hdb.
    let hsb_content = format!("{sha256_hex}:*:ClamAV.SHA256.Test\n");

    let mut tar_buf = Vec::new();
    {
        let gz = flate2::write::GzEncoder::new(&mut tar_buf, flate2::Compression::fast());
        let mut tar_builder = tar::Builder::new(gz);

        let data = hsb_content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_path("test.hsb").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, data).unwrap();
        tar_builder.finish().unwrap();
    }

    let header_str = "ClamAV-VDB:01 Jan 2026:600:1:90:md5val:builder:0";
    let mut cvd_data = vec![0u8; 512];
    cvd_data[..header_str.len()].copy_from_slice(header_str.as_bytes());
    cvd_data.extend_from_slice(&tar_buf);

    let stats = import_cvd_bytes(&cvd_data, &db).expect("import CVD with HSB");
    assert_eq!(stats.sha256_imported, 1);
    assert_eq!(stats.md5_imported, 0);

    // Verify SHA-256 lookup.
    let result = db.hash_lookup(sample).unwrap();
    assert_eq!(result, Some("ClamAV.SHA256.Test".to_string()));
}
