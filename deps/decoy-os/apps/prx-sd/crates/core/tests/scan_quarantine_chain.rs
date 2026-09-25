//! Integration tests: full scan → quarantine → restore chain.
//!
//! These tests exercise the complete pipeline:
//!   1. Detecting a malicious file via the scan engine.
//!   2. Passing the result to the quarantine vault.
//!   3. Verifying the original file is removed.
//!   4. Restoring the file and confirming content integrity.

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
use prx_sd_quarantine::Quarantine;
use prx_sd_signatures::SignatureDatabase;

/// The canonical EICAR test string (same as used in `eicar.rs`).
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Set up temp directories, import a hash into the signature DB, build an
/// engine, and return a `(TempDir, ScanEngine)` pair.
///
/// The `SignatureDatabase` handle is dropped before `ScanEngine::new` is
/// called to avoid an LMDB write-lock conflict on the same directory.
fn setup_engine(tmp: &tempfile::TempDir, hashes: &[(Vec<u8>, String)]) -> ScanEngine {
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let qdir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&qdir).unwrap();

    if !hashes.is_empty() {
        let db = SignatureDatabase::open(&sigs_dir).expect("open sig db");
        db.import_hashes(hashes).expect("import hashes");
        // Drop before engine opens the same LMDB directory.
        drop(db);
    } else {
        // Still initialise the DB so it exists on disk.
        let _db = SignatureDatabase::open(&sigs_dir).expect("open sig db");
    }

    let config = ScanConfig::default()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&qdir)
        .with_scan_threads(1);

    ScanEngine::new(config).expect("create scan engine")
}

// ---------------------------------------------------------------------------
// Test 1: EICAR detect → quarantine → verify original deleted → restore → content intact
// ---------------------------------------------------------------------------

/// Full chain: EICAR file is detected as malicious, quarantined (original
/// deleted), then restored to a new path with identical contents.
#[tokio::test]
async fn eicar_detect_quarantine_restore() {
    let tmp = tempfile::tempdir().unwrap();

    let eicar_hash = prx_sd_signatures::hash::sha256_hash(EICAR);
    let engine = setup_engine(&tmp, &[(eicar_hash, "EICAR-Test-File".to_string())]);

    // Write the EICAR file.
    let eicar_path = tmp.path().join("eicar.com");
    fs::write(&eicar_path, EICAR).unwrap();

    // --- Step 1: scan --------------------------------------------------------
    let result = engine.scan_file(&eicar_path).await.expect("scan_file failed");

    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "EICAR must be detected as Malicious"
    );

    // --- Step 2: quarantine --------------------------------------------------
    let qdir = tmp.path().join("quarantine");
    let vault = Quarantine::new(qdir.clone()).expect("create quarantine vault");

    let threat_name = result.threat_name.as_deref().unwrap_or("Unknown");
    let id = vault.quarantine(&eicar_path, threat_name).expect("quarantine failed");

    // --- Step 3: original must be deleted ------------------------------------
    assert!(!eicar_path.exists(), "original file must be deleted after quarantine");

    // Quarantine vault must have exactly one entry.
    let entries = vault.list().expect("list quarantine");
    assert_eq!(entries.len(), 1, "vault must contain exactly one entry");
    assert_eq!(entries[0].0, id, "entry ID must match the quarantined ID");
    assert_eq!(
        entries[0].1.threat_name, "EICAR-Test-File",
        "threat name must be preserved in metadata"
    );

    // --- Step 4: restore and verify content ----------------------------------
    let restore_path = tmp.path().join("restored_eicar.com");
    vault.restore(id, &restore_path).expect("restore failed");

    let restored = fs::read(&restore_path).expect("read restored file");
    assert_eq!(
        restored.as_slice(),
        EICAR,
        "restored file content must match the original EICAR bytes"
    );

    // The vault entry must still exist after restore (restore does not delete).
    let entries_after = vault.list().expect("list after restore");
    assert_eq!(entries_after.len(), 1, "vault entry must persist after restore");
}

// ---------------------------------------------------------------------------
// Test 2: custom hash import → detect → quarantine → list has entry
// ---------------------------------------------------------------------------

/// Import a custom SHA-256 hash, write a matching file, scan it to confirm
/// Malicious detection, quarantine it, then verify the vault list is non-empty.
#[tokio::test]
async fn hash_import_detect_quarantine() {
    let tmp = tempfile::tempdir().unwrap();

    // Unique payload so it will not collide with other tests.
    let payload: &[u8] = b"__custom_hash_quarantine_chain_integration_test__";
    let hash = prx_sd_signatures::hash::sha256_hash(payload);
    let sig_name = "Test.Custom.QuarantineChain".to_string();

    let engine = setup_engine(&tmp, &[(hash, sig_name.clone())]);

    // Write the payload to a file.
    let payload_path = tmp.path().join("custom_malware.bin");
    fs::write(&payload_path, payload).unwrap();

    // --- Step 1: scan --------------------------------------------------------
    let result = engine.scan_file(&payload_path).await.expect("scan_file failed");

    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "custom hash must be detected as Malicious"
    );
    assert_eq!(
        result.threat_name.as_deref(),
        Some("Test.Custom.QuarantineChain"),
        "threat name must match the imported signature"
    );

    // --- Step 2: quarantine --------------------------------------------------
    let qdir = tmp.path().join("quarantine");
    let vault = Quarantine::new(qdir).expect("create quarantine vault");

    let threat = result.threat_name.as_deref().unwrap_or("Unknown");
    let _id = vault.quarantine(&payload_path, threat).expect("quarantine failed");

    // Original must be gone.
    assert!(
        !payload_path.exists(),
        "original payload file must be deleted after quarantine"
    );

    // --- Step 3: vault must have exactly one entry ---------------------------
    let entries = vault.list().expect("list quarantine");
    assert_eq!(
        entries.len(),
        1,
        "vault must contain exactly one entry after quarantine"
    );
    assert_eq!(
        entries[0].1.threat_name, sig_name,
        "vault entry must preserve the threat name"
    );
    assert_eq!(
        entries[0].1.file_size,
        payload.len() as u64,
        "vault entry must record the correct original file size"
    );
}

// ---------------------------------------------------------------------------
// Test 3: clean file is NOT quarantined; original remains on disk
// ---------------------------------------------------------------------------

/// A benign file must scan as Clean.  We explicitly verify that the file is
/// not moved/deleted (i.e., the caller would never call quarantine on it).
/// Also ensures the vault stays empty when no quarantine is performed.
#[tokio::test]
async fn clean_file_not_quarantined() {
    let tmp = tempfile::tempdir().unwrap();

    // Engine with empty signature DB — no hashes imported.
    let engine = setup_engine(&tmp, &[]);

    let clean_path = tmp.path().join("readme.txt");
    let clean_content = b"This is a perfectly safe text file used for testing.";
    fs::write(&clean_path, clean_content).unwrap();

    // --- Step 1: scan --------------------------------------------------------
    let result = engine.scan_file(&clean_path).await.expect("scan_file failed");

    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "benign file must scan as Clean"
    );
    assert!(!result.is_threat(), "benign file must not be a threat");

    // --- Step 2: file must still exist (not quarantined) ---------------------
    assert!(
        clean_path.exists(),
        "clean file must still exist on disk after a clean scan"
    );

    let on_disk = fs::read(&clean_path).expect("read clean file");
    assert_eq!(
        on_disk.as_slice(),
        clean_content,
        "clean file content must be unchanged"
    );

    // --- Step 3: vault must remain empty ------------------------------------
    let qdir = tmp.path().join("quarantine");
    let vault = Quarantine::new(qdir).expect("create quarantine vault");

    let entries = vault.list().expect("list quarantine");
    assert_eq!(entries.len(), 0, "vault must be empty when no file was quarantined");
}
