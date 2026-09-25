//! Cross-crate integration tests: core + signatures + updater collaboration.
//!
//! These tests exercise complex scenarios that span multiple crates:
//!   - Signature hot-reload after delta patch application
//!   - Signature revocation to clear false positives
//!   - Dual-engine (hash + YARA) cooperative detection
//!   - Cryptographic integrity verification of update payloads

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

use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use prx_sd_core::{DetectionType, ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_signatures::SignatureDatabase;
use prx_sd_updater::delta::{DeltaPatch, RuleAction, YaraRuleEntry, decode_delta, encode_delta};
use prx_sd_updater::verify::{sign_payload, verify_payload};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Initialise temp directories and return their paths.
/// Does NOT create a DB or engine — callers control the lifecycle.
struct TestDirs {
    _tmp: tempfile::TempDir,
    sigs_dir: std::path::PathBuf,
    yara_dir: std::path::PathBuf,
    qdir: std::path::PathBuf,
}

impl TestDirs {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let sigs_dir = tmp.path().join("signatures");
        let yara_dir = tmp.path().join("yara");
        let qdir = tmp.path().join("quarantine");

        fs::create_dir_all(&sigs_dir).unwrap();
        fs::create_dir_all(&yara_dir).unwrap();
        fs::create_dir_all(&qdir).unwrap();

        Self {
            _tmp: tmp,
            sigs_dir,
            yara_dir,
            qdir,
        }
    }

    /// Build a ScanConfig pointing at these directories.
    fn config(&self) -> ScanConfig {
        ScanConfig::default()
            .with_signatures_dir(&self.sigs_dir)
            .with_yara_rules_dir(&self.yara_dir)
            .with_quarantine_dir(&self.qdir)
            .with_scan_threads(1)
    }

    /// Initialise an empty DB so the LMDB files exist, then drop it.
    fn init_empty_db(&self) {
        let _db = SignatureDatabase::open(&self.sigs_dir).expect("init empty DB");
    }

    /// Open the signature database (caller must drop before creating an engine).
    fn open_db(&self) -> SignatureDatabase {
        SignatureDatabase::open(&self.sigs_dir).expect("open DB")
    }

    /// Write a file inside the temp dir and return its path.
    fn write_file(&self, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = self._tmp.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }
}

/// Generate an Ed25519 keypair.
fn generate_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

// ---------------------------------------------------------------------------
// Scenario 5: signature_hot_reload_detects_new_threat
// ---------------------------------------------------------------------------

/// After a delta patch is applied (encode → sign → verify → decode → import),
/// `reload_signatures` makes the engine detect a previously-unknown file.
#[tokio::test]
async fn signature_hot_reload_detects_new_threat() {
    let dirs = TestDirs::new();
    dirs.init_empty_db();

    // -- Step 1: engine with empty DB → file scans clean ----------------------
    let mut engine = ScanEngine::new(dirs.config()).expect("create engine");

    let malware_payload = b"__cross_detection_hot_reload_unique_payload_v5__";
    let malware_path = dirs.write_file("unknown_malware.bin", malware_payload);

    let result = engine.scan_file(&malware_path).await.expect("scan_file #1");
    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "file must be clean before signature import"
    );

    // -- Step 2: construct DeltaPatch -----------------------------------------
    let file_hash = prx_sd_signatures::hash::sha256_hash(malware_payload);
    let patch = DeltaPatch {
        version: 2,
        timestamp: Utc::now(),
        add_hashes: vec![(file_hash.clone(), "NewMalware.APT29".to_string())],
        remove_hashes: vec![],
        yara_rules: vec![],
    };

    // -- Step 3: encode → sign → verify → decode (full pipeline) --------------
    let compressed = encode_delta(&patch).expect("encode_delta");

    let (sk, vk) = generate_keypair();
    let signed = sign_payload(&sk, &compressed);
    let verified_data = verify_payload(&vk, &signed).expect("verify_payload");
    let decoded = decode_delta(&verified_data).expect("decode_delta");

    // Sanity: roundtrip preserves the patch content.
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.add_hashes.len(), 1);
    assert_eq!(decoded.add_hashes[0].0, file_hash);
    assert_eq!(decoded.add_hashes[0].1, "NewMalware.APT29");

    // -- Step 4: import into DB then drop DB before reload --------------------
    {
        let db = dirs.open_db();
        let imported = db.import_hashes(&decoded.add_hashes).expect("import");
        assert_eq!(imported, 1);
        db.set_version(decoded.version).expect("set_version");
        // db drops here
    }

    // -- Step 5: hot-reload ---------------------------------------------------
    engine.reload_signatures().expect("reload_signatures");

    // -- Step 6: re-scan → Malicious + Hash -----------------------------------
    let result2 = engine.scan_file(&malware_path).await.expect("scan_file #2");
    assert_eq!(
        result2.threat_level,
        ThreatLevel::Malicious,
        "file must be malicious after hot-reload"
    );
    assert_eq!(
        result2.detection_type,
        Some(DetectionType::Hash),
        "detection must be Hash"
    );

    // -- Step 7: threat_name contains "NewMalware" ----------------------------
    let name = result2.threat_name.as_deref().expect("threat_name must be Some");
    assert!(
        name.contains("NewMalware"),
        "threat_name '{name}' must contain 'NewMalware'"
    );
}

// ---------------------------------------------------------------------------
// Scenario 6: signature_revocation_clears_false_positive
// ---------------------------------------------------------------------------

/// After removing a hash via delta patch, a previously-flagged file becomes clean.
#[tokio::test]
async fn signature_revocation_clears_false_positive() {
    let dirs = TestDirs::new();

    let benign_payload = b"__cross_detection_false_positive_benign_file_v6__";
    let file_hash = prx_sd_signatures::hash::sha256_hash(benign_payload);

    // -- Step 1: import custom hash → scan → Malicious ------------------------
    {
        let db = dirs.open_db();
        db.import_hashes(&[(file_hash.clone(), "FalsePositive.Benign".to_string())])
            .expect("import");
        let stats = db.get_stats().expect("stats");
        assert_eq!(stats.hash_count, 1, "DB must have 1 hash after import");
    }

    let mut engine = ScanEngine::new(dirs.config()).expect("create engine");

    let file_path = dirs.write_file("benign_flagged.dat", benign_payload);
    let result1 = engine.scan_file(&file_path).await.expect("scan #1");
    assert_eq!(
        result1.threat_level,
        ThreatLevel::Malicious,
        "file must be flagged before revocation"
    );
    assert_eq!(
        result1.detection_type,
        Some(DetectionType::Hash),
        "pre-revocation detection must be Hash-based"
    );

    // -- Step 2: construct revocation DeltaPatch ------------------------------
    let revoke_patch = DeltaPatch {
        version: 3,
        timestamp: Utc::now(),
        add_hashes: vec![],
        remove_hashes: vec![file_hash.clone()],
        yara_rules: vec![],
    };

    // -- Step 3: encode → decode roundtrip verification -----------------------
    let compressed = encode_delta(&revoke_patch).expect("encode");
    let decoded = decode_delta(&compressed).expect("decode");
    assert_eq!(decoded.version, 3);
    assert_eq!(decoded.remove_hashes.len(), 1);
    assert_eq!(decoded.remove_hashes[0], file_hash);

    // -- Step 4: apply revocation to DB → drop → reload -----------------------
    {
        let db = dirs.open_db();
        let removed = db.remove_hashes(&decoded.remove_hashes).expect("remove");
        assert_eq!(removed, 1, "exactly 1 hash must be removed");
        let stats_after = db.get_stats().expect("stats after");
        assert_eq!(stats_after.hash_count, 0, "hash_count must be 0 after revocation");
    }

    engine.reload_signatures().expect("reload");

    // -- Step 5: re-scan → Clean ----------------------------------------------
    let result2 = engine.scan_file(&file_path).await.expect("scan #2");
    assert_eq!(
        result2.threat_level,
        ThreatLevel::Clean,
        "file must be clean after revocation"
    );

    // -- Step 6: final stats verification -------------------------------------
    {
        let db = dirs.open_db();
        let final_stats = db.get_stats().expect("final stats");
        assert_eq!(final_stats.hash_count, 0, "DB must have 0 hashes at end");
    }
}

// ---------------------------------------------------------------------------
// Scenario 7: dual_engine_hash_yara_variant_detection
// ---------------------------------------------------------------------------

/// Hash engine catches the original sample; YARA catches a variant after
/// a rule is added via hot-reload. The original sample remains detected
/// by Hash (fast-path priority).
#[tokio::test]
async fn dual_engine_hash_yara_variant_detection() {
    let dirs = TestDirs::new();

    // -- Step 1: import "original sample" hash --------------------------------
    let original_payload = b"ORIGINAL_SAMPLE__EVIL_FAMILY_MARKER__original_end";
    let original_hash = prx_sd_signatures::hash::sha256_hash(original_payload);

    {
        let db = dirs.open_db();
        db.import_hashes(&[(original_hash, "EvilFamily.Original".to_string())])
            .expect("import original hash");
    }

    let mut engine = ScanEngine::new(dirs.config()).expect("create engine");

    let original_path = dirs.write_file("original_sample.bin", original_payload);

    // -- Step 2: scan original → Malicious (Hash) -----------------------------
    let r_original = engine.scan_file(&original_path).await.expect("scan original");
    assert_eq!(r_original.threat_level, ThreatLevel::Malicious);
    assert_eq!(
        r_original.detection_type,
        Some(DetectionType::Hash),
        "original must be detected by Hash"
    );

    // -- Step 3: create "variant" file (different content, same marker) → Clean
    let variant_payload = b"VARIANT_v2__EVIL_FAMILY_MARKER__variant_end_different";
    let variant_path = dirs.write_file("variant_sample.bin", variant_payload);

    let r_variant_before = engine.scan_file(&variant_path).await.expect("scan variant pre-yara");
    assert_eq!(
        r_variant_before.threat_level,
        ThreatLevel::Clean,
        "variant must be clean before YARA rule"
    );

    // -- Step 4: write YARA rule to yara_dir ----------------------------------
    let yara_rule = r#"rule FamilyDetector {
    strings:
        $m = "__EVIL_FAMILY_MARKER__"
    condition:
        $m
}"#;
    let yara_path = dirs.yara_dir.join("family_detector.yar");
    fs::write(&yara_path, yara_rule).unwrap();

    // -- Step 5: reload -------------------------------------------------------
    engine.reload_signatures().expect("reload after YARA add");

    // -- Step 6: scan variant → Malicious (YaraRule) --------------------------
    let r_variant_after = engine.scan_file(&variant_path).await.expect("scan variant post-yara");
    assert_eq!(
        r_variant_after.threat_level,
        ThreatLevel::Malicious,
        "variant must be malicious after YARA rule"
    );
    assert_eq!(
        r_variant_after.detection_type,
        Some(DetectionType::YaraRule),
        "variant detection must be YaraRule"
    );

    // -- Step 7: scan original → still Malicious (Hash takes priority) --------
    let r_original2 = engine.scan_file(&original_path).await.expect("scan original post-yara");
    assert_eq!(
        r_original2.threat_level,
        ThreatLevel::Malicious,
        "original must remain malicious"
    );
    assert_eq!(
        r_original2.detection_type,
        Some(DetectionType::Hash),
        "original must still be detected by Hash (fast-path priority)"
    );

    // Cleanup YARA file so it doesn't interfere with other tests.
    let _ = fs::remove_file(&yara_path);
}

// ---------------------------------------------------------------------------
// Scenario 8: tampered_signature_update_rejected
// ---------------------------------------------------------------------------

/// Cryptographic integrity verification: only legitimately signed payloads
/// pass verification; tampered data, wrong key, and truncated payloads are
/// all rejected.
#[tokio::test]
async fn tampered_signature_update_rejected() {
    // -- Step 1: create two keypairs (A = legitimate, B = attacker) -----------
    let (sk_a, vk_a) = generate_keypair();
    let (sk_b, _vk_b) = generate_keypair();

    // -- Step 2: construct and encode a DeltaPatch ----------------------------
    let patch = DeltaPatch {
        version: 99,
        timestamp: Utc::now(),
        add_hashes: vec![(vec![0xde; 32], "Trojan.Tamper.Test".to_string())],
        remove_hashes: vec![],
        yara_rules: vec![YaraRuleEntry {
            name: "test_rule".to_string(),
            content: "rule test { condition: true }".to_string(),
            action: RuleAction::Add,
        }],
    };
    let encoded = encode_delta(&patch).expect("encode");

    // -- Step 3: legitimate sign → verify → success ---------------------------
    let signed_a = sign_payload(&sk_a, &encoded);
    let verified = verify_payload(&vk_a, &signed_a);
    assert!(verified.is_ok(), "legitimate signature must verify");

    let recovered_data = verified.unwrap();
    let decoded = decode_delta(&recovered_data).expect("decode after verify");
    assert_eq!(decoded.version, 99);
    assert_eq!(decoded.add_hashes.len(), 1);
    assert_eq!(decoded.add_hashes[0].1, "Trojan.Tamper.Test");
    assert_eq!(decoded.yara_rules.len(), 1);
    assert_eq!(decoded.yara_rules[0].action, RuleAction::Add);

    // -- Step 4: tamper last byte of signed payload → Err ---------------------
    let mut tampered = signed_a.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0xff;
    }
    let tamper_result = verify_payload(&vk_a, &tampered);
    assert!(tamper_result.is_err(), "tampered payload must fail verification");

    // -- Step 5: wrong key signs same data → Err with legitimate pubkey ------
    let signed_b = sign_payload(&sk_b, &encoded);
    let wrong_key_result = verify_payload(&vk_a, &signed_b);
    assert!(
        wrong_key_result.is_err(),
        "payload signed by wrong key must fail verification"
    );

    // -- Step 6: truncated payload (only 63 bytes) → Err ----------------------
    let short_payload = vec![0u8; 63];
    let short_result = verify_payload(&vk_a, &short_payload);
    assert!(
        short_result.is_err(),
        "payload shorter than 64 bytes must fail verification"
    );

    // -- Step 7: summary assertion — 1 success, 3 failures --------------------
    // (Already asserted above; this is a documentation-level summary.)
    // Legitimate sign+verify: OK
    // Tampered data: Err
    // Wrong signing key: Err
    // Truncated payload: Err
}
