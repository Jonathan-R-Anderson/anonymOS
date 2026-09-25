//! Cross-pipeline integration tests: exercises core + signatures + quarantine +
//! remediation crates working together in realistic multi-stage scenarios.
//!
//! Each test covers a complex threat lifecycle involving detection, policy
//! evaluation, remediation actions, audit logging, and verification.

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
use std::path::PathBuf;
use std::sync::Arc;

use prx_sd_core::{DetectionType, ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_quarantine::Quarantine;
use prx_sd_remediation::RemediationAction;
use prx_sd_remediation::actions::RemediationEngine;
use prx_sd_remediation::policy::{ActionType, RemediationPolicy};
use prx_sd_signatures::SignatureDatabase;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up temp directories, import hashes into the signature DB, optionally
/// write YARA rules, build a `ScanEngine`, and return it.
///
/// The `SignatureDatabase` handle is dropped before `ScanEngine::new` to
/// avoid an LMDB write-lock conflict.
fn setup_engine(
    tmp: &tempfile::TempDir,
    hashes: &[(Vec<u8>, String)],
    yara_rules: Option<&[(&str, &str)]>, // (filename, rule_content)
) -> ScanEngine {
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let qdir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&qdir).unwrap();

    // Import hashes.
    {
        let db = SignatureDatabase::open(&sigs_dir).expect("open sig db");
        if !hashes.is_empty() {
            db.import_hashes(hashes).expect("import hashes");
        }
        // db dropped here -- releases LMDB write lock.
    }

    // Write YARA rule files if provided.
    if let Some(rules) = yara_rules {
        for (name, content) in rules {
            fs::write(yara_dir.join(name), content).unwrap();
        }
    }

    let config = ScanConfig::default()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&qdir)
        .with_scan_threads(1);

    ScanEngine::new(config).expect("create scan engine")
}

/// Create a `RemediationEngine` backed by a `Quarantine` vault at
/// `vault_dir` with the given policy, returning both the engine and the
/// shared `Arc<Quarantine>` for later inspection.
fn setup_remediation(
    policy: RemediationPolicy,
    vault_dir: PathBuf,
    audit_dir: PathBuf,
) -> (RemediationEngine, Arc<Quarantine>) {
    let vault = Arc::new(Quarantine::new(vault_dir).expect("create quarantine vault"));
    let engine = RemediationEngine::new(policy, Arc::clone(&vault), audit_dir).expect("create remediation");
    (engine, vault)
}

// ---------------------------------------------------------------------------
// Scenario 1: APT full-chain -- detect -> quarantine -> remediate -> audit -> restore
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apt_full_chain_detect_quarantine_remediate_audit() {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Create a unique payload and import its hash.
    let payload = b"__apt_full_chain_cross_pipeline_payload_2026__";
    let hash = prx_sd_signatures::hash::sha256_hash(payload);
    let sha256_hex = prx_sd_signatures::hash::sha256_hex(payload);
    let threat_name = "APT.CrossPipeline.FullChain";

    let engine = setup_engine(&tmp, &[(hash, threat_name.to_string())], None);

    // Write the malicious file.
    let malicious_path = tmp.path().join("apt_implant.bin");
    fs::write(&malicious_path, payload).unwrap();

    // 2. Scan and verify detection.
    let scan_result = engine.scan_file(&malicious_path).await.expect("scan_file failed");

    assert_eq!(scan_result.threat_level, ThreatLevel::Malicious);
    assert_eq!(scan_result.detection_type, Some(DetectionType::Hash));
    assert_eq!(scan_result.threat_name.as_deref(), Some(threat_name),);

    // 3. Set up remediation policy: Report + AddToBlocklist + Quarantine.
    //    AddToBlocklist must come before Quarantine because quarantine
    //    deletes the original file, preventing hash computation.
    let vault_dir = tmp.path().join("vault");
    let audit_dir = tmp.path().join("audit");
    let policy = RemediationPolicy {
        on_malicious: vec![ActionType::Report, ActionType::AddToBlocklist, ActionType::Quarantine],
        on_suspicious: vec![ActionType::Report],
        whitelist_hashes: vec![],
        whitelist_paths: vec![],
        kill_processes: false,
        clean_persistence: false,
        network_isolation: false,
        audit_logging: true,
    };

    let (rem_engine, vault) = setup_remediation(policy, vault_dir, audit_dir.clone());

    // 4. Handle the threat (file must still exist for hash computation).
    let results = rem_engine
        .handle_threat(&malicious_path, threat_name, "malicious", "hash")
        .await;

    // 5. Assertions on remediation results.
    // We expect Report + Quarantine + AddToBlocklist = 3 results.
    assert!(results.len() >= 3, "expected at least 3 results, got {}", results.len());
    assert!(matches!(results[0].action, RemediationAction::ReportOnly));
    assert!(results[0].success);

    // Quarantine result.
    let quarantine_result = results
        .iter()
        .find(|r| matches!(r.action, RemediationAction::Quarantined { .. }));
    assert!(quarantine_result.is_some(), "expected a Quarantined action in results");
    assert!(quarantine_result.unwrap().success);

    // AddToBlocklist result — runs before Quarantine so file still exists.
    let blocklist_result = results
        .iter()
        .find(|r| matches!(r.action, RemediationAction::AddedToBlocklist));
    assert!(
        blocklist_result.is_some(),
        "expected an AddedToBlocklist action in results"
    );
    assert!(
        blocklist_result.unwrap().success,
        "AddToBlocklist must succeed when file still exists"
    );

    // 6. Verify original file is deleted.
    assert!(
        !malicious_path.exists(),
        "original file must be deleted after quarantine"
    );

    // 7. Vault must have exactly one entry.
    let entries = vault.list().expect("list quarantine");
    assert_eq!(entries.len(), 1, "vault must contain exactly one entry");
    assert_eq!(entries[0].1.threat_name, threat_name);

    // 8. Audit directory should contain a .jsonl file.
    let audit_files: Vec<_> = fs::read_dir(&audit_dir)
        .expect("read audit dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("jsonl"))
        .collect();
    assert!(
        !audit_files.is_empty(),
        "audit directory must contain at least one .jsonl file"
    );

    // Read the audit file and verify it mentions our threat.
    let audit_content = fs::read_to_string(audit_files[0].path()).expect("read audit file");
    assert!(
        audit_content.contains(threat_name),
        "audit log must reference the threat name"
    );
    assert!(
        audit_content.contains(&sha256_hex) || audit_content.contains("malicious"),
        "audit log must reference the threat level or hash"
    );

    // 9. Restore from quarantine and verify content integrity.
    let quarantine_id = entries[0].0;
    let restore_path = tmp.path().join("restored_implant.bin");
    vault.restore(quarantine_id, &restore_path).expect("restore failed");

    let restored_content = fs::read(&restore_path).expect("read restored file");
    assert_eq!(
        restored_content.as_slice(),
        payload,
        "restored content must match original payload"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: False positive -- whitelisted hash skips all remediation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn false_positive_whitelist_skips_remediation() {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Import a hash that will trigger detection.
    let payload = b"__false_positive_whitelist_cross_pipeline_2026__";
    let hash = prx_sd_signatures::hash::sha256_hash(payload);
    let sha256_hex = prx_sd_signatures::hash::sha256_hex(payload);
    let threat_name = "FP.Whitelist.Test";

    let engine = setup_engine(&tmp, &[(hash, threat_name.to_string())], None);

    // Write the file.
    let file_path = tmp.path().join("false_positive.bin");
    fs::write(&file_path, payload).unwrap();

    // 2. Scan confirms it as Malicious.
    let scan_result = engine.scan_file(&file_path).await.expect("scan_file failed");
    assert_eq!(scan_result.threat_level, ThreatLevel::Malicious);

    // 3. Set up remediation with the file's hash in the whitelist.
    let vault_dir = tmp.path().join("vault");
    let audit_dir = tmp.path().join("audit");
    let policy = RemediationPolicy {
        on_malicious: vec![ActionType::Quarantine, ActionType::AddToBlocklist, ActionType::Report],
        on_suspicious: vec![ActionType::Report],
        whitelist_hashes: vec![sha256_hex],
        whitelist_paths: vec![],
        kill_processes: false,
        clean_persistence: false,
        network_isolation: false,
        audit_logging: true,
    };

    let (rem_engine, vault) = setup_remediation(policy, vault_dir, audit_dir);

    // 4. Handle the threat -- should be whitelisted.
    let results = rem_engine
        .handle_threat(&file_path, threat_name, "malicious", "hash")
        .await;

    // 5. Expect exactly one result: Whitelisted.
    assert_eq!(
        results.len(),
        1,
        "whitelisted file should produce exactly one result, got {}",
        results.len()
    );
    assert!(matches!(results[0].action, RemediationAction::Whitelisted));
    assert!(results[0].success);

    // 6. File must still exist (not quarantined or deleted).
    assert!(file_path.exists(), "whitelisted file must not be removed");
    let on_disk = fs::read(&file_path).expect("read file");
    assert_eq!(
        on_disk.as_slice(),
        payload,
        "whitelisted file content must be unchanged"
    );

    // 7. Vault must be empty.
    let entries = vault.list().expect("list quarantine");
    assert_eq!(entries.len(), 0, "vault must be empty when file is whitelisted");
}

// ---------------------------------------------------------------------------
// Scenario 3: Mixed threats batch scan with graded response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mixed_threats_batch_scan_graded_response() {
    let tmp = tempfile::tempdir().unwrap();

    // Payloads.
    let hash_payload = b"__mixed_batch_hash_malware_cross_pipeline_2026__";
    let yara_payload = b"data contains CROSS_PIPELINE_YARA_MARKER end";
    let clean_payload = b"this is a perfectly safe document for testing";

    // Hash for the hash-detected payload.
    let hash_bytes = prx_sd_signatures::hash::sha256_hash(hash_payload);

    // YARA rule to detect the yara_payload.
    let yara_rule = r#"
rule CrossPipelineYaraTest {
    meta:
        description = "Test rule for cross-pipeline batch scenario"
    strings:
        $marker = "CROSS_PIPELINE_YARA_MARKER"
    condition:
        $marker
}
"#;

    let engine = setup_engine(
        &tmp,
        &[(hash_bytes, "Mixed.Hash.BatchTest".to_string())],
        Some(&[("cross_pipeline_test.yar", yara_rule)]),
    );

    // Create a scan directory with 3 files.
    let scan_dir = tmp.path().join("scan_target");
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("malware_hash.bin"), hash_payload).unwrap();
    fs::write(scan_dir.join("malware_yara.bin"), yara_payload).unwrap();
    fs::write(scan_dir.join("clean_doc.txt"), clean_payload).unwrap();

    // 1. Batch scan the directory.
    let scan_results = engine.scan_directory(&scan_dir);
    assert_eq!(scan_results.len(), 3, "should scan all 3 files");

    // Categorise results.
    let malicious: Vec<_> = scan_results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    let clean: Vec<_> = scan_results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Clean)
        .collect();

    assert_eq!(
        malicious.len(),
        2,
        "expected 2 malicious files, got {}",
        malicious.len()
    );
    assert_eq!(clean.len(), 1, "expected 1 clean file, got {}", clean.len());

    // Verify clean file is the expected one.
    assert!(clean[0].path.to_string_lossy().contains("clean_doc.txt"));

    // Verify detection engine attribution for each malicious file.
    let hash_detected = malicious.iter().find(|r| {
        r.path.to_string_lossy().contains("malware_hash.bin") && r.detection_type == Some(DetectionType::Hash)
    });
    assert!(hash_detected.is_some(), "hash malware must be detected by Hash engine");
    let yara_detected = malicious.iter().find(|r| {
        r.path.to_string_lossy().contains("malware_yara.bin") && r.detection_type == Some(DetectionType::YaraRule)
    });
    assert!(yara_detected.is_some(), "YARA malware must be detected by YARA engine");

    // 2. Set up remediation: Quarantine + AddToBlocklist for malicious.
    let vault_dir = tmp.path().join("vault");
    let audit_dir = tmp.path().join("audit");
    let policy = RemediationPolicy {
        on_malicious: vec![ActionType::Quarantine, ActionType::AddToBlocklist],
        on_suspicious: vec![ActionType::Report],
        whitelist_hashes: vec![],
        whitelist_paths: vec![],
        kill_processes: false,
        clean_persistence: false,
        network_isolation: false,
        audit_logging: true,
    };

    let (rem_engine, vault) = setup_remediation(policy, vault_dir, audit_dir);

    // 3. Handle each malicious file.
    for result in &malicious {
        let name = result.threat_name.as_deref().unwrap_or("Unknown");
        let det_type = match &result.detection_type {
            Some(DetectionType::Hash) => "hash",
            Some(DetectionType::YaraRule) => "yara",
            Some(DetectionType::Heuristic) => "heuristic",
            Some(DetectionType::Behavioral) => "behavioral",
            None => "unknown",
        };
        rem_engine
            .handle_threat(&result.path, name, "malicious", det_type)
            .await;
    }

    // 4. Verify: vault has 2 entries.
    let entries = vault.list().expect("list quarantine");
    assert_eq!(
        entries.len(),
        2,
        "vault must contain 2 quarantined files, got {}",
        entries.len()
    );

    // 5. Verify: malicious files are deleted from original directory.
    assert!(
        !scan_dir.join("malware_hash.bin").exists(),
        "hash malware file must be quarantined (deleted)"
    );
    assert!(
        !scan_dir.join("malware_yara.bin").exists(),
        "YARA malware file must be quarantined (deleted)"
    );

    // 6. Verify: clean file is untouched.
    assert!(
        scan_dir.join("clean_doc.txt").exists(),
        "clean file must remain on disk"
    );
    let clean_on_disk = fs::read(scan_dir.join("clean_doc.txt")).expect("read clean file");
    assert_eq!(
        clean_on_disk.as_slice(),
        clean_payload,
        "clean file content must be unchanged"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Scan -> remediate -> verify clean loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_remediate_verify_clean_loop() {
    let tmp = tempfile::tempdir().unwrap();

    // Two distinct malicious payloads.
    let payload_a = b"__scan_remediate_loop_payload_A_2026__";
    let payload_b = b"__scan_remediate_loop_payload_B_2026__";
    let clean_data = b"this is an innocent test file for the loop scenario";

    let hash_a = prx_sd_signatures::hash::sha256_hash(payload_a);
    let hash_b = prx_sd_signatures::hash::sha256_hash(payload_b);

    let engine = setup_engine(
        &tmp,
        &[
            (hash_a, "Loop.Malware.A".to_string()),
            (hash_b, "Loop.Malware.B".to_string()),
        ],
        None,
    );

    // Populate a scan directory: 2 malicious + 1 clean.
    let scan_dir = tmp.path().join("scan_loop");
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("mal_a.bin"), payload_a).unwrap();
    fs::write(scan_dir.join("mal_b.bin"), payload_b).unwrap();
    fs::write(scan_dir.join("safe.txt"), clean_data).unwrap();

    // 1. First scan: expect 2 Malicious + 1 Clean.
    let first_scan = engine.scan_directory(&scan_dir);
    assert_eq!(first_scan.len(), 3, "first scan must cover all 3 files");

    let first_malicious: Vec<_> = first_scan
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .collect();
    let first_clean: Vec<_> = first_scan
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Clean)
        .collect();

    assert_eq!(
        first_malicious.len(),
        2,
        "first scan: expected 2 malicious, got {}",
        first_malicious.len()
    );
    assert_eq!(
        first_clean.len(),
        1,
        "first scan: expected 1 clean, got {}",
        first_clean.len()
    );

    // 2. Quarantine each malicious file directly via the vault.
    let vault_dir = tmp.path().join("vault");
    let vault = Quarantine::new(vault_dir).expect("create quarantine vault");

    for result in &first_malicious {
        let threat = result.threat_name.as_deref().unwrap_or("Unknown");
        vault.quarantine(&result.path, threat).expect("quarantine failed");
    }

    // 3. Verify vault has 2 entries.
    let vault_entries = vault.list().expect("list quarantine");
    assert_eq!(vault_entries.len(), 2, "vault must have 2 entries after quarantine");

    // 4. Verify original malicious files are gone.
    assert!(
        !scan_dir.join("mal_a.bin").exists(),
        "mal_a.bin must be removed after quarantine"
    );
    assert!(
        !scan_dir.join("mal_b.bin").exists(),
        "mal_b.bin must be removed after quarantine"
    );

    // 5. Second scan: only the clean file remains.
    let second_scan = engine.scan_directory(&scan_dir);
    assert_eq!(
        second_scan.len(),
        1,
        "second scan must find only 1 file (the clean one)"
    );
    assert_eq!(
        second_scan[0].threat_level,
        ThreatLevel::Clean,
        "remaining file must be clean"
    );
    assert!(
        second_scan[0].path.to_string_lossy().contains("safe.txt"),
        "remaining file must be safe.txt"
    );

    // 6. Verify vault stats.
    let stats = vault.stats().expect("vault stats");
    assert_eq!(stats.count, 2, "vault count must be 2");
    assert!(stats.total_size > 0, "vault total_size must be non-zero");

    // 7. Confirm the directory only contains the clean file.
    let remaining_files: Vec<_> = fs::read_dir(&scan_dir)
        .expect("read scan dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();
    assert_eq!(
        remaining_files.len(),
        1,
        "directory must contain exactly 1 file after quarantine"
    );
    assert!(remaining_files[0].file_name().to_string_lossy().contains("safe.txt"));
}
