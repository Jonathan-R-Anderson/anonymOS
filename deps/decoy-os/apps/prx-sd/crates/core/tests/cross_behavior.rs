//! Cross-crate integration tests: sandbox + realtime + core + quarantine.
//!
//! These tests exercise complex multi-crate collaboration scenarios that
//! mirror real-world attack chains:
//!
//! - Scenario 9:  Ransomware full-chain (detect + analyze + quarantine)
//! - Scenario 10: APT multi-stage (credential theft + lateral + persistence)
//! - Scenario 11: Dropper + anti-analysis + YARA auto-generation

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

use prx_sd_core::{ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_quarantine::Quarantine;
use prx_sd_realtime::{
    FileEvent, ProtectedDirsConfig, ProtectedDirsEnforcer, ProtectionVerdict, RansomwareConfig, RansomwareDetector,
    RansomwareVerdict,
};
use prx_sd_sandbox::behavior::BehaviorAnalyzer;
use prx_sd_sandbox::{
    FileOpType, FileOperation, NetworkAttempt, ProcessOpType, ProcessOperation, SandboxResult, SandboxVerdict,
    ThreatCategory,
};
use prx_sd_signatures::SignatureDatabase;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Construct an empty `SandboxResult` suitable for populating with test data.
fn empty_sandbox_result() -> SandboxResult {
    SandboxResult {
        exit_code: 0,
        syscalls: Vec::new(),
        behaviors: Vec::new(),
        verdict: SandboxVerdict::Clean,
        threat_score: 0,
        network_attempts: Vec::new(),
        file_operations: Vec::new(),
        process_operations: Vec::new(),
        execution_time_ms: 100,
    }
}

/// Set up temp directories, import hashes into the signature DB, create
/// a `ScanEngine`, and return it. The `SignatureDatabase` is dropped before
/// `ScanEngine::new()` to avoid the LMDB write-lock conflict.
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
        drop(db);
    } else {
        let _db = SignatureDatabase::open(&sigs_dir).expect("open sig db");
    }

    let config = ScanConfig::default()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&qdir)
        .with_scan_threads(1);

    ScanEngine::new(config).expect("create scan engine")
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 9: Ransomware full chain - detect + analyze + quarantine
// ═══════════════════════════════════════════════════════════════════════════

/// Exercises the complete ransomware detection pipeline:
///
/// 1. `RansomwareDetector` detects rapid `.encrypted` renames (realtime crate)
/// 2. `BehaviorAnalyzer` flags ransomware patterns in sandbox results (sandbox crate)
/// 3. `ScanEngine` detects the malware hash (core crate)
/// 4. `Quarantine` isolates the malicious file (quarantine crate)
///
/// Both independent detection systems (realtime + sandbox) must agree on
/// the ransomware verdict.
#[tokio::test]
async fn ransomware_full_chain_detect_analyze_quarantine() {
    // ── Phase 1: RansomwareDetector (realtime) ─────────────────────────
    let config = RansomwareConfig {
        window_secs: 60,
        modification_threshold: 100, // high: rely on rename_threshold
        rename_threshold: 5,
        ransomware_extensions: vec![".encrypted".into()],
    };
    let mut detector = RansomwareDetector::new(config);

    let mut last_verdict = RansomwareVerdict::Clean;
    for i in 0..8u32 {
        let event = FileEvent::Rename {
            from: PathBuf::from(format!("/home/user/doc_{i}.pdf")),
            to: PathBuf::from(format!("/home/user/doc_{i}.pdf.encrypted")),
            pid: 1000,
        };
        last_verdict = detector.on_file_event(&event);
    }

    // After 8 ransomware-extension renames with threshold=5, should be detected.
    assert!(
        matches!(last_verdict, RansomwareVerdict::RansomwareDetected { .. }),
        "RansomwareDetector should flag ransomware after 8 renames, got: {last_verdict:?}"
    );

    // ── Phase 2: BehaviorAnalyzer (sandbox) ────────────────────────────
    let mut result = empty_sandbox_result();

    // 15 reads of .pdf files
    for i in 0..15 {
        result.file_operations.push(FileOperation {
            op: FileOpType::Read,
            path: format!("/home/user/doc_{i}.pdf"),
            blocked: false,
        });
    }
    // 15 writes of .pdf.encrypted files
    for i in 0..15 {
        result.file_operations.push(FileOperation {
            op: FileOpType::Write,
            path: format!("/home/user/doc_{i}.pdf.encrypted"),
            blocked: false,
        });
    }
    // 10 deletes of original .pdf files
    for i in 0..10 {
        result.file_operations.push(FileOperation {
            op: FileOpType::Delete,
            path: format!("/home/user/doc_{i}.pdf"),
            blocked: false,
        });
    }

    let analyzer = BehaviorAnalyzer::new();
    analyzer.analyze(&mut result);

    assert!(
        matches!(result.verdict, SandboxVerdict::Malicious { .. }),
        "BehaviorAnalyzer should classify as Malicious, got: {:?}",
        result.verdict
    );
    assert!(
        result.threat_score >= 70,
        "threat_score should be >= 70, got: {}",
        result.threat_score
    );
    assert!(
        result
            .behaviors
            .iter()
            .any(|b| b.category == ThreatCategory::Ransomware),
        "behaviors must include Ransomware category"
    );

    // ── Phase 3: ScanEngine hash detection (core) ──────────────────────
    let tmp = tempfile::tempdir().unwrap();
    let payload = b"__ransomware_full_chain_test_payload_unique_v9__";
    let hash = prx_sd_signatures::hash::sha256_hash(payload);
    let engine = setup_engine(&tmp, &[(hash, "Ransom.TestChain.V9".to_string())]);

    let malware_path = tmp.path().join("ransomware_tool.bin");
    fs::write(&malware_path, payload).unwrap();

    let scan_result = engine.scan_file(&malware_path).await.expect("scan_file failed");
    assert_eq!(
        scan_result.threat_level,
        ThreatLevel::Malicious,
        "engine should detect the ransomware hash"
    );
    assert_eq!(
        scan_result.detection_type,
        Some(prx_sd_core::DetectionType::Hash),
        "ransomware detection must be via Hash engine"
    );

    // ── Phase 4: Quarantine (quarantine crate) ─────────────────────────
    let qdir = tmp.path().join("quarantine");
    let vault = Quarantine::new(qdir).expect("create quarantine vault");

    let threat_name = scan_result.threat_name.as_deref().unwrap_or("Unknown");
    let _id = vault.quarantine(&malware_path, threat_name).expect("quarantine failed");

    assert!(!malware_path.exists(), "original file must be deleted after quarantine");

    let entries = vault.list().expect("list quarantine");
    assert_eq!(entries.len(), 1, "vault must contain exactly one entry");

    // ── Cross-system agreement assertion ───────────────────────────────
    // Both the realtime RansomwareDetector and the sandbox BehaviorAnalyzer
    // independently confirmed ransomware behavior.
    let realtime_confirmed = matches!(last_verdict, RansomwareVerdict::RansomwareDetected { .. });
    let sandbox_confirmed = result
        .behaviors
        .iter()
        .any(|b| b.category == ThreatCategory::Ransomware);
    assert!(
        realtime_confirmed && sandbox_confirmed,
        "both RansomwareDetector and BehaviorAnalyzer must confirm ransomware"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 10: APT multi-stage - credential theft + lateral + persistence
// ═══════════════════════════════════════════════════════════════════════════

/// Simulates an Advanced Persistent Threat (APT) attack that progresses
/// through three stages:
///
/// 1. **Credential theft**: reads /etc/shadow and SSH private key
/// 2. **Lateral movement**: SSH connection to internal host on port 22
/// 3. **Persistence**: writes a cron backdoor
///
/// Verifies that:
/// - `BehaviorAnalyzer` detects all three threat categories simultaneously
/// - Threat score is capped at 100
/// - `ProtectedDirsEnforcer` blocks access to sensitive paths
#[test]
fn apt_multi_stage_credential_lateral_persistence() {
    // ── Phase 1: Construct multi-stage SandboxResult ───────────────────
    let mut result = empty_sandbox_result();

    // Stage 1: Credential theft -- read /etc/shadow and SSH key
    result.file_operations.push(FileOperation {
        op: FileOpType::Read,
        path: "/etc/shadow".into(),
        blocked: false,
    });
    result.file_operations.push(FileOperation {
        op: FileOpType::Read,
        path: "/home/user/.ssh/id_rsa".into(),
        blocked: false,
    });

    // Stage 2: Lateral movement -- SSH to internal host
    result.network_attempts.push(NetworkAttempt {
        address: "10.0.0.5".into(),
        port: 22,
        protocol: "tcp".into(),
        blocked: false,
    });
    result.process_operations.push(ProcessOperation {
        op: ProcessOpType::Exec,
        target: "ssh".into(),
    });

    // Stage 3: Persistence -- write cron backdoor
    result.file_operations.push(FileOperation {
        op: FileOpType::Write,
        path: "/etc/cron.d/backdoor".into(),
        blocked: false,
    });

    // ── Phase 2: BehaviorAnalyzer ──────────────────────────────────────
    let analyzer = BehaviorAnalyzer::new();
    analyzer.analyze(&mut result);

    // Verify all three threat categories were detected.
    let categories: Vec<&ThreatCategory> = result.behaviors.iter().map(|b| &b.category).collect();

    assert!(
        categories.contains(&&ThreatCategory::CredentialTheft),
        "must detect CredentialTheft, found: {categories:?}"
    );
    assert!(
        categories.contains(&&ThreatCategory::LateralMovement),
        "must detect LateralMovement, found: {categories:?}"
    );
    assert!(
        categories.contains(&&ThreatCategory::Persistence),
        "must detect Persistence, found: {categories:?}"
    );

    // Verdict must be Malicious.
    assert!(
        matches!(result.verdict, SandboxVerdict::Malicious { .. }),
        "verdict should be Malicious, got: {:?}",
        result.verdict
    );

    // Scores: CredentialTheft=85, LateralMovement=80, Persistence=75 => sum=240 => capped at 100.
    assert_eq!(
        result.threat_score, 100,
        "threat_score must be capped at 100, got: {}",
        result.threat_score
    );

    // ── Phase 3: ProtectedDirsEnforcer (realtime) ──────────────────────
    // Protected-path enforcement is platform-specific (Linux: /home, /etc/cron.d;
    // macOS: /Users, /Library/LaunchDaemons). Only assert on supported platforms.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let enforcer = ProtectedDirsEnforcer::new(ProtectedDirsConfig::default());

        // Check access to SSH key -- should be blocked for unknown PID 9999.
        #[cfg(target_os = "linux")]
        let ssh_path = "/home/user/.ssh/id_rsa";
        #[cfg(target_os = "macos")]
        let ssh_path = "/Users/user/.ssh/id_rsa";

        let ssh_verdict = enforcer.check_access(std::path::Path::new(ssh_path), 9999);
        assert!(
            matches!(ssh_verdict, ProtectionVerdict::Blocked { .. }),
            "SSH key access should be Blocked for unknown process, got: {ssh_verdict:?}"
        );

        // Check access to persistence path -- should be blocked for unknown PID 9999.
        #[cfg(target_os = "linux")]
        let persist_path = "/etc/cron.d/backdoor";
        #[cfg(target_os = "macos")]
        let persist_path = "/Library/LaunchDaemons/com.backdoor.plist";

        let cron_verdict = enforcer.check_access(std::path::Path::new(persist_path), 9999);
        assert!(
            matches!(cron_verdict, ProtectionVerdict::Blocked { .. }),
            "persistence path access should be Blocked for unknown process, got: {cron_verdict:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 11: Dropper + anti-analysis + YARA rule auto-generation
// ═══════════════════════════════════════════════════════════════════════════

/// Exercises the dropper-to-YARA feedback loop:
///
/// 1. `BehaviorAnalyzer` detects anti-analysis + dropper behavior
/// 2. `generate_rules()` produces YARA rules from the sample + behaviors
/// 3. YARA rules are written to disk and loaded by a new `ScanEngine`
/// 4. `scan_bytes()` confirms the auto-generated rule catches the sample
///
/// This validates the complete closed-loop: behavior detection -> rule
/// generation -> automated detection of future samples.
#[test]
fn dropper_anti_analysis_yara_gen() {
    // ── Phase 1: Build sample data with MZ header + suspicious strings ─
    let mut sample_data: Vec<u8> = Vec::new();
    // MZ header (PE magic)
    sample_data.extend_from_slice(&[0x4D, 0x5A]);
    // Padding to ensure non-trivial byte patterns
    sample_data.extend_from_slice(&[0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    // Suspicious strings that generate_rules will extract
    sample_data.extend_from_slice(b"\x00http://evil.example.com/payload\x00");
    sample_data.extend_from_slice(b"/tmp/payload.bin\x00");
    sample_data.extend_from_slice(b"chmod \x00");
    sample_data.extend_from_slice(b"/bin/sh\x00");
    sample_data.extend_from_slice(b"MALICIOUS_MARKER_FOR_YARA_DETECTION\x00");
    // Padding to ensure enough data for byte pattern extraction
    for i in 0u8..128 {
        sample_data.push(i.wrapping_mul(7).wrapping_add(0x41));
    }

    // ── Phase 2: Construct SandboxResult with dropper + anti-analysis ──
    let mut result = empty_sandbox_result();

    // Anti-analysis: ptrace self (debugger detection)
    result.process_operations.push(ProcessOperation {
        op: ProcessOpType::Ptrace,
        target: "self".into(),
    });

    // Anti-analysis: read /proc/self/status (VM/debugger check)
    result.file_operations.push(FileOperation {
        op: FileOpType::Read,
        path: "/proc/self/status".into(),
        blocked: false,
    });

    // Dropper stage 1: write payload to disk
    result.file_operations.push(FileOperation {
        op: FileOpType::Write,
        path: "/tmp/payload.bin".into(),
        blocked: false,
    });

    // Dropper stage 2: make executable
    result.file_operations.push(FileOperation {
        op: FileOpType::Chmod,
        path: "/tmp/payload.bin".into(),
        blocked: false,
    });

    // Dropper stage 3: execute payload
    result.process_operations.push(ProcessOperation {
        op: ProcessOpType::Exec,
        target: "/tmp/payload.bin".into(),
    });

    // ── Phase 3: BehaviorAnalyzer ──────────────────────────────────────
    let analyzer = BehaviorAnalyzer::new();
    analyzer.analyze(&mut result);

    let categories: Vec<&ThreatCategory> = result.behaviors.iter().map(|b| &b.category).collect();
    assert!(
        categories.contains(&&ThreatCategory::AntiAnalysis),
        "must detect AntiAnalysis, found: {categories:?}"
    );
    assert!(
        categories.contains(&&ThreatCategory::Dropper),
        "must detect Dropper, found: {categories:?}"
    );
    assert!(
        matches!(result.verdict, SandboxVerdict::Malicious { .. }),
        "verdict should be Malicious, got: {:?}",
        result.verdict
    );

    // ── Phase 4: generate_rules from sample + behaviors ────────────────
    let rules = prx_sd_sandbox::generate_rules(&sample_data, "dropper.elf", "Linux.Dropper.TestV11", &result.behaviors);
    assert!(!rules.is_empty(), "generate_rules must produce at least one YARA rule");

    // Verify the generated rules have valid YARA structure.
    for rule in &rules {
        assert!(rule.source.contains("rule "), "rule source must contain 'rule' keyword");
        assert!(
            rule.source.contains("condition:"),
            "rule source must contain 'condition:'"
        );
        assert!(rule.confidence > 0, "confidence should be > 0");
    }

    // ── Phase 5: Write YARA rules to disk, load into ScanEngine ────────
    let tmp = tempfile::tempdir().unwrap();
    let sigs_dir = tmp.path().join("signatures");
    let yara_dir = tmp.path().join("yara");
    let qdir = tmp.path().join("quarantine");

    fs::create_dir_all(&sigs_dir).unwrap();
    fs::create_dir_all(&yara_dir).unwrap();
    fs::create_dir_all(&qdir).unwrap();

    // Initialize signature DB (required for ScanEngine).
    {
        let _db = SignatureDatabase::open(&sigs_dir).expect("open sig db");
    }

    // Write all generated YARA rules to .yar files.
    for (i, rule) in rules.iter().enumerate() {
        let yar_path = yara_dir.join(format!("auto_rule_{i}.yar"));
        fs::write(&yar_path, &rule.source).unwrap();
    }

    let config = ScanConfig::default()
        .with_signatures_dir(&sigs_dir)
        .with_yara_rules_dir(&yara_dir)
        .with_quarantine_dir(&qdir)
        .with_scan_threads(1);

    let engine = ScanEngine::new(config).expect("create scan engine with YARA rules");

    // ── Phase 6: scan_bytes with sample data ───────────────────────────
    let scan_result = engine.scan_bytes(&sample_data, "dropper_sample.elf");

    assert_eq!(
        scan_result.threat_level,
        ThreatLevel::Malicious,
        "auto-generated YARA rules must detect the sample as Malicious, got: {:?}",
        scan_result.threat_level
    );
    assert_eq!(
        scan_result.detection_type,
        Some(prx_sd_core::DetectionType::YaraRule),
        "detection must be via YARA engine (not heuristic), got: {:?}",
        scan_result.detection_type
    );

    // ── Closed-loop assertion ──────────────────────────────────────────
    // The complete feedback loop is validated:
    //   behavior detection -> YARA generation -> automated detection
    let behavior_detected = !result.behaviors.is_empty();
    let yara_generated = !rules.is_empty();
    let auto_detected = scan_result.detection_type == Some(prx_sd_core::DetectionType::YaraRule);
    assert!(
        behavior_detected && yara_generated && auto_detected,
        "full closed loop must work: behavior={behavior_detected}, \
         yara_gen={yara_generated}, auto_detect={auto_detected}"
    );
}
