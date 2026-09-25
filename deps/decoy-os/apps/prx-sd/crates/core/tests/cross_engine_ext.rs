//! Extended cross-engine tests: YARA-only purity, aggregate priority,
//! threshold boundary consistency, and CAFEBABE disambiguation.
//!
//! Scenarios 35-38: regression and gap-coverage tests for multi-engine
//! interactions, score thresholds, and magic-byte edge cases.

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

use prx_sd_core::ScanConfig;
use prx_sd_core::magic::{FileType, detect_magic};
use prx_sd_core::result::{DetectionType, ScanResult, ThreatLevel};
use prx_sd_signatures::SignatureDatabase;

// ---------------------------------------------------------------------------
// Helpers (mirrors TestDirs from cross_multiengine.rs)
// ---------------------------------------------------------------------------

struct TestDirs {
    _tmp: tempfile::TempDir,
    sigs_dir: PathBuf,
    yara_dir: PathBuf,
    qdir: PathBuf,
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

    fn config(&self) -> ScanConfig {
        ScanConfig::default()
            .with_signatures_dir(&self.sigs_dir)
            .with_yara_rules_dir(&self.yara_dir)
            .with_quarantine_dir(&self.qdir)
            .with_scan_threads(1)
    }
}

// ---------------------------------------------------------------------------
// Scenario 35: Pure YARA match without heuristic interference
// ---------------------------------------------------------------------------

/// Verifies that scanning the EICAR test signature with its hash imported
/// produces a Malicious result via Hash detection, and that no spurious
/// heuristic findings contaminate the result.
///
/// The EICAR string is short ASCII text with no PE/ELF/MachO structure,
/// so the heuristic engine should produce zero findings. Detection must
/// come exclusively from the hash engine (DetectionType::Hash).
///
/// This covers gap 5: confirming that signature-only detection fires
/// cleanly without heuristic interference on non-binary payloads.
#[test]
fn yara_only_no_heuristic_interference() {
    let dirs = TestDirs::new();

    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Import the EICAR SHA-256 hash so the hash engine can detect it.
    {
        let db = SignatureDatabase::open(&dirs.sigs_dir).expect("open DB");
        let hash = prx_sd_signatures::hash::sha256_hash(eicar);
        db.import_hashes(&[(hash, "EICAR-Test-File".to_string())])
            .expect("import EICAR hash");
    } // db dropped before engine creation

    let engine = prx_sd_core::ScanEngine::new(dirs.config()).expect("create engine");
    let result = engine.scan_bytes(eicar, "eicar_yara_test");

    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "EICAR signature must be detected as Malicious"
    );

    // EICAR is caught by hash lookup (fast path, early return).
    assert_eq!(
        result.detection_type,
        Some(DetectionType::Hash),
        "EICAR should be detected via Hash (fast path)"
    );

    // Verify no heuristic findings leaked into the result details.
    // The hash engine returns early before heuristics run, so details
    // should only contain hash-related entries.
    let has_heuristic_detail = result.details.iter().any(|d| d.starts_with("heuristic:"));
    assert!(
        !has_heuristic_detail,
        "hash fast-path should not produce heuristic details, got: {:?}",
        result.details
    );
}

// ---------------------------------------------------------------------------
// Scenario 36: Aggregate detection-type priority (Hash > YARA > Heuristic)
// ---------------------------------------------------------------------------

/// Regression test for BUG-M01: ensures ScanResult::aggregate() respects
/// the Hash > YaraRule > Heuristic > Behavioral priority ordering when
/// multiple engines report the same threat level.
///
/// Three sub-results are constructed, all at Malicious level but with
/// different detection types. The aggregate must select Hash as the
/// winning detection type and carry its threat_name.
#[test]
fn aggregate_detection_type_priority() {
    let path = "/synthetic/aggregate_test";

    let r_heuristic = ScanResult::detected(
        path,
        ThreatLevel::Malicious,
        DetectionType::Heuristic,
        "Heuristic.Generic",
        vec!["heuristic finding".into()],
        10,
    );

    let r_yara = ScanResult::detected(
        path,
        ThreatLevel::Malicious,
        DetectionType::YaraRule,
        "YARA.Trojan",
        vec!["yara rule matched".into()],
        5,
    );

    let r_hash = ScanResult::detected(
        path,
        ThreatLevel::Malicious,
        DetectionType::Hash,
        "SHA256.Match",
        vec!["hash match".into()],
        2,
    );

    // Aggregate in the order Heuristic, YARA, Hash to ensure priority
    // is not simply "first wins".
    let agg = ScanResult::aggregate(path, &[r_heuristic, r_yara, r_hash]);

    assert_eq!(
        agg.threat_level,
        ThreatLevel::Malicious,
        "aggregated threat_level must remain Malicious"
    );
    assert_eq!(
        agg.detection_type,
        Some(DetectionType::Hash),
        "Hash must win over YaraRule and Heuristic in aggregate priority"
    );
    assert_eq!(
        agg.threat_name.as_deref(),
        Some("SHA256.Match"),
        "threat_name must come from the Hash sub-result"
    );

    // All details from every sub-result must be collected.
    assert_eq!(
        agg.details.len(),
        3,
        "aggregate must collect details from all sub-results"
    );

    // Scan times are summed.
    assert_eq!(agg.scan_time_ms, 17, "scan_time_ms must be sum of sub-results");
}

// ---------------------------------------------------------------------------
// Scenario 37: Threshold boundary consistency (core vs heuristic)
// ---------------------------------------------------------------------------

/// Regression test for BUG-C01: confirms that core::ThreatLevel and
/// heuristic::ThreatLevel use identical score-to-level mappings at the
/// critical 59/60 boundary.
///
/// Both crates define their own ThreatLevel enum with a from_score()
/// method. This test ensures they produce the same classification for
/// boundary values, preventing silent divergence.
#[test]
fn threshold_unified_59_60_boundary() {
    // ── core boundaries ──
    assert_eq!(
        ThreatLevel::from_score(59),
        ThreatLevel::Suspicious,
        "core: score 59 must be Suspicious"
    );
    assert_eq!(
        ThreatLevel::from_score(60),
        ThreatLevel::Malicious,
        "core: score 60 must be Malicious"
    );

    // ── heuristic boundaries ──
    assert_eq!(
        prx_sd_heuristic::ThreatLevel::from_score(59),
        prx_sd_heuristic::ThreatLevel::Suspicious,
        "heuristic: score 59 must be Suspicious"
    );
    assert_eq!(
        prx_sd_heuristic::ThreatLevel::from_score(60),
        prx_sd_heuristic::ThreatLevel::Malicious,
        "heuristic: score 60 must be Malicious"
    );

    // Cross-crate equivalence at additional boundary points.
    // score 0 => Clean in both
    assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
    assert_eq!(
        prx_sd_heuristic::ThreatLevel::from_score(0),
        prx_sd_heuristic::ThreatLevel::Clean,
    );

    // score 29 => Clean, score 30 => Suspicious in both
    assert_eq!(ThreatLevel::from_score(29), ThreatLevel::Clean);
    assert_eq!(
        prx_sd_heuristic::ThreatLevel::from_score(29),
        prx_sd_heuristic::ThreatLevel::Clean,
    );
    assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Suspicious);
    assert_eq!(
        prx_sd_heuristic::ThreatLevel::from_score(30),
        prx_sd_heuristic::ThreatLevel::Suspicious,
    );

    // score 100 => Malicious in both
    assert_eq!(ThreatLevel::from_score(100), ThreatLevel::Malicious);
    assert_eq!(
        prx_sd_heuristic::ThreatLevel::from_score(100),
        prx_sd_heuristic::ThreatLevel::Malicious,
    );
}

// ---------------------------------------------------------------------------
// Scenario 38: 0xCAFEBABE disambiguation — Java .class vs FAT Mach-O
// ---------------------------------------------------------------------------

/// Regression test for BUG-M05: the 0xCAFEBABE magic is shared between
/// Java .class files and FAT (universal) Mach-O binaries. The disambiguator
/// uses bytes 4-7 as `nfat_arch`: values 1-20 are treated as FAT Mach-O,
/// while higher values (Java major_version 45-67) fall through to Unknown.
///
/// This test exercises:
/// 1. Java .class (major_version=55, Java 11) => Unknown
/// 2. FAT Mach-O (nfat_arch=2) => MachO
/// 3. FAT Mach-O (nfat_arch=1) => MachO
/// 4. Short buffer (only 4 bytes of 0xCAFEBABE) => MachO (conservative)
#[test]
fn java_class_not_macho() {
    // 1. Java .class file: 0xCAFEBABE + minor_version(0x0000) + major_version(0x0037 = 55)
    //    nfat_arch interpretation: 0x00000037 = 55, which exceeds the 1-20 range.
    let java_class: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37];
    assert_eq!(
        detect_magic(&java_class),
        FileType::Unknown,
        "Java .class (major_version=55) must be detected as Unknown, not MachO"
    );

    // 2. FAT Mach-O with nfat_arch=2 (two architectures, e.g. x86_64 + arm64).
    let fat_macho_2: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
    assert_eq!(
        detect_magic(&fat_macho_2),
        FileType::MachO,
        "FAT Mach-O (nfat_arch=2) must be detected as MachO"
    );

    // 3. FAT Mach-O with nfat_arch=1 (single architecture universal binary).
    let fat_macho_1: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        detect_magic(&fat_macho_1),
        FileType::MachO,
        "FAT Mach-O (nfat_arch=1) must be detected as MachO"
    );

    // 4. Short buffer: only 4 bytes (0xCAFEBABE without the arch count).
    //    With insufficient data to disambiguate, the engine conservatively
    //    returns MachO.
    let short_cafebabe: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
    assert_eq!(
        detect_magic(&short_cafebabe),
        FileType::MachO,
        "Short 0xCAFEBABE buffer (4 bytes) must conservatively return MachO"
    );
}
