//! Cross-crate heuristic analysis tests: PE attack patterns + scoring.
//!
//! Scenarios 12-16: PE process injection, packer detection, anti-debug,
//! scoring boundaries, and API bonus mechanism.
//! Based on AMTSO/AV-TEST/MITRE ATT&CK research.

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
use prx_sd_heuristic::scoring::{ScoringWeights, aggregate_score, aggregate_score_with_weights};
use prx_sd_heuristic::{Finding, HeuristicEngine, ThreatLevel};
use prx_sd_parsers::{
    ParsedFile,
    pe::{ImportInfo, PeInfo, SectionInfo},
};

// ── Helpers ────────────────────────────────────────────────────────────────

/// Build a `ParsedFile::PE` from the given parts.
fn make_pe(sections: Vec<SectionInfo>, imports: Vec<ImportInfo>, timestamp: u32) -> ParsedFile {
    ParsedFile::PE(PeInfo {
        is_64bit: true,
        is_dll: false,
        entry_point: 0x1000,
        timestamp,
        sections,
        imports,
        exports: vec![],
        imphash: String::new(),
        debug_info: None,
    })
}

/// Embed a list of ASCII strings into a byte buffer starting at `offset`.
/// Returns the buffer so tests can pass it as `data`.
fn make_pe_bytes_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 2048];
    // MZ magic so the engine treats this as a PE header candidate.
    data[0] = b'M';
    data[1] = b'Z';
    let mut off = 64usize;
    for s in strings {
        let bytes = s.as_bytes();
        if off + bytes.len() + 1 <= data.len() {
            data[off..off + bytes.len()].copy_from_slice(bytes);
            off += bytes.len() + 1;
        }
    }
    data
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 12: PE process-injection combo → Malicious (score capped at 100)
// ═══════════════════════════════════════════════════════════════════════════

/// Verifies that a PE combining process-injection APIs, a writable+executable
/// section with entropy > 7.0, and a zeroed timestamp accumulates enough
/// heuristic findings to be classified Malicious with a capped score of 100.
///
/// MITRE ATT&CK: T1055 (Process Injection), T1027 (Obfuscated Files).
#[test]
fn pe_process_injection_combo_scores_malicious() {
    // Section: CODE | MEM_EXECUTE | MEM_WRITE (0xE000_0020) + entropy > 7.0
    // → triggers PackedSection, WritableCodeSection, SelfModifying.
    let section = SectionInfo {
        name: ".text".to_string(),
        virtual_size: 0x10000,
        raw_size: 0x8000,
        entropy: 7.5,
        characteristics: 0xE000_0020,
    };

    let imports = vec![ImportInfo {
        dll: "kernel32.dll".to_string(),
        functions: vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
            "CreateRemoteThread".to_string(),
        ],
    }];

    // timestamp == 0 → ZeroTimestamp finding.
    let parsed = make_pe(vec![section], imports, 0);

    // Raw bytes contain the API strings so the raw-byte scan can also find
    // them (duplicates are suppressed by the engine, so this is safe).
    let data = make_pe_bytes_with_strings(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    // Overall classification must be Malicious.
    assert_eq!(
        result.threat_level,
        ThreatLevel::Malicious,
        "process-injection PE must be Malicious, got {:?} (score={}): {:?}",
        result.threat_level,
        result.score,
        result.findings
    );

    // Score is capped at 100.
    assert_eq!(result.score, 100, "score must be capped at 100, got {}", result.score);

    // Import-table scan must detect all three injection APIs.
    let has_api = |name: &str| {
        result
            .findings
            .iter()
            .any(|f| matches!(f, Finding::SuspiciousApi(n) if n == name))
    };
    assert!(has_api("VirtualAllocEx"), "VirtualAllocEx must be flagged");
    assert!(has_api("WriteProcessMemory"), "WriteProcessMemory must be flagged");
    assert!(has_api("CreateRemoteThread"), "CreateRemoteThread must be flagged");

    // Section with entropy > 7.0 and characteristics CODE|WRITE → PackedSection.
    let has_packed_text = result
        .findings
        .iter()
        .any(|f| matches!(f, Finding::PackedSection { name, .. } if name.contains(".text")));
    assert!(
        has_packed_text,
        "PackedSection(.text) must be present in findings: {:?}",
        result.findings
    );

    // CODE|WRITE → WritableCodeSection.
    assert!(
        result.findings.contains(&Finding::WritableCodeSection),
        "WritableCodeSection must be present: {:?}",
        result.findings
    );

    // CODE|WRITE + entropy > 6.5 → SelfModifying.
    assert!(
        result.findings.contains(&Finding::SelfModifying),
        "SelfModifying must be present: {:?}",
        result.findings
    );

    // timestamp == 0 → ZeroTimestamp.
    assert!(
        result.findings.contains(&Finding::ZeroTimestamp),
        "ZeroTimestamp must be present: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 13: Packer detection — all 11 known families
// ═══════════════════════════════════════════════════════════════════════════

/// Builds a PE whose sections carry the given names, calls `analyze`, and
/// asserts that `PackerDetected(expected_name)` is present in findings.
///
/// A non-zero timestamp (0x1234_5678) avoids ZeroTimestamp noise so that
/// assertions are purely about the packer findings.
fn assert_packer_detected(section_names: &[&str], expected_packer: &str, also_upx_packed: bool) {
    let sections: Vec<SectionInfo> = section_names
        .iter()
        .map(|&n| SectionInfo {
            name: n.to_string(),
            virtual_size: 0x1000,
            raw_size: 0,
            entropy: 0.0,
            characteristics: 0x6000_0020,
        })
        .collect();

    let parsed = make_pe(sections, vec![], 0x1234_5678);
    let data = vec![b'M', b'Z'];
    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    let has_packer = result
        .findings
        .iter()
        .any(|f| matches!(f, Finding::PackerDetected(name) if name.contains(expected_packer)));
    assert!(
        has_packer,
        "expected PackerDetected containing '{}' for sections {:?}, findings: {:?}",
        expected_packer, section_names, result.findings
    );

    if also_upx_packed {
        assert!(
            result.findings.contains(&Finding::UPXPacked),
            "UPXPacked must be present alongside PackerDetected(UPX): {:?}",
            result.findings
        );
    }
}

/// Tests all 11 packer families recognised by the engine's section-name
/// heuristic.  Each sub-case exercises one distinct packer family using the
/// canonical section names documented in the PE packer catalogue.
///
/// Coverage: UPX, ASPack, Themida, VMProtect, PECompact, MPRESS, Enigma,
/// NSPack, PEtite, Yoda, MEW.
#[test]
fn pe_packer_detection_all_families() {
    // UPX — also expects the dedicated UPXPacked finding.
    assert_packer_detected(&["UPX0", "UPX1"], "UPX", true);

    // ASPack
    assert_packer_detected(&[".aspack"], "ASPack", false);

    // Themida (section name matching is case-insensitive in the engine).
    assert_packer_detected(&[".themida"], "Themida", false);

    // VMProtect
    assert_packer_detected(&[".vmp0", ".vmp1"], "VMProtect", false);

    // PECompact
    assert_packer_detected(&[".pec"], "PECompact", false);

    // MPRESS
    assert_packer_detected(&[".MPRESS1", ".MPRESS2"], "MPRESS", false);

    // Enigma Protector
    assert_packer_detected(&[".enigma1"], "Enigma", false);

    // NSPack
    assert_packer_detected(&[".nsp0", ".nsp1"], "NSPack", false);

    // PEtite
    assert_packer_detected(&[".petite"], "PEtite", false);

    // Yoda Protector
    assert_packer_detected(&[".yP"], "Yoda", false);

    // MEW
    assert_packer_detected(&[".MEW"], "MEW", false);
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 14: Anti-debug API detection
// ═══════════════════════════════════════════════════════════════════════════

/// Confirms that a PE importing only `IsDebuggerPresent` and
/// `CheckRemoteDebuggerPresent` is correctly classified as at least Suspicious
/// and that both the per-API `SuspiciousApi` findings and the aggregate
/// `AntiDebug` finding are emitted.
///
/// MITRE ATT&CK: T1622 (Debugger Evasion).
#[test]
fn pe_anti_debug_detection() {
    let section = SectionInfo {
        name: ".text".to_string(),
        virtual_size: 0x8000,
        raw_size: 0x4000,
        entropy: 5.0,
        // CODE | EXECUTE | READ (no WRITE) — normal section flags.
        characteristics: 0x6000_0020,
    };

    let imports = vec![ImportInfo {
        dll: "kernel32.dll".to_string(),
        functions: vec![
            "IsDebuggerPresent".to_string(),
            "CheckRemoteDebuggerPresent".to_string(),
        ],
    }];

    // Non-zero timestamp to avoid ZeroTimestamp noise.
    let parsed = make_pe(vec![section], imports, 0x5F00_0000);
    let data = make_pe_bytes_with_strings(&["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]);

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    // Both anti-debug APIs must appear as individual SuspiciousApi findings.
    let has_is_debugger = result
        .findings
        .iter()
        .any(|f| matches!(f, Finding::SuspiciousApi(n) if n == "IsDebuggerPresent"));
    let has_check_remote = result
        .findings
        .iter()
        .any(|f| matches!(f, Finding::SuspiciousApi(n) if n == "CheckRemoteDebuggerPresent"));

    assert!(
        has_is_debugger,
        "SuspiciousApi(IsDebuggerPresent) must be present: {:?}",
        result.findings
    );
    assert!(
        has_check_remote,
        "SuspiciousApi(CheckRemoteDebuggerPresent) must be present: {:?}",
        result.findings
    );

    // The aggregate AntiDebug finding must be emitted when any anti-debug API
    // is detected.
    assert!(
        result.findings.contains(&Finding::AntiDebug),
        "AntiDebug must be present: {:?}",
        result.findings
    );

    // Classification must be at least Suspicious (score >= 30).
    assert!(
        result.threat_level >= ThreatLevel::Suspicious,
        "anti-debug PE must be at least Suspicious, got {:?} (score={}): {:?}",
        result.threat_level,
        result.score,
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 15: Score boundary classification — 29/30/59/60 and cap at 100
// ═══════════════════════════════════════════════════════════════════════════

/// Verifies the exact ThreatLevel boundaries defined by `ThreatLevel::from_score`:
///
/// * 0–29   → Clean
/// * 30–59  → Suspicious
/// * 60–100 → Malicious
///
/// NOTE: These boundaries apply to the **heuristic crate's** `ThreatLevel`.
/// The core crate's `ThreatLevel::from_score` uses a different threshold
/// (≥70 for Malicious).  This test exercises the heuristic scoring functions
/// directly, so it uses the heuristic crate's thresholds.
///
/// Each boundary value is tested using `aggregate_score_with_weights` with
/// a custom weight so that a single finding produces the exact target score.
#[test]
fn scoring_boundary_29_30_59_60() {
    // ── Case 1: score exactly 29 → Clean ──────────────────────────────────
    {
        let w = ScoringWeights {
            zero_timestamp: 29,
            ..ScoringWeights::default()
        };
        let (s, l) = aggregate_score_with_weights(&[Finding::ZeroTimestamp], &w);
        assert_eq!(s, 29, "score should be 29");
        assert_eq!(l, ThreatLevel::Clean, "score 29 must be Clean");
    }

    // ── Case 2: score exactly 30 → Suspicious ─────────────────────────────
    // Default HighEntropy weight is 30.
    {
        let (s, l) = aggregate_score(&[Finding::HighEntropy(7.5)]);
        assert_eq!(s, 30, "score should be 30");
        assert_eq!(l, ThreatLevel::Suspicious, "score 30 must be Suspicious");
    }

    // ── Case 3: score exactly 59 → Suspicious ─────────────────────────────
    {
        let w = ScoringWeights {
            high_entropy: 59,
            ..ScoringWeights::default()
        };
        let (s, l) = aggregate_score_with_weights(&[Finding::HighEntropy(7.5)], &w);
        assert_eq!(s, 59, "score should be 59");
        assert_eq!(l, ThreatLevel::Suspicious, "score 59 must be Suspicious");
    }

    // ── Case 4: score exactly 60 → Malicious ──────────────────────────────
    {
        let w = ScoringWeights {
            high_entropy: 60,
            ..ScoringWeights::default()
        };
        let (s, l) = aggregate_score_with_weights(&[Finding::HighEntropy(7.5)], &w);
        assert_eq!(s, 60, "score should be 60");
        assert_eq!(l, ThreatLevel::Malicious, "score 60 must be Malicious");
    }

    // ── Case 5: raw sum > 100 → capped at 100 ─────────────────────────────
    // Raw contributions: 30 + 25 + 20 + 20 + 20 + 25 + 10 = 150 → capped at 100.
    {
        let findings = vec![
            Finding::HighEntropy(7.9), // 30
            Finding::PackedSection {
                name: "s".into(),
                entropy: 7.8,
            }, // 25
            Finding::PackerDetected("UPX".into()), // 20
            Finding::AntiDebug,        // 20
            Finding::WritableCodeSection, // 20
            Finding::NoImports,        // 25
            Finding::ZeroTimestamp,    // 10
        ];
        let (s, _) = aggregate_score(&findings);
        assert_eq!(s, 100, "score should be capped at 100, got {s}");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 16: SuspiciousApi bonus — +15 when ≥ 3 distinct APIs found
// ═══════════════════════════════════════════════════════════════════════════

/// Validates the API co-occurrence bonus: when 3 or more `SuspiciousApi`
/// findings are present, `aggregate_score` adds a flat +15 bonus on top of
/// the per-finding weights.
///
/// This models the intuition that a single suspicious API can be benign
/// (e.g. a security scanner), but three or more together strongly suggest
/// an injection or evasion toolkit.
#[test]
fn api_bonus_15_at_three_or_more() {
    // ── Case 1: exactly 2 SuspiciousApi → no bonus ────────────────────────
    // 2 × 20 = 40, bonus = 0 → total 40.
    {
        let f = vec![Finding::SuspiciousApi("A".into()), Finding::SuspiciousApi("B".into())];
        let (s, _) = aggregate_score(&f);
        assert_eq!(s, 40, "2 SuspiciousApi should score 40 (no bonus), got {s}");
    }

    // ── Case 2: exactly 3 SuspiciousApi → +15 bonus ───────────────────────
    // 3 × 20 + 15 = 75.
    {
        let f = vec![
            Finding::SuspiciousApi("A".into()),
            Finding::SuspiciousApi("B".into()),
            Finding::SuspiciousApi("C".into()),
        ];
        let (s, _) = aggregate_score(&f);
        assert_eq!(s, 75, "3 SuspiciousApi should score 75 (3×20 + bonus 15), got {s}");
    }

    // ── Case 3: 6 SuspiciousApi → raw 135 → capped at 100, Malicious ──────
    // 6 × 20 + 15 = 135 → capped at 100.
    {
        let f: Vec<_> = (0..6).map(|i| Finding::SuspiciousApi(format!("API{i}"))).collect();
        let (s, l) = aggregate_score(&f);
        assert_eq!(s, 100, "6 SuspiciousApi should be capped at 100, got {s}");
        assert_eq!(
            l,
            ThreatLevel::Malicious,
            "6 SuspiciousApi capped at 100 must be Malicious"
        );
    }
}
