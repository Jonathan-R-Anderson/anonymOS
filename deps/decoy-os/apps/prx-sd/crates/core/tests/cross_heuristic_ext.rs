//! Extended cross-crate heuristic tests: MachO, ELF, PE edge cases + scoring.
//!
//! Scenarios 26-30: MachO packed section, ELF static+packed, PE high import count,
//! SelfModifying weight verification, and zero-sections PE baseline.

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
use prx_sd_heuristic::scoring::aggregate_score;
use prx_sd_heuristic::{Finding, HeuristicEngine, ThreatLevel};
use prx_sd_parsers::ParsedFile;
use prx_sd_parsers::elf::ElfInfo;
use prx_sd_parsers::macho::MachOInfo;
use prx_sd_parsers::pe::{ImportInfo, PeInfo, SectionInfo};

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

/// Build a `ParsedFile::ELF` from the given parts.
fn make_elf(
    elf_type: &str,
    sections: Vec<SectionInfo>,
    symbols: Vec<String>,
    dynamic_libs: Vec<String>,
    interpreter: Option<String>,
) -> ParsedFile {
    ParsedFile::ELF(ElfInfo {
        is_64bit: true,
        elf_type: elf_type.to_string(),
        entry_point: 0x400000,
        sections,
        symbols,
        dynamic_libs,
        interpreter,
    })
}

/// Build a `ParsedFile::MachO` from the given parts.
fn make_macho(sections: Vec<SectionInfo>, imports: Vec<String>) -> ParsedFile {
    ParsedFile::MachO(MachOInfo {
        is_64bit: true,
        cpu_type: "x86_64".to_string(),
        file_type: "execute".to_string(),
        sections,
        imports,
    })
}

/// Generate high-entropy data: all 256 byte values in a cycle, repeated to
/// reach `len` bytes. Shannon entropy approaches 8.0 for large `len`.
fn high_entropy_data(len: usize) -> Vec<u8> {
    (0..=255u8).cycle().take(len).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 26: MachO packed section detection
// ═══════════════════════════════════════════════════════════════════════════

/// Verifies that a Mach-O section with entropy > 7.0 and raw_size > 512
/// triggers a `PackedSection` finding.
///
/// Coverage gap 1: MachO high-entropy section detection path.
#[test]
fn macho_packed_section_detection() {
    let section = SectionInfo {
        name: "__TEXT,__text".to_string(),
        virtual_size: 2048,
        raw_size: 1024,
        entropy: 7.5,
        characteristics: 0,
    };

    let parsed = make_macho(vec![section], vec![]);

    // Use high-entropy data so overall entropy is also high (but the engine
    // suppresses lone HighEntropy for non-PE/non-ELF if no other findings
    // exist -- however MachO IS checked by as_macho(), so PackedSection
    // will be the corroborating finding).
    let data = high_entropy_data(4096);

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    let has_packed_section = result.findings.iter().any(|f| {
        matches!(
            f,
            Finding::PackedSection { name, entropy }
            if name == "__TEXT,__text" && *entropy > 7.0
        )
    });
    assert!(
        has_packed_section,
        "MachO section with entropy=7.5 and raw_size=1024 must trigger PackedSection, \
         got findings: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 27: ELF static + packed detection
// ═══════════════════════════════════════════════════════════════════════════

/// Verifies that an ELF with no dynamic_libs, no interpreter, and overall
/// entropy > 6.8 triggers `PackerDetected("static+packed ELF")`.
///
/// Coverage gap 2: statically linked ELF with high entropy.
#[test]
fn elf_static_packed_detection() {
    // ELF with no dynamic libraries and no interpreter = statically linked.
    // Sections are not critical for this check; the engine computes overall
    // entropy from the raw data bytes.
    let parsed = make_elf(
        "EXEC",
        vec![SectionInfo {
            name: ".text".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            entropy: 5.0,
            characteristics: 0,
        }],
        vec!["main".to_string()],
        vec![], // no dynamic_libs
        None,   // no interpreter
    );

    // Generate data with high enough entropy (> 6.8).
    // 256 distinct byte values cycled over 8192 bytes gives entropy ~8.0.
    let data = high_entropy_data(8192);

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    let has_static_packed = result
        .findings
        .iter()
        .any(|f| matches!(f, Finding::PackerDetected(name) if name.contains("static+packed ELF")));
    assert!(
        has_static_packed,
        "statically linked ELF with high entropy must trigger \
         PackerDetected(\"static+packed ELF\"), got findings: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 28: PE high import count detection
// ═══════════════════════════════════════════════════════════════════════════

/// Verifies that a PE with > 1000 imports triggers `HighImportCount`.
///
/// Coverage gap 6: high import count detection threshold.
#[test]
fn high_import_count_detection() {
    // Build a single DLL entry with 1001 functions.
    let functions: Vec<String> = (0..1001).map(|i| format!("Func{i}")).collect();
    let imports = vec![ImportInfo {
        dll: "mega.dll".to_string(),
        functions,
    }];

    let section = SectionInfo {
        name: ".text".to_string(),
        virtual_size: 0x5000,
        raw_size: 0x4800,
        entropy: 5.0,
        characteristics: 0x6000_0020, // CODE | EXECUTE | READ
    };

    let parsed = make_pe(vec![section], imports, 0x6000_0000);
    let data = vec![0u8; 256];

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    assert!(
        result.findings.contains(&Finding::HighImportCount),
        "PE with 1001 imports must trigger HighImportCount, got findings: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 29: SelfModifying weight is exactly 15
// ═══════════════════════════════════════════════════════════════════════════

/// Verifies that `Finding::SelfModifying` contributes exactly 15 points
/// to the aggregate score. Uses `aggregate_score` directly with a single
/// finding to isolate the weight.
///
/// Coverage gap 8: SelfModifying weight verification.
#[test]
fn self_modifying_weight_exactly_15() {
    // Test aggregate_score directly: a single SelfModifying finding should
    // produce exactly 15 points (as defined in scoring.rs weight_for).
    let (score, level) = aggregate_score(&[Finding::SelfModifying]);
    assert_eq!(
        score, 15,
        "SelfModifying alone must contribute exactly 15 points, got {score}"
    );
    assert_eq!(level, ThreatLevel::Clean, "score 15 must map to Clean, got {level:?}");

    // Also verify through the engine that a PE with CODE|EXECUTE|WRITE and
    // entropy > 6.5 produces both WritableCodeSection and SelfModifying.
    let section = SectionInfo {
        name: ".text".to_string(),
        virtual_size: 0x10000,
        raw_size: 0x8000,
        entropy: 7.0,
        // CODE (0x20) | MEM_EXECUTE (0x2000_0000) | MEM_WRITE (0x8000_0000)
        characteristics: 0xE000_0020,
    };

    let parsed = make_pe(
        vec![section],
        vec![ImportInfo {
            dll: "kernel32.dll".to_string(),
            functions: vec!["GetProcAddress".to_string()],
        }],
        0x6000_0000, // non-zero timestamp
    );
    let data = vec![0u8; 256];

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    assert!(
        result.findings.contains(&Finding::SelfModifying),
        "PE section with CODE|EXECUTE|WRITE + entropy=7.0 must trigger SelfModifying, \
         got findings: {:?}",
        result.findings
    );
    assert!(
        result.findings.contains(&Finding::WritableCodeSection),
        "PE section with CODE|EXECUTE|WRITE must trigger WritableCodeSection, \
         got findings: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 30: PE with zero sections — baseline behaviour
// ═══════════════════════════════════════════════════════════════════════════

/// Records the current behaviour of the engine when a PE has zero sections.
///
/// BUG-L06: A PE with zero sections is anatomically suspicious but the
/// engine currently does not have a dedicated check for this. This test
/// documents the baseline: the score should be low (< 30, Clean) because
/// no section-based findings fire. If a zero-section check is added later,
/// this test should be updated to assert the new expected score.
#[test]
fn pe_zero_sections_baseline() {
    let imports = vec![ImportInfo {
        dll: "kernel32.dll".to_string(),
        functions: vec!["GetProcAddress".to_string(), "LoadLibraryA".to_string()],
    }];

    // Zero sections, normal timestamp, normal imports.
    let parsed = make_pe(vec![], imports, 0x6000_0000);
    let data = vec![0u8; 256];

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    // Current expected behaviour: no section-based findings fire, so the
    // PE should be classified as Clean (score < 30). This serves as a
    // regression baseline.
    assert!(
        result.score < 30,
        "zero-section PE with normal imports/timestamp should currently score < 30 (Clean), \
         got score={} level={:?} findings={:?}",
        result.score,
        result.threat_level,
        result.findings
    );
    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "zero-section PE should be Clean under current rules, got {:?}",
        result.threat_level
    );
}
