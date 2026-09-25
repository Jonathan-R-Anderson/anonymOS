//! Unit tests for heuristic analysis of non-PE file formats.
//!
//! Covers the ELF, Mach-O, PDF, and unknown-data branches of
//! `HeuristicEngine::analyze` that are not exercised by the existing PE tests.
//!
//! Run with:
//!   cargo test -p prx-sd-core -- heuristic_elf_macho

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
use prx_sd_heuristic::{Finding, HeuristicEngine, ThreatLevel};
use prx_sd_parsers::{FileType, ParsedFile, elf::ElfInfo, macho::MachOInfo, pe::SectionInfo};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn engine() -> HeuristicEngine {
    HeuristicEngine::new()
}

/// Build a minimal `ParsedFile::ELF` directly (no binary parsing needed).
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
        entry_point: 0x0040_1000,
        sections,
        symbols,
        dynamic_libs,
        interpreter,
    })
}

/// Build a minimal `ParsedFile::MachO` directly (no binary parsing needed).
fn make_macho(sections: Vec<SectionInfo>, imports: Vec<String>) -> ParsedFile {
    ParsedFile::MachO(MachOInfo {
        is_64bit: true,
        cpu_type: "x86_64".to_string(),
        file_type: "execute".to_string(),
        sections,
        imports,
    })
}

/// 64 bytes of zeroed data — minimal, low-entropy, no suspicious content.
fn zero_data(n: usize) -> Vec<u8> {
    vec![0u8; n]
}

// ── Test 1: minimal ELF EXEC scores Clean ────────────────────────────────────

/// A minimal ELF binary with no sections and no suspicious content should
/// score 0 (Clean).  This exercises the ELF code path without triggering
/// any heuristic rules.
#[test]
fn analyze_minimal_elf_scores_low() {
    let parsed = make_elf(
        "EXEC",
        vec![],                        // no sections
        vec!["main".to_string()],      // has a symbol → NoImports not triggered
        vec!["libc.so.6".to_string()], // has dynamic lib
        Some("/lib64/ld-linux-x86-64.so.2".to_string()),
    );

    let result = engine().analyze(&zero_data(256), &parsed);

    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "minimal ELF should be Clean, got score {} with findings: {:?}",
        result.score,
        result.findings
    );
    assert!(
        result.score < 30,
        "score should be < 30 for clean ELF, got {}",
        result.score
    );
}

// ── Test 2: ELF with high-entropy section produces PackedSection finding ──────

/// An ELF with a section whose entropy exceeds 7.0 and raw_size > 512
/// should produce a `Finding::PackedSection` entry.
///
/// We use `elf_type = "DYN"` with dynamic_libs present but no symbols.
/// This triggers `Finding::NoImports` (symbols empty + dynamic_libs non-empty),
/// which is a packer indicator.  Because `has_packer == true` the DYN
/// suppression path is skipped, so `PackedSection` survives in the findings.
#[test]
fn analyze_elf_high_entropy_section() {
    let high_entropy_section = SectionInfo {
        name: ".packed".to_string(),
        virtual_size: 2048,
        raw_size: 2048,               // > 512, so the per-section entropy check fires
        entropy: 7.8,                 // > 7.0 threshold
        characteristics: 0x0000_0006, // SHF_ALLOC | SHF_EXECINSTR
    };

    // DYN + no symbols + at least one dynamic_lib → NoImports fires.
    // NoImports is listed as a packer indicator, so DYN suppression is skipped
    // and PackedSection survives.
    let parsed = make_elf(
        "DYN",
        vec![high_entropy_section],
        vec![],                             // no symbols → NoImports will fire
        vec!["libcrypto.so.1".to_string()], // has a dynamic lib
        None,
    );

    let result = engine().analyze(&zero_data(512), &parsed);

    let has_packed_section = result
        .findings
        .iter()
        .any(|f| matches!(f, Finding::PackedSection { .. }));

    assert!(
        has_packed_section,
        "ELF with high-entropy section should produce PackedSection finding, \
         got findings: {:?}",
        result.findings
    );
}

// ── Test 3: minimal MachO does not panic ─────────────────────────────────────

/// A minimal Mach-O binary constructed in-memory should parse cleanly and
/// return a valid (non-panicking) `HeuristicResult`.  We do not assert a
/// specific threat level — just that the call completes without panic.
#[test]
fn analyze_minimal_macho() {
    // Build the smallest valid 64-bit Mach-O binary (32-byte header, no load commands).
    let mut data = vec![0u8; 4096];
    // magic: MH_MAGIC_64 = 0xFEEDFACF (little-endian)
    data[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    // cputype: CPU_TYPE_X86_64 = 0x01000007
    data[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    // cpusubtype: 3
    data[8..12].copy_from_slice(&3u32.to_le_bytes());
    // filetype: MH_EXECUTE = 2
    data[12..16].copy_from_slice(&2u32.to_le_bytes());
    // ncmds: 0, sizeofcmds: 0, flags: 0, reserved: 0

    let file_type = prx_sd_parsers::detect_file_type(&data);
    assert_eq!(file_type, FileType::MachO);

    let parsed = prx_sd_parsers::parse(&data, file_type).expect("should parse minimal Mach-O");
    assert!(parsed.as_macho().is_some());

    // Must not panic, and a minimal clean MachO should score low.
    let result = engine().analyze(&data, &parsed);
    assert!(
        result.score < 30,
        "minimal clean MachO should score < 30, got {} with findings: {:?}",
        result.score,
        result.findings
    );
    assert_eq!(
        result.threat_level,
        ThreatLevel::Clean,
        "minimal MachO should be Clean, got score {} with findings: {:?}",
        result.score,
        result.findings
    );
}

// ── Test 4: PDF with /JavaScript produces PdfJavaScript finding ──────────────

/// A minimal PDF that contains the `/JavaScript` keyword should trigger the
/// `Finding::PdfJavaScript` heuristic.
#[test]
fn analyze_pdf_with_js() {
    // Minimal PDF with an embedded JavaScript action.
    let pdf_data = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('pwn');) >>\nendobj\n\
xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000068 00000 n \n\
trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n149\n%%EOF\n";

    let file_type = prx_sd_parsers::detect_file_type(pdf_data);
    assert_eq!(file_type, FileType::PDF);

    let parsed = prx_sd_parsers::parse(pdf_data, file_type).expect("should parse PDF");
    assert!(parsed.as_pdf().is_some());

    let result = engine().analyze(pdf_data, &parsed);

    let has_js_finding = result.findings.iter().any(|f| matches!(f, Finding::PdfJavaScript));

    assert!(
        has_js_finding,
        "PDF with /JavaScript should produce PdfJavaScript finding, \
         got findings: {:?}",
        result.findings
    );
}

// ── Test 5: non-binary data (Unknown) scores 0 ───────────────────────────────

/// Plain text / unknown data that does not parse as any known format should
/// score exactly 0 with no findings.
#[test]
fn analyze_clean_data() {
    let text = b"Hello, world! This is perfectly normal plain text content.";

    let parsed = ParsedFile::Unparsed {
        file_type: FileType::Unknown,
        size: text.len(),
    };

    let result = engine().analyze(text, &parsed);

    assert_eq!(
        result.score, 0,
        "plain text / Unknown file should score 0, got {} with findings: {:?}",
        result.score, result.findings
    );
    assert!(
        result.findings.is_empty(),
        "plain text should have no findings, got: {:?}",
        result.findings
    );
    assert_eq!(result.threat_level, ThreatLevel::Clean, "plain text should be Clean");
}

// ── Bonus: MachO with suspicious import produces finding ─────────────────────

/// A Mach-O with a known-suspicious import (`osascript`) should produce at
/// least one `SuspiciousApi` finding.
#[test]
fn analyze_macho_with_suspicious_import() {
    let parsed = make_macho(vec![], vec!["osascript".to_string(), "_NSTask".to_string()]);

    let result = engine().analyze(&zero_data(256), &parsed);

    let has_suspicious = result.findings.iter().any(|f| matches!(f, Finding::SuspiciousApi(_)));

    assert!(
        has_suspicious,
        "Mach-O with osascript import should produce SuspiciousApi finding, \
         got findings: {:?}",
        result.findings
    );
}

// ── Bonus: ELF DYN with no symbols and no dynamic libs → NoImports ───────────

/// A DYN ELF with dynamic libraries but no symbols is suspicious:
/// the engine adds `Finding::NoImports`.  Because `NoImports` is a packer
/// indicator the DYN suppression path is skipped and the finding survives.
#[test]
fn analyze_elf_dyn_no_symbols_has_no_imports_finding() {
    let parsed = make_elf(
        "DYN",
        vec![],
        vec![],                          // no symbols
        vec!["libfoo.so.1".to_string()], // has dynamic lib but no resolved symbols
        None,
    );

    let result = engine().analyze(&zero_data(128), &parsed);

    let has_no_imports = result.findings.iter().any(|f| matches!(f, Finding::NoImports));

    assert!(
        has_no_imports,
        "ELF DYN with dynamic libs but no symbols should produce NoImports, \
         got findings: {:?}",
        result.findings
    );
}
