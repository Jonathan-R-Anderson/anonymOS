//! Extended cross-crate document exploit tests.
//!
//! Scenarios 31-34: PDF CVE pattern detection, PDF case-insensitive keywords,
//! Office macro detection without "VBA" string, Office obfuscation detection.

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
use prx_sd_heuristic::{Finding, HeuristicEngine};
use prx_sd_parsers::ParsedFile;

// ── Helpers ────────────────────────────────────────────────────────────────

fn engine() -> HeuristicEngine {
    HeuristicEngine::new()
}

/// Build a minimal PDF with injected content between the page object and %%EOF.
fn make_pdf(extra: &str) -> Vec<u8> {
    format!(
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
         2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
         3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n{extra}\n%%EOF\n"
    )
    .into_bytes()
}

/// Build a minimal OLE2-like buffer with the compound binary magic, a
/// WordDocument stream marker, and caller-supplied extra bytes.
fn make_ole2(extra_bytes: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    // OLE2 magic
    data.extend_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    data.extend_from_slice(&[0u8; 100]);
    data.extend_from_slice(b"WordDocument");
    data.extend_from_slice(&[0u8; 50]);
    data.extend_from_slice(extra_bytes);
    data
}

/// Parse raw PDF bytes into a `ParsedFile::PDF` variant.
fn parse_pdf_file(data: &[u8]) -> ParsedFile {
    let pdf_info = prx_sd_parsers::pdf::parse_pdf(data).expect("test PDF data must parse successfully");
    ParsedFile::PDF(pdf_info)
}

/// Parse raw OLE2 bytes into a `ParsedFile::Office` variant.
fn parse_office_file(data: &[u8]) -> ParsedFile {
    let office_info = prx_sd_parsers::office::parse_office(data).expect("test OLE2 data must parse successfully");
    ParsedFile::Office(office_info)
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 31: pdf_cve_pattern_detection
//
// Coverage gap 3: PdfCvePattern (CVE-2010-0188) detection.
//
// CVE-2010-0188 is triggered when /DecodeParms is followed within 4096
// bytes by /JBIG2Globals, and the document also contains /JBIG2Decode.
// The heuristic engine's `analyze_pdf_exploits` delegates to
// `prx_sd_parsers::pdf::analyze_pdf` which runs `check_cve_patterns`.
//
// The scoring weight for PdfCvePattern is 50 (scoring.rs) plus the
// PdfThreatScore carries the pdf-level score of 60 → well above Malicious.
// ═══════════════════════════════════════════════════════════════════════════

/// PDF with /DecodeParms + /JBIG2Decode + /JBIG2Globals → CVE-2010-0188.
#[test]
fn pdf_cve_pattern_detection() {
    // /JBIG2Globals must appear within 4096 bytes of /DecodeParms.
    // We place them close together in the extra content.
    let extra = "\
        4 0 obj\n<< /Type /XObject /Subtype /Image \
        /Filter /JBIG2Decode \
        /DecodeParms << /JBIG2Globals 5 0 R >> >>\nendobj\n\
        5 0 obj\n<< /Type /JBIG2Globals >>\nendobj";

    let data = make_pdf(extra);
    let parsed = parse_pdf_file(&data);

    assert!(parsed.as_pdf().is_some(), "parsed result must be a PDF variant");

    let result = engine().analyze(&data, &parsed);

    // Must contain a PdfCvePattern finding referencing CVE-2010-0188.
    let has_cve = result.findings.iter().any(|f| match f {
        Finding::PdfCvePattern(cve) => cve.contains("CVE-2010-0188"),
        _ => false,
    });
    assert!(
        has_cve,
        "PdfCvePattern(CVE-2010-0188) must be detected; findings: {:?}",
        result.findings
    );

    // Score must reach Malicious threshold (>= 60).
    assert!(
        result.score >= 60,
        "PDF CVE-2010-0188 score must be >= 60, got {}",
        result.score
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 32: pdf_case_insensitive_keywords
//
// BUG-M06 regression: mixed-case /javascript and /openaction must be
// detected. The PDF parser lowercases the text before keyword matching,
// so "/javascript" (all lowercase) and "/openaction" should trigger
// PdfJavaScript and PdfAutoExecJavaScript respectively.
// ═══════════════════════════════════════════════════════════════════════════

/// Mixed-case /javascript + /openaction must trigger JS + auto-exec findings.
#[test]
fn pdf_case_insensitive_keywords() {
    // Use lowercase variants of the keywords — the parser's
    // `to_lowercase()` normalisation should still match.
    let extra = "\
        4 0 obj\n<< /Type /Catalog /openaction 5 0 R >>\nendobj\n\
        5 0 obj\n<< /S /javascript /JS (app.alert('test')) >>\nendobj";

    let data = make_pdf(extra);
    let parsed = parse_pdf_file(&data);

    let result = engine().analyze(&data, &parsed);

    // PdfJavaScript must be detected from "/javascript".
    assert!(
        result.findings.iter().any(|f| matches!(f, Finding::PdfJavaScript)),
        "PdfJavaScript must be detected with lowercase /javascript; findings: {:?}",
        result.findings
    );

    // PdfAutoExecJavaScript must be detected from "/openaction" + JavaScript.
    assert!(
        result
            .findings
            .iter()
            .any(|f| matches!(f, Finding::PdfAutoExecJavaScript)),
        "PdfAutoExecJavaScript must be detected with lowercase /openaction; findings: {:?}",
        result.findings
    );

    // Combined score >= 60 (PdfJavaScript(20) + PdfAutoExecJavaScript(40) + PdfThreatScore).
    assert!(
        result.score >= 60,
        "PDF case-insensitive keywords score must be >= 60, got {}",
        result.score
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 33: office_macro_without_vba_string
//
// BUG-M09 regression: an OLE2 document containing "_VBA_PROJECT" but not
// the standalone string "VBA" should still be detected as having macros.
//
// The `parse_ole2` function checks for `_VBA_PROJECT` as the first
// condition, so this should work without a standalone "VBA" marker.
// The `analyze_ole2_macros` function has the same logic.
// ═══════════════════════════════════════════════════════════════════════════

/// OLE2 with _VBA_PROJECT + AutoOpen + Shell but no standalone "VBA" → OfficeMacros.
#[test]
fn office_macro_without_vba_string() {
    let mut extra = Vec::new();
    // _VBA_PROJECT marker (the parser checks for this first, before the
    // "VBA" + "PROJECT" fallback).
    extra.extend_from_slice(b"_VBA_PROJECT");
    extra.extend_from_slice(&[0u8; 50]);
    // Auto-exec trigger + shell execution (to boost the score).
    extra.extend_from_slice(b"AutoOpen");
    extra.extend_from_slice(&[0u8; 20]);
    extra.extend_from_slice(b"Shell(");
    extra.extend_from_slice(&[0u8; 100]);

    let data = make_ole2(&extra);
    let parsed = parse_office_file(&data);

    assert!(parsed.as_office().is_some(), "parsed result must be an Office variant");

    let result = engine().analyze(&data, &parsed);

    // OfficeMacros must be detected.
    assert!(
        result.findings.iter().any(|f| matches!(f, Finding::OfficeMacros)),
        "OfficeMacros must be detected without standalone 'VBA' string; findings: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 34: office_obfuscation_detection
//
// Coverage gap 4: OfficeObfuscation finding verification.
//
// The heuristic engine emits `Finding::OfficeObfuscation(score)` when
// `analysis.obfuscation_score > 15`. The obfuscation score is driven by
// `compute_obfuscation_score`, which awards 40 points for >20 Chr() calls.
//
// We construct OLE2 data containing >20 Chr() calls plus VBA/_VBA_PROJECT
// and AutoOpen to ensure macros are detected (obfuscation is only scored
// when has_macros is true in the threat score computation).
// ═══════════════════════════════════════════════════════════════════════════

/// OLE2 with >20 Chr() calls + VBA macros → OfficeObfuscation(score > 15).
#[test]
fn office_obfuscation_detection() {
    let mut extra = Vec::new();
    // VBA macro markers — include both "VBA" and "_VBA_PROJECT" to ensure
    // has_macros is true.
    extra.extend_from_slice(b"VBA");
    extra.extend_from_slice(&[0u8; 20]);
    extra.extend_from_slice(b"_VBA_PROJECT");
    extra.extend_from_slice(&[0u8; 20]);
    // Auto-exec trigger (needed for realistic macro scenario).
    extra.extend_from_slice(b"AutoOpen");
    extra.extend_from_slice(&[0u8; 20]);
    // >20 Chr() calls to trigger obfuscation scoring (>20 → score += 40).
    let mut chr_content = String::new();
    for i in 0..25 {
        if i > 0 {
            chr_content.push_str(" & ");
        }
        chr_content.push_str(&format!("Chr({})", 65 + (i % 26)));
    }
    extra.extend_from_slice(chr_content.as_bytes());
    extra.extend_from_slice(&[0u8; 100]);

    let data = make_ole2(&extra);
    let parsed = parse_office_file(&data);

    let result = engine().analyze(&data, &parsed);

    // OfficeObfuscation must be present with score > 15.
    let obfuscation_finding = result.findings.iter().find_map(|f| match f {
        Finding::OfficeObfuscation(score) => Some(*score),
        _ => None,
    });
    assert!(
        obfuscation_finding.is_some(),
        "OfficeObfuscation finding must be present; findings: {:?}",
        result.findings
    );
    let obf_score = obfuscation_finding.unwrap();
    assert!(
        obf_score > 15,
        "OfficeObfuscation score must be > 15, got {}",
        obf_score
    );
}
