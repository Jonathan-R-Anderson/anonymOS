//! PDF exploit and malware detection.
//!
//! Scans PDF files for indicators of exploit attempts including:
//! - Embedded JavaScript
//! - Launch/URI/SubmitForm actions
//! - Known CVE exploit patterns
//! - Suspicious automatic actions
//! - Encoded/obfuscated content
//!
//! This is a lightweight, heuristic parser that does not fully decode the PDF
//! object graph. It scans raw bytes for known suspicious keywords and structural
//! patterns.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

// ─── Basic PdfInfo (existing API, kept for backward compatibility) ────────────

/// Information about a PDF document relevant to security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PdfInfo {
    /// PDF version string (e.g. "1.7").
    pub version: String,
    /// Whether the PDF contains JavaScript actions.
    pub has_javascript: bool,
    /// Whether the PDF contains embedded files.
    pub has_embedded_files: bool,
    /// Whether the PDF contains /Launch actions (can execute programs).
    pub has_launch_action: bool,
    /// Whether the PDF contains /URI actions.
    pub has_uri_action: bool,
    /// Suspicious keywords found in the document.
    pub suspicious_keywords: Vec<String>,
}

/// Keywords that may indicate malicious intent in a PDF.
static SUSPICIOUS_KEYWORDS: &[&str] = &[
    "/JavaScript",
    "/JS",
    "/EmbeddedFile",
    "/Launch",
    "/URI",
    "/OpenAction",
    "/AA",
    "/AcroForm",
    "/XFA",
    "/RichMedia",
    "/ObjStm",
    "/Encrypt",
    "/JBIG2Decode",
    "/Colors > 2",
];

/// Parse a PDF file from raw bytes, scanning for security-relevant indicators.
///
/// This is a lightweight, heuristic parser that does not fully decode the PDF
/// object graph. It scans the raw bytes for known suspicious keywords and
/// structural patterns.
pub fn parse_pdf(data: &[u8]) -> Result<PdfInfo> {
    let header = find_pdf_header(data)?;
    let version = extract_version(&header);

    let text = String::from_utf8_lossy(data);
    let text_lower = text.to_lowercase();

    let has_javascript = text_lower.contains("/javascript") || text_lower.contains("/js ");
    let has_embedded_files = text_lower.contains("/embeddedfile");
    let has_launch_action = text_lower.contains("/launch");
    let has_uri_action = text_lower.contains("/uri");

    let suspicious_keywords: Vec<String> = SUSPICIOUS_KEYWORDS
        .iter()
        .filter(|kw| text_lower.contains(&kw.to_lowercase()))
        .map(std::string::ToString::to_string)
        .collect();

    debug!(
        %version,
        has_javascript,
        has_embedded_files,
        has_launch_action,
        has_uri_action,
        suspicious_count = suspicious_keywords.len(),
        "parsed PDF metadata"
    );

    Ok(PdfInfo {
        version,
        has_javascript,
        has_embedded_files,
        has_launch_action,
        has_uri_action,
        suspicious_keywords,
    })
}

// ─── Extended PDF exploit analysis ───────────────────────────────────────────

/// Severity of a suspicious pattern found in a PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single suspicious pattern detected in a PDF file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfSuspiciousPattern {
    pub pattern_name: String,
    pub description: String,
    pub severity: PatternSeverity,
    pub offset: Option<usize>,
}

/// Extended PDF analysis result with exploit detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PdfAnalysis {
    pub version: Option<String>,
    pub page_count: u32,
    pub has_javascript: bool,
    pub javascript_count: u32,
    pub has_launch_action: bool,
    pub has_open_action: bool,
    pub has_auto_action: bool,
    pub has_embedded_file: bool,
    pub has_encrypted_content: bool,
    pub suspicious_patterns: Vec<PdfSuspiciousPattern>,
    /// Composite threat score in the range 0..=100.
    pub threat_score: u32,
}

/// Perform extended exploit-oriented analysis of PDF data.
///
/// Checks for embedded JavaScript, launch actions, known CVE patterns,
/// obfuscation indicators, and other structural anomalies.
pub fn analyze_pdf(data: &[u8]) -> Result<PdfAnalysis> {
    let header = find_pdf_header(data)?;
    let version = Some(extract_version(&header));

    let text = String::from_utf8_lossy(data);
    let text_lower = text.to_lowercase();
    let mut patterns: Vec<PdfSuspiciousPattern> = Vec::new();
    let mut score: u32 = 0;

    // ── Page count ───────────────────────────────────────────────────
    let page_count = count_pages(&text);

    // ── JavaScript detection ────────────────────────────────────────
    let javascript_count = count_javascript(&text_lower);
    let has_javascript = javascript_count > 0;
    if has_javascript {
        score += 30;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "JavaScript".to_string(),
            description: format!("PDF contains {javascript_count} JavaScript reference(s)"),
            severity: PatternSeverity::High,
            offset: find_bytes(data, b"/JavaScript"),
        });
    }

    // ── Launch / SubmitForm / ImportData actions ─────────────────────
    let has_launch_action =
        text_lower.contains("/launch") || text_lower.contains("/submitform") || text_lower.contains("/importdata");
    if has_launch_action {
        score += 40;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "LaunchAction".to_string(),
            description: "PDF contains Launch/SubmitForm/ImportData action".to_string(),
            severity: PatternSeverity::Critical,
            offset: find_bytes(data, b"/Launch")
                .or_else(|| find_bytes(data, b"/SubmitForm"))
                .or_else(|| find_bytes(data, b"/ImportData")),
        });
    }

    // ── OpenAction ──────────────────────────────────────────────────
    let has_open_action = text_lower.contains("/openaction");
    if has_open_action {
        let severity = if has_javascript {
            // OpenAction combined with JS is very dangerous
            score += 50;
            PatternSeverity::Critical
        } else {
            score += 10;
            PatternSeverity::Medium
        };
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "OpenAction".to_string(),
            description: "PDF contains automatic open action".to_string(),
            severity,
            offset: find_bytes(data, b"/OpenAction"),
        });
    }

    // ── Automatic actions (/AA) ─────────────────────────────────────
    let has_auto_action = text_lower.contains("/aa");
    if has_auto_action {
        score += 15;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "AutoAction".to_string(),
            description: "PDF contains additional automatic actions (/AA)".to_string(),
            severity: PatternSeverity::Medium,
            offset: find_bytes(data, b"/AA"),
        });
    }

    // ── Embedded files ──────────────────────────────────────────────
    let has_embedded_file = text_lower.contains("/embeddedfile") || text_lower.contains("/filespec");
    if has_embedded_file {
        score += 10;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "EmbeddedFile".to_string(),
            description: "PDF contains embedded file(s)".to_string(),
            severity: PatternSeverity::Medium,
            offset: find_bytes(data, b"/EmbeddedFile").or_else(|| find_bytes(data, b"/Filespec")),
        });
    }

    // ── Encryption ──────────────────────────────────────────────────
    let has_encrypted_content = text_lower.contains("/encrypt");
    if has_encrypted_content {
        score += 5;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "Encrypted".to_string(),
            description: "PDF contains encrypted content".to_string(),
            severity: PatternSeverity::Low,
            offset: find_bytes(data, b"/Encrypt"),
        });
    }

    // ── Known CVE patterns ──────────────────────────────────────────
    check_cve_patterns(data, &text_lower, &mut patterns, &mut score);

    // ── Obfuscation indicators ──────────────────────────────────────
    check_obfuscation(&text_lower, &mut patterns, &mut score);

    // ── Very long streams (heap spray) ──────────────────────────────
    check_heap_spray(&text_lower, &mut patterns, &mut score);

    let score = score.min(100);

    debug!(
        version = version.as_deref().unwrap_or("unknown"),
        page_count,
        has_javascript,
        javascript_count,
        has_launch_action,
        has_open_action,
        pattern_count = patterns.len(),
        threat_score = score,
        "PDF exploit analysis complete"
    );

    Ok(PdfAnalysis {
        version,
        page_count,
        has_javascript,
        javascript_count,
        has_launch_action,
        has_open_action,
        has_auto_action,
        has_embedded_file,
        has_encrypted_content,
        suspicious_patterns: patterns,
        threat_score: score,
    })
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Count approximate number of pages by counting `/Type /Page` (excluding
/// `/Type /Pages` which is the page tree node).
fn count_pages(text: &str) -> u32 {
    let mut count: u32 = 0;
    let mut search_from = 0;
    while let Some(remaining) = text.get(search_from..) {
        let Some(pos) = remaining.find("/Type /Page") else {
            break;
        };
        let abs = search_from + pos;
        // Make sure this is "/Type /Page" and not "/Type /Pages"
        let after = abs + "/Type /Page".len();
        if after >= text.len() || text.as_bytes().get(after).is_none_or(|&b| b != b's') {
            count += 1;
        }
        search_from = abs + 1;
    }
    count
}

/// Count JavaScript references in the PDF text (expects lowercased input).
fn count_javascript(text: &str) -> u32 {
    let mut count: u32 = 0;
    for needle in &["/javascript", "/js "] {
        let mut from = 0;
        while let Some(remaining) = text.get(from..) {
            let Some(pos) = remaining.find(needle) else {
                break;
            };
            count += 1;
            from += pos + needle.len();
        }
    }
    count
}

/// Find the byte offset of `needle` in `data`.
fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

/// Check for known CVE exploit patterns.
///
/// `text_lower` must be the lowercased text representation of the PDF data.
/// Raw `data` is used only for byte-offset lookups on the original bytes.
fn check_cve_patterns(data: &[u8], text_lower: &str, patterns: &mut Vec<PdfSuspiciousPattern>, score: &mut u32) {
    // CVE-2010-0188: TIFF overflow via very long /DecodeParms
    // Triggered by crafted TIFF images with oversized DecodeParms dictionaries
    if let Some(offset) = find_bytes(data, b"/DecodeParms") {
        // Check if there is an unusually large dictionary following it
        let region_end = (offset + 4096).min(data.len());
        let region = data.get(offset..region_end).unwrap_or(&[]);
        // JBIG2Decode combined with long DecodeParms is a strong CVE-2010-0188 indicator
        if text_lower.contains("/jbig2decode") && region.windows(b"/JBIG2Globals".len()).any(|w| w == b"/JBIG2Globals")
        {
            *score += 60;
            patterns.push(PdfSuspiciousPattern {
                pattern_name: "CVE-2010-0188".to_string(),
                description: "JBIG2Decode with globals — potential TIFF overflow exploit".to_string(),
                severity: PatternSeverity::Critical,
                offset: Some(offset),
            });
        }
    }

    // CVE-2013-0640: Adobe Reader sandbox escape
    // Indicator: JavaScript + XFA forms combination
    if text_lower.contains("/xfa") && (text_lower.contains("/javascript") || text_lower.contains("/js ")) {
        *score += 60;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "CVE-2013-0640".to_string(),
            description: "XFA forms with JavaScript — potential sandbox escape".to_string(),
            severity: PatternSeverity::Critical,
            offset: find_bytes(data, b"/XFA"),
        });
    }

    // CVE-2017-11882: Equation Editor OLE exploit
    // Indicator: OLE object embedding patterns in PDF
    let ole_indicators: &[&[u8]] = &[
        b"Equation.3",
        b"Equation.DSMT",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", // OLE compound document signature
    ];
    for indicator in ole_indicators {
        if let Some(offset) = find_bytes(data, indicator) {
            *score += 60;
            patterns.push(PdfSuspiciousPattern {
                pattern_name: "CVE-2017-11882".to_string(),
                description: "OLE Equation Editor object — potential exploit".to_string(),
                severity: PatternSeverity::Critical,
                offset: Some(offset),
            });
            break;
        }
    }
}

/// Check for obfuscation indicators (expects lowercased `text_lower`).
fn check_obfuscation(text_lower: &str, patterns: &mut Vec<PdfSuspiciousPattern>, score: &mut u32) {
    // Hex-encoded object names (e.g. #4A#61#76#61#53#63#72#69#70#74 = JavaScript)
    let hex_sequences = count_hex_encoded_names(text_lower);
    if hex_sequences > 2 {
        *score += 10;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "HexObfuscation".to_string(),
            description: format!("{hex_sequences} hex-encoded name(s) detected"),
            severity: PatternSeverity::Medium,
            offset: None,
        });
    }

    // ASCII85Decode + FlateDecode chain (common obfuscation technique)
    if text_lower.contains("/ascii85decode") && text_lower.contains("/flatedecode") {
        *score += 10;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "EncodingChain".to_string(),
            description: "ASCII85Decode + FlateDecode filter chain (obfuscation indicator)".to_string(),
            severity: PatternSeverity::Medium,
            offset: None,
        });
    }

    // Multiple levels of /ObjStm (object streams hide content)
    if text_lower.contains("/objstm") {
        let obj_stm_count = text_lower.matches("/objstm").count();
        if obj_stm_count > 3 {
            *score += 10;
            patterns.push(PdfSuspiciousPattern {
                pattern_name: "ObjectStreamObfuscation".to_string(),
                description: format!("{obj_stm_count} object streams — content hiding indicator"),
                severity: PatternSeverity::Medium,
                offset: None,
            });
        }
    }
}

/// Count hex-encoded PDF names (sequences like `#XX` in name tokens).
// Loop indices are always bounds-checked by the `while` conditions.
#[allow(clippy::indexing_slicing)]
fn count_hex_encoded_names(text: &str) -> u32 {
    let bytes = text.as_bytes();
    let mut count: u32 = 0;
    let mut i = 0;

    // `i + 3 < bytes.len()` guarantees `bytes[i]` is safe.
    while i + 3 < bytes.len() {
        // Look for / followed by sequences containing #XX
        if bytes[i] == b'/' {
            let mut hex_in_name = 0u32;
            let mut j = i + 1;
            // `j + 2 < bytes.len()` guarantees `bytes[j]` is safe.
            while j + 2 < bytes.len() && !bytes[j].is_ascii_whitespace() && bytes[j] != b'/' {
                if bytes[j] == b'#'
                    && bytes.get(j + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(j + 2).is_some_and(u8::is_ascii_hexdigit)
                {
                    hex_in_name += 1;
                    j += 3;
                } else {
                    j += 1;
                }
            }
            if hex_in_name >= 3 {
                count += 1;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    count
}

/// Check for heap spray indicators (very large /Length values or repeated
/// patterns like `%u0c0c`).
fn check_heap_spray(text: &str, patterns: &mut Vec<PdfSuspiciousPattern>, score: &mut u32) {
    // Check for very large stream lengths (> 1 MB is suspicious for PDFs
    // that are not primarily image containers)
    let mut from = 0;
    while let Some(remaining) = text.get(from..) {
        let Some(pos) = remaining.find("/length ") else {
            break;
        };
        let abs = from + pos + "/length ".len();
        // Parse the numeric value
        let num_str: String = text
            .get(abs..)
            .unwrap_or("")
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(length) = num_str.parse::<u64>() {
            // 10 MB+ stream is a heap spray indicator
            if length > 10_000_000 {
                *score += 20;
                patterns.push(PdfSuspiciousPattern {
                    pattern_name: "HeapSpray".to_string(),
                    description: format!("Very large stream length ({length} bytes)"),
                    severity: PatternSeverity::High,
                    offset: None,
                });
                break; // One finding is enough
            }
        }
        from = abs;
    }

    // Heap spray shellcode pattern: %u0c0c or 0x0c0c0c0c repeated
    if text.contains("%u0c0c") || text.contains("0c0c0c0c") {
        *score += 20;
        patterns.push(PdfSuspiciousPattern {
            pattern_name: "HeapSprayShellcode".to_string(),
            description: "Heap spray NOP sled pattern detected (%u0c0c / 0c0c0c0c)".to_string(),
            severity: PatternSeverity::Critical,
            offset: None,
        });
    }
}

/// Locate the `%PDF-x.y` header, which may not be at offset 0 (some PDFs have
/// a small preamble).
fn find_pdf_header(data: &[u8]) -> Result<String> {
    let search_range = data.get(..data.len().min(1024)).unwrap_or(data);
    let needle = b"%PDF-";

    for i in 0..search_range.len().saturating_sub(needle.len()) {
        if search_range.get(i..i + needle.len()) == Some(needle.as_slice()) {
            let start = i;
            let end = search_range
                .get(start..)
                .and_then(|s| s.iter().position(|&b| b == b'\n' || b == b'\r'))
                .map_or_else(|| (start + 16).min(data.len()), |pos| start + pos);
            let header_bytes = data.get(start..end).unwrap_or(&[]);
            return Ok(String::from_utf8_lossy(header_bytes).to_string());
        }
    }

    bail!("no %PDF header found; data does not appear to be a PDF")
}

/// Extract the version number from a `%PDF-x.y` header string.
fn extract_version(header: &str) -> String {
    header.strip_prefix("%PDF-").unwrap_or("unknown").trim().to_string()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Helper: build a minimal PDF with injected content.
    fn make_pdf(extra_content: &str) -> Vec<u8> {
        format!(
            "%PDF-1.7\n\
             1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
             {extra_content}\n\
             %%EOF\n"
        )
        .into_bytes()
    }

    #[test]
    fn clean_pdf_zero_score() {
        let data = make_pdf("");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert_eq!(analysis.threat_score, 0);
        assert!(!analysis.has_javascript);
        assert!(!analysis.has_launch_action);
        assert!(!analysis.has_open_action);
        assert!(!analysis.has_embedded_file);
        assert!(analysis.suspicious_patterns.is_empty());
        assert_eq!(analysis.page_count, 1);
        assert_eq!(analysis.version.as_deref(), Some("1.7"));
    }

    #[test]
    fn detect_javascript() {
        let data = make_pdf("4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('hi')) >>\nendobj");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(analysis.has_javascript);
        assert!(analysis.javascript_count >= 1);
        assert!(analysis.threat_score >= 30);
        assert!(
            analysis
                .suspicious_patterns
                .iter()
                .any(|p| p.pattern_name == "JavaScript")
        );
    }

    #[test]
    fn detect_launch_action() {
        let data = make_pdf("4 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(analysis.has_launch_action);
        assert!(analysis.threat_score >= 40);
        assert!(
            analysis
                .suspicious_patterns
                .iter()
                .any(|p| p.pattern_name == "LaunchAction")
        );
    }

    #[test]
    fn detect_open_action_with_js() {
        let data = make_pdf(
            "4 0 obj\n<< /Type /Catalog /OpenAction 5 0 R >>\nendobj\n\
             5 0 obj\n<< /S /JavaScript /JS (malicious()) >>\nendobj",
        );
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(analysis.has_open_action);
        assert!(analysis.has_javascript);
        // JavaScript (30) + OpenAction-with-JS (50) = 80
        assert!(analysis.threat_score >= 80);
    }

    #[test]
    fn detect_cve_2017_11882() {
        let mut data = make_pdf("4 0 obj\n<< /Type /OLE >>\nendobj\n");
        data.extend_from_slice(b"Equation.3");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(
            analysis
                .suspicious_patterns
                .iter()
                .any(|p| p.pattern_name == "CVE-2017-11882")
        );
        assert!(analysis.threat_score >= 60);
    }

    #[test]
    fn detect_obfuscation_hex_names() {
        // #4A#61#76#61 = Java (4 hex-encoded chars => qualifies)
        let data = make_pdf("4 0 obj\n<< /#4A#61#76#61Script (x) /#4A#61#76#61 (y) /#4A#61#76#61 (z) >>\nendobj");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(
            analysis
                .suspicious_patterns
                .iter()
                .any(|p| p.pattern_name == "HexObfuscation")
        );
    }

    #[test]
    fn detect_heap_spray_pattern() {
        let data = make_pdf("stream\n%u0c0c%u0c0c%u0c0c\nendstream");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(
            analysis
                .suspicious_patterns
                .iter()
                .any(|p| p.pattern_name == "HeapSprayShellcode")
        );
    }

    #[test]
    fn parse_pdf_backward_compat() {
        let data = make_pdf("");
        let info = parse_pdf(&data).expect("parse should succeed");
        assert_eq!(info.version, "1.7");
        assert!(!info.has_javascript);
    }

    #[test]
    fn invalid_data_returns_error() {
        let data = b"not a pdf";
        assert!(analyze_pdf(data).is_err());
    }

    #[test]
    fn detect_case_insensitive_javascript() {
        let data = make_pdf("4 0 obj\n<< /Type /Action /S /javascript /js (app.alert('hi')) >>\nendobj");
        let analysis = analyze_pdf(&data).expect("analysis should succeed");
        assert!(analysis.has_javascript);
        assert!(analysis.threat_score >= 30);
    }
}
