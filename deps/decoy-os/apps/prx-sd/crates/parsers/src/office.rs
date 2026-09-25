use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Office document format classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfficeFormat {
    /// Modern OOXML formats (ZIP-based)
    Docx,
    Xlsx,
    Pptx,
    /// Legacy OLE2 / Compound Binary formats
    Doc,
    Xls,
    Ppt,
}

/// Information about an Office document relevant to security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeInfo {
    pub format: OfficeFormat,
    /// Whether the document contains VBA macros.
    pub has_macros: bool,
    /// Whether the document references external links / relationships.
    pub has_external_links: bool,
    /// Names of embedded OLE objects or other embedded content.
    pub embedded_objects: Vec<String>,
}

// ─── Macro analysis types ────────────────────────────────────────────────────

/// Category of suspicious VBA macro function call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::doc_markdown)]
pub enum MacroThreatCategory {
    /// Shell, WScript.Shell, cmd.exe, powershell
    ShellExecution,
    /// FileSystemObject, CreateTextFile, OpenTextFile
    FileSystem,
    /// XMLHTTP, WinHttp, URLDownloadToFile
    Network,
    /// RegWrite, RegRead, RegDelete
    Registry,
    /// CreateObject("WScript.Shell").Run
    ProcessCreation,
    /// Chr(), ChrW(), Base64, StrReverse
    Encoding,
    /// Environ(), %TEMP%, %APPDATA%
    EnvironmentAccess,
}

/// A single suspicious function call detected in VBA macro content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroSuspiciousCall {
    pub function_name: String,
    pub category: MacroThreatCategory,
    pub severity: u32,
}

/// Result of Office macro analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeAnalysis {
    /// Whether macros were found at all.
    pub has_macros: bool,
    /// Number of detected macro indicators.
    pub macro_count: u32,
    /// Auto-execution trigger names found (e.g. `AutoOpen`, `Document_Open`).
    pub auto_exec_macros: Vec<String>,
    /// Suspicious function calls found in macro content.
    pub suspicious_functions: Vec<MacroSuspiciousCall>,
    /// Whether DDE (Dynamic Data Exchange) was detected.
    pub has_dde: bool,
    /// Whether external links were detected.
    pub has_external_links: bool,
    /// Obfuscation score (0-100).
    pub obfuscation_score: u32,
    /// Aggregate threat score (0-100).
    pub threat_score: u32,
}

/// OLE2 Compound Binary File magic bytes.
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Parse an Office document from raw bytes.
pub fn parse_office(data: &[u8]) -> Result<OfficeInfo> {
    if is_ooxml(data) {
        parse_ooxml(data)
    } else if is_ole2(data) {
        parse_ole2(data)
    } else {
        bail!("data does not appear to be a recognized Office format")
    }
}

/// Check if data starts with ZIP magic (PK\x03\x04), indicating OOXML.
fn is_ooxml(data: &[u8]) -> bool {
    data.len() >= 4 && data.starts_with(b"PK\x03\x04")
}

/// Check if data starts with OLE2 compound binary magic.
fn is_ole2(data: &[u8]) -> bool {
    data.len() >= OLE2_MAGIC.len() && data.starts_with(OLE2_MAGIC)
}

/// Parse a modern OOXML (docx/xlsx/pptx) document by treating it as a ZIP
/// archive and inspecting its internal structure.
fn parse_ooxml(data: &[u8]) -> Result<OfficeInfo> {
    let reader = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).context("failed to open OOXML document as ZIP")?;

    // Determine specific format from content types
    let format = detect_ooxml_format(&mut archive);

    let mut has_macros = false;
    let mut has_external_links = false;
    let mut embedded_objects: Vec<String> = Vec::new();

    // Scan all entries in the ZIP
    for i in 0..archive.len() {
        let Ok(mut file) = archive.by_index(i) else {
            continue;
        };
        let name = file.name().to_string();
        let name_lower = name.to_lowercase();

        // VBA macros indicator
        if name_lower.contains("vbaproject.bin") || name_lower.contains("vbadata.xml") {
            has_macros = true;
        }

        // Embedded OLE objects
        if name_lower.contains("oleobject") || name_lower.contains("embeddings/") {
            embedded_objects.push(name.clone());
        }

        // ActiveX controls
        if name_lower.contains("activex") {
            embedded_objects.push(name.clone());
        }

        // Check .rels files for external targets
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if name_lower.ends_with(".rels") {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                // Look for Target= with TargetMode="External"
                if content.contains("TargetMode=\"External\"") || content.contains("TargetMode='External'") {
                    has_external_links = true;
                }
            }
        }

        // Check XML parts for external references
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if name_lower.ends_with(".xml") && !has_external_links {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok()
                && (content.contains("http://") || content.contains("https://"))
            {
                // Only flag if it looks like an actual link, not a namespace
                if content.contains("r:link") || content.contains("externalLink") || content.contains("hyperlink") {
                    has_external_links = true;
                }
            }
        }
    }

    embedded_objects.sort();
    embedded_objects.dedup();

    debug!(
        ?format,
        has_macros,
        has_external_links,
        embedded_count = embedded_objects.len(),
        "parsed OOXML document"
    );

    Ok(OfficeInfo {
        format,
        has_macros,
        has_external_links,
        embedded_objects,
    })
}

/// Detect the specific OOXML format by inspecting `[Content_Types].xml`.
fn detect_ooxml_format(archive: &mut zip::ZipArchive<Cursor<&[u8]>>) -> OfficeFormat {
    if let Ok(mut ct) = archive.by_name("[Content_Types].xml") {
        let mut content = String::new();
        if ct.read_to_string(&mut content).is_ok() {
            let cl = content.to_lowercase();
            if cl.contains("wordprocessingml") || cl.contains("word/") {
                return OfficeFormat::Docx;
            }
            if cl.contains("spreadsheetml") || cl.contains("xl/") {
                return OfficeFormat::Xlsx;
            }
            if cl.contains("presentationml") || cl.contains("ppt/") {
                return OfficeFormat::Pptx;
            }
        }
    }

    // Fallback: check for known directory prefixes
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_lowercase();
            if name.starts_with("word/") {
                return OfficeFormat::Docx;
            }
            if name.starts_with("xl/") {
                return OfficeFormat::Xlsx;
            }
            if name.starts_with("ppt/") {
                return OfficeFormat::Pptx;
            }
        }
    }

    // Default to Docx if we can't determine
    OfficeFormat::Docx
}

/// Parse a legacy OLE2 Compound Binary document by scanning raw bytes for
/// known structural indicators. This is a heuristic approach since fully
/// parsing the OLE2 FAT/directory structure requires a dedicated crate.
#[allow(clippy::unnecessary_wraps)]
fn parse_ole2(data: &[u8]) -> Result<OfficeInfo> {
    let text = String::from_utf8_lossy(data);

    // Detect format by scanning for known OLE2 stream markers
    let format = detect_ole2_format(data);

    // Check for VBA macro storage: the string "VBA" in directory entries,
    // or the _VBA_PROJECT stream marker.
    let has_macros = contains_bytes(data, b"_VBA_PROJECT")
        || contains_bytes(data, b"VBA_PROJECT")
        || (contains_bytes(data, b"VBA") && (contains_bytes(data, b"PROJECT") || contains_bytes(data, b"Macros")));

    // External links: look for hyperlink-related OLE markers
    let has_external_links = text.contains("http://") || text.contains("https://") || contains_bytes(data, b"HYPER");

    // Embedded objects: look for known OLE object markers
    let mut embedded_objects: Vec<String> = Vec::new();
    if contains_bytes(data, b"\x01Ole") {
        embedded_objects.push("OLE embedded object".to_string());
    }
    if contains_bytes(data, b"Package") {
        embedded_objects.push("OLE Package object".to_string());
    }
    if contains_bytes(data, b"Equation") {
        embedded_objects.push("Equation Editor object".to_string());
    }

    debug!(
        ?format,
        has_macros,
        has_external_links,
        embedded_count = embedded_objects.len(),
        "parsed OLE2 document"
    );

    Ok(OfficeInfo {
        format,
        has_macros,
        has_external_links,
        embedded_objects,
    })
}

/// Detect OLE2 format by scanning for characteristic stream/storage names.
fn detect_ole2_format(data: &[u8]) -> OfficeFormat {
    if contains_bytes(data, b"WordDocument") || contains_bytes(data, b"Word.Document") {
        return OfficeFormat::Doc;
    }
    if contains_bytes(data, b"Workbook") || contains_bytes(data, b"Book") {
        return OfficeFormat::Xls;
    }
    if contains_bytes(data, b"PowerPoint") || contains_bytes(data, b"Current User") {
        return OfficeFormat::Ppt;
    }
    // Default fallback
    OfficeFormat::Doc
}

/// Simple byte-sequence search (like `memmem`).
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

// ─── Macro analysis engine ──────────────────────────────────────────────────

/// Auto-execution trigger patterns in VBA macros (case-insensitive matching).
const AUTO_EXEC_PATTERNS: &[&str] = &[
    "autoopen",
    "auto_open",
    "document_open",
    "workbook_open",
    "autoexec",
    "autoclose",
    "auto_close",
    "document_close",
    "workbook_beforeclose",
    "document_new",
    "autonew",
    "auto_new",
];

/// Suspicious function patterns with their category and severity.
const SUSPICIOUS_FUNCTIONS: &[(&str, MacroThreatCategory, u32)] = &[
    // Shell execution
    ("shell(", MacroThreatCategory::ShellExecution, 9),
    ("wscript.shell", MacroThreatCategory::ShellExecution, 9),
    ("cmd.exe", MacroThreatCategory::ShellExecution, 9),
    ("cmd /c", MacroThreatCategory::ShellExecution, 9),
    ("powershell", MacroThreatCategory::ShellExecution, 10),
    (".run", MacroThreatCategory::ProcessCreation, 8),
    (".exec", MacroThreatCategory::ProcessCreation, 8),
    ("createobject", MacroThreatCategory::ProcessCreation, 7),
    ("callbyname", MacroThreatCategory::ProcessCreation, 7),
    // File system
    ("filesystemobject", MacroThreatCategory::FileSystem, 7),
    ("createtextfile", MacroThreatCategory::FileSystem, 6),
    ("opentextfile", MacroThreatCategory::FileSystem, 6),
    ("kill ", MacroThreatCategory::FileSystem, 6),
    ("filecopy", MacroThreatCategory::FileSystem, 5),
    ("adodb.stream", MacroThreatCategory::FileSystem, 7),
    ("savetofile", MacroThreatCategory::FileSystem, 7),
    // Network
    ("xmlhttp", MacroThreatCategory::Network, 8),
    ("winhttp", MacroThreatCategory::Network, 8),
    ("msxml2.serverxmlhttp", MacroThreatCategory::Network, 8),
    ("urldownloadtofile", MacroThreatCategory::Network, 9),
    ("internetopen", MacroThreatCategory::Network, 8),
    ("urlmon", MacroThreatCategory::Network, 8),
    // Registry
    ("regwrite", MacroThreatCategory::Registry, 7),
    ("regread", MacroThreatCategory::Registry, 5),
    ("regdelete", MacroThreatCategory::Registry, 7),
    // Encoding / obfuscation
    ("chr(", MacroThreatCategory::Encoding, 3),
    ("chrw(", MacroThreatCategory::Encoding, 3),
    ("chrb(", MacroThreatCategory::Encoding, 3),
    ("asc(", MacroThreatCategory::Encoding, 2),
    ("mid$(", MacroThreatCategory::Encoding, 2),
    ("strreverse(", MacroThreatCategory::Encoding, 4),
    ("replace(", MacroThreatCategory::Encoding, 2),
    // Environment access
    ("environ(", MacroThreatCategory::EnvironmentAccess, 5),
    ("%temp%", MacroThreatCategory::EnvironmentAccess, 5),
    ("%appdata%", MacroThreatCategory::EnvironmentAccess, 5),
    ("%userprofile%", MacroThreatCategory::EnvironmentAccess, 4),
];

/// DDE-related patterns.
const DDE_PATTERNS: &[&[u8]] = &[
    b"DDEAUTO", b"\\dde",
    // "DDE" alone in text content (checked case-insensitively via contains_ci)
];

/// Analyse an Office document for malicious VBA macros.
///
/// Works on both OLE2 (`.doc`, `.xls`) and OOXML (`.docx`, `.docm`, `.xlsm`)
/// formats. Extracts VBA-related content via pattern matching and produces a
/// threat score.
pub fn analyze_office(data: &[u8]) -> Result<OfficeAnalysis> {
    if is_ooxml(data) {
        analyze_ooxml_macros(data)
    } else if is_ole2(data) {
        analyze_ole2_macros(data)
    } else {
        // Not a recognised Office file — return clean result.
        Ok(OfficeAnalysis {
            has_macros: false,
            macro_count: 0,
            auto_exec_macros: Vec::new(),
            suspicious_functions: Vec::new(),
            has_dde: false,
            has_external_links: false,
            obfuscation_score: 0,
            threat_score: 0,
        })
    }
}

/// Analyse macros in an OOXML document (ZIP-based).
fn analyze_ooxml_macros(data: &[u8]) -> Result<OfficeAnalysis> {
    let reader = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).context("failed to open OOXML as ZIP for macro analysis")?;

    let mut vba_content = Vec::new();
    let mut has_macros = false;
    let mut has_external_links = false;
    let mut has_macro_sheets = false;

    for i in 0..archive.len() {
        let Ok(mut file) = archive.by_index(i) else {
            continue;
        };
        let name = file.name().to_lowercase();

        // Extract vbaProject.bin content for pattern scanning
        if name.contains("vbaproject.bin") {
            has_macros = true;
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                vba_content.extend_from_slice(&buf);
            }
        }

        // Excel 4.0 macro sheets
        if name.contains("macrosheets/") || name.contains("macrosheet") {
            has_macros = true;
            has_macro_sheets = true;
        }

        // VBA data XML
        if name.contains("vbadata.xml") {
            has_macros = true;
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                vba_content.extend_from_slice(&buf);
            }
        }

        // Check .rels for external targets
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if name.ends_with(".rels") {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok()
                && (content.contains("TargetMode=\"External\"") || content.contains("TargetMode='External'"))
            {
                has_external_links = true;
            }
        }
    }

    let mut analysis = scan_vba_content(&vba_content, has_macros, has_external_links);

    // Excel 4.0 macro sheets are inherently suspicious
    if has_macro_sheets {
        analysis.threat_score = analysis.threat_score.saturating_add(15).min(100);
    }

    debug!(
        has_macros = analysis.has_macros,
        threat_score = analysis.threat_score,
        auto_exec_count = analysis.auto_exec_macros.len(),
        suspicious_count = analysis.suspicious_functions.len(),
        "OOXML macro analysis complete"
    );

    Ok(analysis)
}

/// Analyse macros in an OLE2 (legacy) document by scanning raw bytes.
#[allow(clippy::unnecessary_wraps)]
fn analyze_ole2_macros(data: &[u8]) -> Result<OfficeAnalysis> {
    let has_macros = contains_bytes(data, b"_VBA_PROJECT")
        || contains_bytes(data, b"VBA_PROJECT")
        || (contains_bytes(data, b"VBA") && (contains_bytes(data, b"PROJECT") || contains_bytes(data, b"Macros")));

    let has_external_links = {
        let text = String::from_utf8_lossy(data);
        text.contains("http://") || text.contains("https://") || contains_bytes(data, b"HYPER")
    };

    let analysis = scan_vba_content(data, has_macros, has_external_links);

    debug!(
        has_macros = analysis.has_macros,
        threat_score = analysis.threat_score,
        auto_exec_count = analysis.auto_exec_macros.len(),
        suspicious_count = analysis.suspicious_functions.len(),
        "OLE2 macro analysis complete"
    );

    Ok(analysis)
}

/// Scan byte content for VBA macro patterns and produce an [`OfficeAnalysis`].
fn scan_vba_content(content: &[u8], has_macros: bool, has_external_links: bool) -> OfficeAnalysis {
    let text_lossy = String::from_utf8_lossy(content);
    let text_lower = text_lossy.to_lowercase();

    // ── Auto-execution triggers ──────────────────────────────────────────
    let mut auto_exec_macros = Vec::new();
    for pattern in AUTO_EXEC_PATTERNS {
        if text_lower.contains(pattern) {
            auto_exec_macros.push((*pattern).to_string());
        }
    }

    // ── Suspicious function calls ────────────────────────────────────────
    let mut suspicious_functions = Vec::new();
    for &(pattern, ref category, severity) in SUSPICIOUS_FUNCTIONS {
        if text_lower.contains(pattern) {
            suspicious_functions.push(MacroSuspiciousCall {
                function_name: pattern.to_string(),
                category: category.clone(),
                severity,
            });
        }
    }

    // ── DDE detection ────────────────────────────────────────────────────
    let has_dde = DDE_PATTERNS.iter().any(|p| contains_bytes(content, p))
        || text_lower.contains("ddeauto")
        || (text_lower.contains("dde") && text_lower.contains("field"));

    // ── Obfuscation scoring ──────────────────────────────────────────────
    let obfuscation_score = compute_obfuscation_score(&text_lower);

    // ── Macro count estimate ─────────────────────────────────────────────
    let macro_count = count_macro_indicators(&text_lower);

    // ── Threat score ─────────────────────────────────────────────────────
    let threat_score = compute_threat_score(
        has_macros,
        &auto_exec_macros,
        &suspicious_functions,
        has_dde,
        has_external_links,
        obfuscation_score,
    );

    OfficeAnalysis {
        has_macros,
        macro_count,
        auto_exec_macros,
        suspicious_functions,
        has_dde,
        has_external_links,
        obfuscation_score,
        threat_score,
    }
}

/// Count macro-related indicators to estimate the number of macros.
fn count_macro_indicators(text: &str) -> u32 {
    let indicators = ["sub ", "function ", "private sub ", "public sub "];
    let mut count: u32 = 0;
    for ind in &indicators {
        #[allow(clippy::cast_possible_truncation)]
        let match_count = text.matches(ind).count() as u32;
        count = count.saturating_add(match_count);
    }
    count
}

/// Score obfuscation level (0-100) based on encoding/string-manipulation patterns.
fn compute_obfuscation_score(text: &str) -> u32 {
    let mut score: u32 = 0;

    // Count Chr() calls — long chains indicate obfuscation
    let chr_count = text.matches("chr(").count() + text.matches("chrw(").count() + text.matches("chrb(").count();

    if chr_count > 20 {
        score = score.saturating_add(40);
    } else if chr_count > 10 {
        score = score.saturating_add(25);
    } else if chr_count > 5 {
        score = score.saturating_add(15);
    }

    // String manipulation functions
    if text.contains("strreverse(") {
        score = score.saturating_add(15);
    }
    if text.contains("replace(") && chr_count > 3 {
        score = score.saturating_add(10);
    }

    // Multiple Mid$ calls suggest character-by-character construction
    let mid_count = text.matches("mid$(").count() + text.matches("mid(").count();
    if mid_count > 10 {
        score = score.saturating_add(20);
    } else if mid_count > 5 {
        score = score.saturating_add(10);
    }

    // String concatenation with & (high count)
    let concat_count = text.matches(" & ").count();
    if concat_count > 30 {
        score = score.saturating_add(15);
    } else if concat_count > 15 {
        score = score.saturating_add(8);
    }

    score.min(100)
}

/// Compute aggregate threat score (0-100) from macro analysis findings.
fn compute_threat_score(
    has_macros: bool,
    auto_exec_macros: &[String],
    suspicious_functions: &[MacroSuspiciousCall],
    has_dde: bool,
    has_external_links: bool,
    obfuscation_score: u32,
) -> u32 {
    if !has_macros && !has_dde {
        return 0;
    }

    let mut score: u32 = 0;

    // Has macros at all
    if has_macros {
        score = score.saturating_add(5);
    }

    // Auto-exec macros are a strong indicator
    if !auto_exec_macros.is_empty() {
        score = score.saturating_add(20);
    }

    // DDE
    if has_dde {
        score = score.saturating_add(25);
    }

    // External links combined with macros
    if has_external_links && has_macros {
        score = score.saturating_add(10);
    }

    // Suspicious functions by category (add highest severity per category)
    let mut shell_score: u32 = 0;
    let mut network_score: u32 = 0;
    let mut filesystem_score: u32 = 0;
    let mut registry_score: u32 = 0;
    let mut process_score: u32 = 0;
    let mut encoding_score: u32 = 0;
    let mut environ_score: u32 = 0;

    for call in suspicious_functions {
        let s = call.severity;
        match call.category {
            MacroThreatCategory::ShellExecution => shell_score = shell_score.max(s),
            MacroThreatCategory::Network => network_score = network_score.max(s),
            MacroThreatCategory::FileSystem => filesystem_score = filesystem_score.max(s),
            MacroThreatCategory::Registry => registry_score = registry_score.max(s),
            MacroThreatCategory::ProcessCreation => process_score = process_score.max(s),
            MacroThreatCategory::Encoding => encoding_score = encoding_score.max(s),
            MacroThreatCategory::EnvironmentAccess => environ_score = environ_score.max(s),
        }
    }

    // Map category severities to score contributions
    if shell_score > 0 {
        score = score.saturating_add(30);
    }
    if network_score > 0 {
        score = score.saturating_add(25);
    }
    if filesystem_score > 0 {
        score = score.saturating_add(15);
    }
    if registry_score > 0 {
        score = score.saturating_add(20);
    }
    if process_score > 0 {
        score = score.saturating_add(15);
    }
    if encoding_score > 0 {
        // Encoding alone is weak, but combined with obfuscation it's stronger
        let enc_add = if obfuscation_score > 30 { 15 } else { 5 };
        score = score.saturating_add(enc_add);
    }
    if environ_score > 0 {
        score = score.saturating_add(10);
    }

    // Obfuscation adds directly (scaled)
    score = score.saturating_add(obfuscation_score / 5);

    score.min(100)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::format_push_string)]
mod tests {
    use super::*;

    #[test]
    fn detect_auto_exec_macros() {
        let content = b"Sub AutoOpen()\nMsgBox \"Hello\"\nEnd Sub";
        let analysis = scan_vba_content(content, true, false);
        assert!(analysis.auto_exec_macros.contains(&"autoopen".to_string()));
        assert!(analysis.threat_score >= 20);
    }

    #[test]
    fn detect_shell_function() {
        let content = b"Sub Test()\nShell(\"cmd.exe /c calc.exe\")\nEnd Sub";
        let analysis = scan_vba_content(content, true, false);
        let has_shell = analysis
            .suspicious_functions
            .iter()
            .any(|f| f.category == MacroThreatCategory::ShellExecution);
        assert!(has_shell);
        assert!(analysis.threat_score >= 30);
    }

    #[test]
    fn detect_dde() {
        let content = b"Some text with DDEAUTO field code";
        let analysis = scan_vba_content(content, false, false);
        assert!(analysis.has_dde);
        assert!(analysis.threat_score >= 25);
    }

    #[test]
    fn clean_document_zero_score() {
        let content = b"Just some normal text content without any macros";
        let analysis = scan_vba_content(content, false, false);
        assert!(!analysis.has_macros);
        assert!(!analysis.has_dde);
        assert_eq!(analysis.threat_score, 0);
        assert!(analysis.auto_exec_macros.is_empty());
        assert!(analysis.suspicious_functions.is_empty());
    }

    #[test]
    fn obfuscation_scoring() {
        // Build a string with many Chr() calls
        let mut content = String::from("Sub Test()\nDim s As String\ns = ");
        for i in 0..25 {
            if i > 0 {
                content.push_str(" & ");
            }
            content.push_str(&format!("Chr({})", 65 + (i % 26)));
        }
        content.push_str("\nEnd Sub");

        let analysis = scan_vba_content(content.as_bytes(), true, false);
        assert!(analysis.obfuscation_score > 0, "obfuscation score should be > 0");
        assert!(
            analysis.obfuscation_score >= 25,
            "expected >= 25, got {}",
            analysis.obfuscation_score
        );
    }

    #[test]
    fn network_and_autoexec_combined() {
        let content = b"Sub Document_Open()\nSet x = CreateObject(\"MSXML2.XMLHTTP\")\nx.Open \"GET\", url\nEnd Sub";
        let analysis = scan_vba_content(content, true, false);
        assert!(!analysis.auto_exec_macros.is_empty());
        let has_network = analysis
            .suspicious_functions
            .iter()
            .any(|f| f.category == MacroThreatCategory::Network);
        assert!(has_network);
        // Auto-exec (20) + macros (5) + network (25) + process (15) = 65+
        assert!(
            analysis.threat_score >= 60,
            "expected >= 60, got {}",
            analysis.threat_score
        );
    }

    #[test]
    fn analyze_office_non_office_data() {
        let data = b"This is just plain text, not an Office file.";
        let result = analyze_office(data).unwrap();
        assert_eq!(result.threat_score, 0);
        assert!(!result.has_macros);
    }

    #[test]
    fn macro_count_estimation() {
        let content = b"Sub Foo()\nEnd Sub\nFunction Bar()\nEnd Function\nPrivate Sub Baz()\nEnd Sub";
        let analysis = scan_vba_content(content, true, false);
        assert!(analysis.macro_count >= 3, "expected >= 3, got {}", analysis.macro_count);
    }

    #[test]
    fn detect_macros_without_vba_string() {
        // OLE2 header + _VBA_PROJECT but no standalone "VBA" string
        let mut data = Vec::new();
        data.extend_from_slice(OLE2_MAGIC);
        data.extend_from_slice(&[0x00; 100]);
        data.extend_from_slice(b"WordDocument");
        data.extend_from_slice(&[0x00; 50]);
        data.extend_from_slice(b"_VBA_PROJECT");
        data.extend_from_slice(&[0x00; 50]);

        let info = parse_ole2(&data).unwrap();
        assert!(info.has_macros, "_VBA_PROJECT alone should detect macros");
    }
}
