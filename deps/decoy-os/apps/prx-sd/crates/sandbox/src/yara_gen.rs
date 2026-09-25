//! Automatic YARA rule generation from sandbox analysis results.
//!
//! Extracts unique byte patterns, strings, and behavioral indicators from
//! analyzed malware samples and generates YARA rules for future detection.

use std::collections::HashSet;
use std::fmt::Write as _;

use crate::{BehaviorFinding, ThreatCategory};

// ── Public types ────────────────────────────────────────────────────────────

/// A YARA rule generated automatically from sandbox analysis.
#[derive(Debug, Clone)]
pub struct GeneratedRule {
    /// Rule name (sanitized, prefixed with `prx_auto_`).
    pub name: String,
    /// Rule source text (valid YARA syntax).
    pub source: String,
    /// What triggered the rule generation.
    pub generation_reason: String,
    /// Confidence level (0–100).
    pub confidence: u32,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Generate YARA rules from binary data and sandbox behavior findings.
///
/// Returns zero or more [`GeneratedRule`]s depending on the richness of the
/// extracted indicators. An empty `data` slice or an empty `behaviors` list
/// will still produce a rule if the other source yields useful strings.
pub fn generate_rules(
    data: &[u8],
    file_name: &str,
    threat_name: &str,
    behaviors: &[BehaviorFinding],
) -> Vec<GeneratedRule> {
    let mut rules = Vec::new();

    // 1. Main rule from binary content analysis.
    let suspicious_strings = extract_suspicious_strings(data);
    let byte_patterns = extract_unique_patterns(data);

    if !suspicious_strings.is_empty() || !byte_patterns.is_empty() {
        let confidence = compute_confidence(&suspicious_strings, &byte_patterns, behaviors);
        let rule_name = sanitize_rule_name(threat_name);
        let source = build_rule_source(
            &rule_name,
            threat_name,
            file_name,
            confidence,
            &suspicious_strings,
            &byte_patterns,
            data,
        );
        rules.push(GeneratedRule {
            name: rule_name,
            source,
            generation_reason: format!(
                "Extracted {} suspicious strings and {} byte patterns from binary",
                suspicious_strings.len(),
                byte_patterns.len(),
            ),
            confidence,
        });
    }

    // 2. Behavior-specific rules.
    if let Some(rule) = generate_behavior_rule(threat_name, file_name, behaviors, data) {
        rules.push(rule);
    }

    rules
}

// ── String extraction ───────────────────────────────────────────────────────

/// Suspicious-pattern keywords used to filter extracted strings.
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "/bin/bash",
    "/tmp/",
    "/dev/shm",
    "HKEY_",
    "\\Registry\\",
    "\\AppData\\",
    "\\System32\\",
    "crontab",
    "/etc/cron",
    "/etc/passwd",
    "/etc/shadow",
    "stratum+tcp",
    "User-Agent",
    "Mozilla/",
    "wget ",
    "curl ",
    "chmod ",
    "base64",
    "eval(",
    "exec(",
    ".onion",
    "ransom",
    "decrypt",
    "encrypt",
    "bitcoin",
    "wallet",
    "BEGIN RSA",
    "BEGIN OPENSSH",
    "password",
    "credential",
];

/// Extract ASCII and wide (UTF-16LE) strings from binary data that match
/// suspicious patterns.
fn extract_suspicious_strings(data: &[u8]) -> Vec<String> {
    let mut result_set: HashSet<String> = HashSet::new();

    // ASCII strings >= 6 chars.
    for s in extract_ascii_strings(data, 6) {
        if is_suspicious_string(&s) {
            result_set.insert(s);
        }
    }

    // Wide (UTF-16LE) strings >= 6 chars.
    for s in extract_wide_strings(data, 6) {
        if is_suspicious_string(&s) {
            result_set.insert(s);
        }
    }

    // Also look for IP-address patterns.
    for s in extract_ascii_strings(data, 7) {
        if looks_like_ip(&s) {
            result_set.insert(s);
        }
    }

    let mut out: Vec<String> = result_set.into_iter().collect();
    out.sort();
    // Cap to avoid enormous rules.
    out.truncate(20);
    out
}

/// Extract printable ASCII runs of at least `min_len` bytes.
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if (0x20..0x7F).contains(&byte) {
            current.push(byte as char);
        } else if current.len() >= min_len {
            strings.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push(current);
    }
    strings
}

/// Extract UTF-16LE strings (ASCII char followed by 0x00) of at least
/// `min_len` decoded characters.
fn extract_wide_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut i = 0;

    while i + 1 < data.len() {
        // Both indices are guaranteed in-bounds: i < data.len()-1 and i+1 < data.len().
        let (Some(&lo), Some(&hi)) = (data.get(i), data.get(i + 1)) else {
            break;
        };
        if hi == 0 && (0x20..0x7F).contains(&lo) {
            current.push(lo as char);
            i += 2;
        } else {
            if current.len() >= min_len {
                strings.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            i += 1;
        }
    }
    if current.len() >= min_len {
        strings.push(current);
    }
    strings
}

/// Return `true` if `s` contains any suspicious keyword (case-insensitive).
fn is_suspicious_string(s: &str) -> bool {
    let lower = s.to_lowercase();
    SUSPICIOUS_KEYWORDS.iter().any(|kw| lower.contains(&kw.to_lowercase()))
}

/// Heuristic check for IPv4-like strings.
fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u16>().is_ok_and(|n| n <= 255)
    })
}

// ── Byte pattern extraction ─────────────────────────────────────────────────

/// Maximum number of byte patterns to extract.
const MAX_BYTE_PATTERNS: usize = 5;
/// Minimum / maximum length of an individual byte pattern.
const MIN_PATTERN_LEN: usize = 8;
const MAX_PATTERN_LEN: usize = 32;

/// Extract unique byte sequences suitable for YARA hex patterns.
///
/// Focuses on:
/// 1. The first 64 bytes (entry point region for PE/ELF headers).
/// 2. Non-trivial byte runs found throughout the binary.
fn extract_unique_patterns(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < MIN_PATTERN_LEN {
        return Vec::new();
    }

    let mut patterns: Vec<Vec<u8>> = Vec::new();

    // 1. Entry-point region (first 64 bytes, capped to data length).
    let header_len = data.len().min(64);
    if let Some(header_block) = data.get(..header_len) {
        if header_len >= MIN_PATTERN_LEN && !is_trivial_block(header_block) {
            let take = header_len.min(MAX_PATTERN_LEN);
            if let Some(take_block) = data.get(..take) {
                patterns.push(take_block.to_vec());
            }
        }
    }

    // 2. Scan for non-trivial blocks at regular intervals.
    let step = if data.len() > 4096 { data.len() / 16 } else { 256 };

    let mut offset = 64;
    while offset + MIN_PATTERN_LEN <= data.len() && patterns.len() < MAX_BYTE_PATTERNS {
        let end = (offset + MAX_PATTERN_LEN).min(data.len());
        if let Some(candidate) = data.get(offset..end) {
            if !is_trivial_block(candidate) && !patterns.iter().any(|p| p.as_slice() == candidate) {
                patterns.push(candidate.to_vec());
            }
        }
        offset += step;
    }

    patterns.truncate(MAX_BYTE_PATTERNS);
    patterns
}

/// A block is "trivial" if all bytes are the same (e.g. all zeros).
fn is_trivial_block(block: &[u8]) -> bool {
    let Some(&first) = block.first() else {
        return true;
    };
    block.iter().all(|&b| b == first)
}

// ── Rule building ───────────────────────────────────────────────────────────

/// Produce a sanitized YARA rule name.
///
/// Non-alphanumeric characters become underscores; the result is prefixed
/// with `prx_auto_` and suffixed with the current date (YYYYMMDD).
fn sanitize_rule_name(threat_name: &str) -> String {
    let sanitized: String = threat_name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();

    let date = chrono::Utc::now().format("%Y%m%d");
    format!("prx_auto_{sanitized}_{date}")
}

/// Build the full YARA rule source text.
#[allow(clippy::similar_names)] // `data` (binary content) and `today` are semantically distinct
fn build_rule_source(
    rule_name: &str,
    threat_name: &str,
    file_name: &str,
    confidence: u32,
    strings: &[String],
    byte_patterns: &[Vec<u8>],
    data: &[u8],
) -> String {
    let mut src = String::new();
    let today = chrono::Utc::now().format("%Y-%m-%d");

    // Rule header.
    let _ = writeln!(src, "rule {rule_name} {{");

    // Meta section.
    let _ = writeln!(src, "    meta:");
    let _ = writeln!(src, "        description = \"Auto-generated from sandbox analysis\"");
    let _ = writeln!(src, "        threat_name = \"{threat_name}\"");
    let _ = writeln!(src, "        source_file = \"{file_name}\"");
    let _ = writeln!(src, "        date = \"{today}\"");
    let _ = writeln!(src, "        confidence = {confidence}");
    let _ = writeln!(src, "        generator = \"prx-sd\"");

    // Strings section.
    if !strings.is_empty() || !byte_patterns.is_empty() {
        let _ = writeln!(src, "    strings:");

        for (i, s) in strings.iter().enumerate() {
            let escaped = escape_yara_string(s);
            let _ = writeln!(src, "        $s{} = \"{}\" ascii wide", i + 1, escaped);
        }

        for (i, pat) in byte_patterns.iter().enumerate() {
            let hex = bytes_to_hex_string(pat);
            let _ = writeln!(src, "        $b{} = {{ {} }}", i + 1, hex);
        }
    }

    // Condition section.
    let _ = writeln!(src, "    condition:");
    let condition = build_condition(strings.len(), byte_patterns.len(), data);
    let _ = writeln!(src, "        {condition}");

    let _ = write!(src, "}}");
    src
}

/// Build the YARA condition clause.
fn build_condition(string_count: usize, pattern_count: usize, data: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();

    // File-type magic check.
    if let Some(magic_bytes) = data.get(..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) {
        let magic = u16::from_le_bytes(magic_bytes);
        match magic {
            0x5A4D => parts.push("uint16(0) == 0x5A4D".into()), // PE / MZ
            0x457F => parts.push("uint16(0) == 0x457F".into()), // ELF
            _ => {}
        }
    }

    // String matching.
    match (string_count, pattern_count) {
        (0, 0) => {
            // Should not happen; caller checks before building.
            parts.push("true".into());
        }
        (s, 0) if s <= 3 => {
            parts.push("any of ($s*)".into());
        }
        (s, 0) => {
            let threshold = (s / 2).max(2);
            parts.push(format!("{threshold} of ($s*)"));
        }
        (0, _) => {
            parts.push("any of ($b*)".into());
        }
        (s, _) => {
            let threshold = (s / 2).max(1);
            parts.push(format!("({threshold} of ($s*) or any of ($b*))"));
        }
    }

    parts.join(" and ")
}

/// Escape special characters for a YARA string literal.
fn escape_yara_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Convert a byte slice to a space-separated hex string (e.g. "4D 5A 90 00").
fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Compute a confidence score based on the number and quality of indicators.
fn compute_confidence(strings: &[String], byte_patterns: &[Vec<u8>], behaviors: &[BehaviorFinding]) -> u32 {
    let mut score: u32 = 30; // base

    // More suspicious strings -> higher confidence.
    #[allow(clippy::cast_possible_truncation)] // len() <= 20, fits in u32
    let str_count = strings.len().min(20) as u32;
    score = score.saturating_add(str_count * 2);

    // Byte patterns contribute moderately.
    #[allow(clippy::cast_possible_truncation)] // len() <= 5, fits in u32
    let pat_count = byte_patterns.len().min(5) as u32;
    score = score.saturating_add(pat_count * 3);

    // Behavior findings boost confidence.
    #[allow(clippy::cast_possible_truncation)] // len() <= 5, fits in u32
    let beh_count = behaviors.len().min(5) as u32;
    score = score.saturating_add(beh_count * 5);

    score.min(100)
}

// ── Behavior-specific rule generation ───────────────────────────────────────

/// IOC strings associated with specific threat categories.
fn behavior_ioc_strings(category: &ThreatCategory) -> Vec<&'static str> {
    match category {
        ThreatCategory::ReverseShell => vec![
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
            "powershell",
            "/dev/tcp/",
            "socket",
            "connect",
        ],
        ThreatCategory::Persistence => vec![
            "/etc/cron",
            "crontab",
            "/etc/systemd/system/",
            "LaunchAgents",
            "LaunchDaemons",
            "/etc/init.d/",
            "autostart",
            ".bashrc",
            "Startup",
        ],
        ThreatCategory::CryptoMining => vec![
            "stratum+tcp",
            "pool.",
            "xmr.",
            "monero",
            "nicehash",
            "nanopool",
            "f2pool",
            "hashvault",
            "minexmr",
        ],
        ThreatCategory::Ransomware => vec![
            "YOUR FILES HAVE BEEN ENCRYPTED",
            "pay the ransom",
            "bitcoin",
            ".onion",
            "decrypt",
            "recover your files",
            "wallet",
            "AES-256",
            "RSA-2048",
        ],
        _ => Vec::new(),
    }
}

/// Attempt to generate a behavior-specific YARA rule.
///
/// Returns `None` if no behavior findings map to categories with known IOCs.
#[allow(clippy::similar_names)] // `data` (binary content) and `today` are semantically distinct
fn generate_behavior_rule(
    threat_name: &str,
    file_name: &str,
    behaviors: &[BehaviorFinding],
    data: &[u8],
) -> Option<GeneratedRule> {
    // Collect IOC strings from all matched behavior categories.
    let mut ioc_strings: Vec<String> = Vec::new();
    let mut categories_used: Vec<String> = Vec::new();

    for finding in behaviors {
        let iocs = behavior_ioc_strings(&finding.category);
        if !iocs.is_empty() {
            categories_used.push(finding.category.to_string());
            for ioc in iocs {
                let s = ioc.to_string();
                if !ioc_strings.contains(&s) {
                    ioc_strings.push(s);
                }
            }
        }
    }

    if ioc_strings.is_empty() {
        return None;
    }

    // Cap IOC strings.
    ioc_strings.truncate(15);

    let base_name = sanitize_rule_name(&format!("{threat_name}_behavior"));
    let confidence = compute_confidence(&ioc_strings, &[], behaviors);

    let mut src = String::new();
    let today = chrono::Utc::now().format("%Y-%m-%d");

    let _ = writeln!(src, "rule {base_name} {{");
    let _ = writeln!(src, "    meta:");
    let _ = writeln!(
        src,
        "        description = \"Behavior-based rule from sandbox analysis\""
    );
    let _ = writeln!(src, "        threat_name = \"{threat_name}\"");
    let _ = writeln!(src, "        source_file = \"{file_name}\"");
    let _ = writeln!(src, "        date = \"{today}\"");
    let _ = writeln!(src, "        confidence = {confidence}");
    let _ = writeln!(src, "        generator = \"prx-sd\"");
    let _ = writeln!(src, "        categories = \"{}\"", categories_used.join(", "));
    let _ = writeln!(src, "    strings:");

    for (i, s) in ioc_strings.iter().enumerate() {
        let escaped = escape_yara_string(s);
        let _ = writeln!(src, "        $ioc{} = \"{}\" ascii wide", i + 1, escaped);
    }

    let _ = writeln!(src, "    condition:");
    let threshold = (ioc_strings.len() / 3).max(2).min(ioc_strings.len());

    // Add file-type check if we can detect it.
    let mut cond_parts: Vec<String> = Vec::new();
    if let Some(magic_bytes) = data.get(..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) {
        let magic = u16::from_le_bytes(magic_bytes);
        match magic {
            0x5A4D => cond_parts.push("uint16(0) == 0x5A4D".into()),
            0x457F => cond_parts.push("uint16(0) == 0x457F".into()),
            _ => {}
        }
    }
    cond_parts.push(format!("{threshold} of ($ioc*)"));
    let _ = writeln!(src, "        {}", cond_parts.join(" and "));
    let _ = write!(src, "}}");

    Some(GeneratedRule {
        name: base_name,
        source: src,
        generation_reason: format!("Behavior-based rule from categories: {}", categories_used.join(", "),),
        confidence,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ThreatCategory;

    #[test]
    fn test_sanitize_rule_name() {
        let name = sanitize_rule_name("Win.Trojan.Sample");
        assert!(name.starts_with("prx_auto_Win_Trojan_Sample_"));
        // Should end with YYYYMMDD.
        let suffix = &name[name.len() - 8..];
        assert!(suffix.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_sanitize_rule_name_special_chars() {
        let name = sanitize_rule_name("Mal/Ware-Gen!A");
        assert!(name.starts_with("prx_auto_Mal_Ware_Gen_A_"));
    }

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"short\x00this_is_a_longer_string\x00tiny\x00another_long_one!\x00";
        let strings = extract_ascii_strings(data, 6);
        assert!(strings.contains(&"this_is_a_longer_string".to_string()));
        assert!(strings.contains(&"another_long_one!".to_string()));
        // "short" and "tiny" are < 6 chars, should be excluded.
        assert!(!strings.iter().any(|s| s == "short"));
        assert!(!strings.iter().any(|s| s == "tiny"));
    }

    #[test]
    fn test_extract_wide_strings() {
        // "http://" encoded as UTF-16LE.
        let wide: Vec<u8> = "http://evil.com".chars().flat_map(|c| vec![c as u8, 0x00]).collect();
        let strings = extract_wide_strings(&wide, 6);
        assert!(strings.iter().any(|s| s.contains("http://evil.com")));
    }

    #[test]
    fn test_suspicious_string_detection() {
        assert!(is_suspicious_string("http://evil.com/payload"));
        assert!(is_suspicious_string("cmd.exe /c del *"));
        assert!(is_suspicious_string("/etc/shadow"));
        assert!(!is_suspicious_string("hello world"));
        assert!(!is_suspicious_string("normal_variable_name"));
    }

    #[test]
    fn test_looks_like_ip() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("10.0.0.1"));
        assert!(looks_like_ip("255.255.255.0"));
        assert!(!looks_like_ip("999.999.999.999"));
        assert!(!looks_like_ip("not.an.ip"));
        assert!(!looks_like_ip("1.2.3"));
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn test_extract_unique_patterns_empty_data() {
        let patterns = extract_unique_patterns(&[]);
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_extract_unique_patterns_short_data() {
        let patterns = extract_unique_patterns(&[0x4D, 0x5A, 0x90]);
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_extract_unique_patterns_nontrivial() {
        let data: Vec<u8> = (0..128).collect();
        let patterns = extract_unique_patterns(&data);
        assert!(!patterns.is_empty());
        assert!(patterns.len() <= MAX_BYTE_PATTERNS);
        for pat in &patterns {
            assert!(pat.len() >= MIN_PATTERN_LEN);
            assert!(pat.len() <= MAX_PATTERN_LEN);
        }
    }

    #[test]
    fn test_trivial_block_detection() {
        assert!(is_trivial_block(&[0; 32]));
        assert!(is_trivial_block(&[0xFF; 16]));
        assert!(!is_trivial_block(&[0x00, 0x01]));
        assert!(is_trivial_block(&[]));
    }

    #[test]
    fn test_generate_rules_with_suspicious_content() {
        // Build a fake binary with suspicious strings embedded.
        let mut data = vec![0x4D, 0x5A]; // MZ header
        data.extend_from_slice(b"\x00\x00\x00\x00\x00\x00");
        data.extend_from_slice(b"http://evil.com/payload\x00");
        data.extend_from_slice(b"cmd.exe /c whoami\x00");
        // Pad to have enough for byte patterns.
        data.extend_from_slice(&[0xCC; 64]);

        let behaviors = vec![BehaviorFinding {
            rule_name: "Reverse Shell".into(),
            category: ThreatCategory::ReverseShell,
            score: 90,
            description: "Detected reverse shell behavior".into(),
        }];

        let rules = generate_rules(&data, "sample.exe", "Win.Trojan.Sample", &behaviors);
        assert!(!rules.is_empty());

        // Check that the main rule has valid YARA structure.
        let main_rule = &rules[0];
        assert!(main_rule.source.contains("rule prx_auto_"));
        assert!(main_rule.source.contains("meta:"));
        assert!(main_rule.source.contains("strings:"));
        assert!(main_rule.source.contains("condition:"));
        assert!(main_rule.source.contains("generator = \"prx-sd\""));
        assert!(main_rule.confidence > 0 && main_rule.confidence <= 100);
    }

    #[test]
    fn test_generate_rules_empty_data_no_behaviors() {
        let rules = generate_rules(&[], "empty.bin", "Unknown", &[]);
        assert!(rules.is_empty());
    }

    #[test]
    fn test_generate_rules_behavior_only() {
        let behaviors = vec![
            BehaviorFinding {
                rule_name: "Crypto Miner".into(),
                category: ThreatCategory::CryptoMining,
                score: 70,
                description: "Mining pool connection detected".into(),
            },
            BehaviorFinding {
                rule_name: "Persistence Install".into(),
                category: ThreatCategory::Persistence,
                score: 75,
                description: "Persistence mechanism detected".into(),
            },
        ];

        // Minimal data with no suspicious strings or meaningful patterns.
        let data = vec![0x00; 4];
        let rules = generate_rules(&data, "miner.elf", "Linux.Miner.Generic", &behaviors);

        // Should produce at least the behavior rule.
        let behavior_rule = rules.iter().find(|r| r.name.contains("behavior"));
        assert!(behavior_rule.is_some());

        let src = &behavior_rule.as_ref().map(|r| &r.source);
        assert!(src.is_some());
    }

    #[test]
    fn test_escape_yara_string() {
        assert_eq!(escape_yara_string(r#"hello"world"#), r#"hello\"world"#);
        assert_eq!(escape_yara_string("path\\to\\file"), "path\\\\to\\\\file");
        assert_eq!(escape_yara_string("line\nnewline"), "line\\nnewline");
    }

    #[test]
    fn test_bytes_to_hex_string() {
        assert_eq!(bytes_to_hex_string(&[0x4D, 0x5A, 0x90, 0x00]), "4D 5A 90 00");
        assert_eq!(bytes_to_hex_string(&[0xFF]), "FF");
        assert_eq!(bytes_to_hex_string(&[]), "");
    }

    #[test]
    fn test_pe_magic_in_condition() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let condition = build_condition(2, 1, &data);
        assert!(condition.contains("uint16(0) == 0x5A4D"));
    }

    #[test]
    fn test_elf_magic_in_condition() {
        let data = vec![0x7F, 0x45, 0x4C, 0x46]; // \x7FELF
        let condition = build_condition(1, 0, &data);
        assert!(condition.contains("uint16(0) == 0x457F"));
    }

    #[test]
    fn test_confidence_computation() {
        let no_strings: Vec<String> = Vec::new();
        let no_patterns: Vec<Vec<u8>> = Vec::new();
        let no_behaviors: Vec<BehaviorFinding> = Vec::new();

        // Base confidence with nothing.
        let c = compute_confidence(&no_strings, &no_patterns, &no_behaviors);
        assert_eq!(c, 30);

        // With strings.
        let strings: Vec<String> = (0..10).map(|i| format!("str{i}")).collect();
        let c = compute_confidence(&strings, &no_patterns, &no_behaviors);
        assert!(c > 30);

        // With everything.
        let patterns = vec![vec![0u8; 8]];
        let behaviors = vec![BehaviorFinding {
            rule_name: "test".into(),
            category: ThreatCategory::Dropper,
            score: 80,
            description: "test".into(),
        }];
        let c = compute_confidence(&strings, &patterns, &behaviors);
        assert!(c > 50);
    }

    #[test]
    fn test_behavior_ioc_strings_coverage() {
        // Verify that key categories return IOCs.
        assert!(!behavior_ioc_strings(&ThreatCategory::ReverseShell).is_empty());
        assert!(!behavior_ioc_strings(&ThreatCategory::Persistence).is_empty());
        assert!(!behavior_ioc_strings(&ThreatCategory::CryptoMining).is_empty());
        assert!(!behavior_ioc_strings(&ThreatCategory::Ransomware).is_empty());

        // Categories without specific IOCs return empty.
        assert!(behavior_ioc_strings(&ThreatCategory::AntiAnalysis).is_empty());
    }
}
