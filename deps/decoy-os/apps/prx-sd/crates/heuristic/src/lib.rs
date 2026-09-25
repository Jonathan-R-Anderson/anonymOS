//! # prx-sd-heuristic
//!
//! Heuristic / static analysis engine for antivirus detection. Analyses binary
//! structure, entropy, import tables, packer signatures, and other indicators
//! to produce a composite threat score without relying on hash or signature
//! databases.

pub mod entropy;
pub mod ml_behavior;
pub mod ml_features;
pub mod ml_model;
pub mod packer;
pub mod scoring;
pub mod suspicious_api;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use prx_sd_parsers::ParsedFile;

use crate::entropy::shannon_entropy;
use crate::packer::{check_entry_point_anomaly, detect_packer};
use crate::scoring::aggregate_score;
use crate::suspicious_api::{ApiCategory, check_suspicious_imports};

// ─── Public types ────────────────────────────────────────────────────────────

/// A single heuristic observation about a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Finding {
    /// Overall file entropy exceeds the suspicion threshold (typically >7.2).
    HighEntropy(f64),
    /// A named PE section has suspiciously high entropy, suggesting packing or
    /// encryption.
    PackedSection { name: String, entropy: f64 },
    /// A suspicious Windows API was found in the import table.
    SuspiciousApi(String),
    /// The PE timestamp is zero (often zeroed by malware authors).
    ZeroTimestamp,
    /// Anti-debugging API imports were detected.
    AntiDebug,
    /// The binary appears to contain self-modifying code (writable + executable
    /// section attributes combined with high entropy).
    SelfModifying,
    /// UPX packer specifically detected (subset of `PackerDetected` kept for
    /// backwards compatibility / granularity).
    UPXPacked,
    /// Unusually high number of imports (may indicate API-hashing unpacker stub).
    HighImportCount,
    /// A section with a suspicious name was found (e.g. non-standard, packer-like).
    SuspiciousSection(String),
    /// A code section (`IMAGE_SCN_CNT_CODE` or `IMAGE_SCN_MEM_EXECUTE`) is also
    /// writable (`IMAGE_SCN_MEM_WRITE`), which is abnormal for legitimate software.
    WritableCodeSection,
    /// The PE has zero imports, suggesting manual API resolution or packing.
    NoImports,
    /// A resource anomaly was detected (e.g. suspiciously large resource, or
    /// resource with high entropy).
    ResourceAnomaly(String),
    /// A known packer was detected by name.
    PackerDetected(String),
    /// Office document contains VBA macros.
    OfficeMacros,
    /// Office VBA macro with auto-execution trigger (e.g. `AutoOpen`).
    OfficeAutoExecMacro(String),
    /// Office VBA macro contains shell execution calls.
    OfficeShellExecution,
    /// Office VBA macro contains network access calls.
    OfficeNetworkAccess,
    /// Office document contains DDE (Dynamic Data Exchange).
    OfficeDde,
    /// Office VBA macro shows obfuscation patterns.
    OfficeObfuscation(u32),
    /// Office macro aggregate threat score.
    OfficeMacroThreatScore(u32),
    /// PDF contains embedded JavaScript.
    PdfJavaScript,
    /// PDF contains a Launch/SubmitForm/ImportData action.
    PdfLaunchAction,
    /// PDF auto-executes JavaScript via `OpenAction`.
    PdfAutoExecJavaScript,
    /// A known CVE exploit pattern was detected in a PDF.
    PdfCvePattern(String),
    /// PDF threat score from exploit analysis.
    PdfThreatScore(u32),
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighEntropy(e) => write!(f, "High overall entropy: {e:.2}"),
            Self::PackedSection { name, entropy } => {
                write!(f, "Packed section '{name}' (entropy {entropy:.2})")
            }
            Self::SuspiciousApi(api) => write!(f, "Suspicious API import: {api}"),
            Self::ZeroTimestamp => write!(f, "PE timestamp is zero"),
            Self::AntiDebug => write!(f, "Anti-debug API imports detected"),
            Self::SelfModifying => write!(f, "Self-modifying code indicators"),
            Self::UPXPacked => write!(f, "UPX packer detected"),
            Self::HighImportCount => write!(f, "Unusually high import count"),
            Self::SuspiciousSection(name) => write!(f, "Suspicious section: {name}"),
            Self::WritableCodeSection => write!(f, "Writable code section (W+X)"),
            Self::NoImports => write!(f, "No imports found"),
            Self::ResourceAnomaly(desc) => write!(f, "Resource anomaly: {desc}"),
            Self::PackerDetected(name) => write!(f, "Packer detected: {name}"),
            Self::OfficeMacros => write!(f, "Office document contains VBA macros"),
            Self::OfficeAutoExecMacro(name) => {
                write!(f, "Office auto-exec macro: {name}")
            }
            Self::OfficeShellExecution => {
                write!(f, "Office macro contains shell execution")
            }
            Self::OfficeNetworkAccess => {
                write!(f, "Office macro contains network access")
            }
            Self::OfficeDde => write!(f, "Office document contains DDE"),
            Self::OfficeObfuscation(score) => {
                write!(f, "Office macro obfuscation (score: {score})")
            }
            Self::OfficeMacroThreatScore(s) => {
                write!(f, "Office macro threat score: {s}")
            }
            Self::PdfJavaScript => write!(f, "PDF contains JavaScript"),
            Self::PdfLaunchAction => write!(f, "PDF contains Launch action"),
            Self::PdfAutoExecJavaScript => {
                write!(f, "PDF auto-executes JavaScript")
            }
            Self::PdfCvePattern(cve) => write!(f, "PDF CVE pattern: {cve}"),
            Self::PdfThreatScore(s) => write!(f, "PDF threat score: {s}"),
        }
    }
}

/// Threat severity derived from the aggregate heuristic score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Score < 30: no significant indicators.
    Clean,
    /// Score 30..=59: suspicious but not conclusive.
    Suspicious,
    /// Score >= 60: strong malicious indicators.
    Malicious,
}

impl ThreatLevel {
    /// Map a numeric heuristic score to a threat level.
    ///
    /// * `0..=29`  -> `Clean`
    /// * `30..=59` -> `Suspicious`
    /// * `60..`    -> `Malicious`
    pub const fn from_score(score: u32) -> Self {
        match score {
            0..=29 => Self::Clean,
            30..=59 => Self::Suspicious,
            _ => Self::Malicious,
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Suspicious => write!(f, "Suspicious"),
            Self::Malicious => write!(f, "Malicious"),
        }
    }
}

/// The complete result of running heuristic analysis on a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicResult {
    /// Aggregate score in the range 0..=100.
    pub score: u32,
    /// Threat classification derived from `score`.
    pub threat_level: ThreatLevel,
    /// Individual findings that contributed to the score.
    pub findings: Vec<Finding>,
}

// ─── Engine ──────────────────────────────────────────────────────────────────

/// The heuristic analysis engine.
///
/// Holds an optional ML model for enhanced detection. Instantiate with
/// [`HeuristicEngine::new`] and call [`HeuristicEngine::analyze`] to scan a
/// file.
pub struct HeuristicEngine {
    ml_model: ml_model::MlModel,
}

impl HeuristicEngine {
    /// Create a new heuristic engine instance with fallback ML model.
    pub fn new() -> Self {
        Self {
            ml_model: ml_model::MlModel::new_fallback(),
        }
    }

    /// Create a new engine, attempting to load ONNX models from `model_dir`.
    ///
    /// Falls back to the heuristic scorer if model files are not found.
    pub fn with_models(model_dir: &std::path::Path) -> Self {
        let ml_model = ml_model::MlModel::load(model_dir).unwrap_or_else(|e| {
            debug!("failed to load ML models: {e}, using fallback");
            ml_model::MlModel::new_fallback()
        });
        Self { ml_model }
    }

    /// Run all heuristic checks against `data` (the raw file bytes) and
    /// `parsed` (the structured parse result from `prx_sd_parsers`).
    ///
    /// Returns a [`HeuristicResult`] containing the aggregate score, threat
    /// level, and individual findings.
    pub fn analyze(&self, data: &[u8], parsed: &ParsedFile) -> HeuristicResult {
        let mut findings = Vec::new();

        // ── (a) Overall entropy check ────────────────────────────────
        let overall_entropy = shannon_entropy(data);
        trace!(overall_entropy, "computed overall entropy");

        if overall_entropy > 7.2 {
            debug!(overall_entropy, "high overall entropy detected");
            findings.push(Finding::HighEntropy(overall_entropy));
        }

        // ── (b) Format-specific checks ─────────────────────────────────
        if let Some(pe) = parsed.as_pe() {
            self.analyze_pe(pe, data, &mut findings);
        }
        if let Some(elf) = parsed.as_elf() {
            self.analyze_elf(elf, data, &mut findings);
        }
        if let Some(macho) = parsed.as_macho() {
            self.analyze_macho(macho, data, &mut findings);
        }
        if parsed.as_pdf().is_some() {
            self.analyze_pdf_exploits(data, &mut findings);
        }
        if parsed.as_office().is_some() {
            self.analyze_office_macros(data, &mut findings);
        }

        // ── (b1) Suppress false positives ────────────────────────────
        // Principle: a single indicator alone should not cause detection.
        // Entropy alone is never enough — legitimate compressed/crypto
        // libraries (libc, libssl, .gz archives) always have high entropy.

        let non_entropy_findings = findings
            .iter()
            .filter(|f| !matches!(f, Finding::HighEntropy(_)))
            .count();

        // If HighEntropy is the ONLY finding, suppress it regardless of
        // file type — entropy alone is not a reliable malware indicator.
        if non_entropy_findings == 0 && findings.iter().any(|f| matches!(f, Finding::HighEntropy(_))) {
            debug!("suppressing lone HighEntropy finding (need corroborating evidence)");
            findings.clear();
        }

        // ELF shared libraries (DYN type) contain many "suspicious" strings
        // as legitimate standard library functions (ptrace, execve, getdents,
        // /bin/sh are all normal in libc/glibc). Only flag ELF DYN if there
        // are truly anomalous indicators like packers or no imports.
        if let Some(elf) = parsed.as_elf() {
            if elf.elf_type == "DYN" {
                let has_packer = findings.iter().any(|f| {
                    matches!(
                        f,
                        Finding::PackerDetected(_) | Finding::NoImports | Finding::SelfModifying
                    )
                });
                if !has_packer {
                    debug!("suppressing findings on ELF shared library (normal APIs)");
                    findings.clear();
                }
            }
        }

        // ELF EXEC: suppress if findings are only common system strings.
        // Binaries like bash, coreutils naturally contain these strings.
        if let Some(elf) = parsed.as_elf() {
            if elf.elf_type == "EXEC" {
                let generic_apis = [
                    "/bin/sh",
                    "/bin/bash",
                    "socket",
                    "connect",
                    "execve",
                    "ptrace",
                    "dup2",
                    "getdents",
                    "/etc/shadow",
                    "reverse",
                    "crontab",
                    "authorized_keys",
                ];
                let has_non_generic = findings.iter().any(|f| match f {
                    Finding::SuspiciousApi(api) => !generic_apis.iter().any(|g| api.contains(g)),
                    Finding::HighEntropy(_) | Finding::PackedSection { .. } => false,
                    _ => true, // Packer, NoImports, etc. are always non-generic
                });
                if !has_non_generic {
                    debug!("suppressing generic system API findings on ELF EXEC");
                    findings.clear();
                }
            }
        }

        // Non-PE/non-ELF files with only HighEntropy (archives, compressed)
        // should not be flagged.
        if parsed.as_pe().is_none()
            && parsed.as_elf().is_none()
            && parsed.as_macho().is_none()
            && parsed.as_pdf().is_none()
            && parsed.as_office().is_none()
        {
            let only_entropy = findings.iter().all(|f| matches!(f, Finding::HighEntropy(_)));
            if only_entropy && !findings.is_empty() {
                debug!("suppressing HighEntropy on non-executable file");
                findings.clear();
            }
        }

        // ── (b2) ML-based scoring ───────────────────────────────────
        let ml_prediction = self.ml_score(data, parsed);

        // ── (c) Aggregate score ──────────────────────────────────────
        let (mut score, _) = aggregate_score(&findings);

        // Blend ML prediction into the heuristic score.
        // The ML score can boost or confirm the heuristic score.
        if let Some(pred) = &ml_prediction {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ml_contribution = (pred.malicious_probability * 30.0 * pred.confidence) as u32;
            score = (score + ml_contribution).min(100);
            if pred.malicious_probability > 0.7 {
                debug!(
                    prob = pred.malicious_probability,
                    model = pred.model_type,
                    "ML model indicates high malicious probability"
                );
            }
        }
        let threat_level = ThreatLevel::from_score(score);

        debug!(
            score,
            %threat_level,
            finding_count = findings.len(),
            "heuristic analysis complete"
        );

        HeuristicResult {
            score,
            threat_level,
            findings,
        }
    }

    /// Run ML-based scoring on the parsed file, returning a prediction
    /// if the file type is supported (PE or ELF).
    #[allow(clippy::option_if_let_else)] // Chained if-let-else is clearer than map_or_else here
    pub fn ml_score(&self, data: &[u8], parsed: &ParsedFile) -> Option<ml_model::MlPrediction> {
        if let Some(pe) = parsed.as_pe() {
            let features = ml_features::extract_pe_features(pe, data);
            Some(self.ml_model.predict_pe(&features))
        } else if let Some(elf) = parsed.as_elf() {
            let features = ml_features::extract_elf_features(elf, data);
            Some(self.ml_model.predict_elf(&features))
        } else {
            None
        }
    }

    /// PE-specific heuristic checks.
    #[allow(clippy::unused_self)] // Method for future ML model integration
    fn analyze_pe(&self, pe: &prx_sd_parsers::pe::PeInfo, data: &[u8], findings: &mut Vec<Finding>) {
        // PE section characteristics bit flags (from the PE/COFF specification).
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
        const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;

        for section in &pe.sections {
            // High-entropy section (>7.0) is a packing indicator.
            if section.entropy > 7.0 && section.raw_size > 0 {
                debug!(
                    section = %section.name,
                    entropy = section.entropy,
                    "high entropy section"
                );
                findings.push(Finding::PackedSection {
                    name: section.name.clone(),
                    entropy: section.entropy,
                });
            }

            // Writable + executable section is suspicious.
            let is_code = section.characteristics & IMAGE_SCN_CNT_CODE != 0
                || section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
            let is_writable = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;

            if is_code && is_writable {
                debug!(section = %section.name, "writable code section");
                findings.push(Finding::WritableCodeSection);
            }

            // Self-modifying code: writable + executable + high entropy.
            if is_code && is_writable && section.entropy > 6.5 {
                findings.push(Finding::SelfModifying);
            }
        }

        // ── Suspicious API imports ───────────────────────────────────
        let api_hits = check_suspicious_imports(&pe.imports);
        let mut has_anti_debug = false;

        for (category, api_name, _weight) in &api_hits {
            trace!(api = %api_name, category = %category, "suspicious API hit");
            findings.push(Finding::SuspiciousApi(api_name.clone()));

            if *category == ApiCategory::AntiDebug && !has_anti_debug {
                has_anti_debug = true;
                findings.push(Finding::AntiDebug);
            }
        }

        // ── Raw byte scan for suspicious API strings ────────────────
        // Synthetic or packed PEs may not have a real import table, so
        // also scan raw bytes for well-known injection/evasion strings.
        let suspicious_pe_strings: &[&[u8]] = &[
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"NtCreateThread",
            b"RtlCreateUserThread",
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"InternetOpenA",
            b"URLDownloadToFile",
            b"cmd.exe",
            b"powershell",
            b"RegSetValueEx",
            b"CreateService",
        ];
        for pattern in suspicious_pe_strings {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                let name = String::from_utf8_lossy(pattern).to_string();
                // Avoid duplicates from the import-table scan above.
                // Strip trailing A/W suffix for comparison, because imports
                // like VirtualAllocExW and raw strings VirtualAllocEx refer
                // to the same API.
                let name_base = name
                    .strip_suffix('A')
                    .or_else(|| name.strip_suffix('W'))
                    .unwrap_or(&name);
                let already_found = findings.iter().any(|f| {
                    if let Finding::SuspiciousApi(n) = f {
                        let n_base = n.strip_suffix('A').or_else(|| n.strip_suffix('W')).unwrap_or(n);
                        n_base.eq_ignore_ascii_case(name_base)
                    } else {
                        false
                    }
                });
                if !already_found {
                    findings.push(Finding::SuspiciousApi(name));
                }
            }
        }

        // ── Packer detection ─────────────────────────────────────────
        if let Some(packer) = detect_packer(pe) {
            let name = packer.to_string();
            debug!(%name, "packer detected");
            findings.push(Finding::PackerDetected(name));

            if matches!(packer, packer::PackerType::UPX) {
                findings.push(Finding::UPXPacked);
            }
        }

        // ── Entry point anomaly ──────────────────────────────────────
        if check_entry_point_anomaly(pe) {
            debug!("entry point anomaly detected");
            // Entry point anomalies strengthen packer suspicion. If no packer
            // was detected by section name, record a suspicious section.
            if !findings.iter().any(|f| matches!(f, Finding::PackerDetected(_))) {
                findings.push(Finding::SuspiciousSection("EP anomaly".to_string()));
            }
        }

        // ── Timestamp check ──────────────────────────────────────────
        if pe.timestamp == 0 {
            debug!("PE timestamp is zero");
            findings.push(Finding::ZeroTimestamp);
        }

        // ── No imports ───────────────────────────────────────────────
        let total_imports: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
        if total_imports == 0 {
            debug!("PE has no imports");
            findings.push(Finding::NoImports);
        }

        // ── Unusually high import count ──────────────────────────────
        // Very high import counts (>1000 unique functions) can indicate
        // API-hash resolvers that import everything.
        if total_imports > 1000 {
            debug!(total_imports, "unusually high import count");
            findings.push(Finding::HighImportCount);
        }
    }

    /// ELF-specific heuristic checks (Linux malware detection).
    #[allow(clippy::unused_self)] // Method for future ML model integration
    fn analyze_elf(&self, elf: &prx_sd_parsers::elf::ElfInfo, data: &[u8], findings: &mut Vec<Finding>) {
        // High-entropy ELF sections (packed/encrypted)
        for section in &elf.sections {
            if section.entropy > 7.0 && section.raw_size > 512 {
                findings.push(Finding::PackedSection {
                    name: section.name.clone(),
                    entropy: section.entropy,
                });
            }
        }

        // Suspicious strings in ELF binaries
        let suspicious_patterns: &[&[u8]] = &[
            b"/dev/tcp/",       // bash reverse shell
            b"LD_PRELOAD",      // rootkit injection
            b"/proc/self/exe",  // self-replication
            b"ptrace",          // anti-debug (was ptrace(PTRACE_ — too specific)
            b"getdents",        // directory listing hook — matches getdents and getdents64
            b"/etc/shadow",     // credential theft
            b"authorized_keys", // SSH backdoor
            b"crontab",         // persistence
            b"/etc/systemd",    // systemd persistence (was /etc/systemd/system — too specific)
            b"stratum+tcp",     // cryptominer (was stratum+tcp:// — too specific)
            b"kdevtmpfsi",      // Kinsing miner
            b"xmrig",           // cryptominer
            b"rootkit",         // explicit rootkit string
            b"hide_pid",        // rootkit indicator
            b"sys_call_table",  // rootkit indicator
            b"module_hide",     // rootkit indicator
            b"/bin/sh",         // shell access
            b"reverse",         // reverse shell
            b"backdoor",        // explicit backdoor string
        ];

        for pattern in suspicious_patterns {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                let name = String::from_utf8_lossy(pattern).to_string();
                findings.push(Finding::SuspiciousApi(name));
            }
        }

        // No symbols at all in a dynamically linked ELF is suspicious
        if elf.symbols.is_empty() && !elf.dynamic_libs.is_empty() {
            findings.push(Finding::NoImports);
        }

        // Statically linked + high entropy = likely packed malware
        if elf.dynamic_libs.is_empty() && elf.interpreter.is_none() {
            let overall = crate::entropy::shannon_entropy(data);
            if overall > 6.8 {
                findings.push(Finding::PackerDetected("static+packed ELF".to_string()));
            }
        }
    }

    /// Mach-O-specific heuristic checks (macOS malware detection).
    #[allow(clippy::unused_self)] // Method for future ML model integration
    fn analyze_macho(&self, macho: &prx_sd_parsers::macho::MachOInfo, data: &[u8], findings: &mut Vec<Finding>) {
        // High-entropy Mach-O sections
        for section in &macho.sections {
            if section.entropy > 7.0 && section.raw_size > 512 {
                findings.push(Finding::PackedSection {
                    name: section.name.clone(),
                    entropy: section.entropy,
                });
            }
        }

        // Suspicious macOS-specific strings
        let suspicious_patterns: &[&[u8]] = &[
            b"osascript",                  // AppleScript execution
            b"DYLD_INSERT_LIBRARIES",      // dylib injection
            b"LaunchAgents",               // persistence
            b"LaunchDaemons",              // persistence
            b"security find-generic-pass", // keychain theft
            b"spctl --master-disable",     // Gatekeeper bypass
            b"com.apple.quarantine",       // quarantine flag manipulation
            b"xattr -d",                   // remove extended attributes
            b"screencapture",              // screen spying
            b"AVCaptureSession",           // camera access
            b"CGWindowListCreateImage",    // screen capture API
        ];

        for pattern in suspicious_patterns {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                let name = String::from_utf8_lossy(pattern).to_string();
                findings.push(Finding::SuspiciousApi(name));
            }
        }

        // Suspicious imports
        let suspicious_imports = [
            "ptrace",
            "dlopen",
            "NSTask",
            "system",
            "popen",
            "SecKeychainCopyDefault",
            "IOServiceGetMatchingService",
        ];
        for imp in &macho.imports {
            if suspicious_imports.iter().any(|s| imp.contains(s)) {
                findings.push(Finding::SuspiciousApi(imp.clone()));
            }
        }
    }

    /// Office-specific macro analysis.
    #[allow(clippy::unused_self)] // Method for future ML model integration
    fn analyze_office_macros(&self, data: &[u8], findings: &mut Vec<Finding>) {
        let analysis = match prx_sd_parsers::office::analyze_office(data) {
            Ok(a) => a,
            Err(e) => {
                debug!("Office macro analysis failed: {e}");
                return;
            }
        };

        if analysis.has_macros {
            findings.push(Finding::OfficeMacros);
        }

        for trigger in &analysis.auto_exec_macros {
            findings.push(Finding::OfficeAutoExecMacro(trigger.clone()));
        }

        let has_shell = analysis.suspicious_functions.iter().any(|f| {
            matches!(
                f.category,
                prx_sd_parsers::MacroThreatCategory::ShellExecution
                    | prx_sd_parsers::MacroThreatCategory::ProcessCreation
            )
        });
        if has_shell {
            findings.push(Finding::OfficeShellExecution);
        }

        let has_network = analysis
            .suspicious_functions
            .iter()
            .any(|f| f.category == prx_sd_parsers::MacroThreatCategory::Network);
        if has_network {
            findings.push(Finding::OfficeNetworkAccess);
        }

        if analysis.has_dde {
            findings.push(Finding::OfficeDde);
        }

        if analysis.obfuscation_score > 15 {
            findings.push(Finding::OfficeObfuscation(analysis.obfuscation_score));
        }

        if analysis.threat_score > 0 {
            findings.push(Finding::OfficeMacroThreatScore(analysis.threat_score));
        }
    }

    /// PDF-specific exploit analysis.
    #[allow(clippy::unused_self)] // Method for future ML model integration
    fn analyze_pdf_exploits(&self, data: &[u8], findings: &mut Vec<Finding>) {
        let analysis = match prx_sd_parsers::pdf::analyze_pdf(data) {
            Ok(a) => a,
            Err(e) => {
                debug!("PDF exploit analysis failed: {e}");
                return;
            }
        };

        if analysis.has_javascript {
            debug!(count = analysis.javascript_count, "PDF contains JavaScript");
            findings.push(Finding::PdfJavaScript);
        }

        if analysis.has_launch_action {
            debug!("PDF contains Launch action");
            findings.push(Finding::PdfLaunchAction);
        }

        if analysis.has_open_action && analysis.has_javascript {
            debug!("PDF auto-executes JavaScript");
            findings.push(Finding::PdfAutoExecJavaScript);
        }

        // Report individual CVE patterns
        for pattern in &analysis.suspicious_patterns {
            if pattern.pattern_name.starts_with("CVE-") {
                debug!(cve = %pattern.pattern_name, "PDF CVE pattern detected");
                findings.push(Finding::PdfCvePattern(pattern.pattern_name.clone()));
            }
        }

        // Contribute the PDF-specific threat score to the overall heuristic
        if analysis.threat_score > 0 {
            findings.push(Finding::PdfThreatScore(analysis.threat_score));
        }
    }
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::needless_collect
)]
mod tests {
    use super::*;
    use prx_sd_parsers::pe::{ImportInfo, PeInfo, SectionInfo};

    fn make_pe(sections: Vec<SectionInfo>, imports: Vec<ImportInfo>, timestamp: u32) -> ParsedFile {
        ParsedFile::PE(PeInfo {
            is_64bit: false,
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

    #[test]
    fn clean_pe_scores_low() {
        let parsed = make_pe(
            vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x5000,
                raw_size: 0x4800,
                entropy: 6.2,
                characteristics: 0x6000_0020, // CODE | EXECUTE | READ
            }],
            vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec!["GetProcAddress".to_string(), "LoadLibraryA".to_string()],
            }],
            0x6000_0000,
        );

        let engine = HeuristicEngine::new();
        let result = engine.analyze(&[0u8; 100], &parsed);

        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(result.score < 30);
    }

    #[test]
    fn packed_pe_scores_high() {
        let parsed = make_pe(
            vec![
                SectionInfo {
                    name: "UPX0".to_string(),
                    virtual_size: 0x10000,
                    raw_size: 0,
                    entropy: 0.0,
                    characteristics: 0xE000_0020,
                },
                SectionInfo {
                    name: "UPX1".to_string(),
                    virtual_size: 0x8000,
                    raw_size: 0x7000,
                    entropy: 7.8,
                    characteristics: 0xE000_0020,
                },
            ],
            vec![],
            0,
        );

        // Simulate high-entropy data.
        let mut data = Vec::with_capacity(256 * 40);
        for _ in 0..40 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }

        let engine = HeuristicEngine::new();
        let result = engine.analyze(&data, &parsed);

        assert!(result.score >= 60, "expected malicious score, got {}", result.score);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);

        // Should have packer-related findings.
        assert!(result.findings.iter().any(|f| matches!(f, Finding::PackerDetected(_))));
        assert!(result.findings.iter().any(|f| matches!(f, Finding::UPXPacked)));
        assert!(result.findings.iter().any(|f| matches!(f, Finding::NoImports)));
    }

    #[test]
    fn suspicious_api_detection() {
        let parsed = make_pe(
            vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x5000,
                raw_size: 0x4800,
                entropy: 6.0,
                characteristics: 0x6000_0020,
            }],
            vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec![
                    "VirtualAllocEx".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ],
            }],
            0x6000_0000,
        );

        let engine = HeuristicEngine::new();
        let result = engine.analyze(&[0u8; 100], &parsed);

        let api_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| matches!(f, Finding::SuspiciousApi(_)))
            .collect();
        assert_eq!(api_findings.len(), 3);
    }

    #[test]
    fn zero_timestamp_detected() {
        let parsed = make_pe(
            vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x1000,
                raw_size: 0x1000,
                entropy: 5.0,
                characteristics: 0x6000_0020,
            }],
            vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec!["GetProcAddress".to_string()],
            }],
            0, // zero timestamp
        );

        let engine = HeuristicEngine::new();
        let result = engine.analyze(&[0u8; 100], &parsed);

        assert!(result.findings.contains(&Finding::ZeroTimestamp));
    }

    #[test]
    fn writable_code_section_detected() {
        let parsed = make_pe(
            vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x5000,
                raw_size: 0x4800,
                entropy: 6.0,
                // CODE | EXECUTE | READ | WRITE
                characteristics: 0xE000_0020,
            }],
            vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec!["GetProcAddress".to_string()],
            }],
            0x6000_0000,
        );

        let engine = HeuristicEngine::new();
        let result = engine.analyze(&[0u8; 100], &parsed);

        assert!(result.findings.contains(&Finding::WritableCodeSection));
    }

    #[test]
    fn threat_level_display() {
        assert_eq!(ThreatLevel::Clean.to_string(), "Clean");
        assert_eq!(ThreatLevel::Suspicious.to_string(), "Suspicious");
        assert_eq!(ThreatLevel::Malicious.to_string(), "Malicious");
    }

    #[test]
    fn threat_level_from_score_boundaries() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(29), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(59), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(60), ThreatLevel::Malicious);
        assert_eq!(ThreatLevel::from_score(100), ThreatLevel::Malicious);
    }

    #[test]
    fn finding_display() {
        let f = Finding::HighEntropy(7.85);
        assert_eq!(f.to_string(), "High overall entropy: 7.85");

        let f = Finding::PackerDetected("UPX".to_string());
        assert_eq!(f.to_string(), "Packer detected: UPX");
    }

    #[test]
    fn engine_default() {
        let engine = HeuristicEngine::default();
        let parsed = make_pe(
            vec![],
            vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec!["GetProcAddress".to_string()],
            }],
            0x6000_0000,
        );
        let result = engine.analyze(&[0u8; 10], &parsed);
        assert_eq!(result.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn engine_initialises_without_onnx_models() {
        // Default engine should work in fallback mode
        let engine = HeuristicEngine::new();
        assert!(!engine.ml_model.has_onnx_models());
    }

    #[test]
    fn ml_score_returns_prediction_for_pe() {
        let parsed = make_pe(
            vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x5000,
                raw_size: 0x4800,
                entropy: 6.2,
                characteristics: 0x6000_0020,
            }],
            vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec!["GetProcAddress".to_string()],
            }],
            0x6000_0000,
        );

        let engine = HeuristicEngine::new();
        let pred = engine.ml_score(&[0u8; 100], &parsed);
        assert!(pred.is_some());
        let pred = pred.unwrap();
        assert!(pred.malicious_probability >= 0.0);
        assert!(pred.malicious_probability <= 1.0);
        assert_eq!(pred.model_type, "heuristic_fallback");
    }

    #[test]
    fn ml_score_returns_none_for_unparsed() {
        let parsed = ParsedFile::Unparsed {
            file_type: prx_sd_parsers::FileType::Unknown,
            size: 100,
        };
        let engine = HeuristicEngine::new();
        let pred = engine.ml_score(&[0u8; 100], &parsed);
        assert!(pred.is_none());
    }

    #[test]
    fn with_models_nonexistent_path() {
        let engine = HeuristicEngine::with_models(std::path::Path::new("/nonexistent"));
        assert!(!engine.ml_model.has_onnx_models());
        // Should still work
        let parsed = make_pe(vec![], vec![], 0);
        let result = engine.analyze(&[0u8; 10], &parsed);
        assert!(result.score <= 100);
    }
}
