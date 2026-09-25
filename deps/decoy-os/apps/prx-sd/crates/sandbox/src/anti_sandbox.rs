//! Anti-sandbox evasion detection.
//!
//! Detects when malware attempts to evade sandbox analysis through:
//! - Sleep/timing checks (extended delays to outlast sandbox timeout)
//! - VM/hypervisor detection (CPUID, MAC address, hardware fingerprinting)
//! - Environment fingerprinting (username, hostname, disk size, process count)
//! - Debugger detection (ptrace, `IsDebuggerPresent`, timing checks)
//! - User interaction checks (mouse movement, click count, screen resolution)

use serde::{Deserialize, Serialize};

/// Result of anti-sandbox evasion analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiSandboxResult {
    /// Detected evasion techniques.
    pub techniques: Vec<EvasionTechnique>,
    /// Overall evasion score (0-100). Higher = more evasive.
    pub evasion_score: u32,
    /// Whether the sample is likely sandbox-aware.
    pub is_evasive: bool,
}

/// A detected anti-sandbox evasion technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionTechnique {
    /// Technique name.
    pub name: String,
    /// MITRE ATT&CK technique ID, if applicable.
    pub mitre_id: Option<String>,
    /// Category of evasion.
    pub category: EvasionCategory,
    /// Description of the detection.
    pub description: String,
    /// Severity (1-10).
    pub severity: u32,
}

/// Categories of anti-sandbox evasion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvasionCategory {
    /// Timing-based evasion (sleep, `GetTickCount`, rdtsc).
    Timing,
    /// Virtual machine detection (CPUID, registry, hardware).
    VmDetection,
    /// Environment fingerprinting (username, hostname, processes).
    EnvironmentCheck,
    /// Debugger detection (ptrace, `IsDebuggerPresent`, int3).
    DebuggerDetection,
    /// User interaction check (mouse, keyboard, window focus).
    UserInteraction,
    /// Hardware fingerprinting (disk size, RAM, CPU count).
    HardwareCheck,
}

/// Analyze binary data (PE/ELF) for anti-sandbox evasion indicators.
///
/// Scans for strings and byte patterns commonly used by malware to detect
/// analysis environments and evade detection.
pub fn detect_evasion(data: &[u8]) -> AntiSandboxResult {
    let mut techniques = Vec::new();

    // Extract printable strings for pattern matching.
    let strings = extract_strings(data, 5);

    // ── Timing evasion ─────────────────────────────────────────────────
    check_timing_evasion(&strings, data, &mut techniques);

    // ── VM detection ───────────────────────────────────────────────────
    check_vm_detection(&strings, data, &mut techniques);

    // ── Environment fingerprinting ─────────────────────────────────────
    check_environment_fingerprinting(&strings, &mut techniques);

    // ── Debugger detection ─────────────────────────────────────────────
    check_debugger_detection(&strings, data, &mut techniques);

    // ── User interaction checks ────────────────────────────────────────
    check_user_interaction(&strings, &mut techniques);

    // ── Hardware fingerprinting ────────────────────────────────────────
    check_hardware_fingerprinting(&strings, &mut techniques);

    let evasion_score = techniques.iter().map(|t| t.severity * 5).sum::<u32>().min(100);

    AntiSandboxResult {
        is_evasive: evasion_score >= 30,
        evasion_score,
        techniques,
    }
}

// ── Timing evasion ──────────────────────────────────────────────────────────

fn check_timing_evasion(strings: &[String], data: &[u8], out: &mut Vec<EvasionTechnique>) {
    let timing_apis = [
        ("GetTickCount", "T1497.003"),
        ("QueryPerformanceCounter", "T1497.003"),
        ("NtQuerySystemTime", "T1497.003"),
        ("timeGetTime", "T1497.003"),
        ("NtDelayExecution", "T1497.003"),
        ("SetTimer", "T1497.003"),
    ];

    for (api, mitre) in &timing_apis {
        if strings.iter().any(|s| s.contains(api)) {
            out.push(EvasionTechnique {
                name: format!("Timing API: {api}"),
                mitre_id: Some(mitre.to_string()),
                category: EvasionCategory::Timing,
                description: format!("References timing API {api} (potential sandbox delay check)"),
                severity: 3,
            });
        }
    }

    // Check for rdtsc instruction (x86: 0F 31)
    if contains_bytes(data, &[0x0F, 0x31]) {
        out.push(EvasionTechnique {
            name: "RDTSC instruction".to_string(),
            mitre_id: Some("T1497.003".to_string()),
            category: EvasionCategory::Timing,
            description: "Contains RDTSC instruction for CPU cycle timing measurement".to_string(),
            severity: 4,
        });
    }

    // Large sleep values
    let sleep_patterns = ["Sleep(", "sleep(", "nanosleep", "usleep"];
    for pat in &sleep_patterns {
        if strings.iter().any(|s| s.contains(pat)) {
            out.push(EvasionTechnique {
                name: format!("Sleep API: {pat}"),
                mitre_id: Some("T1497.003".to_string()),
                category: EvasionCategory::Timing,
                description: "References sleep function (may use extended delay to evade sandbox timeout)".to_string(),
                severity: 2,
            });
            break;
        }
    }
}

// ── VM detection ────────────────────────────────────────────────────────────

fn check_vm_detection(strings: &[String], data: &[u8], out: &mut Vec<EvasionTechnique>) {
    // Hypervisor-specific strings
    let vm_indicators = [
        ("VMware", "VMware hypervisor", 5),
        ("VBoxGuest", "VirtualBox guest additions", 5),
        ("VBOX", "VirtualBox indicator", 4),
        ("vbox", "VirtualBox indicator", 4),
        ("Virtual HD", "Virtual hard disk", 4),
        ("QEMU", "QEMU hypervisor", 5),
        ("Xen", "Xen hypervisor", 3),
        ("Hyper-V", "Hyper-V hypervisor", 4),
        ("vmtoolsd", "VMware Tools daemon", 6),
        ("vmwaretray", "VMware Tray", 6),
        ("VBoxService", "VirtualBox service", 6),
        ("VBoxTray", "VirtualBox tray", 6),
        ("wine_get_unix_file_name", "Wine detection", 5),
        ("sbiedll", "Sandboxie DLL", 7),
        ("SbieDll", "Sandboxie DLL", 7),
        ("cuckoomon", "Cuckoo sandbox monitor", 8),
        ("dbghelp", "Debug helper (analysis tool)", 3),
    ];

    for (indicator, desc, severity) in &vm_indicators {
        if strings.iter().any(|s| s.contains(indicator)) {
            out.push(EvasionTechnique {
                name: format!("VM indicator: {indicator}"),
                mitre_id: Some("T1497.001".to_string()),
                category: EvasionCategory::VmDetection,
                description: format!("References {desc}"),
                severity: *severity,
            });
        }
    }

    // VM-specific MAC address prefixes (OUI)
    let vm_macs = [
        "00:05:69", // VMware
        "00:0C:29", // VMware
        "00:1C:14", // VMware
        "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "52:54:00", // QEMU/KVM
    ];
    for mac in &vm_macs {
        if strings.iter().any(|s| s.contains(mac)) {
            out.push(EvasionTechnique {
                name: format!("VM MAC address: {mac}"),
                mitre_id: Some("T1497.001".to_string()),
                category: EvasionCategory::VmDetection,
                description: format!("Checks for VM-specific MAC prefix {mac}"),
                severity: 6,
            });
        }
    }

    // CPUID check (x86: 0F A2)
    if contains_bytes(data, &[0x0F, 0xA2]) {
        // CPUID is common, only flag if combined with other VM checks
        let has_other_vm = out.iter().any(|t| t.category == EvasionCategory::VmDetection);
        if has_other_vm {
            out.push(EvasionTechnique {
                name: "CPUID instruction".to_string(),
                mitre_id: Some("T1497.001".to_string()),
                category: EvasionCategory::VmDetection,
                description: "Contains CPUID instruction (combined with other VM checks)".to_string(),
                severity: 4,
            });
        }
    }
}

// ── Environment fingerprinting ──────────────────────────────────────────────

fn check_environment_fingerprinting(strings: &[String], out: &mut Vec<EvasionTechnique>) {
    let env_checks = [
        ("GetComputerName", "Computer name check", 3),
        ("GetUserName", "Username check", 3),
        ("COMPUTERNAME", "Computer name env var", 3),
        ("USERNAME", "Username env var", 2),
        ("NUMBER_OF_PROCESSORS", "CPU count check", 4),
        ("SystemRoot", "System root check", 2),
        ("PROCESSOR_IDENTIFIER", "CPU identifier check", 4),
        ("GetSystemInfo", "System info query", 3),
        ("GlobalMemoryStatusEx", "Memory size check", 4),
        ("GetDiskFreeSpace", "Disk size check", 4),
    ];

    let mut env_count = 0u32;
    for (pattern, desc, severity) in &env_checks {
        if strings.iter().any(|s| s.contains(pattern)) {
            env_count += 1;
            // Only report individual if severity >= 4
            if *severity >= 4 {
                out.push(EvasionTechnique {
                    name: format!("Environment check: {pattern}"),
                    mitre_id: Some("T1497.001".to_string()),
                    category: EvasionCategory::EnvironmentCheck,
                    description: format!("{desc} (potential sandbox fingerprinting)"),
                    severity: *severity,
                });
            }
        }
    }

    // Flag if multiple environment checks are present (fingerprinting behavior)
    if env_count >= 3 {
        out.push(EvasionTechnique {
            name: "Multiple environment checks".to_string(),
            mitre_id: Some("T1497.001".to_string()),
            category: EvasionCategory::EnvironmentCheck,
            description: format!("{env_count} environment queries detected (sandbox fingerprinting)"),
            severity: 5,
        });
    }
}

// ── Debugger detection ──────────────────────────────────────────────────────

fn check_debugger_detection(strings: &[String], data: &[u8], out: &mut Vec<EvasionTechnique>) {
    let dbg_apis = [
        ("IsDebuggerPresent", "T1622", 6),
        ("CheckRemoteDebuggerPresent", "T1622", 7),
        ("NtQueryInformationProcess", "T1622", 5),
        ("OutputDebugString", "T1622", 3),
        ("CloseHandle", "T1622", 2), // Anti-debug trick with invalid handle
    ];

    for (api, mitre, severity) in &dbg_apis {
        if strings.iter().any(|s| s.contains(api)) {
            out.push(EvasionTechnique {
                name: format!("Anti-debug: {api}"),
                mitre_id: Some(mitre.to_string()),
                category: EvasionCategory::DebuggerDetection,
                description: format!("References debugger detection API {api}"),
                severity: *severity,
            });
        }
    }

    // Linux: ptrace(PTRACE_TRACEME) self-check
    if strings.iter().any(|s| s.contains("ptrace")) {
        out.push(EvasionTechnique {
            name: "ptrace anti-debug".to_string(),
            mitre_id: Some("T1622".to_string()),
            category: EvasionCategory::DebuggerDetection,
            description: "References ptrace (Linux anti-debug via PTRACE_TRACEME self-attach)".to_string(),
            severity: 5,
        });
    }

    // INT 3 breakpoint (0xCC) density check -- many int3s may indicate anti-debug
    #[allow(clippy::naive_bytecount)] // avoiding external dependency for simple count
    let int3_count = data.iter().filter(|&&b| b == 0xCC).count();
    let ratio = if data.is_empty() {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)] // precision loss acceptable for ratio computation
        {
            int3_count as f64 / data.len() as f64
        }
    };
    if ratio > 0.01 && int3_count > 50 {
        out.push(EvasionTechnique {
            name: "High INT3 density".to_string(),
            mitre_id: Some("T1622".to_string()),
            category: EvasionCategory::DebuggerDetection,
            description: format!(
                "{int3_count} INT3 (0xCC) instructions detected ({:.2}% of file)",
                ratio * 100.0
            ),
            severity: 4,
        });
    }
}

// ── User interaction checks ─────────────────────────────────────────────────

fn check_user_interaction(strings: &[String], out: &mut Vec<EvasionTechnique>) {
    let ui_checks = [
        ("GetCursorPos", "Mouse position tracking", 5),
        ("GetAsyncKeyState", "Keyboard state polling", 5),
        ("GetForegroundWindow", "Foreground window check", 4),
        ("GetLastInputInfo", "Last user input time", 5),
        ("GetSystemMetrics", "Screen resolution check", 3),
        ("EnumWindows", "Window enumeration", 3),
        ("FindWindow", "Specific window check", 3),
    ];

    for (api, desc, severity) in &ui_checks {
        if strings.iter().any(|s| s.contains(api)) {
            out.push(EvasionTechnique {
                name: format!("UI check: {api}"),
                mitre_id: Some("T1497.002".to_string()),
                category: EvasionCategory::UserInteraction,
                description: format!("{desc} (sandbox usually has no user interaction)"),
                severity: *severity,
            });
        }
    }
}

// ── Hardware fingerprinting ─────────────────────────────────────────────────

fn check_hardware_fingerprinting(strings: &[String], out: &mut Vec<EvasionTechnique>) {
    let hw_checks = [
        ("Win32_BIOS", "BIOS WMI query", 5),
        ("Win32_ComputerSystem", "System WMI query", 4),
        ("Win32_DiskDrive", "Disk WMI query", 5),
        ("Win32_PhysicalMemory", "RAM WMI query", 4),
        ("Win32_Processor", "CPU WMI query", 3),
        ("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOS registry key", 5),
        ("SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "Disk registry enum", 5),
        ("/sys/class/dmi/id/", "Linux DMI hardware info", 4),
        ("/sys/devices/virtual/", "Linux virtual device check", 5),
        ("systemd-detect-virt", "Linux VM detection command", 6),
        ("dmidecode", "Linux hardware fingerprinting", 4),
    ];

    for (pattern, desc, severity) in &hw_checks {
        if strings.iter().any(|s| s.contains(pattern)) {
            out.push(EvasionTechnique {
                name: format!("Hardware check: {pattern}"),
                mitre_id: Some("T1497.001".to_string()),
                category: EvasionCategory::HardwareCheck,
                description: format!("{desc} (potential sandbox/VM detection)"),
                severity: *severity,
            });
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract printable ASCII strings of at least `min_len` characters from binary data.
fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
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

/// Check if `data` contains the byte sequence `needle`.
fn contains_bytes(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_data() {
        let data = b"This is a perfectly normal file with nothing suspicious.";
        let result = detect_evasion(data);
        assert!(!result.is_evasive);
        assert_eq!(result.evasion_score, 0);
        assert!(result.techniques.is_empty());
    }

    #[test]
    fn test_vm_detection_strings() {
        let data = b"checking VMware\x00VBoxService.exe\x00\x00normal text";
        let result = detect_evasion(data);
        assert!(result.is_evasive);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| t.category == EvasionCategory::VmDetection)
        );
    }

    #[test]
    fn test_debugger_detection() {
        let data = b"call IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00";
        let result = detect_evasion(data);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| t.category == EvasionCategory::DebuggerDetection)
        );
    }

    #[test]
    fn test_timing_evasion_rdtsc() {
        // 0F 31 = RDTSC instruction
        let mut data = vec![0u8; 100];
        data[50] = 0x0F;
        data[51] = 0x31;
        // Add a timing API string to trigger combined detection
        data.extend_from_slice(b"GetTickCount\x00Sleep(\x00");
        let result = detect_evasion(&data);
        assert!(result.techniques.iter().any(|t| t.category == EvasionCategory::Timing));
    }

    #[test]
    fn test_sandbox_specific_strings() {
        let data = b"\x00cuckoomon.dll\x00sbiedll.dll\x00";
        let result = detect_evasion(data);
        assert!(result.is_evasive);
        assert!(result.techniques.iter().any(|t| t.severity >= 7));
    }

    #[test]
    fn test_environment_fingerprinting() {
        let data = b"GetComputerNameA\x00GetUserNameW\x00NUMBER_OF_PROCESSORS\x00GetDiskFreeSpace\x00";
        let result = detect_evasion(data);
        assert!(
            result
                .techniques
                .iter()
                .any(|t| t.category == EvasionCategory::EnvironmentCheck)
        );
        // Should detect "multiple environment checks"
        assert!(result.techniques.iter().any(|t| t.name.contains("Multiple")));
    }

    #[test]
    fn test_extract_strings() {
        let data = b"\x00hello world\x00ab\x00longer string here\x00";
        let strings = extract_strings(data, 5);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0], "hello world");
        assert_eq!(strings[1], "longer string here");
    }

    #[test]
    fn test_contains_bytes() {
        assert!(contains_bytes(&[1, 2, 3, 4, 5], &[3, 4]));
        assert!(!contains_bytes(&[1, 2, 3], &[4, 5]));
        assert!(contains_bytes(&[0x0F, 0x31], &[0x0F, 0x31]));
    }
}
