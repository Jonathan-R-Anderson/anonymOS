//! Detection of suspicious Windows API imports and Linux syscalls.
//!
//! Many malware families use a characteristic set of API calls for process
//! injection, anti-debugging, persistence, and data exfiltration. This module
//! provides a static catalogue of such APIs along with risk weights.

use prx_sd_parsers::pe::ImportInfo;
use serde::{Deserialize, Serialize};

/// Broad categories of suspicious API behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    /// Code injection into another process (e.g. `VirtualAllocEx` + `WriteProcessMemory`).
    ProcessInjection,
    /// Techniques to detect or evade debuggers.
    AntiDebug,
    /// Registry / service manipulation for persistence.
    Persistence,
    /// Network operations commonly used for data exfiltration or C2.
    NetworkExfil,
    /// Cryptographic APIs (potential ransomware indicator).
    Crypto,
    /// Privilege escalation / token manipulation.
    Privilege,
    /// Suspicious filesystem operations.
    FileSystem,
}

impl std::fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessInjection => write!(f, "ProcessInjection"),
            Self::AntiDebug => write!(f, "AntiDebug"),
            Self::Persistence => write!(f, "Persistence"),
            Self::NetworkExfil => write!(f, "NetworkExfil"),
            Self::Crypto => write!(f, "Crypto"),
            Self::Privilege => write!(f, "Privilege"),
            Self::FileSystem => write!(f, "FileSystem"),
        }
    }
}

/// A single suspicious API entry with its category and risk weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousApiEntry {
    pub category: ApiCategory,
    pub name: &'static str,
    /// Risk weight in the range 1..=10. Higher values indicate greater malicious
    /// likelihood when this API is found in an import table.
    pub weight: u32,
}

/// Comprehensive list of suspicious Windows API imports.
///
/// Each entry carries a risk weight (1-10) reflecting how indicative of
/// malicious behaviour the import is in isolation.
pub static WINDOWS_SUSPICIOUS_APIS: &[SuspiciousApiEntry] = &[
    // ── Process Injection ──────────────────────────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "VirtualAlloc",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "VirtualAllocEx",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "WriteProcessMemory",
        weight: 8,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "ReadProcessMemory",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "CreateRemoteThread",
        weight: 9,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "CreateRemoteThreadEx",
        weight: 9,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "NtUnmapViewOfSection",
        weight: 8,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "QueueUserAPC",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "NtWriteVirtualMemory",
        weight: 8,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "RtlCreateUserThread",
        weight: 8,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "SetWindowsHookEx",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::ProcessInjection,
        name: "NtAllocateVirtualMemory",
        weight: 6,
    },
    // ── Anti-Debug ─────────────────────────────────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "IsDebuggerPresent",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "CheckRemoteDebuggerPresent",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "NtQueryInformationProcess",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "OutputDebugStringA",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "OutputDebugStringW",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "NtSetInformationThread",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::AntiDebug,
        name: "NtQuerySystemInformation",
        weight: 5,
    },
    // ── Persistence ────────────────────────────────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "RegSetValueExA",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "RegSetValueExW",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "RegOpenKeyExA",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "RegOpenKeyExW",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "CreateServiceA",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "CreateServiceW",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "RegCreateKeyExA",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Persistence,
        name: "RegCreateKeyExW",
        weight: 4,
    },
    // ── Network Exfiltration / C2 ──────────────────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "InternetOpenA",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "InternetOpenW",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "InternetOpenUrlA",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "InternetOpenUrlW",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "URLDownloadToFileA",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "URLDownloadToFileW",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "HttpSendRequestA",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "HttpSendRequestW",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "WinHttpOpen",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "WinHttpSendRequest",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::NetworkExfil,
        name: "WSAStartup",
        weight: 3,
    },
    // ── Crypto (ransomware indicators) ─────────────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptEncrypt",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptDecrypt",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptAcquireContextA",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptAcquireContextW",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptGenKey",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptImportKey",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "CryptDestroyKey",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "BCryptEncrypt",
        weight: 6,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Crypto,
        name: "BCryptDecrypt",
        weight: 5,
    },
    // ── Privilege Escalation ───────────────────────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::Privilege,
        name: "AdjustTokenPrivileges",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Privilege,
        name: "OpenProcessToken",
        weight: 5,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Privilege,
        name: "LookupPrivilegeValueA",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Privilege,
        name: "LookupPrivilegeValueW",
        weight: 4,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Privilege,
        name: "ImpersonateLoggedOnUser",
        weight: 7,
    },
    SuspiciousApiEntry {
        category: ApiCategory::Privilege,
        name: "DuplicateToken",
        weight: 5,
    },
    // ── Filesystem (suspicious usage patterns) ─────────────────────────
    SuspiciousApiEntry {
        category: ApiCategory::FileSystem,
        name: "DeleteFileA",
        weight: 2,
    },
    SuspiciousApiEntry {
        category: ApiCategory::FileSystem,
        name: "DeleteFileW",
        weight: 2,
    },
    SuspiciousApiEntry {
        category: ApiCategory::FileSystem,
        name: "MoveFileExA",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::FileSystem,
        name: "MoveFileExW",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::FileSystem,
        name: "CreateFileMapping",
        weight: 3,
    },
    SuspiciousApiEntry {
        category: ApiCategory::FileSystem,
        name: "MapViewOfFile",
        weight: 3,
    },
];

/// Suspicious Linux syscalls / libc calls commonly abused by malware.
pub static LINUX_SUSPICIOUS_CALLS: &[&str] = &[
    "ptrace",
    "mprotect",
    "memfd_create",
    "execveat",
    "process_vm_readv",
    "process_vm_writev",
    "mmap",
    "prctl",
    "clone3",
    "unlinkat",
    "fexecve",
    "dlopen",
    "dlsym",
    "syscall",
    "fork",
    "execve",
    "kill",
    "socket",
    "connect",
    "sendto",
    "recvfrom",
];

/// Scan a PE file's import table for suspicious API calls.
///
/// Returns a vector of `(category, api_name, weight)` tuples for every
/// imported function that matches the known-suspicious catalogue.
pub fn check_suspicious_imports(imports: &[ImportInfo]) -> Vec<(ApiCategory, String, u32)> {
    let mut hits = Vec::new();

    for imp in imports {
        for func in &imp.functions {
            // Try both an exact match and a suffix-stripped match (some imports
            // appear as ordinals like "Ordinal123" which we skip).
            for entry in WINDOWS_SUSPICIOUS_APIS {
                if func_matches(func, entry.name) {
                    hits.push((entry.category, func.clone(), entry.weight));
                    break;
                }
            }
        }
    }

    hits
}

/// Check whether an imported function name matches a suspicious API entry.
///
/// Handles common variations:
/// - Exact match (case-insensitive)
/// - Match ignoring trailing A/W suffix (e.g. "`RegSetValueEx`" matches
///   both "`RegSetValueExA`" and "`RegSetValueExW`" entries)
fn func_matches(imported: &str, suspicious: &str) -> bool {
    if imported.eq_ignore_ascii_case(suspicious) {
        return true;
    }

    // Bidirectional A/W suffix stripping — both the imported name and the
    // suspicious-API catalog entry may carry platform-specific suffixes.
    let imported_base = imported
        .strip_suffix('A')
        .or_else(|| imported.strip_suffix('W'))
        .unwrap_or(imported);
    let suspicious_base = suspicious
        .strip_suffix('A')
        .or_else(|| suspicious.strip_suffix('W'))
        .unwrap_or(suspicious);

    imported_base.eq_ignore_ascii_case(suspicious_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(func_matches("VirtualAllocEx", "VirtualAllocEx"));
    }

    #[test]
    fn case_insensitive_match() {
        assert!(func_matches("virtualallocex", "VirtualAllocEx"));
    }

    #[test]
    fn suffix_stripped_match() {
        assert!(func_matches("RegSetValueExA", "RegSetValueExA"));
        assert!(func_matches("RegSetValueExW", "RegSetValueExW"));
    }

    #[test]
    fn no_false_positive() {
        assert!(!func_matches("GetProcAddress", "VirtualAllocEx"));
    }

    #[test]
    fn check_suspicious_imports_finds_hits() {
        let imports = vec![
            ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec![
                    "VirtualAllocEx".to_string(),
                    "GetProcAddress".to_string(),
                    "WriteProcessMemory".to_string(),
                ],
            },
            ImportInfo {
                dll: "ntdll.dll".to_string(),
                functions: vec!["NtQueryInformationProcess".to_string()],
            },
        ];

        let hits = check_suspicious_imports(&imports);
        assert_eq!(hits.len(), 3);

        let names: Vec<&str> = hits.iter().map(|(_, n, _)| n.as_str()).collect();
        assert!(names.contains(&"VirtualAllocEx"));
        assert!(names.contains(&"WriteProcessMemory"));
        assert!(names.contains(&"NtQueryInformationProcess"));
    }

    #[test]
    fn empty_imports_no_hits() {
        assert!(check_suspicious_imports(&[]).is_empty());
    }

    #[test]
    fn linux_suspicious_calls_populated() {
        assert!(LINUX_SUSPICIOUS_CALLS.contains(&"ptrace"));
        assert!(LINUX_SUSPICIOUS_CALLS.contains(&"memfd_create"));
        assert!(LINUX_SUSPICIOUS_CALLS.contains(&"execveat"));
    }

    #[test]
    fn suffix_match_bidirectional() {
        // imported has no suffix, suspicious has A suffix
        assert!(func_matches("RegSetValueEx", "RegSetValueExA"));
        // imported has W suffix, suspicious has A suffix
        assert!(func_matches("RegSetValueExW", "RegSetValueExA"));
        // both have same suffix
        assert!(func_matches("RegSetValueExA", "RegSetValueExA"));
        // imported has suffix, suspicious has none
        assert!(func_matches("VirtualAllocExW", "VirtualAllocEx"));
    }
}
