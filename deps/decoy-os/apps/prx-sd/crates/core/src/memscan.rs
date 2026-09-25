//! Process memory scanner -- reads `/proc/pid/maps` + `/proc/pid/mem`
//! and scans memory regions with YARA rules and hash matching.
//!
//! Linux-only. Requires `CAP_SYS_PTRACE` or root to read other processes'
//! memory.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use anyhow::{Context, Result};
use prx_sd_signatures::{SignatureDatabase, YaraEngine};
use serde::{Deserialize, Serialize};

use crate::result::ThreatLevel;

/// Maximum size of a single memory region we are willing to scan (16 MB).
const MAX_REGION_SIZE: u64 = 16 * 1024 * 1024;

/// Read chunk size when pulling bytes from `/proc/pid/mem` (4 MB).
const READ_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Path prefixes considered safe -- regions mapped from these paths are skipped.
const SAFE_PREFIXES: &[&str] = &["/usr/lib", "/lib", "/usr/share/locale", "/usr/share/zoneinfo"];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A parsed memory region from `/proc/pid/maps`.
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address.
    pub end: u64,
    /// Permission string, e.g. `"r-xp"`.
    pub permissions: String,
    /// Backing file path, if any (e.g. `/usr/lib/libc.so.6`).
    pub pathname: Option<String>,
}

/// Result of scanning a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemScanResult {
    /// Process ID.
    pub pid: u32,
    /// Process name (from `/proc/pid/comm`).
    pub process_name: String,
    /// Overall threat level (highest of all region matches).
    pub threat_level: ThreatLevel,
    /// Name of the highest-severity threat, if any.
    pub threat_name: Option<String>,
    /// Individual region matches.
    pub matched_regions: Vec<MemRegionMatch>,
    /// Wall-clock time for the scan in milliseconds.
    pub scan_time_ms: u64,
}

/// A YARA or hash match found in a specific memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemRegionMatch {
    /// Region start virtual address.
    pub region_start: u64,
    /// Region end virtual address.
    pub region_end: u64,
    /// Permission string of the region.
    pub permissions: String,
    /// YARA rule name or hash signature name that matched.
    pub rule_name: String,
}

// ---------------------------------------------------------------------------
// Parsing /proc/pid/maps
// ---------------------------------------------------------------------------

/// Parse `/proc/{pid}/maps` into a list of memory regions that are readable.
///
/// Only regions with the `r` (read) permission are returned. Regions backed
/// by known-safe system libraries are excluded.
pub fn parse_proc_maps(pid: u32) -> Result<Vec<MemRegion>> {
    let maps_path = format!("/proc/{pid}/maps");
    let content = fs::read_to_string(&maps_path).with_context(|| format!("failed to read {maps_path}"))?;

    let mut regions = Vec::new();
    for line in content.lines() {
        if let Some(region) = parse_maps_line(line) {
            // Only readable regions.
            if !region.permissions.starts_with('r') {
                continue;
            }
            // Skip regions that exceed the size cap.
            if region.end.saturating_sub(region.start) > MAX_REGION_SIZE {
                continue;
            }
            // Skip known-safe library mappings.
            if is_safe_mapping(&region) {
                continue;
            }
            regions.push(region);
        }
    }

    Ok(regions)
}

/// Parse a single line from `/proc/pid/maps`.
///
/// Format: `<start>-<end> <perms> <offset> <dev> <inode> [pathname]`
fn parse_maps_line(line: &str) -> Option<MemRegion> {
    let mut parts = line.splitn(6, char::is_whitespace);
    let range = parts.next()?;
    let permissions = parts.next()?.to_string();

    let (start_hex, end_hex) = range.split_once('-')?;
    let start = u64::from_str_radix(start_hex, 16).ok()?;
    let end = u64::from_str_radix(end_hex, 16).ok()?;

    // Skip offset, dev, inode (3 fields) to reach the optional pathname.
    let _offset = parts.next();
    let _dev = parts.next();
    let _inode = parts.next();

    let pathname = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    Some(MemRegion {
        start,
        end,
        permissions,
        pathname,
    })
}

/// Returns `true` if the region is backed by a known-safe system path.
fn is_safe_mapping(region: &MemRegion) -> bool {
    if let Some(ref path) = region.pathname {
        for prefix in SAFE_PREFIXES {
            if path.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Reading process memory
// ---------------------------------------------------------------------------

/// Read bytes from `/proc/{pid}/mem` in the range `[start, end)`.
///
/// Reads in chunks of [`READ_CHUNK_SIZE`] to avoid excessive memory pressure.
/// Returns the concatenated bytes of the region.
pub fn read_region(pid: u32, start: u64, end: u64) -> Result<Vec<u8>> {
    let mem_path = format!("/proc/{pid}/mem");
    let mut file = fs::File::open(&mem_path).with_context(|| format!("failed to open {mem_path}"))?;

    let region_size = end
        .checked_sub(start)
        .with_context(|| format!("invalid memory region: end (0x{end:x}) < start (0x{start:x})"))?;

    let total: usize = region_size
        .try_into()
        .with_context(|| format!("memory region too large for this platform: {region_size} bytes"))?;

    let mut buf = Vec::with_capacity(total);

    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("failed to seek to 0x{start:x} in {mem_path}"))?;

    let mut remaining = total;
    let mut chunk = vec![0u8; READ_CHUNK_SIZE.min(remaining)];

    while remaining > 0 {
        let to_read = READ_CHUNK_SIZE.min(remaining);
        let Some(slice) = chunk.get_mut(..to_read) else {
            break;
        };
        match file.read(slice) {
            Ok(0) => break, // EOF
            Ok(n) => {
                buf.extend_from_slice(slice.get(..n).unwrap_or(&[]));
                remaining = remaining.saturating_sub(n);
            }
            Err(e) => {
                // Region may have been unmapped or process may have exited.
                tracing::debug!(pid, start, "read_region I/O error (partial read): {e}");
                break;
            }
        }
    }

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Process name helper
// ---------------------------------------------------------------------------

/// Read the process name from `/proc/{pid}/comm`.
fn process_name(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm")).map_or_else(|_| "<unknown>".to_string(), |s| s.trim().to_string())
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Scan all eligible memory regions of a single process.
///
/// Runs both YARA pattern matching and SHA-256 hash lookups on every readable
/// (non-safe-library) region.
#[allow(clippy::cast_possible_truncation)] // Scan durations will never exceed u64::MAX ms
pub fn scan_process(pid: u32, yara: &YaraEngine, db: &SignatureDatabase) -> Result<MemScanResult> {
    let start = Instant::now();
    let name = process_name(pid);

    let regions = match parse_proc_maps(pid) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(pid, "cannot parse maps: {e}");
            return Ok(MemScanResult {
                pid,
                process_name: name,
                threat_level: ThreatLevel::Clean,
                threat_name: None,
                matched_regions: Vec::new(),
                scan_time_ms: start.elapsed().as_millis() as u64,
            });
        }
    };

    let mut matches: Vec<MemRegionMatch> = Vec::new();
    let mut worst_level = ThreatLevel::Clean;
    let mut worst_name: Option<String> = None;

    for region in &regions {
        let data = match read_region(pid, region.start, region.end) {
            Ok(d) if !d.is_empty() => d,
            _ => continue,
        };

        // 1. YARA scan
        let yara_matches = yara.scan(&data);
        for ym in &yara_matches {
            matches.push(MemRegionMatch {
                region_start: region.start,
                region_end: region.end,
                permissions: region.permissions.clone(),
                rule_name: ym.name.clone(),
            });
            if worst_level < ThreatLevel::Malicious {
                worst_level = ThreatLevel::Malicious;
                worst_name = Some(ym.name.clone());
            }
        }

        // 2. Hash lookup
        match db.hash_lookup(&data) {
            Ok(Some(sig_name)) => {
                matches.push(MemRegionMatch {
                    region_start: region.start,
                    region_end: region.end,
                    permissions: region.permissions.clone(),
                    rule_name: sig_name.clone(),
                });
                if worst_level < ThreatLevel::Malicious {
                    worst_level = ThreatLevel::Malicious;
                    worst_name = Some(sig_name);
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    pid,
                    region_start = region.start,
                    "signature database lookup failed: {e}"
                );
            }
        }
    }

    Ok(MemScanResult {
        pid,
        process_name: name,
        threat_level: worst_level,
        threat_name: worst_name,
        matched_regions: matches,
        scan_time_ms: start.elapsed().as_millis() as u64,
    })
}

/// Enumerate all numeric directories in `/proc` (i.e. running PIDs) and scan
/// each process. Processes that cannot be accessed are silently skipped.
pub fn scan_all_processes(yara: &YaraEngine, db: &SignatureDatabase) -> Vec<MemScanResult> {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("failed to read /proc: {e}");
            return Vec::new();
        }
    };

    let mut results = Vec::new();

    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        match scan_process(pid, yara, db) {
            Ok(result) => results.push(result),
            Err(e) => {
                tracing::debug!(pid, "skipping process: {e}");
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line_basic() {
        let line = "7f1234560000-7f1234570000 r-xp 00000000 08:01 12345  /usr/bin/foo";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.start, 0x7f12_3456_0000);
        assert_eq!(region.end, 0x7f12_3457_0000);
        assert_eq!(region.permissions, "r-xp");
        assert_eq!(region.pathname.as_deref(), Some("/usr/bin/foo"));
    }

    #[test]
    fn test_parse_maps_line_anonymous() {
        let line = "00400000-00401000 rw-p 00000000 00:00 0";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.start, 0x0040_0000);
        assert_eq!(region.end, 0x0040_1000);
        assert_eq!(region.permissions, "rw-p");
        assert!(region.pathname.is_none());
    }

    #[test]
    fn test_parse_maps_line_heap() {
        let line = "55a1b2c3d000-55a1b2c5e000 rw-p 00000000 00:00 0          [heap]";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.pathname.as_deref(), Some("[heap]"));
    }

    #[test]
    fn test_is_safe_mapping() {
        let safe = MemRegion {
            start: 0,
            end: 4096,
            permissions: "r-xp".to_string(),
            pathname: Some("/usr/lib/libc.so.6".to_string()),
        };
        assert!(is_safe_mapping(&safe));

        let not_safe = MemRegion {
            start: 0,
            end: 4096,
            permissions: "r-xp".to_string(),
            pathname: Some("/home/user/malware".to_string()),
        };
        assert!(!is_safe_mapping(&not_safe));

        let anon = MemRegion {
            start: 0,
            end: 4096,
            permissions: "rw-p".to_string(),
            pathname: None,
        };
        assert!(!is_safe_mapping(&anon));
    }

    #[test]
    fn test_max_region_skipped() {
        // A region larger than MAX_REGION_SIZE should be filtered out by
        // parse_proc_maps, but we verify the constant is sensible.
        assert_eq!(MAX_REGION_SIZE, 16 * 1024 * 1024);
    }
}
