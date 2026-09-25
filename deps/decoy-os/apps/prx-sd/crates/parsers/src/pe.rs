use anyhow::{Context, Result};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::shannon_entropy;

/// Information about a PE (Portable Executable) file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub is_64bit: bool,
    pub is_dll: bool,
    pub entry_point: u64,
    pub timestamp: u32,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<String>,
    pub imphash: String,
    pub debug_info: Option<String>,
}

/// Information about a PE/ELF/Mach-O section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: u32,
}

/// A DLL import entry listing the DLL name and imported function names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

/// Parse a PE file from raw bytes, extracting structural metadata for analysis.
pub fn parse_pe(data: &[u8]) -> Result<PeInfo> {
    let pe = goblin::pe::PE::parse(data).context("failed to parse PE file")?;

    let is_64bit = pe.is_64;
    let is_dll = pe.is_lib;
    let entry_point = pe.entry as u64;

    let timestamp = pe.header.coff_header.time_date_stamp;

    debug!(is_64bit, is_dll, entry_point, timestamp, "parsed PE header");

    // Sections
    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|s| {
            let name_end = s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len());
            let name = String::from_utf8_lossy(s.name.get(..name_end).unwrap_or(&s.name)).to_string();

            let raw_offset = s.pointer_to_raw_data as usize;
            let raw_size = s.size_of_raw_data as usize;
            let section_data = data.get(raw_offset..raw_offset.saturating_add(raw_size)).unwrap_or(&[]);
            let entropy = shannon_entropy(section_data);

            SectionInfo {
                name,
                virtual_size: u64::from(s.virtual_size),
                raw_size: u64::from(s.size_of_raw_data),
                entropy,
                characteristics: s.characteristics,
            }
        })
        .collect();

    // Imports
    let imports: Vec<ImportInfo> = pe
        .imports
        .iter()
        .fold(
            std::collections::HashMap::<String, Vec<String>>::new(),
            |mut acc, imp| {
                acc.entry(imp.dll.to_string()).or_default().push(imp.name.to_string());
                acc
            },
        )
        .into_iter()
        .map(|(dll, functions)| ImportInfo { dll, functions })
        .collect();

    // Exports
    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(std::string::ToString::to_string))
        .collect();

    let imphash = compute_imphash(&imports);

    // Debug info: look for CodeView PDB path in debug data
    let debug_info = extract_debug_info(&pe, data);

    debug!(
        sections = sections.len(),
        imports = imports.len(),
        exports = exports.len(),
        %imphash,
        "extracted PE metadata"
    );

    Ok(PeInfo {
        is_64bit,
        is_dll,
        entry_point,
        timestamp,
        sections,
        imports,
        exports,
        imphash,
        debug_info,
    })
}

/// Compute the standard import hash (imphash) for a PE file.
///
/// The algorithm concatenates `dll_name.function_name` pairs (lowercase,
/// with the DLL extension stripped), sorts them, joins with commas, and
/// returns the MD5 hex digest.
pub fn compute_imphash(imports: &[ImportInfo]) -> String {
    let mut pairs: Vec<String> = Vec::new();

    for imp in imports {
        // Strip extension from DLL name (e.g. "kernel32.dll" -> "kernel32")
        let dll_lower = imp.dll.to_lowercase();
        let dll_stem = dll_lower
            .strip_suffix(".dll")
            .or_else(|| dll_lower.strip_suffix(".ocx"))
            .or_else(|| dll_lower.strip_suffix(".sys"))
            .or_else(|| dll_lower.strip_suffix(".drv"))
            .unwrap_or(&dll_lower);

        for func in &imp.functions {
            let func_lower = func.to_lowercase();
            pairs.push(format!("{dll_stem}.{func_lower}"));
        }
    }

    if pairs.is_empty() {
        return String::new();
    }

    pairs.sort();
    let joined = pairs.join(",");

    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Try to extract a PDB path or debug GUID from the PE debug directory.
fn extract_debug_info(pe: &goblin::pe::PE, data: &[u8]) -> Option<String> {
    // goblin exposes debug_data which may contain a CodeView entry
    if let Some(debug_data) = pe.debug_data {
        if let Some(codeview) = debug_data.codeview_pdb70_debug_info {
            let path = std::str::from_utf8(codeview.filename)
                .unwrap_or("<invalid utf8>")
                .trim_end_matches('\0');
            return Some(path.to_string());
        }
    }

    // Fallback: scan for RSDS signature in the raw data using debug directory
    // entries from the PE header.
    for section in &pe.sections {
        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let Some(section_data) = data.get(offset..offset.saturating_add(size)) else {
            continue;
        };
        // Search for RSDS signature within this section
        if let Some(path) = find_rsds_pdb_path(section_data) {
            return Some(path);
        }
    }

    None
}

/// Scan a section's raw bytes for an RSDS `CodeView` signature and extract the
/// PDB path that follows it.
fn find_rsds_pdb_path(section_data: &[u8]) -> Option<String> {
    for i in 0..section_data.len().saturating_sub(24) {
        if section_data.get(i..i + 4) != Some(b"RSDS".as_slice()) {
            continue;
        }
        // PDB path starts at RSDS + 24, null-terminated
        let path_bytes = section_data.get(i + 24..)?;
        let end = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or_else(|| path_bytes.len().min(260));
        let pdb_path = String::from_utf8_lossy(path_bytes.get(..end).unwrap_or(&[])).to_string();
        if !pdb_path.is_empty() && pdb_path.len() < 260 {
            return Some(pdb_path);
        }
    }
    None
}

// We need hex encoding for imphash. A minimal inline implementation to avoid
// adding another dependency (though in practice you'd use the `hex` crate).
mod hex {
    use std::fmt::Write;

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::branches_sharing_code,
    clippy::doc_markdown
)]
mod tests {
    use super::*;

    /// Build a minimal PE file with the given COFF characteristics and optional header magic.
    /// `is_64bit`: if true, uses PE32+ (0x20b); otherwise PE32 (0x10b).
    /// `is_dll`: if true, sets IMAGE_FILE_DLL (0x2000) in COFF characteristics.
    /// Returns raw bytes representing a valid-enough PE for goblin to parse.
    fn make_minimal_pe(is_64bit: bool, is_dll: bool) -> Vec<u8> {
        let pe_offset: u32 = 0x80;
        // COFF header is 20 bytes
        // Optional header: PE32 = 0x60 standard + 0x40 data dirs = 0xE0 (224)
        //                  PE32+ = 0x70 standard + 0x40 data dirs = 0xF0 (240)
        let optional_header_size: u16 = if is_64bit { 0xF0 } else { 0xE0 };
        let optional_magic: u16 = if is_64bit { 0x20b } else { 0x10b };
        let num_sections: u16 = 1;
        let mut coff_chars: u16 = 0x0002; // IMAGE_FILE_EXECUTABLE_IMAGE
        if is_dll {
            coff_chars |= 0x2000; // IMAGE_FILE_DLL
        }

        // Total size: pe_offset + 4 (sig) + 20 (COFF) + optional_header_size + 40 (one section header)
        let total_size = pe_offset as usize + 4 + 20 + optional_header_size as usize + 40;
        // We also need raw section data at some offset; put it at a page boundary.
        let section_raw_offset: u32 = (total_size.div_ceil(512) * 512) as u32;
        let section_raw_size: u32 = 512;
        let file_size = section_raw_offset as usize + section_raw_size as usize;
        let mut pe = vec![0u8; file_size];

        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        let base = pe_offset as usize;
        // PE signature
        pe[base..base + 4].copy_from_slice(b"PE\0\0");

        // COFF header (20 bytes at base+4)
        let coff = base + 4;
        // Machine: x86_64 = 0x8664, x86 = 0x14c
        let machine: u16 = if is_64bit { 0x8664 } else { 0x14c };
        pe[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        pe[coff + 2..coff + 4].copy_from_slice(&num_sections.to_le_bytes());
        // TimeDateStamp
        let timestamp: u32 = 0x6789ABCD;
        pe[coff + 4..coff + 8].copy_from_slice(&timestamp.to_le_bytes());
        // PointerToSymbolTable = 0, NumberOfSymbols = 0
        // SizeOfOptionalHeader
        pe[coff + 16..coff + 18].copy_from_slice(&optional_header_size.to_le_bytes());
        // Characteristics
        pe[coff + 18..coff + 20].copy_from_slice(&coff_chars.to_le_bytes());

        // Optional header
        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&optional_magic.to_le_bytes());
        // AddressOfEntryPoint at offset 16 from opt
        let entry_point: u32 = 0x1000;
        pe[opt + 16..opt + 20].copy_from_slice(&entry_point.to_le_bytes());
        // SectionAlignment at offset 32
        let section_alignment: u32 = 0x1000;
        if is_64bit {
            pe[opt + 32..opt + 36].copy_from_slice(&section_alignment.to_le_bytes());
            // FileAlignment at offset 36
            pe[opt + 36..opt + 40].copy_from_slice(&512u32.to_le_bytes());
            // SizeOfImage at offset 56
            pe[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
            // SizeOfHeaders at offset 60
            pe[opt + 60..opt + 64].copy_from_slice(&section_raw_offset.to_le_bytes());
            // NumberOfRvaAndSizes at offset 108
            pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        } else {
            pe[opt + 32..opt + 36].copy_from_slice(&section_alignment.to_le_bytes());
            pe[opt + 36..opt + 40].copy_from_slice(&512u32.to_le_bytes());
            pe[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
            pe[opt + 60..opt + 64].copy_from_slice(&section_raw_offset.to_le_bytes());
            // NumberOfRvaAndSizes at offset 92
            pe[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        }

        // Section header (40 bytes, immediately after optional header)
        let sec = opt + optional_header_size as usize;
        // Name: ".text\0\0\0"
        pe[sec..sec + 5].copy_from_slice(b".text");
        // VirtualSize
        pe[sec + 8..sec + 12].copy_from_slice(&section_raw_size.to_le_bytes());
        // VirtualAddress
        pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData
        pe[sec + 16..sec + 20].copy_from_slice(&section_raw_size.to_le_bytes());
        // PointerToRawData
        pe[sec + 20..sec + 24].copy_from_slice(&section_raw_offset.to_le_bytes());
        // Characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        let sec_chars: u32 = 0x60000020;
        pe[sec + 36..sec + 40].copy_from_slice(&sec_chars.to_le_bytes());

        // Fill section data with some non-zero bytes so entropy is non-zero
        for i in 0..section_raw_size as usize {
            pe[section_raw_offset as usize + i] = (i % 256) as u8;
        }

        pe
    }

    #[test]
    fn parse_pe_64bit() {
        let data = make_minimal_pe(true, false);
        let info = parse_pe(&data).expect("should parse valid 64-bit PE");
        assert!(info.is_64bit);
        assert!(!info.is_dll);
        assert_eq!(info.entry_point, 0x1000);
        assert_eq!(info.timestamp, 0x6789ABCD);
    }

    #[test]
    fn parse_pe_32bit() {
        let data = make_minimal_pe(false, false);
        let info = parse_pe(&data).expect("should parse valid 32-bit PE");
        assert!(!info.is_64bit);
        assert!(!info.is_dll);
    }

    #[test]
    fn parse_pe_dll_detection() {
        let data = make_minimal_pe(true, true);
        let info = parse_pe(&data).expect("should parse PE DLL");
        assert!(info.is_dll);
    }

    #[test]
    fn parse_pe_section_info() {
        let data = make_minimal_pe(true, false);
        let info = parse_pe(&data).expect("should parse PE with sections");
        assert!(!info.sections.is_empty());
        let text_section = info
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .expect("should have .text section");
        assert_eq!(text_section.raw_size, 512);
        assert!(
            text_section.entropy > 0.0,
            "section with data should have non-zero entropy"
        );
    }

    #[test]
    fn parse_pe_section_entropy() {
        let mut data = make_minimal_pe(true, false);
        // Fill section data with all zeros for zero entropy (all same byte)
        let section_raw_offset = {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
            let coff = pe_offset as usize + 4;
            let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
            let sec = coff + 20 + opt_size;
            u32::from_le_bytes([data[sec + 20], data[sec + 21], data[sec + 22], data[sec + 23]]) as usize
        };
        for i in 0..512 {
            data[section_raw_offset + i] = 0;
        }
        let info = parse_pe(&data).expect("should parse PE");
        let text_section = info
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .expect("should have .text section");
        assert!(
            text_section.entropy < 0.01,
            "all-zero section should have ~0 entropy, got {}",
            text_section.entropy
        );
    }

    #[test]
    fn parse_pe_empty_input() {
        let result = parse_pe(&[]);
        assert!(result.is_err(), "empty input should return error");
    }

    #[test]
    fn parse_pe_truncated_header() {
        // Just the MZ magic and a few bytes — not enough for a full PE
        let data = b"MZ\x00\x00";
        let result = parse_pe(data);
        assert!(result.is_err(), "truncated PE should return error");
    }

    #[test]
    fn parse_pe_invalid_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // Wrong PE signature
        data[0x80..0x84].copy_from_slice(b"XX\0\0");
        let result = parse_pe(&data);
        assert!(result.is_err(), "invalid PE signature should return error");
    }

    #[test]
    fn parse_pe_zero_sections() {
        // Build a PE with zero sections — goblin should still parse the header
        let pe_offset: u32 = 0x80;
        let optional_header_size: u16 = 0xF0;
        let total_size = pe_offset as usize + 4 + 20 + optional_header_size as usize;
        let mut pe = vec![0u8; total_size + 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        let base = pe_offset as usize;
        pe[base..base + 4].copy_from_slice(b"PE\0\0");
        let coff = base + 4;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
        pe[coff + 2..coff + 4].copy_from_slice(&0u16.to_le_bytes()); // zero sections
        pe[coff + 16..coff + 18].copy_from_slice(&optional_header_size.to_le_bytes());
        pe[coff + 18..coff + 20].copy_from_slice(&0x0002u16.to_le_bytes()); // chars
        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        pe[opt + 56..opt + 60].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfImage
        pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        let info = parse_pe(&pe).expect("PE with zero sections should still parse");
        assert!(info.sections.is_empty());
    }

    #[test]
    fn compute_imphash_basic() {
        let imports = vec![
            ImportInfo {
                dll: "KERNEL32.dll".to_string(),
                functions: vec!["CreateFileA".to_string(), "ReadFile".to_string()],
            },
            ImportInfo {
                dll: "USER32.DLL".to_string(),
                functions: vec!["MessageBoxA".to_string()],
            },
        ];
        let hash = compute_imphash(&imports);
        assert!(!hash.is_empty(), "imphash should not be empty");
        assert_eq!(hash.len(), 32, "MD5 hex digest should be 32 chars");
        // All lowercase hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_imphash_empty() {
        let imports: Vec<ImportInfo> = Vec::new();
        let hash = compute_imphash(&imports);
        assert!(hash.is_empty(), "imphash of no imports should be empty");
    }

    #[test]
    fn compute_imphash_strips_extensions() {
        let imports_dll = vec![ImportInfo {
            dll: "advapi32.dll".to_string(),
            functions: vec!["RegOpenKeyA".to_string()],
        }];
        let imports_ocx = vec![ImportInfo {
            dll: "advapi32.ocx".to_string(),
            functions: vec!["RegOpenKeyA".to_string()],
        }];
        let hash_dll = compute_imphash(&imports_dll);
        let hash_ocx = compute_imphash(&imports_ocx);
        assert_eq!(
            hash_dll, hash_ocx,
            "imphash should strip both .dll and .ocx extensions identically"
        );
    }

    #[test]
    fn compute_imphash_deterministic() {
        let imports = vec![ImportInfo {
            dll: "kernel32.dll".to_string(),
            functions: vec!["ExitProcess".to_string()],
        }];
        let h1 = compute_imphash(&imports);
        let h2 = compute_imphash(&imports);
        assert_eq!(h1, h2, "imphash should be deterministic");
    }

    #[test]
    fn parse_pe_no_imports_no_exports() {
        let data = make_minimal_pe(true, false);
        let info = parse_pe(&data).expect("should parse PE");
        // Our minimal PE has no import directory, so imports should be empty
        assert!(info.imports.is_empty());
        assert!(info.exports.is_empty());
        assert!(info.imphash.is_empty());
    }

    #[test]
    fn parse_pe_no_debug_info() {
        let data = make_minimal_pe(true, false);
        let info = parse_pe(&data).expect("should parse PE");
        assert!(info.debug_info.is_none(), "minimal PE should have no debug info");
    }
}
