//! # prx-sd-parsers
//!
//! Binary and document format parsers for antivirus analysis. Provides a
//! unified interface to parse PE, ELF, Mach-O, PDF, Office, and archive files,
//! extracting structural metadata used by downstream heuristic and signature
//! engines.

pub mod archive;
pub mod elf;
pub mod macho;
pub mod office;
pub mod pdf;
pub mod pe;

// Re-export primary types for convenience.
pub use archive::{ArchiveEntry, ArchiveFormat, ArchiveInfo};
pub use elf::ElfInfo;
pub use macho::MachOInfo;
pub use office::{MacroSuspiciousCall, MacroThreatCategory, OfficeAnalysis, OfficeFormat, OfficeInfo, analyze_office};
pub use pdf::{PdfAnalysis, PdfInfo, PdfSuspiciousPattern, analyze_pdf};
pub use pe::{ImportInfo, PeInfo, SectionInfo};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// High-level file type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    PE,
    ELF,
    MachO,
    PDF,
    Zip,
    Gzip,
    Tar,
    TarGz,
    SevenZip,
    OfficeOoxml,
    OfficeLegacy,
    Script,
    Unknown,
}

/// Result of parsing a file. Each variant holds the typed metadata for the
/// corresponding format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParsedFile {
    PE(PeInfo),
    ELF(ElfInfo),
    MachO(MachOInfo),
    PDF(PdfInfo),
    Archive(ArchiveInfo),
    Office(OfficeInfo),
    /// Script or unknown file types are not parsed into structured metadata.
    Unparsed {
        file_type: FileType,
        size: usize,
    },
}

impl ParsedFile {
    /// Return the PE info if this is a PE file, or `None` otherwise.
    pub const fn as_pe(&self) -> Option<&PeInfo> {
        match self {
            Self::PE(info) => Some(info),
            _ => None,
        }
    }

    /// Return the ELF info if this is an ELF file, or `None` otherwise.
    pub const fn as_elf(&self) -> Option<&ElfInfo> {
        match self {
            Self::ELF(info) => Some(info),
            _ => None,
        }
    }

    /// Return the Mach-O info if this is a Mach-O file, or `None` otherwise.
    pub const fn as_macho(&self) -> Option<&MachOInfo> {
        match self {
            Self::MachO(info) => Some(info),
            _ => None,
        }
    }

    /// Return the PDF info if this is a PDF file, or `None` otherwise.
    pub const fn as_pdf(&self) -> Option<&PdfInfo> {
        match self {
            Self::PDF(info) => Some(info),
            _ => None,
        }
    }

    /// Return the archive info if this is an archive file, or `None` otherwise.
    pub const fn as_archive(&self) -> Option<&ArchiveInfo> {
        match self {
            Self::Archive(info) => Some(info),
            _ => None,
        }
    }

    /// Return the Office info if this is an Office file, or `None` otherwise.
    pub const fn as_office(&self) -> Option<&OfficeInfo> {
        match self {
            Self::Office(info) => Some(info),
            _ => None,
        }
    }
}

/// Unified entry point: parse `data` according to the given `file_type`.
pub fn parse(data: &[u8], file_type: FileType) -> Result<ParsedFile> {
    match file_type {
        FileType::PE => pe::parse_pe(data).map(ParsedFile::PE),
        FileType::ELF => elf::parse_elf(data).map(ParsedFile::ELF),
        FileType::MachO => macho::parse_macho(data).map(ParsedFile::MachO),
        FileType::PDF => pdf::parse_pdf(data).map(ParsedFile::PDF),
        FileType::Zip => archive::inspect_archive(data, ArchiveFormat::Zip).map(ParsedFile::Archive),
        FileType::Gzip => archive::inspect_archive(data, ArchiveFormat::Gzip).map(ParsedFile::Archive),
        FileType::Tar => archive::inspect_archive(data, ArchiveFormat::Tar).map(ParsedFile::Archive),
        FileType::TarGz => archive::inspect_archive(data, ArchiveFormat::TarGz).map(ParsedFile::Archive),
        FileType::SevenZip => archive::inspect_archive(data, ArchiveFormat::SevenZip).map(ParsedFile::Archive),
        FileType::OfficeOoxml | FileType::OfficeLegacy => office::parse_office(data).map(ParsedFile::Office),
        FileType::Script | FileType::Unknown => Ok(ParsedFile::Unparsed {
            file_type,
            size: data.len(),
        }),
    }
}

/// Attempt to detect the file type from magic bytes / header signatures.
pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 4 {
        return FileType::Unknown;
    }

    // PE: MZ header
    if data.starts_with(b"MZ") {
        return FileType::PE;
    }

    // ELF: \x7fELF
    if data.starts_with(b"\x7fELF") {
        return FileType::ELF;
    }

    // Mach-O: various magic values (32/64-bit, big/little endian)
    // data.len() >= 4 is guaranteed by the guard above, so indices 0..3 are safe.
    #[allow(clippy::indexing_slicing)]
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE => {
            return FileType::MachO;
        }
        // Fat binary: 0xCAFEBABE (big-endian) or 0xBEBAFECA (little-endian)
        // Distinguish from Java class files by checking arch count.
        0xCAFE_BABE | 0xBEBA_FECA => {
            if let (Some(&b4), Some(&b5), Some(&b6), Some(&b7)) = (data.get(4), data.get(5), data.get(6), data.get(7)) {
                let count = u32::from_be_bytes([b4, b5, b6, b7]);
                if count > 0 && count < 30 {
                    return FileType::MachO;
                }
            }
        }
        _ => {}
    }

    // PDF: %PDF- (possibly with preamble up to 1024 bytes)
    if data.len() >= 5 {
        let search = data.get(..data.len().min(1024)).unwrap_or(data);
        if search.windows(5).any(|w| w == b"%PDF-") {
            return FileType::PDF;
        }
    }

    // OLE2 Compound Binary (legacy Office)
    if data.len() >= 8 && data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileType::OfficeLegacy;
    }

    // ZIP-based (could be OOXML or plain ZIP)
    if data.starts_with(b"PK\x03\x04") {
        if is_ooxml_zip(data) {
            return FileType::OfficeOoxml;
        }
        return FileType::Zip;
    }

    // Gzip
    if data.starts_with(&[0x1f, 0x8b]) {
        return FileType::Gzip;
    }

    // Tar (ustar magic at offset 257)
    if data.get(257..262).is_some_and(|slice| slice == b"ustar") {
        return FileType::Tar;
    }

    // 7z
    if data.get(..6).is_some_and(|slice| slice == b"7z\xBC\xAF\x27\x1C") {
        return FileType::SevenZip;
    }

    // Script detection: shebang
    if data.starts_with(b"#!") {
        return FileType::Script;
    }

    FileType::Unknown
}

/// Check if a ZIP file is an OOXML Office document by looking for
/// characteristic OOXML entries.
fn is_ooxml_zip(data: &[u8]) -> bool {
    use std::io::Cursor;
    let reader = Cursor::new(data);
    if let Ok(mut archive) = zip::ZipArchive::new(reader) {
        for i in 0..archive.len().min(20) {
            if let Ok(file) = archive.by_index_raw(i) {
                let name = file.name().to_lowercase();
                if name == "[content_types].xml"
                    || name.starts_with("word/")
                    || name.starts_with("xl/")
                    || name.starts_with("ppt/")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Compute the Shannon entropy of a byte slice.
///
/// Returns a value in the range `[0.0, 8.0]` where 0.0 indicates perfectly
/// uniform data (all identical bytes) and 8.0 indicates maximum randomness.
/// Used to detect packed, encrypted, or compressed sections in executables.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        // `byte as usize` is always in 0..=255, which is within bounds of `freq[256]`.
        #[allow(clippy::indexing_slicing)]
        {
            freq[byte as usize] += 1;
        }
    }

    #[allow(clippy::cast_precision_loss)]
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            #[allow(clippy::cast_precision_loss)]
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unreadable_literal,
    clippy::float_cmp,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    // ── detect_file_type tests ──

    #[test]
    fn detect_pe_file_type() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        assert_eq!(detect_file_type(&data), FileType::PE);
    }

    #[test]
    fn detect_elf_file_type() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert_eq!(detect_file_type(&data), FileType::ELF);
    }

    #[test]
    fn detect_macho_64_file_type() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        assert_eq!(detect_file_type(&data), FileType::MachO);
    }

    #[test]
    fn detect_macho_32_file_type() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xFEEDFACEu32.to_le_bytes());
        assert_eq!(detect_file_type(&data), FileType::MachO);
    }

    #[test]
    fn detect_pdf_file_type() {
        let data = b"%PDF-1.7\n1 0 obj\nendobj\n";
        assert_eq!(detect_file_type(data), FileType::PDF);
    }

    #[test]
    fn detect_pdf_with_preamble() {
        let mut data = vec![0u8; 128];
        // PDF header at offset 10
        data[10..15].copy_from_slice(b"%PDF-");
        assert_eq!(detect_file_type(&data), FileType::PDF);
    }

    #[test]
    fn detect_zip_file_type() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(detect_file_type(&data), FileType::Zip);
    }

    #[test]
    fn detect_gzip_file_type() {
        let mut data = vec![0u8; 64];
        data[0] = 0x1f;
        data[1] = 0x8b;
        assert_eq!(detect_file_type(&data), FileType::Gzip);
    }

    #[test]
    fn detect_tar_file_type() {
        let mut data = vec![0u8; 512];
        data[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_file_type(&data), FileType::Tar);
    }

    #[test]
    fn detect_7z_file_type() {
        let mut data = vec![0u8; 64];
        data[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
        assert_eq!(detect_file_type(&data), FileType::SevenZip);
    }

    #[test]
    fn detect_script_file_type() {
        let data = b"#!/bin/bash\necho hello";
        assert_eq!(detect_file_type(data), FileType::Script);
    }

    #[test]
    fn detect_unknown_file_type() {
        let data = b"Some random text content";
        assert_eq!(detect_file_type(data), FileType::Unknown);
    }

    #[test]
    fn detect_empty_input() {
        assert_eq!(detect_file_type(&[]), FileType::Unknown);
    }

    #[test]
    fn detect_too_short_input() {
        assert_eq!(detect_file_type(&[0x7f, b'E', b'L']), FileType::Unknown);
    }

    #[test]
    fn detect_ole2_legacy_office() {
        let mut data = vec![0u8; 64];
        data[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        assert_eq!(detect_file_type(&data), FileType::OfficeLegacy);
    }

    // ── parse() dispatcher tests ──

    #[test]
    fn parse_unknown_returns_unparsed() {
        let data = b"some random data";
        let result = parse(data, FileType::Unknown).expect("Unknown type should succeed");
        match result {
            ParsedFile::Unparsed { file_type, size } => {
                assert_eq!(file_type, FileType::Unknown);
                assert_eq!(size, data.len());
            }
            _ => panic!("expected Unparsed variant"),
        }
    }

    #[test]
    fn parse_script_returns_unparsed() {
        let data = b"#!/bin/bash\necho hello";
        let result = parse(data, FileType::Script).expect("Script type should succeed");
        match result {
            ParsedFile::Unparsed { file_type, size } => {
                assert_eq!(file_type, FileType::Script);
                assert_eq!(size, data.len());
            }
            _ => panic!("expected Unparsed variant"),
        }
    }

    #[test]
    fn parse_invalid_pe_returns_error() {
        let data = b"not a PE file";
        let result = parse(data, FileType::PE);
        assert!(result.is_err(), "invalid PE data should fail");
    }

    #[test]
    fn parse_invalid_elf_returns_error() {
        let data = b"not an ELF file";
        let result = parse(data, FileType::ELF);
        assert!(result.is_err(), "invalid ELF data should fail");
    }

    #[test]
    fn parse_invalid_macho_returns_error() {
        let data = b"not a Mach-O file";
        let result = parse(data, FileType::MachO);
        assert!(result.is_err(), "invalid Mach-O data should fail");
    }

    #[test]
    fn parse_invalid_pdf_returns_error() {
        let data = b"not a PDF file";
        let result = parse(data, FileType::PDF);
        assert!(result.is_err(), "invalid PDF data should fail");
    }

    #[test]
    fn parse_valid_pdf_returns_pdf_variant() {
        let data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
        let result = parse(data, FileType::PDF).expect("valid PDF should succeed");
        assert!(result.as_pdf().is_some());
    }

    // ── ParsedFile accessor tests ──

    #[test]
    fn parsed_file_as_pe_returns_none_for_other() {
        let unparsed = ParsedFile::Unparsed {
            file_type: FileType::Unknown,
            size: 0,
        };
        assert!(unparsed.as_pe().is_none());
        assert!(unparsed.as_elf().is_none());
        assert!(unparsed.as_macho().is_none());
        assert!(unparsed.as_pdf().is_none());
        assert!(unparsed.as_archive().is_none());
        assert!(unparsed.as_office().is_none());
    }

    // ── shannon_entropy tests ──

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        // All same byte => entropy = 0
        let data = vec![0xAA; 1024];
        let e = shannon_entropy(&data);
        assert!(e < 0.001, "uniform data should have ~0 entropy, got {}", e);
    }

    #[test]
    fn entropy_two_values() {
        // Equal distribution of two byte values => entropy = 1.0
        let mut data = vec![0u8; 1000];
        for item in data.iter_mut().take(500) {
            *item = 0;
        }
        for item in data.iter_mut().take(1000).skip(500) {
            *item = 1;
        }
        let e = shannon_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.01,
            "two equally distributed values should have entropy ~1.0, got {}",
            e
        );
    }

    #[test]
    fn entropy_max() {
        // All 256 byte values equally distributed => entropy = 8.0
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "uniformly distributed 256 values should have entropy ~8.0, got {}",
            e
        );
    }

    #[test]
    fn entropy_single_byte() {
        let data = vec![42u8; 1];
        let e = shannon_entropy(&data);
        assert!(e < 0.001, "single byte should have 0 entropy, got {}", e);
    }
}
