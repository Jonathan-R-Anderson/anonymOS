use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::pe::SectionInfo;
use crate::shannon_entropy;

/// Information about a Mach-O executable file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachOInfo {
    pub is_64bit: bool,
    pub cpu_type: String,
    pub file_type: String,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<String>,
}

/// Parse a Mach-O file from raw bytes, extracting structural metadata for analysis.
pub fn parse_macho(data: &[u8]) -> Result<MachOInfo> {
    use goblin::mach::Mach;

    let mach = Mach::parse(data).context("failed to parse Mach-O file")?;

    match mach {
        Mach::Binary(macho) => parse_single_macho(&macho, data),
        Mach::Fat(fat) => {
            // For fat/universal binaries, parse the first architecture
            let first = fat
                .into_iter()
                .next()
                .context("empty fat binary")?
                .context("failed to parse fat binary entry")?;
            match first {
                goblin::mach::SingleArch::MachO(macho) => parse_single_macho(&macho, data),
                goblin::mach::SingleArch::Archive(_) => {
                    bail!("fat binary contains an archive, not a Mach-O")
                }
            }
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
fn parse_single_macho(macho: &goblin::mach::MachO, data: &[u8]) -> Result<MachOInfo> {
    use goblin::mach::cputype;

    let is_64bit = macho.is_64;

    let cpu_type = match macho.header.cputype() {
        cputype::CPU_TYPE_X86 => "x86",
        cputype::CPU_TYPE_X86_64 => "x86_64",
        cputype::CPU_TYPE_ARM => "arm",
        cputype::CPU_TYPE_ARM64 => "arm64",
        cputype::CPU_TYPE_POWERPC => "powerpc",
        cputype::CPU_TYPE_POWERPC64 => "powerpc64",
        _ => "unknown",
    }
    .to_string();

    let file_type = match macho.header.filetype {
        goblin::mach::header::MH_OBJECT => "object",
        goblin::mach::header::MH_EXECUTE => "execute",
        goblin::mach::header::MH_DYLIB => "dylib",
        goblin::mach::header::MH_BUNDLE => "bundle",
        goblin::mach::header::MH_DYLINKER => "dylinker",
        goblin::mach::header::MH_CORE => "core",
        goblin::mach::header::MH_PRELOAD => "preload",
        _ => "unknown",
    }
    .to_string();

    // Sections
    let sections: Vec<SectionInfo> = macho
        .segments
        .iter()
        .flat_map(|seg| {
            seg.sections()
                .unwrap_or_default()
                .into_iter()
                .map(|(section, _data_bytes)| {
                    let name = format!(
                        "{},{}",
                        std::str::from_utf8(&section.segname)
                            .unwrap_or("")
                            .trim_end_matches('\0'),
                        std::str::from_utf8(&section.sectname)
                            .unwrap_or("")
                            .trim_end_matches('\0'),
                    );

                    #[allow(clippy::cast_possible_truncation)]
                    let offset = section.offset as usize;
                    #[allow(clippy::cast_possible_truncation)]
                    let size = section.size as usize;
                    let section_data = data.get(offset..offset.saturating_add(size)).unwrap_or(&[]);
                    let entropy = shannon_entropy(section_data);

                    SectionInfo {
                        name,
                        virtual_size: section.size,
                        raw_size: section.size,
                        entropy,
                        characteristics: section.flags,
                    }
                })
        })
        .collect();

    // Imports (symbols from external dylibs)
    let imports: Vec<String> = macho
        .imports()
        .unwrap_or_default()
        .into_iter()
        .map(|imp| imp.name.to_string())
        .collect();

    debug!(
        is_64bit,
        %cpu_type,
        %file_type,
        sections = sections.len(),
        imports = imports.len(),
        "parsed Mach-O metadata"
    );

    Ok(MachOInfo {
        is_64bit,
        cpu_type,
        file_type,
        sections,
        imports,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::doc_markdown, clippy::unreadable_literal)]
mod tests {
    use super::*;

    /// Build a minimal 64-bit Mach-O (x86_64, `MH_EXECUTE`).
    /// Magic: 0xFEEDFACF, ncmds=0, sizeofcmds=0
    fn make_minimal_macho64() -> Vec<u8> {
        // Mach-O 64-bit header is 32 bytes
        let mut m = vec![0u8; 4096];

        // magic: MH_MAGIC_64 = 0xFEEDFACF
        m[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        // cputype: CPU_TYPE_X86_64 = 0x01000007
        m[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        // cpusubtype: CPU_SUBTYPE_ALL = 3
        m[8..12].copy_from_slice(&3u32.to_le_bytes());
        // filetype: MH_EXECUTE = 2
        m[12..16].copy_from_slice(&2u32.to_le_bytes());
        // ncmds: 0
        m[16..20].copy_from_slice(&0u32.to_le_bytes());
        // sizeofcmds: 0
        m[20..24].copy_from_slice(&0u32.to_le_bytes());
        // flags: 0
        m[24..28].copy_from_slice(&0u32.to_le_bytes());
        // reserved (64-bit only): 0
        m[28..32].copy_from_slice(&0u32.to_le_bytes());

        m
    }

    /// Build a minimal 32-bit Mach-O (x86, MH_EXECUTE).
    fn make_minimal_macho32() -> Vec<u8> {
        // Mach-O 32-bit header is 28 bytes
        let mut m = vec![0u8; 4096];

        // magic: MH_MAGIC = 0xFEEDFACE
        m[0..4].copy_from_slice(&0xFEEDFACEu32.to_le_bytes());
        // cputype: CPU_TYPE_X86 = 7
        m[4..8].copy_from_slice(&7u32.to_le_bytes());
        // cpusubtype: CPU_SUBTYPE_ALL = 3
        m[8..12].copy_from_slice(&3u32.to_le_bytes());
        // filetype: MH_EXECUTE = 2
        m[12..16].copy_from_slice(&2u32.to_le_bytes());
        // ncmds: 0
        m[16..20].copy_from_slice(&0u32.to_le_bytes());
        // sizeofcmds: 0
        m[20..24].copy_from_slice(&0u32.to_le_bytes());
        // flags: 0
        m[24..28].copy_from_slice(&0u32.to_le_bytes());

        m
    }

    #[test]
    fn parse_macho_64bit() {
        let data = make_minimal_macho64();
        let info = parse_macho(&data).expect("should parse valid 64-bit Mach-O");
        assert!(info.is_64bit);
        assert_eq!(info.cpu_type, "x86_64");
        assert_eq!(info.file_type, "execute");
    }

    #[test]
    fn parse_macho_32bit() {
        let data = make_minimal_macho32();
        let info = parse_macho(&data).expect("should parse valid 32-bit Mach-O");
        assert!(!info.is_64bit);
        assert_eq!(info.cpu_type, "x86");
        assert_eq!(info.file_type, "execute");
    }

    #[test]
    fn parse_macho_arm64() {
        let mut data = make_minimal_macho64();
        // cputype: CPU_TYPE_ARM64 = 0x0100000C
        data[4..8].copy_from_slice(&0x0100000Cu32.to_le_bytes());
        let info = parse_macho(&data).expect("should parse arm64 Mach-O");
        assert_eq!(info.cpu_type, "arm64");
    }

    #[test]
    fn parse_macho_dylib_type() {
        let mut data = make_minimal_macho64();
        // filetype: MH_DYLIB = 6
        data[12..16].copy_from_slice(&6u32.to_le_bytes());
        let info = parse_macho(&data).expect("should parse dylib Mach-O");
        assert_eq!(info.file_type, "dylib");
    }

    #[test]
    fn parse_macho_empty_input() {
        let result = parse_macho(&[]);
        assert!(result.is_err(), "empty input should return error");
    }

    #[test]
    fn parse_macho_truncated() {
        let data = [0xCF, 0xFA, 0xED, 0xFE]; // just the magic, nothing else
        let result = parse_macho(&data);
        assert!(result.is_err(), "truncated Mach-O should return error");
    }

    #[test]
    fn parse_macho_invalid_magic() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let result = parse_macho(&data);
        assert!(result.is_err(), "invalid magic should return error");
    }

    #[test]
    fn parse_macho_no_sections_no_imports() {
        let data = make_minimal_macho64();
        let info = parse_macho(&data).expect("should parse minimal Mach-O");
        assert!(info.sections.is_empty());
        assert!(info.imports.is_empty());
    }

    #[test]
    fn parse_macho_object_type() {
        let mut data = make_minimal_macho64();
        // filetype: MH_OBJECT = 1
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        let info = parse_macho(&data).expect("should parse object Mach-O");
        assert_eq!(info.file_type, "object");
    }
}
