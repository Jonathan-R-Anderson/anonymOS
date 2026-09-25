use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::pe::SectionInfo;
use crate::shannon_entropy;

/// Information about an ELF (Executable and Linkable Format) file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfInfo {
    pub is_64bit: bool,
    pub elf_type: String,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<String>,
    pub dynamic_libs: Vec<String>,
    pub interpreter: Option<String>,
}

/// Parse an ELF file from raw bytes, extracting structural metadata for analysis.
pub fn parse_elf(data: &[u8]) -> Result<ElfInfo> {
    let elf = goblin::elf::Elf::parse(data).context("failed to parse ELF file")?;

    let is_64bit = elf.is_64;

    let elf_type = match elf.header.e_type {
        goblin::elf::header::ET_NONE => "NONE",
        goblin::elf::header::ET_REL => "REL",
        goblin::elf::header::ET_EXEC => "EXEC",
        goblin::elf::header::ET_DYN => "DYN",
        goblin::elf::header::ET_CORE => "CORE",
        _ => "UNKNOWN",
    }
    .to_string();

    let entry_point = elf.entry;

    // Sections
    let sections: Vec<SectionInfo> = elf
        .section_headers
        .iter()
        .map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();

            #[allow(clippy::cast_possible_truncation)]
            let offset = sh.sh_offset as usize;
            #[allow(clippy::cast_possible_truncation)]
            let size = sh.sh_size as usize;
            let is_nobits = sh.sh_type == goblin::elf::section_header::SHT_NOBITS;
            let section_data = if is_nobits {
                &[]
            } else {
                data.get(offset..offset.saturating_add(size)).unwrap_or(&[])
            };
            let entropy = shannon_entropy(section_data);

            #[allow(clippy::cast_possible_truncation)]
            let characteristics = sh.sh_flags as u32;
            SectionInfo {
                name,
                virtual_size: sh.sh_size,
                raw_size: if is_nobits { 0 } else { sh.sh_size },
                entropy,
                characteristics,
            }
        })
        .collect();

    // Symbols (both static and dynamic)
    let mut symbols: Vec<String> = Vec::new();
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                symbols.push(name.to_string());
            }
        }
    }
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if !name.is_empty() {
                symbols.push(name.to_string());
            }
        }
    }
    symbols.sort();
    symbols.dedup();

    // Dynamic libraries (DT_NEEDED entries)
    let dynamic_libs: Vec<String> = elf.libraries.iter().map(std::string::ToString::to_string).collect();

    // Interpreter (e.g. /lib64/ld-linux-x86-64.so.2)
    let interpreter = elf.interpreter.map(std::string::ToString::to_string);

    debug!(
        is_64bit,
        %elf_type,
        entry_point,
        sections = sections.len(),
        symbols = symbols.len(),
        dynamic_libs = dynamic_libs.len(),
        "parsed ELF metadata"
    );

    Ok(ElfInfo {
        is_64bit,
        elf_type,
        entry_point,
        sections,
        symbols,
        dynamic_libs,
        interpreter,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unreadable_literal)]
mod tests {
    use super::*;

    /// Build a minimal 64-bit little-endian ELF executable.
    fn make_minimal_elf64() -> Vec<u8> {
        // ELF64 header = 64 bytes
        // We'll create an ELF with e_shnum=0 (no sections), e_phnum=0 (no program headers)
        let mut elf = vec![0u8; 256];

        // ELF magic
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        // EI_CLASS: 2 = 64-bit
        elf[4] = 2;
        // EI_DATA: 1 = little-endian
        elf[5] = 1;
        // EI_VERSION: 1
        elf[6] = 1;
        // EI_OSABI: 0 = ELFOSABI_NONE
        elf[7] = 0;

        // e_type: ET_EXEC = 2 (offset 16, 2 bytes)
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine: EM_X86_64 = 62 (offset 18, 2 bytes)
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version: 1 (offset 20, 4 bytes)
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry: 0x400000 (offset 24, 8 bytes for ELF64)
        elf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        // e_phoff: 0 (no program headers) (offset 32, 8 bytes)
        elf[32..40].copy_from_slice(&0u64.to_le_bytes());
        // e_shoff: 0 (no section headers) (offset 40, 8 bytes)
        elf[40..48].copy_from_slice(&0u64.to_le_bytes());
        // e_flags: 0 (offset 48, 4 bytes)
        // e_ehsize: 64 (offset 52, 2 bytes)
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize: 56 (offset 54, 2 bytes)
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum: 0 (offset 56, 2 bytes)
        elf[56..58].copy_from_slice(&0u16.to_le_bytes());
        // e_shentsize: 64 (offset 58, 2 bytes)
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        // e_shnum: 0 (offset 60, 2 bytes)
        elf[60..62].copy_from_slice(&0u16.to_le_bytes());
        // e_shstrndx: 0 (offset 62, 2 bytes)
        elf[62..64].copy_from_slice(&0u16.to_le_bytes());

        elf
    }

    /// Build a minimal 32-bit little-endian ELF executable.
    fn make_minimal_elf32() -> Vec<u8> {
        // ELF32 header = 52 bytes
        let mut elf = vec![0u8; 256];

        // ELF magic
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        // EI_CLASS: 1 = 32-bit
        elf[4] = 1;
        // EI_DATA: 1 = little-endian
        elf[5] = 1;
        // EI_VERSION: 1
        elf[6] = 1;

        // e_type: ET_EXEC = 2 (offset 16, 2 bytes)
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine: EM_386 = 3 (offset 18, 2 bytes)
        elf[18..20].copy_from_slice(&3u16.to_le_bytes());
        // e_version: 1 (offset 20, 4 bytes)
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry: 0x08048000 (offset 24, 4 bytes for ELF32)
        elf[24..28].copy_from_slice(&0x08048000u32.to_le_bytes());
        // e_phoff: 0 (offset 28, 4 bytes)
        elf[28..32].copy_from_slice(&0u32.to_le_bytes());
        // e_shoff: 0 (offset 32, 4 bytes)
        elf[32..36].copy_from_slice(&0u32.to_le_bytes());
        // e_flags: 0 (offset 36, 4 bytes)
        // e_ehsize: 52 (offset 40, 2 bytes)
        elf[40..42].copy_from_slice(&52u16.to_le_bytes());
        // e_phentsize: 32 (offset 42, 2 bytes)
        elf[42..44].copy_from_slice(&32u16.to_le_bytes());
        // e_phnum: 0 (offset 44, 2 bytes)
        elf[44..46].copy_from_slice(&0u16.to_le_bytes());
        // e_shentsize: 40 (offset 46, 2 bytes)
        elf[46..48].copy_from_slice(&40u16.to_le_bytes());
        // e_shnum: 0 (offset 48, 2 bytes)
        elf[48..50].copy_from_slice(&0u16.to_le_bytes());
        // e_shstrndx: 0 (offset 50, 2 bytes)
        elf[50..52].copy_from_slice(&0u16.to_le_bytes());

        elf
    }

    #[test]
    fn parse_elf_64bit() {
        let data = make_minimal_elf64();
        let info = parse_elf(&data).expect("should parse valid 64-bit ELF");
        assert!(info.is_64bit);
        assert_eq!(info.elf_type, "EXEC");
        assert_eq!(info.entry_point, 0x400000);
    }

    #[test]
    fn parse_elf_32bit() {
        let data = make_minimal_elf32();
        let info = parse_elf(&data).expect("should parse valid 32-bit ELF");
        assert!(!info.is_64bit);
        assert_eq!(info.elf_type, "EXEC");
        assert_eq!(info.entry_point, 0x08048000);
    }

    #[test]
    fn parse_elf_dyn_type() {
        let mut data = make_minimal_elf64();
        // Change e_type to ET_DYN = 3
        data[16..18].copy_from_slice(&3u16.to_le_bytes());
        let info = parse_elf(&data).expect("should parse DYN ELF");
        assert_eq!(info.elf_type, "DYN");
    }

    #[test]
    fn parse_elf_empty_input() {
        let result = parse_elf(&[]);
        assert!(result.is_err(), "empty input should return error");
    }

    #[test]
    fn parse_elf_truncated() {
        // Just the magic bytes, nothing more
        let data = [0x7f, b'E', b'L', b'F'];
        let result = parse_elf(&data);
        assert!(result.is_err(), "truncated ELF should return error");
    }

    #[test]
    fn parse_elf_invalid_magic() {
        let mut data = make_minimal_elf64();
        data[0] = 0x00; // corrupt magic
        let result = parse_elf(&data);
        assert!(result.is_err(), "invalid magic should return error");
    }

    #[test]
    fn parse_elf_no_sections_no_symbols() {
        let data = make_minimal_elf64();
        let info = parse_elf(&data).expect("should parse minimal ELF");
        assert!(info.sections.is_empty());
        assert!(info.symbols.is_empty());
        assert!(info.dynamic_libs.is_empty());
        assert!(info.interpreter.is_none());
    }

    #[test]
    fn parse_elf_rel_type() {
        let mut data = make_minimal_elf64();
        // Change e_type to ET_REL = 1
        data[16..18].copy_from_slice(&1u16.to_le_bytes());
        let info = parse_elf(&data).expect("should parse REL ELF");
        assert_eq!(info.elf_type, "REL");
    }

    #[test]
    fn parse_elf_core_type() {
        let mut data = make_minimal_elf64();
        // Change e_type to ET_CORE = 4
        data[16..18].copy_from_slice(&4u16.to_le_bytes());
        let info = parse_elf(&data).expect("should parse CORE ELF");
        assert_eq!(info.elf_type, "CORE");
    }

    #[test]
    fn parse_elf_garbage_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let result = parse_elf(&data);
        assert!(result.is_err(), "garbage data should return error");
    }
}
