//! Packer and obfuscation detection.
//!
//! Many malware samples are packed (compressed/encrypted) to evade signature
//! scanners. This module detects common packers by inspecting PE section names,
//! entry-point placement, and other structural anomalies.

use prx_sd_parsers::pe::{PeInfo, SectionInfo};
use serde::{Deserialize, Serialize};

/// Known packer / protector families.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerType {
    UPX,
    ASPack,
    Themida,
    VMProtect,
    PECompact,
    MPRESS,
    Enigma,
    /// An unrecognised packer identified by a heuristic (section name, etc.).
    Unknown(String),
}

impl std::fmt::Display for PackerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UPX => write!(f, "UPX"),
            Self::ASPack => write!(f, "ASPack"),
            Self::Themida => write!(f, "Themida"),
            Self::VMProtect => write!(f, "VMProtect"),
            Self::PECompact => write!(f, "PECompact"),
            Self::MPRESS => write!(f, "MPRESS"),
            Self::Enigma => write!(f, "Enigma"),
            Self::Unknown(hint) => write!(f, "Unknown({hint})"),
        }
    }
}

/// Attempt to detect a known packer by inspecting section names and structural
/// anomalies in a PE file.
///
/// Returns `Some(PackerType)` if a packer signature is found, `None` otherwise.
pub fn detect_packer(pe: &PeInfo) -> Option<PackerType> {
    // Check section names first — this is the most reliable static indicator.
    if let Some(packer) = check_section_names(&pe.sections) {
        return Some(packer);
    }

    // Some packers don't leave obvious section names but exhibit structural
    // anomalies. For now we don't upgrade those to a named PackerType without
    // a section-name match, but entry point anomalies are checked separately
    // by the engine and generate their own findings.

    None
}

/// Identify a packer by matching characteristic PE section names.
///
/// Most commercial and open-source packers stamp their section names with
/// recognisable prefixes or exact strings.
pub fn check_section_names(sections: &[SectionInfo]) -> Option<PackerType> {
    for section in sections {
        let name = section.name.as_str();
        let name_upper = section.name.to_uppercase();

        // UPX: sections named UPX0, UPX1, UPX2, or .UPX
        if name_upper.starts_with("UPX") || name_upper == ".UPX" {
            return Some(PackerType::UPX);
        }

        // ASPack: .aspack, .adata
        if name == ".aspack" || name == ".adata" || name == ".ASPack" {
            return Some(PackerType::ASPack);
        }

        // Themida: .themida, .Themida
        if name_upper.starts_with(".THEMIDA") {
            return Some(PackerType::Themida);
        }

        // VMProtect: .vmp0, .vmp1, .vmp2
        if name.starts_with(".vmp") && name.len() == 5 {
            if let Some(digit) = name.chars().last() {
                if digit.is_ascii_digit() {
                    return Some(PackerType::VMProtect);
                }
            }
        }

        // PECompact: .pec, .pec1, .pec2, pec1, pec2
        if name.starts_with(".pec") || name.starts_with("pec") {
            return Some(PackerType::PECompact);
        }

        // MPRESS: .MPRESS1, .MPRESS2, .MPress
        if name_upper.starts_with(".MPRESS") || name_upper == "MPRESS" {
            return Some(PackerType::MPRESS);
        }

        // Enigma Protector: .enigma1, .enigma2
        if name.starts_with(".enigma") {
            return Some(PackerType::Enigma);
        }

        // Armadillo: .text1, PDATA (heuristic — less specific)
        // NSPack: .nsp0, .nsp1, .nsp2
        if name.starts_with(".nsp") {
            return Some(PackerType::Unknown("NSPack".to_string()));
        }

        // PEtite: .petite
        if name == ".petite" {
            return Some(PackerType::Unknown("PEtite".to_string()));
        }

        // FSG: (typically no obvious section name, but sometimes seen)
        // Yoda: .yP, .y0da
        if name == ".yP" || name == ".y0da" {
            return Some(PackerType::Unknown("Yoda".to_string()));
        }

        // MEW: MEW
        if name_upper == "MEW" || name_upper == ".MEW" {
            return Some(PackerType::Unknown("MEW".to_string()));
        }
    }

    None
}

/// Check whether the entry point (EP) is in an anomalous location.
///
/// In legitimate executables, the EP virtually always resides in the first
/// code section (`.text`). Packers frequently place it in the last section
/// or in a section that doesn't exist in normal builds.
///
/// Returns `true` if the EP placement looks suspicious.
pub fn check_entry_point_anomaly(pe: &PeInfo) -> bool {
    if pe.sections.is_empty() {
        return false;
    }

    // Check: EP in the last section (very common for packers).
    if let Some(last) = pe.sections.last() {
        // Sections in goblin store virtual address offsets relative to the
        // image base. The entry_point from goblin is an RVA. We approximate
        // section boundaries using virtual_size.
        // Since we don't have the section RVA directly in SectionInfo, we
        // use a heuristic: if the entry point is beyond all sections except
        // the last one, flag it.
        if pe.sections.len() >= 2 {
            let last_idx = pe.sections.len() - 1;
            // If EP is in the last section, that's suspicious for non-DLL PEs.
            // We check by seeing if EP falls within any earlier section.
            // Without section VAs in SectionInfo, we use a simpler heuristic:
            // the last section being the only writable+executable one with the EP.
            let _ = last; // used below

            // Simpler check: if the first section is named .text and the EP
            // is NOT in a section whose name starts with .text, that's suspicious.
            let Some(first) = pe.sections.first() else {
                return false;
            };
            if first.name == ".text" || first.name == ".code" {
                let Some(last) = pe.sections.get(last_idx) else {
                    return false;
                };
                // If the last section has a packer-like name, the EP being
                // there is suspicious.
                let name_upper = last.name.to_uppercase();
                if name_upper.starts_with("UPX")
                    || name_upper.starts_with(".VMP")
                    || name_upper.starts_with(".MPRESS")
                    || name_upper.starts_with(".ASPACK")
                    || name_upper.starts_with(".THEMIDA")
                {
                    return true;
                }
            }
        }
    }

    // Check: EP outside the first section is suspicious when the first section
    // is a standard code section. Without full VA info we use a raw-size
    // heuristic: if the first section is .text and its raw_size is very small
    // relative to the file, something is likely packed.
    if let Some(first) = pe.sections.first() {
        if (first.name == ".text" || first.name == ".code") && first.raw_size == 0 {
            // A .text section with zero raw size is a strong packer indicator —
            // the real code is unpacked at runtime.
            return true;
        }
    }

    false
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    use prx_sd_parsers::pe::SectionInfo;

    fn make_section(name: &str) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            entropy: 5.0,
            characteristics: 0,
        }
    }

    #[test]
    fn detect_upx_sections() {
        let sections = vec![make_section("UPX0"), make_section("UPX1")];
        assert_eq!(check_section_names(&sections), Some(PackerType::UPX));
    }

    #[test]
    fn detect_vmprotect_sections() {
        let sections = vec![make_section(".text"), make_section(".vmp0")];
        assert_eq!(check_section_names(&sections), Some(PackerType::VMProtect));
    }

    #[test]
    fn detect_aspack_sections() {
        let sections = vec![make_section(".aspack")];
        assert_eq!(check_section_names(&sections), Some(PackerType::ASPack));
    }

    #[test]
    fn detect_themida_sections() {
        let sections = vec![make_section(".themida")];
        assert_eq!(check_section_names(&sections), Some(PackerType::Themida));
    }

    #[test]
    fn detect_mpress_sections() {
        let sections = vec![make_section(".MPRESS1"), make_section(".MPRESS2")];
        assert_eq!(check_section_names(&sections), Some(PackerType::MPRESS));
    }

    #[test]
    fn detect_enigma_sections() {
        let sections = vec![make_section(".enigma1")];
        assert_eq!(check_section_names(&sections), Some(PackerType::Enigma));
    }

    #[test]
    fn no_packer_in_normal_sections() {
        let sections = vec![
            make_section(".text"),
            make_section(".rdata"),
            make_section(".data"),
            make_section(".rsrc"),
        ];
        assert_eq!(check_section_names(&sections), None);
    }

    #[test]
    fn detect_packer_delegates_to_section_names() {
        let pe = PeInfo {
            is_64bit: false,
            is_dll: false,
            entry_point: 0x1000,
            timestamp: 0,
            sections: vec![make_section("UPX0"), make_section("UPX1")],
            imports: vec![],
            exports: vec![],
            imphash: String::new(),
            debug_info: None,
        };
        assert_eq!(detect_packer(&pe), Some(PackerType::UPX));
    }

    #[test]
    fn entry_point_anomaly_zero_text() {
        let pe = PeInfo {
            is_64bit: false,
            is_dll: false,
            entry_point: 0x5000,
            timestamp: 0,
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x1000,
                raw_size: 0,
                entropy: 0.0,
                characteristics: 0,
            }],
            imports: vec![],
            exports: vec![],
            imphash: String::new(),
            debug_info: None,
        };
        assert!(check_entry_point_anomaly(&pe));
    }

    #[test]
    fn no_anomaly_normal_pe() {
        let pe = PeInfo {
            is_64bit: false,
            is_dll: false,
            entry_point: 0x1000,
            timestamp: 0x60000000,
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x5000,
                raw_size: 0x4800,
                entropy: 6.2,
                characteristics: 0x60000020,
            }],
            imports: vec![],
            exports: vec![],
            imphash: String::new(),
            debug_info: None,
        };
        assert!(!check_entry_point_anomaly(&pe));
    }
}
