//! ML feature extraction from parsed binary files.
//!
//! Extracts a fixed-size numerical feature vector suitable for
//! gradient-boosted decision tree or neural network classifiers.

// ML feature extraction intentionally casts integer counts/sizes to floats.
// Precision loss is acceptable: features are normalised to [0,1] anyway.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use prx_sd_parsers::elf::ElfInfo;
use prx_sd_parsers::pe::PeInfo;

use crate::entropy::shannon_entropy;
use crate::suspicious_api::{ApiCategory, WINDOWS_SUSPICIOUS_APIS};

/// Fixed feature vector size for the PE model.
pub const PE_FEATURE_DIM: usize = 64;
/// Fixed feature vector size for the ELF model.
pub const ELF_FEATURE_DIM: usize = 48;

/// Extract a fixed-size feature vector from a parsed PE file.
///
/// The feature layout is documented in the module-level specification.
/// All values are normalised to roughly `[0.0, 1.0]` (or small positive
/// range) for compatibility with gradient-boosted or neural classifiers.
#[allow(clippy::indexing_slicing)] // All indices are compile-time constants within PE_FEATURE_DIM (64)
#[allow(clippy::items_after_statements)] // PE section flag constants are co-located with their usage for clarity
pub fn extract_pe_features(info: &PeInfo, data: &[u8]) -> [f32; PE_FEATURE_DIM] {
    let mut f = [0.0f32; PE_FEATURE_DIM];
    let file_size = data.len().max(1) as f64;

    // [0] is_64bit
    f[0] = if info.is_64bit { 1.0 } else { 0.0 };
    // [1] is_dll
    f[1] = if info.is_dll { 1.0 } else { 0.0 };
    // [2] entry_point normalized
    f[2] = (info.entry_point as f64 / file_size).min(1.0) as f32;
    // [3] timestamp normalised: 0 = zero/invalid, 1 = valid recent, 0.5 = old
    f[3] = normalise_timestamp(info.timestamp);
    // [4] num_sections
    f[4] = info.sections.len() as f32;
    // [5] num_imports (DLL count)
    f[5] = info.imports.len() as f32;
    // [6] num_import_functions
    let total_funcs: usize = info.imports.iter().map(|i| i.functions.len()).sum();
    f[6] = total_funcs as f32;
    // [7] num_exports
    f[7] = info.exports.len() as f32;

    // [8] overall_entropy
    let overall = shannon_entropy(data);
    f[8] = (overall / 8.0) as f32;

    // [9-11] section entropy stats
    if !info.sections.is_empty() {
        let mut max_e = f64::MIN;
        let mut min_e = f64::MAX;
        let mut sum_e = 0.0;
        for s in &info.sections {
            if s.entropy > max_e {
                max_e = s.entropy;
            }
            if s.entropy < min_e {
                min_e = s.entropy;
            }
            sum_e += s.entropy;
        }
        f[9] = (max_e / 8.0) as f32;
        f[10] = (min_e / 8.0) as f32;
        f[11] = (sum_e / (info.sections.len() as f64 * 8.0)) as f32;
    }

    // [12] has_upx_section
    f[12] = if info.sections.iter().any(|s| {
        let n = s.name.to_uppercase();
        n.starts_with("UPX") || n == ".UPX0" || n == ".UPX1"
    }) {
        1.0
    } else {
        0.0
    };

    // [13] has_writable_code
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    f[13] = if info.sections.iter().any(|s| {
        let is_code = s.characteristics & IMAGE_SCN_CNT_CODE != 0 || s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_write = s.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        is_code && is_write
    }) {
        1.0
    } else {
        0.0
    };

    // [14-20] suspicious API category counts (7 categories)
    let cat_counts = count_suspicious_api_categories(info);
    f[14] = cat_counts[0] as f32 / 50.0; // ProcessInjection
    f[15] = cat_counts[1] as f32 / 50.0; // AntiDebug
    f[16] = cat_counts[2] as f32 / 50.0; // Persistence
    f[17] = cat_counts[3] as f32 / 50.0; // NetworkExfil
    f[18] = cat_counts[4] as f32 / 50.0; // Crypto
    f[19] = cat_counts[5] as f32 / 50.0; // Privilege
    f[20] = cat_counts[6] as f32 / 50.0; // FileSystem

    // [21-23] section size ratios
    for s in &info.sections {
        let ratio = (s.raw_size as f64 / file_size).min(1.0) as f32;
        match s.name.as_str() {
            ".text" => f[21] = ratio,
            ".data" => f[22] = ratio,
            ".rsrc" => f[23] = ratio,
            _ => {}
        }
    }

    // [24] num_zero_size_sections
    f[24] = info.sections.iter().filter(|s| s.raw_size == 0).count() as f32;

    // [25] num_high_entropy_sections (>7.0)
    f[25] = info.sections.iter().filter(|s| s.entropy > 7.0).count() as f32;

    // [26-57] section entropy histogram (32 bins across [0,8])
    fill_entropy_histogram(&info.sections, &mut f[26..58], 32);

    // [58] has_debug_info
    f[58] = if info.debug_info.is_some() { 1.0 } else { 0.0 };

    // [59] imphash first 4 bytes as f32 for clustering
    f[59] = imphash_to_f32(&info.imphash);

    // [60-63] reserved (already zeroed)

    f
}

/// Extract a fixed-size feature vector from a parsed ELF file.
#[allow(clippy::indexing_slicing)] // All indices are compile-time constants within ELF_FEATURE_DIM (48)
pub fn extract_elf_features(info: &ElfInfo, data: &[u8]) -> [f32; ELF_FEATURE_DIM] {
    let mut f = [0.0f32; ELF_FEATURE_DIM];
    let file_size = data.len().max(1) as f64;

    // [0] is_64bit
    f[0] = if info.is_64bit { 1.0 } else { 0.0 };
    // [1] elf_type_numeric
    f[1] = match info.elf_type.as_str() {
        "NONE" => 0.0,
        "REL" => 1.0,
        "EXEC" => 2.0,
        "DYN" => 3.0,
        "CORE" => 4.0,
        _ => 5.0,
    };
    // [2] entry_point normalized
    f[2] = (info.entry_point as f64 / file_size).min(1.0) as f32;
    // [3] num_sections
    f[3] = info.sections.len() as f32;
    // [4] num_symbols
    f[4] = info.symbols.len() as f32;
    // [5] num_dynamic_libs
    f[5] = info.dynamic_libs.len() as f32;
    // [6] has_interpreter
    f[6] = if info.interpreter.is_some() { 1.0 } else { 0.0 };

    // [7] overall_entropy
    let overall = shannon_entropy(data);
    f[7] = (overall / 8.0) as f32;

    // [8-10] section entropy stats
    if !info.sections.is_empty() {
        let mut max_e = f64::MIN;
        let mut min_e = f64::MAX;
        let mut sum_e = 0.0;
        for s in &info.sections {
            if s.entropy > max_e {
                max_e = s.entropy;
            }
            if s.entropy < min_e {
                min_e = s.entropy;
            }
            sum_e += s.entropy;
        }
        f[8] = (max_e / 8.0) as f32;
        f[9] = (min_e / 8.0) as f32;
        f[10] = (sum_e / (info.sections.len() as f64 * 8.0)) as f32;
    }

    // [11-16] suspicious Linux API counts
    let linux_apis: [&str; 6] = ["ptrace", "mprotect", "memfd_create", "execveat", "socket", "connect"];
    for (idx, api) in linux_apis.iter().enumerate() {
        f[11 + idx] = info.symbols.iter().filter(|s| s.contains(api)).count() as f32;
    }

    // [17] num_high_entropy_sections
    f[17] = info.sections.iter().filter(|s| s.entropy > 7.0).count() as f32;

    // [18-41] section entropy histogram (24 bins)
    fill_entropy_histogram(&info.sections, &mut f[18..42], 24);

    // [42] has_ld_preload_ref
    f[42] = if info.symbols.iter().any(|s| s.contains("LD_PRELOAD")) {
        1.0
    } else {
        0.0
    };

    // [43] has_ptrace_ref
    f[43] = if info.symbols.iter().any(|s| s.contains("ptrace")) {
        1.0
    } else {
        0.0
    };

    // [44] has_crypto_symbols
    let crypto_names = ["AES", "aes_", "SHA256", "sha256", "EVP_", "crypto_", "CRYPTO_"];
    f[44] = if info.symbols.iter().any(|s| crypto_names.iter().any(|c| s.contains(c))) {
        1.0
    } else {
        0.0
    };

    // [45-47] reserved (already zeroed)

    f
}

// ---- helpers ----------------------------------------------------------------

/// Normalise a PE timestamp to [0, 1].
///
/// - 0 or very large (>2030) → 0.0 (suspicious: zeroed or far-future)
/// - Recent (2015-2030) → 1.0 (likely legitimate)
/// - Old (2000-2014) → 0.5
/// - Very old (<2000) → 0.2
#[allow(clippy::missing_const_for_fn)] // Cannot be const: u64::from() is not const-stable
fn normalise_timestamp(ts: u32) -> f32 {
    if ts == 0 {
        return 0.0;
    }
    // Approximate year from Unix timestamp
    let year = 1970 + (ts as u64 / 31_536_000);
    match year {
        0..=1999 => 0.2,
        2000..=2014 => 0.5,
        2015..=2030 => 1.0,
        _ => 0.0, // far future, suspicious
    }
}

/// Count suspicious Windows API imports by category.
///
/// Returns an array of 7 counts in order:
/// `[ProcessInjection, AntiDebug, Persistence, NetworkExfil, Crypto, Privilege, FileSystem]`
fn count_suspicious_api_categories(info: &PeInfo) -> [u32; 7] {
    let mut counts = [0u32; 7];
    for imp in &info.imports {
        for func in &imp.functions {
            for entry in WINDOWS_SUSPICIOUS_APIS {
                if func.eq_ignore_ascii_case(entry.name) {
                    let idx = match entry.category {
                        ApiCategory::ProcessInjection => 0,
                        ApiCategory::AntiDebug => 1,
                        ApiCategory::Persistence => 2,
                        ApiCategory::NetworkExfil => 3,
                        ApiCategory::Crypto => 4,
                        ApiCategory::Privilege => 5,
                        ApiCategory::FileSystem => 6,
                    };
                    // SAFETY: idx is always 0..=6 from the exhaustive match above,
                    // which is within bounds of the 7-element array.
                    #[allow(clippy::indexing_slicing)]
                    {
                        counts[idx] += 1;
                    }
                    break;
                }
            }
        }
    }
    counts
}

/// Fill an entropy histogram from section entropies.
///
/// Bins span `[0, 8)` evenly. Each section increments its corresponding bin.
/// The histogram is normalised by section count (so values are in `[0, 1]`).
fn fill_entropy_histogram(sections: &[prx_sd_parsers::pe::SectionInfo], out: &mut [f32], num_bins: usize) {
    debug_assert_eq!(out.len(), num_bins);
    if sections.is_empty() || num_bins == 0 {
        return;
    }
    let bin_width = 8.0 / num_bins as f64;
    for s in sections {
        let bin = ((s.entropy / bin_width) as usize).min(num_bins - 1);
        // SAFETY: `bin` is clamped to `num_bins - 1` which equals `out.len() - 1`.
        if let Some(slot) = out.get_mut(bin) {
            *slot += 1.0;
        }
    }
    let count = sections.len() as f32;
    for val in out.iter_mut() {
        *val /= count;
    }
}

/// Convert the first 4 hex chars of an imphash string to a normalised f32.
///
/// Used as a rough clustering feature, not for exact matching.
fn imphash_to_f32(imphash: &str) -> f32 {
    if imphash.len() < 4 {
        return 0.0;
    }
    imphash
        .get(..4)
        .and_then(|s| u16::from_str_radix(s, 16).ok())
        .map_or(0.0, |v| f32::from(v) / 65535.0)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::float_cmp, clippy::unreadable_literal)]
mod tests {
    use super::*;
    use prx_sd_parsers::elf::ElfInfo;
    use prx_sd_parsers::pe::{ImportInfo, PeInfo, SectionInfo};

    fn sample_pe() -> PeInfo {
        PeInfo {
            is_64bit: true,
            is_dll: false,
            entry_point: 0x1000,
            timestamp: 1_700_000_000, // ~2023
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    virtual_size: 0x5000,
                    raw_size: 0x4800,
                    entropy: 6.2,
                    characteristics: 0x6000_0020,
                },
                SectionInfo {
                    name: ".data".to_string(),
                    virtual_size: 0x1000,
                    raw_size: 0x800,
                    entropy: 3.1,
                    characteristics: 0xC000_0040,
                },
            ],
            imports: vec![ImportInfo {
                dll: "kernel32.dll".to_string(),
                functions: vec!["GetProcAddress".to_string(), "VirtualAllocEx".to_string()],
            }],
            exports: vec!["DllMain".to_string()],
            imphash: "abcd1234".to_string(),
            debug_info: Some("test.pdb".to_string()),
        }
    }

    fn sample_elf() -> ElfInfo {
        ElfInfo {
            is_64bit: true,
            elf_type: "EXEC".to_string(),
            entry_point: 0x400000,
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    virtual_size: 0x2000,
                    raw_size: 0x2000,
                    entropy: 5.8,
                    characteristics: 0,
                },
                SectionInfo {
                    name: ".rodata".to_string(),
                    virtual_size: 0x800,
                    raw_size: 0x800,
                    entropy: 4.2,
                    characteristics: 0,
                },
            ],
            symbols: vec!["main".to_string(), "ptrace".to_string(), "socket".to_string()],
            dynamic_libs: vec!["libc.so.6".to_string()],
            interpreter: Some("/lib64/ld-linux-x86-64.so.2".to_string()),
        }
    }

    #[test]
    fn pe_features_correct_dimension() {
        let pe = sample_pe();
        let data = vec![0u8; 0x10000];
        let features = extract_pe_features(&pe, &data);
        assert_eq!(features.len(), PE_FEATURE_DIM);
    }

    #[test]
    fn pe_features_basic_values() {
        let pe = sample_pe();
        let data = vec![0u8; 0x10000];
        let features = extract_pe_features(&pe, &data);

        // is_64bit
        assert_eq!(features[0], 1.0);
        // is_dll
        assert_eq!(features[1], 0.0);
        // num_sections
        assert_eq!(features[4], 2.0);
        // has_debug_info
        assert_eq!(features[58], 1.0);
    }

    #[test]
    fn elf_features_correct_dimension() {
        let elf = sample_elf();
        let data = vec![0u8; 0x10000];
        let features = extract_elf_features(&elf, &data);
        assert_eq!(features.len(), ELF_FEATURE_DIM);
    }

    #[test]
    fn elf_features_basic_values() {
        let elf = sample_elf();
        let data = vec![0u8; 0x10000];
        let features = extract_elf_features(&elf, &data);

        // is_64bit
        assert_eq!(features[0], 1.0);
        // elf_type EXEC = 2.0
        assert_eq!(features[1], 2.0);
        // has_interpreter
        assert_eq!(features[6], 1.0);
        // has_ptrace_ref
        assert_eq!(features[43], 1.0);
    }

    #[test]
    fn normalise_timestamp_boundaries() {
        assert_eq!(normalise_timestamp(0), 0.0);
        // Year ~2023
        assert_eq!(normalise_timestamp(1_700_000_000), 1.0);
        // Year ~2005
        assert_eq!(normalise_timestamp(1_100_000_000), 0.5);
        // Very old
        assert_eq!(normalise_timestamp(100_000_000), 0.2);
    }

    #[test]
    fn imphash_conversion() {
        assert!((imphash_to_f32("ffff") - 1.0).abs() < 0.001);
        assert_eq!(imphash_to_f32("0000"), 0.0);
        assert_eq!(imphash_to_f32(""), 0.0);
        assert_eq!(imphash_to_f32("zz"), 0.0);
    }

    #[test]
    fn entropy_histogram_sums_to_one() {
        let sections = vec![
            SectionInfo {
                name: ".text".to_string(),
                virtual_size: 0x1000,
                raw_size: 0x1000,
                entropy: 5.5,
                characteristics: 0,
            },
            SectionInfo {
                name: ".data".to_string(),
                virtual_size: 0x1000,
                raw_size: 0x1000,
                entropy: 2.3,
                characteristics: 0,
            },
        ];
        let mut hist = [0.0f32; 32];
        fill_entropy_histogram(&sections, &mut hist, 32);
        let sum: f32 = hist.iter().sum();
        assert!((sum - 1.0).abs() < 0.01, "histogram should sum to ~1.0, got {sum}");
    }

    #[test]
    fn empty_sections_zero_histogram() {
        let mut hist = [0.0f32; 32];
        fill_entropy_histogram(&[], &mut hist, 32);
        assert!(hist.iter().all(|&v| v == 0.0));
    }
}
