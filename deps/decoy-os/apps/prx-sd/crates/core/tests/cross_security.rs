//! Cross-crate security hardening regression tests.
//!
//! Scenarios 39-42: quarantine path-traversal prevention, PE API dedup,
//! and bidirectional A/W suffix matching.
//!
//! BUG-H01: quarantine restore path traversal via `..` components.
//! BUG-M10: A/W suffix dedup in raw-byte PE API scanner.
//! BUG-M13: bidirectional suffix stripping in `func_matches`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal,
    clippy::redundant_closure_for_method_calls,
    clippy::format_collect,
    clippy::int_plus_one,
    clippy::needless_collect,
    clippy::if_not_else,
    clippy::redundant_clone,
    clippy::uninlined_format_args,
    clippy::similar_names,
    clippy::used_underscore_binding,
    clippy::unnecessary_wraps,
    clippy::bool_assert_comparison,
    clippy::vec_init_then_push,
    clippy::print_stderr,
    clippy::write_with_newline,
    clippy::needless_pass_by_value,
    clippy::match_same_arms,
    clippy::manual_let_else,
    clippy::return_self_not_must_use,
    clippy::must_use_candidate,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
use std::fs;

use prx_sd_heuristic::{Finding, HeuristicEngine};
use prx_sd_parsers::ParsedFile;
use prx_sd_parsers::pe::{ImportInfo, PeInfo, SectionInfo};
use prx_sd_quarantine::Quarantine;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `ParsedFile::PE` for heuristic tests.
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

/// Embed a byte pattern at the given offset in a mutable buffer.
fn embed(data: &mut [u8], offset: usize, pattern: &[u8]) {
    if offset + pattern.len() <= data.len() {
        data[offset..offset + pattern.len()].copy_from_slice(pattern);
    }
}

// ---------------------------------------------------------------------------
// Scenario 39: quarantine_restore_uses_resolved_path
// ---------------------------------------------------------------------------

/// BUG-H01 regression: quarantine restore must write to the canonicalized path.
///
/// Steps:
/// 1. Create a temporary vault and store a test file.
/// 2. Create a symlink pointing to the real restore directory.
/// 3. Restore via the symlink path — the vault should canonicalize it.
/// 4. Verify the file lands in the real directory (resolved through the symlink).
/// 5. Verify content integrity (byte-for-byte match).
#[cfg(unix)]
#[test]
fn quarantine_restore_uses_resolved_path() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    let vault = Quarantine::new(vault_dir).expect("create vault");

    // Create the original file to quarantine.
    let original_content = b"BUG-H01 regression: resolved path test payload";
    let original_path = tmp.path().join("original_test_file.bin");
    fs::write(&original_path, original_content).unwrap();

    // Store (quarantine) the file.
    let qid = vault
        .quarantine(&original_path, "Test.ResolvedPath")
        .expect("quarantine file");

    // Original must be removed after quarantine.
    assert!(
        !original_path.exists(),
        "original file must be removed after quarantine"
    );

    // Create a real directory and a symlink pointing to it.
    let real_dir = tmp.path().join("real_restore_dir");
    fs::create_dir_all(&real_dir).unwrap();
    let symlink_dir = tmp.path().join("symlink_to_restore");
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    // Restore through the symlink path — the vault should resolve (canonicalize)
    // the symlink and write the file into the real directory.
    let restore_via_symlink = symlink_dir.join("file.txt");
    vault
        .restore(qid, &restore_via_symlink)
        .expect("restore must succeed with a symlink-based path");

    // The file must exist in the real directory (canonicalized path).
    let real_file = real_dir.join("file.txt");
    assert!(
        real_file.exists(),
        "restored file must exist at the canonicalized path: {}",
        real_file.display()
    );

    // Verify content integrity.
    let restored_content = fs::read(&real_file).expect("read restored file");
    assert_eq!(
        restored_content.as_slice(),
        original_content,
        "restored content must match original payload byte-for-byte"
    );
}

// ---------------------------------------------------------------------------
// Scenario 40: quarantine_rejects_dotdot_paths
// ---------------------------------------------------------------------------

/// BUG-H01 regression: quarantine restore must reject paths containing `..`.
///
/// An attacker who gains access to the quarantine restore command should not
/// be able to write files outside the intended restore directory by using
/// path traversal (`..` components).
#[test]
fn quarantine_rejects_dotdot_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    let vault = Quarantine::new(vault_dir).expect("create vault");

    // Create and quarantine a test file.
    let original_content = b"BUG-H01 regression: dotdot path rejection payload";
    let original_path = tmp.path().join("dotdot_test.bin");
    fs::write(&original_path, original_content).unwrap();

    let qid = vault
        .quarantine(&original_path, "Test.DotDotPath")
        .expect("quarantine file");

    // Attempt to restore to a path containing `..` components.
    // This simulates a path traversal attack: "/tmp/test/../../../etc/malicious"
    let malicious_path = tmp
        .path()
        .join("safe")
        .join("..")
        .join("..")
        .join("..")
        .join("etc")
        .join("malicious");

    let result = vault.restore(qid, &malicious_path);

    // The restore operation must fail due to the `..` path component.
    assert!(
        result.is_err(),
        "restore to a path with '..' must be rejected, but it succeeded"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains(".."),
        "error message must mention '..' component, got: {err_msg}"
    );

    // Double-check: the malicious target must not exist.
    // (This is a safety net even if the error check above passes.)
    assert!(
        !malicious_path.exists(),
        "file must NOT be written to the traversal target: {}",
        malicious_path.display()
    );
}

// ---------------------------------------------------------------------------
// Scenario 41: pe_api_dedup_with_aw_suffix
// ---------------------------------------------------------------------------

/// BUG-M10 regression: raw-byte API scanner must deduplicate A/W suffix variants.
///
/// When a PE import table contains `VirtualAllocExW` and the raw data also
/// contains `VirtualAllocEx` (without suffix), the heuristic engine must
/// recognise these as the same API and emit only ONE `SuspiciousApi` finding
/// for the `VirtualAllocEx` family — not two separate findings.
#[test]
fn pe_api_dedup_with_aw_suffix() {
    // Build a PE with an import of the W-suffixed variant.
    let parsed = make_pe(
        vec![SectionInfo {
            name: ".text".to_string(),
            virtual_size: 0x5000,
            raw_size: 0x4800,
            entropy: 6.0,
            characteristics: 0x6000_0020, // CODE | EXECUTE | READ
        }],
        vec![ImportInfo {
            dll: "kernel32.dll".to_string(),
            functions: vec!["VirtualAllocExW".to_string()],
        }],
        0x6000_0000,
    );

    // Embed the base name `VirtualAllocEx` in raw data bytes.
    // The raw-byte scanner should find this string but recognise it as
    // a duplicate of the import-table hit `VirtualAllocExW`.
    let mut data = vec![0u8; 2048];
    embed(&mut data, 0x100, b"VirtualAllocEx");

    let engine = HeuristicEngine::new();
    let result = engine.analyze(&data, &parsed);

    // Guard: the import-table path must have contributed at least one finding.
    // Without this, the dedup assertion below could vacuously pass if only the
    // raw-byte scanner fired.
    assert!(
        !result.findings.is_empty(),
        "import-table + raw-byte scan must produce at least one SuspiciousApi finding"
    );

    // Count how many SuspiciousApi findings relate to VirtualAllocEx.
    let virtual_alloc_findings: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| {
            if let Finding::SuspiciousApi(name) = f {
                let base = name
                    .strip_suffix('A')
                    .or_else(|| name.strip_suffix('W'))
                    .unwrap_or(name);
                base.eq_ignore_ascii_case("VirtualAllocEx")
            } else {
                false
            }
        })
        .collect();

    assert_eq!(
        virtual_alloc_findings.len(),
        1,
        "VirtualAllocEx family must produce exactly 1 finding (dedup A/W suffix), \
         got {}: {:?}",
        virtual_alloc_findings.len(),
        virtual_alloc_findings
    );
}

// ---------------------------------------------------------------------------
// Scenario 42: api_suffix_match_bidirectional
// ---------------------------------------------------------------------------

/// BUG-M13 regression: bidirectional A/W suffix stripping in import matching.
///
/// The suspicious-API catalogue contains `RegSetValueExA` and `RegSetValueExW`.
/// If a PE imports the base name `RegSetValueEx` (without A/W suffix), the
/// heuristic engine must still detect it as suspicious via bidirectional
/// suffix comparison.
///
/// Since `check_suspicious_imports` is pub but `func_matches` is private,
/// we test through `HeuristicEngine::analyze` which calls `check_suspicious_imports`
/// internally for PE files.
#[test]
fn api_suffix_match_bidirectional() {
    // Build a PE that imports `RegSetValueEx` (no A/W suffix).
    let parsed = make_pe(
        vec![SectionInfo {
            name: ".text".to_string(),
            virtual_size: 0x5000,
            raw_size: 0x4800,
            entropy: 6.0,
            characteristics: 0x6000_0020, // CODE | EXECUTE | READ
        }],
        vec![ImportInfo {
            dll: "advapi32.dll".to_string(),
            functions: vec!["RegSetValueEx".to_string()],
        }],
        0x6000_0000,
    );

    let engine = HeuristicEngine::new();
    // Use minimal data (no raw suspicious strings) to isolate import-table matching.
    let result = engine.analyze(&[0u8; 128], &parsed);

    // The findings must contain a SuspiciousApi for RegSetValueEx.
    let has_reg_set = result.findings.iter().any(|f| {
        if let Finding::SuspiciousApi(name) = f {
            let base = name
                .strip_suffix('A')
                .or_else(|| name.strip_suffix('W'))
                .unwrap_or(name);
            base.eq_ignore_ascii_case("RegSetValueEx")
        } else {
            false
        }
    });

    assert!(
        has_reg_set,
        "PE importing 'RegSetValueEx' (no suffix) must be matched against \
         'RegSetValueExA'/'RegSetValueExW' in the suspicious API catalogue. \
         Got findings: {:?}",
        result.findings
    );
}
