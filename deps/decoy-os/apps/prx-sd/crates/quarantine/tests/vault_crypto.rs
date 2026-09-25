//! Cryptographic security tests for the quarantine vault.
//!
//! Covers: ciphertext integrity, nonce uniqueness, path traversal
//! protection, key persistence, large-file round-trip, and concurrent
//! quarantine correctness.

#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use prx_sd_quarantine::Quarantine;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Open or create a vault inside a fresh temporary directory.
/// Returns `(TempDir, Quarantine)` – keep `TempDir` alive for the test.
fn setup_vault() -> (tempfile::TempDir, Quarantine) {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");
    let vault = Quarantine::new(vault_dir).unwrap();
    (tmp, vault)
}

/// Write `contents` to `dir/{name}` and return the full path.
fn write_file(dir: &Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Test 1 – corrupted ciphertext must be rejected
// ---------------------------------------------------------------------------

/// Flip the last byte of the `.enc` file; AES-GCM authentication tag covers
/// the whole ciphertext, so even a single-bit change must cause decryption
/// to fail.
#[test]
fn corrupted_ciphertext_is_rejected() {
    let (tmp, vault) = setup_vault();

    let path = write_file(tmp.path(), "malware.bin", b"EICAR-like payload data");
    let id = vault.quarantine(&path, "Test.Eicar").unwrap();

    // Locate the encrypted blob and corrupt its last byte.
    let enc_path = tmp.path().join("vault").join(format!("{id}.enc"));
    let mut raw = fs::read(&enc_path).unwrap();
    assert!(!raw.is_empty(), "encrypted file must not be empty");
    *raw.last_mut().unwrap() ^= 0xFF; // flip all bits of the last byte
    fs::write(&enc_path, &raw).unwrap();

    // restore() must now fail with an AES-GCM authentication error.
    let restore_path = tmp.path().join("should_not_appear.bin");
    let result = vault.restore(id, &restore_path);
    assert!(result.is_err(), "restore must fail after ciphertext corruption");
    assert!(
        !restore_path.exists(),
        "no plaintext file should be written when decryption fails"
    );
}

// ---------------------------------------------------------------------------
// Test 2 – nonces are unique across calls
// ---------------------------------------------------------------------------

/// Quarantine 50 distinct files and collect the AES-GCM nonce stored in
/// each entry's metadata.  All 50 nonces must be different; nonce reuse
/// under the same key would break confidentiality in AES-GCM.
#[test]
fn nonces_are_unique_across_calls() {
    let (tmp, vault) = setup_vault();
    let sample_count = 50_usize;

    for i in 0..sample_count {
        let contents = format!("file-content-{i}");
        let path = write_file(tmp.path(), &format!("file_{i}.dat"), contents.as_bytes());
        vault.quarantine(&path, &format!("Test.Nonce.{i}")).unwrap();
    }

    let entries = vault.list().unwrap();
    assert_eq!(
        entries.len(),
        sample_count,
        "expected {sample_count} quarantine entries"
    );

    // Collect every nonce into a HashSet keyed on the raw 12 bytes.
    let mut seen: HashSet<[u8; 12]> = HashSet::new();
    for (_, meta) in &entries {
        let inserted = seen.insert(meta.nonce);
        assert!(
            inserted,
            "nonce collision detected: {:?} appeared more than once",
            meta.nonce
        );
    }

    assert_eq!(seen.len(), sample_count, "all {sample_count} nonces must be unique");
}

// ---------------------------------------------------------------------------
// Test 3 – restore rejects a path that contains ".."
// ---------------------------------------------------------------------------

/// Any path component that is `..` (`ParentDir`) must be refused before the
/// vault even attempts decryption, preventing directory-traversal attacks.
#[test]
fn restore_rejects_path_with_dotdot() {
    let (tmp, vault) = setup_vault();

    let path = write_file(tmp.path(), "trojan.bin", b"malicious payload");
    let id = vault.quarantine(&path, "Test.PathTraversal").unwrap();

    // Craft a path that ascends out of a directory via "..".
    let traversal_target = tmp.path().join("safe_dir").join("..").join("escape.bin");

    let result = vault.restore(id, &traversal_target);
    assert!(
        result.is_err(),
        "restore must reject a path containing '..' (got: {traversal_target:?})"
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains(".."),
        "error message should mention the '..' component; got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 – restore rejects system directories
// ---------------------------------------------------------------------------

/// Restoring to `/etc/passwd` (or any other path under a protected system
/// prefix) must be unconditionally denied to prevent overwriting critical
/// system files.
///
/// Only meaningful on Unix systems where `/etc` is a system directory.
#[cfg(unix)]
#[test]
fn restore_rejects_system_directory() {
    let (tmp, vault) = setup_vault();

    let path = write_file(tmp.path(), "rootkit.elf", b"ELF data");
    let id = vault.quarantine(&path, "Test.Rootkit").unwrap();

    // Attempt to restore directly to a system path.
    let system_target = std::path::PathBuf::from("/etc/passwd");
    let result = vault.restore(id, &system_target);
    assert!(result.is_err(), "restore to /etc/passwd must be denied");

    let err_msg = format!("{}", result.unwrap_err());
    // Must be an application-level denial, NOT an OS permission error.
    assert!(
        !err_msg.contains("Permission denied"),
        "error should come from application-level check, not OS permission; got: {err_msg}"
    );
    assert!(
        err_msg.contains("system")
            || err_msg.contains("/etc")
            || err_msg.contains("denied")
            || err_msg.contains("protected"),
        "error message should mention system-directory denial; got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 – vault key persists across Quarantine instances
// ---------------------------------------------------------------------------

/// Close the vault (drop the `Quarantine` value) and re-open the same
/// `vault_dir` as a brand-new `Quarantine` instance.  The new instance must
/// use the same on-disk key and therefore be able to decrypt files that were
/// quarantined by the first instance.
#[test]
fn vault_key_is_persistent() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_dir = tmp.path().join("vault");

    let original_content = b"sensitive data that must survive vault restart";

    // ---- First vault instance: quarantine a file. ----
    let quarantine_id = {
        let vault_1 = Quarantine::new(vault_dir.clone()).unwrap();
        let path = write_file(tmp.path(), "sensitive.dat", original_content);
        vault_1.quarantine(&path, "Test.Persistence").unwrap()
        // vault_1 is dropped here, releasing any in-memory state.
    };

    // ---- Second vault instance (same directory, different process-level object). ----
    let vault_2 = Quarantine::new(vault_dir).unwrap();

    let restore_path = tmp.path().join("restored_after_reopen.dat");
    vault_2.restore(quarantine_id, &restore_path).unwrap();

    let restored = fs::read(&restore_path).unwrap();
    assert_eq!(
        restored, original_content,
        "content restored by a new Quarantine instance must match the original"
    );
}

// ---------------------------------------------------------------------------
// Test 6 – large file round-trip (10 MB)
// ---------------------------------------------------------------------------

/// Quarantine a 10 MiB file filled with deterministic pseudo-random bytes,
/// then restore it and verify every byte matches.  This exercises the
/// streaming encrypt/decrypt path under realistic file sizes.
#[test]
fn large_file_roundtrip() {
    const SIZE: usize = 10 * 1024 * 1024; // 10 MiB

    let (tmp, vault) = setup_vault();

    // Deterministic 10 MiB payload – no external rand dependency needed.
    let mut payload = vec![0u8; SIZE];
    // Fill with a simple LCG so every byte differs while remaining reproducible.
    let mut state: u64 = 0x5EED_CAFE_DEAD_BEEF;
    for chunk in payload.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bytes = state.to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(bytes.get(..len).unwrap());
    }

    let path = write_file(tmp.path(), "large_file.bin", &payload);
    let id = vault.quarantine(&path, "Test.Large").unwrap();

    // Original file must be gone after quarantine.
    assert!(!path.exists(), "original large file must be deleted after quarantine");

    let restore_path = tmp.path().join("large_restored.bin");
    vault.restore(id, &restore_path).unwrap();

    let restored = fs::read(&restore_path).unwrap();
    assert_eq!(
        restored.len(),
        SIZE,
        "restored file size must match original ({SIZE} bytes)"
    );
    assert_eq!(
        restored, payload,
        "restored content must be byte-for-byte identical to the original"
    );
}

// ---------------------------------------------------------------------------
// Test 7 – concurrent quarantine of different files
// ---------------------------------------------------------------------------

/// Spawn 10 threads, each quarantining a unique file concurrently.  After
/// all threads complete, the vault must contain exactly 10 entries with no
/// corruption, ID collisions, or data loss.
#[test]
fn concurrent_quarantine_no_corruption() {
    const THREAD_COUNT: usize = 10;

    let tmp = Arc::new(tempfile::tempdir().unwrap());
    let vault_dir = tmp.path().join("vault");
    let vault = Arc::new(Quarantine::new(vault_dir).unwrap());

    // Prepare files and spawn threads — files are created eagerly by the
    // first map, then each is immediately handed to a thread.
    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|i| {
            let path = tmp.path().join(format!("concurrent_{i}.bin"));
            let content = format!("thread-{i}-unique-content-{}", i * 7919);
            fs::write(&path, content.as_bytes()).unwrap();
            let vault_clone = Arc::clone(&vault);
            thread::spawn(move || {
                vault_clone
                    .quarantine(&path, &format!("Concurrent.Threat.{i}"))
                    .map_err(|e| format!("thread {i} quarantine failed: {e}"))
            })
        })
        .collect();

    // Join all threads and verify each succeeded.
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.join().expect("thread panicked");
        assert!(result.is_ok(), "thread {i} should succeed: {:?}", result.as_ref().err());
    }

    // The vault must have exactly THREAD_COUNT entries.
    let entries = vault.list().unwrap();
    assert_eq!(
        entries.len(),
        THREAD_COUNT,
        "vault must contain exactly {THREAD_COUNT} entries after concurrent quarantine"
    );

    // All quarantine IDs must be unique (no UUID collisions).
    let ids: HashSet<_> = entries.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids.len(),
        THREAD_COUNT,
        "all {THREAD_COUNT} quarantine IDs must be distinct"
    );
}
