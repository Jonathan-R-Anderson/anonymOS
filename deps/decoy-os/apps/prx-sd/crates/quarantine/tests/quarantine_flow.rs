//! Integration tests for the quarantine vault lifecycle.
//!
//! Covers quarantine, restore, delete, stats, batch operations, and
//! expiry-based cleanup.

#![allow(clippy::indexing_slicing, clippy::expect_used)]

use std::fs;

use prx_sd_quarantine::{Quarantine, QuarantineId, batch_delete, batch_restore, cleanup_expired};

/// Create a fresh quarantine vault in a temp directory.
fn setup_vault() -> (tempfile::TempDir, Quarantine) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let vault_dir = tmp.path().join("vault");
    let vault = Quarantine::new(vault_dir).expect("create vault");
    (tmp, vault)
}

#[test]
fn test_quarantine_restore_flow() {
    let (tmp, vault) = setup_vault();

    // Write a test file with known content.
    let original_content = b"This file contains a test virus payload (not really).";
    let original_path = tmp.path().join("suspect.exe");
    fs::write(&original_path, original_content).unwrap();

    // Quarantine the file.
    let id = vault
        .quarantine(&original_path, "Test.Trojan.Alpha")
        .expect("quarantine failed");

    // Original file should no longer exist.
    assert!(
        !original_path.exists(),
        "original file should be deleted after quarantine"
    );

    // List quarantine entries.
    let entries = vault.list().expect("list failed");
    assert_eq!(entries.len(), 1, "should have 1 quarantine entry");
    assert_eq!(entries[0].0, id);
    assert_eq!(entries[0].1.threat_name, "Test.Trojan.Alpha");
    assert_eq!(entries[0].1.file_size, original_content.len() as u64);

    // Restore the file.
    let restore_path = tmp.path().join("restored.exe");
    vault.restore(id, &restore_path).expect("restore failed");

    // Restored file should have identical content.
    let restored_content = fs::read(&restore_path).expect("read restored file");
    assert_eq!(
        restored_content, original_content,
        "restored content must match original"
    );

    // Delete from quarantine.
    vault.delete(id).expect("delete failed");

    // List should now be empty.
    let entries = vault.list().expect("list after delete");
    assert_eq!(entries.len(), 0, "quarantine should be empty after delete");
}

#[test]
fn test_quarantine_stats() {
    let (tmp, vault) = setup_vault();

    let sizes: &[usize] = &[100, 200, 350];
    for (i, &size) in sizes.iter().enumerate() {
        let path = tmp.path().join(format!("file_{i}.bin"));
        fs::write(&path, vec![0xAA; size]).unwrap();
        vault
            .quarantine(&path, &format!("Test.Malware.{i}"))
            .expect("quarantine failed");
    }

    let stats = vault.stats().expect("stats failed");
    assert_eq!(stats.count, 3, "should have 3 quarantined files");
    assert_eq!(stats.total_size, 650, "total size should be 100 + 200 + 350 = 650");
}

#[test]
fn test_batch_restore() {
    let (tmp, vault) = setup_vault();

    let mut ids: Vec<QuarantineId> = Vec::new();
    let contents: Vec<Vec<u8>> = vec![
        b"batch file one".to_vec(),
        b"batch file two".to_vec(),
        b"batch file three".to_vec(),
    ];

    for (i, content) in contents.iter().enumerate() {
        let path = tmp.path().join(format!("batch_{i}.dat"));
        fs::write(&path, content).unwrap();
        let id = vault
            .quarantine(&path, &format!("Batch.Test.{i}"))
            .expect("quarantine failed");
        ids.push(id);
    }

    // All originals should be gone.
    for i in 0..3 {
        assert!(!tmp.path().join(format!("batch_{i}.dat")).exists());
    }

    // Batch restore.
    let results = batch_restore(&vault, &ids);
    assert_eq!(results.len(), 3);
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "batch restore of item {i} should succeed");
    }

    // Verify content after batch restore.
    for (i, content) in contents.iter().enumerate() {
        let path = tmp.path().join(format!("batch_{i}.dat"));
        let actual = fs::read(&path).expect("read restored file");
        assert_eq!(&actual, content, "content mismatch for batch_{i}.dat");
    }
}

#[test]
fn test_batch_delete() {
    let (tmp, vault) = setup_vault();

    let mut ids: Vec<QuarantineId> = Vec::new();
    for i in 0..3 {
        let path = tmp.path().join(format!("del_{i}.bin"));
        fs::write(&path, format!("delete me {i}")).unwrap();
        let id = vault.quarantine(&path, "Batch.Delete").expect("quarantine");
        ids.push(id);
    }

    assert_eq!(vault.list().unwrap().len(), 3);

    let results = batch_delete(&vault, &ids);
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "batch delete of item {i} should succeed");
    }

    assert_eq!(vault.list().unwrap().len(), 0, "all entries should be deleted");
}

#[test]
fn test_cleanup_expired() {
    let (tmp, vault) = setup_vault();

    // Quarantine a few files.
    for i in 0..4 {
        let path = tmp.path().join(format!("expired_{i}.bin"));
        fs::write(&path, format!("expired content {i}")).unwrap();
        vault.quarantine(&path, "Expired.Test").expect("quarantine");
    }

    assert_eq!(vault.list().unwrap().len(), 4);

    // Cleanup with max_age_days = 0 means anything older than 0 days is
    // expired.  Since the entries were just created they are ~0 seconds old,
    // which is right at the boundary.  `cleanup_expired` uses `> max_age`
    // so entries at exactly 0 age will not be removed with max_age_days=0
    // if their age equals the max.
    //
    // To guarantee removal we would need to wait, but the implementation
    // compares `age > max_age` where max_age is 0 days.  A freshly created
    // entry has age > 0 (some microseconds), and chrono::Duration::days(0)
    // is exactly zero, so the comparison should pass.
    let removed = cleanup_expired(&vault, 0).expect("cleanup_expired");

    assert_eq!(removed, 4, "all 4 entries should be expired");
    assert_eq!(vault.list().unwrap().len(), 0, "vault should be empty");
}

#[test]
fn test_quarantine_preserves_sha256() {
    let (tmp, vault) = setup_vault();

    let content = b"content for SHA-256 verification";
    let expected_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    };

    let path = tmp.path().join("hash_check.bin");
    fs::write(&path, content).unwrap();

    let id = vault.quarantine(&path, "Hash.Check").unwrap();

    let entries = vault.list().unwrap();
    let (_, meta) = entries.iter().find(|(eid, _)| *eid == id).unwrap();

    assert_eq!(
        meta.sha256, expected_hash,
        "quarantine metadata should store correct SHA-256"
    );
}

#[test]
fn test_restore_to_different_path() {
    let (tmp, vault) = setup_vault();

    let content = b"file that will be restored elsewhere";
    let original = tmp.path().join("original_location.txt");
    fs::write(&original, content).unwrap();

    let id = vault.quarantine(&original, "Relocate.Test").unwrap();

    // Restore to a completely different path.
    let new_location = tmp.path().join("new_dir").join("relocated.txt");
    vault.restore(id, &new_location).unwrap();

    assert!(new_location.exists(), "file should exist at new location");
    assert_eq!(fs::read(&new_location).unwrap(), content, "content should match");
}

#[test]
fn test_double_delete_is_ok() {
    let (tmp, vault) = setup_vault();

    let path = tmp.path().join("double_del.bin");
    fs::write(&path, b"delete twice").unwrap();

    let id = vault.quarantine(&path, "Double.Delete").unwrap();

    vault.delete(id).expect("first delete should succeed");
    // Second delete should also succeed (files already removed, but no error).
    vault.delete(id).expect("second delete should not error");
}
