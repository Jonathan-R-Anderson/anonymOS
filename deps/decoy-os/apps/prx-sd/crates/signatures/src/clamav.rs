//! `ClamAV` signature importer.
//!
//! Extracts hash-based signatures from `.cvd` container files and imports
//! them into the LMDB signature database. Supports:
//!
//! - `.hdb` — MD5 hash signatures
//! - `.hsb` — SHA-256/SHA-1 hash signatures
//!
//! NDB/LDB pattern signatures are counted but not imported (requires a
//! pattern-matching engine; see YARA-X integration task 1.1.2).

use std::io::{Cursor, Read};
use std::path::Path;

use crate::database::SignatureDatabase;
use crate::formats::cvd::parse_cvd;
use crate::formats::hdb::{self, HashKind};
use anyhow::{Context, Result};
use flate2::read::GzDecoder;

/// Statistics returned after a `ClamAV` import operation.
#[derive(Debug, Clone)]
pub struct ClamavImportStats {
    /// CVD version number.
    pub cvd_version: u32,
    /// Total signatures declared in the CVD header.
    pub header_sig_count: u32,
    /// SHA-256 hash entries imported.
    pub sha256_imported: usize,
    /// MD5 hash entries imported.
    pub md5_imported: usize,
    /// SHA-1 entries skipped (not stored in our DB).
    pub sha1_skipped: usize,
    /// NDB pattern signatures found (not imported).
    pub ndb_count: usize,
    /// LDB logical signatures found (not imported).
    pub ldb_count: usize,
    /// Lines/entries skipped due to parse errors.
    pub parse_errors: usize,
}

/// Import hash signatures from a `ClamAV` `.cvd` file into the database.
///
/// Reads the CVD file, decompresses the tar.gz payload, scans for `.hdb`
/// and `.hsb` files, and batch-imports their entries into LMDB.
pub fn import_cvd(cvd_path: impl AsRef<Path>, db: &SignatureDatabase) -> Result<ClamavImportStats> {
    let cvd_path = cvd_path.as_ref();
    let raw = std::fs::read(cvd_path).with_context(|| format!("failed to read CVD file: {}", cvd_path.display()))?;

    import_cvd_bytes(&raw, db)
}

/// Import hash signatures from raw CVD bytes into the database.
pub fn import_cvd_bytes(data: &[u8], db: &SignatureDatabase) -> Result<ClamavImportStats> {
    const BATCH_SIZE: usize = 50_000;

    let cvd = parse_cvd(data).context("failed to parse CVD header")?;

    tracing::info!(
        version = cvd.header.version,
        sigs = cvd.header.num_signatures,
        "parsed CVD header"
    );

    let mut stats = ClamavImportStats {
        cvd_version: cvd.header.version,
        header_sig_count: cvd.header.num_signatures,
        sha256_imported: 0,
        md5_imported: 0,
        sha1_skipped: 0,
        ndb_count: 0,
        ldb_count: 0,
        parse_errors: 0,
    };

    // Decompress tar.gz payload.
    let gz = GzDecoder::new(Cursor::new(&cvd.data));
    let mut archive = tar::Archive::new(gz);

    let entries = archive
        .entries()
        .context("failed to read tar entries from CVD payload")?;

    // Batch buffers to reduce LMDB write transactions.
    let mut sha256_batch: Vec<(Vec<u8>, String)> = Vec::new();
    let mut md5_batch: Vec<(Vec<u8>, String)> = Vec::new();

    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("skipping corrupt tar entry: {e}");
                stats.parse_errors += 1;
                continue;
            }
        };

        let path = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        match ext.as_str() {
            "hdb" | "hsb" => {
                let mut content = String::new();
                if let Err(e) = entry.read_to_string(&mut content) {
                    tracing::warn!(file = %path.display(), "failed to read entry: {e}");
                    stats.parse_errors += 1;
                    continue;
                }

                let parse_result = if ext == "hdb" {
                    hdb::parse_hdb(&content)
                } else {
                    hdb::parse_hsb(&content)
                };

                let sig_set = match parse_result {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(file = %path.display(), "failed to parse: {e}");
                        stats.parse_errors += 1;
                        continue;
                    }
                };

                stats.parse_errors += sig_set.skipped;

                for sig in &sig_set.entries {
                    let Some(hash_bytes) = hdb::decode_hex(&sig.hash_hex) else {
                        stats.parse_errors += 1;
                        continue;
                    };

                    match sig_set.kind {
                        HashKind::Sha256 => {
                            sha256_batch.push((hash_bytes, sig.name.clone()));
                            if sha256_batch.len() >= BATCH_SIZE {
                                let n = db.import_hashes(&sha256_batch)?;
                                stats.sha256_imported += n;
                                sha256_batch.clear();
                            }
                        }
                        HashKind::Md5 => {
                            md5_batch.push((hash_bytes, sig.name.clone()));
                            if md5_batch.len() >= BATCH_SIZE {
                                let n = db.import_md5_hashes(&md5_batch)?;
                                stats.md5_imported += n;
                                md5_batch.clear();
                            }
                        }
                        HashKind::Sha1 => {
                            stats.sha1_skipped += 1;
                        }
                    }
                }

                tracing::info!(
                    file = %path.display(),
                    kind = ?sig_set.kind,
                    count = sig_set.entries.len(),
                    "processed hash file"
                );
            }
            "ndb" => {
                // Count NDB signatures but don't import (needs pattern engine).
                let mut content = String::new();
                if entry.read_to_string(&mut content).is_ok() {
                    stats.ndb_count += content
                        .lines()
                        .filter(|l| {
                            let l = l.trim();
                            !l.is_empty() && !l.starts_with('#')
                        })
                        .count();
                }
            }
            "ldb" => {
                // Count LDB signatures but don't import (needs pattern engine).
                let mut content = String::new();
                if entry.read_to_string(&mut content).is_ok() {
                    stats.ldb_count += content
                        .lines()
                        .filter(|l| {
                            let l = l.trim();
                            !l.is_empty() && !l.starts_with('#')
                        })
                        .count();
                }
            }
            _ => {
                // Skip other file types (.fp, .sfp, .info, etc.).
            }
        }
    }

    // Flush remaining batches.
    if !sha256_batch.is_empty() {
        let n = db.import_hashes(&sha256_batch)?;
        stats.sha256_imported += n;
    }
    if !md5_batch.is_empty() {
        let n = db.import_md5_hashes(&md5_batch)?;
        stats.md5_imported += n;
    }

    tracing::info!(
        sha256 = stats.sha256_imported,
        md5 = stats.md5_imported,
        ndb = stats.ndb_count,
        ldb = stats.ldb_count,
        "ClamAV import complete"
    );

    Ok(stats)
}

/// Import hash signatures from a standalone `.hdb` or `.hsb` file
/// (not wrapped in a CVD container).
pub fn import_hash_file(path: impl AsRef<Path>, db: &SignatureDatabase) -> Result<ClamavImportStats> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).with_context(|| format!("failed to read: {}", path.display()))?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let sig_set = match ext.as_str() {
        "hdb" => hdb::parse_hdb(&content)?,
        // .hsb and anything else: auto-detect by hash length
        _ => hdb::parse_hsb(&content)?,
    };

    let mut stats = ClamavImportStats {
        cvd_version: 0,
        header_sig_count: 0,
        sha256_imported: 0,
        md5_imported: 0,
        sha1_skipped: 0,
        ndb_count: 0,
        ldb_count: 0,
        parse_errors: sig_set.skipped,
    };

    let mut sha256_batch: Vec<(Vec<u8>, String)> = Vec::new();
    let mut md5_batch: Vec<(Vec<u8>, String)> = Vec::new();

    for sig in &sig_set.entries {
        let Some(hash_bytes) = hdb::decode_hex(&sig.hash_hex) else {
            stats.parse_errors += 1;
            continue;
        };

        match sig_set.kind {
            HashKind::Sha256 => sha256_batch.push((hash_bytes, sig.name.clone())),
            HashKind::Md5 => md5_batch.push((hash_bytes, sig.name.clone())),
            HashKind::Sha1 => stats.sha1_skipped += 1,
        }
    }

    if !sha256_batch.is_empty() {
        stats.sha256_imported = db.import_hashes(&sha256_batch)?;
    }
    if !md5_batch.is_empty() {
        stats.md5_imported = db.import_md5_hashes(&md5_batch)?;
    }

    Ok(stats)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::database::SignatureDatabase;

    fn make_test_db() -> (tempfile::TempDir, SignatureDatabase) {
        let dir = tempfile::tempdir().unwrap();
        let db = SignatureDatabase::open(dir.path()).unwrap();
        (dir, db)
    }

    #[test]
    fn test_import_cvd_bytes_empty_payload() {
        // Create a minimal CVD with an empty gzipped tar as payload.
        let header_str = "ClamAV-VDB:01 Jan 2025:100:0:90:abc123:builder:0";
        let mut header = vec![0u8; 512];
        header[..header_str.len()].copy_from_slice(header_str.as_bytes());

        // Create an empty tar.gz.
        let mut tar_buf = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_buf, flate2::Compression::fast());
            let mut tar_builder = tar::Builder::new(gz);
            tar_builder.finish().unwrap();
        }

        header.extend_from_slice(&tar_buf);

        let (_dir, db) = make_test_db();
        let stats = import_cvd_bytes(&header, &db).unwrap();
        assert_eq!(stats.cvd_version, 100);
        assert_eq!(stats.sha256_imported, 0);
        assert_eq!(stats.md5_imported, 0);
    }

    #[test]
    fn test_import_cvd_with_hdb() {
        let hdb_content = "\
aabbccddaabbccddaabbccddaabbccdd:1024:Win.Test.Malware-1
11223344112233441122334411223344:*:Win.Test.Malware-2
";
        // Build a tar.gz containing a .hdb file.
        let mut tar_buf = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_buf, flate2::Compression::fast());
            let mut tar_builder = tar::Builder::new(gz);

            let data = hdb_content.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_path("main.hdb").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder.append(&header, data).unwrap();
            tar_builder.finish().unwrap();
        }

        // Build CVD.
        let header_str = "ClamAV-VDB:01 Jan 2025:200:2:90:md5hash:builder:0";
        let mut cvd_data = vec![0u8; 512];
        cvd_data[..header_str.len()].copy_from_slice(header_str.as_bytes());
        cvd_data.extend_from_slice(&tar_buf);

        let (_dir, db) = make_test_db();
        let stats = import_cvd_bytes(&cvd_data, &db).unwrap();
        assert_eq!(stats.md5_imported, 2);
        assert_eq!(stats.sha256_imported, 0);

        // Verify entries are in the database.
        let db_stats = db.get_stats().unwrap();
        assert_eq!(db_stats.md5_count, 2);
    }

    #[test]
    fn test_import_cvd_with_hsb() {
        let hash = "a".repeat(64);
        let hsb_content = format!("{hash}:2048:Win.Test.SHA256-1\n");

        let mut tar_buf = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_buf, flate2::Compression::fast());
            let mut tar_builder = tar::Builder::new(gz);

            let data = hsb_content.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_path("main.hsb").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder.append(&header, data).unwrap();
            tar_builder.finish().unwrap();
        }

        let header_str = "ClamAV-VDB:01 Jan 2025:300:1:90:md5hash:builder:0";
        let mut cvd_data = vec![0u8; 512];
        cvd_data[..header_str.len()].copy_from_slice(header_str.as_bytes());
        cvd_data.extend_from_slice(&tar_buf);

        let (_dir, db) = make_test_db();
        let stats = import_cvd_bytes(&cvd_data, &db).unwrap();
        assert_eq!(stats.sha256_imported, 1);
        assert_eq!(stats.md5_imported, 0);

        let db_stats = db.get_stats().unwrap();
        assert_eq!(db_stats.hash_count, 1);
    }
}
