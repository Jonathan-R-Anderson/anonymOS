//! LMDB-backed signature database for fast hash lookups.
//!
//! Stores SHA-256 and MD5 hashes mapped to malware family/signature names.
//! Uses the `heed` crate (a safe LMDB wrapper) for memory-mapped, zero-copy reads.

use std::path::Path;

use anyhow::{Context, Result};
use heed::types::{Bytes, Str};
use heed::{Database, Env, EnvOpenOptions};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Statistics about the signature database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    /// Number of SHA-256 hash entries.
    pub hash_count: u64,
    /// Number of MD5 hash entries.
    pub md5_count: u64,
    /// Database version number.
    pub version: u64,
    /// Timestamp of the last update (Unix epoch seconds), if set.
    pub last_update: Option<i64>,
}

/// An LMDB-backed signature database storing hash-to-name mappings.
pub struct SignatureDatabase {
    env: Env,
    /// SHA-256 hash bytes → signature name.
    sha256_db: Database<Bytes, Str>,
    /// MD5 hash bytes → signature name.
    md5_db: Database<Bytes, Str>,
    /// Metadata key-value store (version, timestamps, etc.).
    meta_db: Database<Str, Bytes>,
}

const META_KEY_VERSION: &str = "version";
const META_KEY_LAST_UPDATE: &str = "last_update";

impl SignatureDatabase {
    /// Open (or create) the signature database at the given directory path.
    ///
    /// Configures LMDB with a 1 GB map size and up to 10 named databases.
    #[instrument(skip_all, fields(path = %path.display()))]
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)
            .with_context(|| format!("failed to create database directory: {}", path.display()))?;

        // SAFETY: The LMDB environment is opened on a directory we just ensured
        // exists. The `open` call is unsafe because LMDB requires that no other
        // process opens the same data file with an incompatible configuration,
        // and that the map size does not exceed available address space. We
        // control both: this is the only opener and 1 GB is well within limits.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(1024 * 1024 * 1024) // 1 GB
                .max_dbs(10)
                .open(path)
                .with_context(|| format!("failed to open LMDB env at {}", path.display()))?
        };

        let mut wtxn = env.write_txn()?;
        let sha256_db = env
            .create_database::<Bytes, Str>(&mut wtxn, Some("sha256"))
            .context("failed to create sha256 database")?;
        let md5_db = env
            .create_database::<Bytes, Str>(&mut wtxn, Some("md5"))
            .context("failed to create md5 database")?;
        let meta_db = env
            .create_database::<Str, Bytes>(&mut wtxn, Some("meta"))
            .context("failed to create meta database")?;
        wtxn.commit()?;

        tracing::info!("signature database opened at {}", path.display());

        Ok(Self {
            env,
            sha256_db,
            md5_db,
            meta_db,
        })
    }

    /// Look up a SHA-256 hash of `data` in the database.
    ///
    /// Computes the SHA-256 of the provided data and checks the database.
    /// Returns the signature name if found, or an error if the database
    /// cannot be read (preventing silent signature bypass).
    #[instrument(skip_all)]
    pub fn hash_lookup(&self, data: &[u8]) -> Result<Option<String>> {
        let hash = crate::hash::sha256_hash(data);
        self.sha256_lookup_raw(&hash)
    }

    /// Look up a raw SHA-256 hash (already computed) in the database.
    pub fn sha256_lookup_raw(&self, hash: &[u8]) -> Result<Option<String>> {
        let rtxn = self
            .env
            .read_txn()
            .context("failed to create LMDB read transaction for SHA-256 lookup")?;
        let result = self
            .sha256_db
            .get(&rtxn, hash)
            .context("failed to look up SHA-256 hash in LMDB")?
            .map(std::borrow::ToOwned::to_owned);
        Ok(result)
    }

    /// Look up an MD5 hash of `data` in the database.
    ///
    /// Computes the MD5 of the provided data and checks the database.
    /// Returns the signature name if found, or an error if the database
    /// cannot be read.
    #[instrument(skip_all)]
    pub fn md5_lookup(&self, data: &[u8]) -> Result<Option<String>> {
        let hash = crate::hash::md5_hash(data);
        self.md5_lookup_raw(&hash)
    }

    /// Look up a raw MD5 hash (already computed) in the database.
    pub fn md5_lookup_raw(&self, hash: &[u8]) -> Result<Option<String>> {
        let rtxn = self
            .env
            .read_txn()
            .context("failed to create LMDB read transaction for MD5 lookup")?;
        let result = self
            .md5_db
            .get(&rtxn, hash)
            .context("failed to look up MD5 hash in LMDB")?
            .map(std::borrow::ToOwned::to_owned);
        Ok(result)
    }

    /// Import SHA-256 hash entries into the database.
    ///
    /// Each entry is a `(hash_bytes, signature_name)` pair. Existing entries
    /// with the same hash are overwritten. Returns the number of entries imported.
    #[instrument(skip_all, fields(count = entries.len()))]
    pub fn import_hashes(&self, entries: &[(Vec<u8>, String)]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut imported = 0usize;

        for (hash, name) in entries {
            self.sha256_db.put(&mut wtxn, hash, name)?;
            imported += 1;
        }

        // Update last_update timestamp.
        let now = chrono::Utc::now().timestamp();
        self.meta_db.put(&mut wtxn, META_KEY_LAST_UPDATE, &now.to_le_bytes())?;

        wtxn.commit()?;
        tracing::info!(imported, "imported SHA-256 hash entries");
        Ok(imported)
    }

    /// Remove SHA-256 hash entries from the database.
    ///
    /// Returns the number of entries actually removed (i.e., that existed).
    #[instrument(skip_all, fields(count = hashes.len()))]
    pub fn remove_hashes(&self, hashes: &[Vec<u8>]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut removed = 0usize;

        for hash in hashes {
            if self.sha256_db.delete(&mut wtxn, hash)? {
                removed += 1;
            }
        }

        wtxn.commit()?;
        tracing::info!(removed, "removed SHA-256 hash entries");
        Ok(removed)
    }

    /// Get the database version number.
    #[instrument(skip_all)]
    pub fn get_version(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        let version = self.meta_db.get(&rtxn, META_KEY_VERSION)?.map_or(0, |bytes| {
            let arr: [u8; 8] = bytes.try_into().unwrap_or([0u8; 8]);
            u64::from_le_bytes(arr)
        });
        Ok(version)
    }

    /// Set the database version number.
    #[instrument(skip_all, fields(version))]
    pub fn set_version(&self, version: u64) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.meta_db.put(&mut wtxn, META_KEY_VERSION, &version.to_le_bytes())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Gather statistics about the database.
    #[instrument(skip_all)]
    pub fn get_stats(&self) -> Result<DbStats> {
        let rtxn = self.env.read_txn()?;

        let hash_count = self.sha256_db.len(&rtxn)?;
        let md5_count = self.md5_db.len(&rtxn)?;

        let version = self.meta_db.get(&rtxn, META_KEY_VERSION)?.map_or(0, |bytes| {
            let arr: [u8; 8] = bytes.try_into().unwrap_or([0u8; 8]);
            u64::from_le_bytes(arr)
        });

        let last_update = self.meta_db.get(&rtxn, META_KEY_LAST_UPDATE)?.map(|bytes| {
            let arr: [u8; 8] = bytes.try_into().unwrap_or([0u8; 8]);
            i64::from_le_bytes(arr)
        });

        Ok(DbStats {
            hash_count,
            md5_count,
            version,
            last_update,
        })
    }

    /// Import MD5 hash entries into the database.
    ///
    /// Each entry is a `(hash_bytes, signature_name)` pair.
    /// Returns the number of entries imported.
    #[instrument(skip_all, fields(count = entries.len()))]
    pub fn import_md5_hashes(&self, entries: &[(Vec<u8>, String)]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut imported = 0usize;

        for (hash, name) in entries {
            self.md5_db.put(&mut wtxn, hash, name)?;
            imported += 1;
        }

        let now = chrono::Utc::now().timestamp();
        self.meta_db.put(&mut wtxn, META_KEY_LAST_UPDATE, &now.to_le_bytes())?;

        wtxn.commit()?;
        tracing::info!(imported, "imported MD5 hash entries");
        Ok(imported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp_db() -> (tempfile::TempDir, SignatureDatabase) {
        let dir = tempfile::tempdir().unwrap();
        let db = SignatureDatabase::open(dir.path()).unwrap();
        (dir, db)
    }

    #[test]
    fn test_open_and_stats() {
        let (_dir, db) = open_temp_db();
        let stats = db.get_stats().unwrap();
        assert_eq!(stats.hash_count, 0);
        assert_eq!(stats.md5_count, 0);
        assert_eq!(stats.version, 0);
        assert!(stats.last_update.is_none());
    }

    #[test]
    fn test_version_roundtrip() {
        let (_dir, db) = open_temp_db();
        assert_eq!(db.get_version().unwrap(), 0);
        db.set_version(42).unwrap();
        assert_eq!(db.get_version().unwrap(), 42);
    }

    #[test]
    fn test_import_and_lookup() {
        let (_dir, db) = open_temp_db();

        let hash = crate::hash::sha256_hash(b"malware_sample");
        let entries = vec![(hash.clone(), "Win.Trojan.Test-1".to_string())];

        let count = db.import_hashes(&entries).unwrap();
        assert_eq!(count, 1);

        // Lookup by data should find it.
        let result = db.hash_lookup(b"malware_sample").unwrap();
        assert_eq!(result, Some("Win.Trojan.Test-1".to_string()));

        // Lookup by raw hash should also work.
        let result = db.sha256_lookup_raw(&hash).unwrap();
        assert_eq!(result, Some("Win.Trojan.Test-1".to_string()));

        // Unknown data should return None.
        assert!(db.hash_lookup(b"benign_file").unwrap().is_none());
    }

    #[test]
    fn test_remove_hashes() {
        let (_dir, db) = open_temp_db();

        let hash = crate::hash::sha256_hash(b"removable");
        db.import_hashes(&[(hash.clone(), "Test.Sig".to_string())]).unwrap();
        assert!(db.sha256_lookup_raw(&hash).unwrap().is_some());

        let removed = db.remove_hashes(std::slice::from_ref(&hash)).unwrap();
        assert_eq!(removed, 1);
        assert!(db.sha256_lookup_raw(&hash).unwrap().is_none());

        // Removing again should return 0.
        let removed = db.remove_hashes(&[hash]).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_md5_import_and_lookup() {
        let (_dir, db) = open_temp_db();

        let hash = crate::hash::md5_hash(b"md5_sample");
        db.import_md5_hashes(&[(hash, "MD5.Test-1".to_string())]).unwrap();

        let result = db.md5_lookup(b"md5_sample").unwrap();
        assert_eq!(result, Some("MD5.Test-1".to_string()));

        assert!(db.md5_lookup(b"other").unwrap().is_none());
    }

    #[test]
    fn test_stats_after_imports() {
        let (_dir, db) = open_temp_db();

        db.import_hashes(&[
            (crate::hash::sha256_hash(b"a"), "Sig.A".into()),
            (crate::hash::sha256_hash(b"b"), "Sig.B".into()),
        ])
        .unwrap();
        db.import_md5_hashes(&[(crate::hash::md5_hash(b"c"), "Sig.C".into())])
            .unwrap();

        let stats = db.get_stats().unwrap();
        assert_eq!(stats.hash_count, 2);
        assert_eq!(stats.md5_count, 1);
        assert!(stats.last_update.is_some());
    }
}
