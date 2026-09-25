//! On-disk storage for signature delta patches and full database snapshots.
//!
//! The storage directory layout:
//! ```text
//! base_dir/
//!   version          # text file with current version number
//!   deltas/
//!     1..2.bin       # signed, compressed delta from v1 to v2
//!     2..3.bin       # signed, compressed delta from v2 to v3
//!   full/
//!     latest.bin     # signed, compressed full database snapshot
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use tracing::info;

use prx_sd_updater::delta::{DeltaPatch, encode_delta};

/// Manages on-disk storage of signed delta patches and full snapshots.
pub struct SignatureStorage {
    /// Root directory for all storage files.
    base_dir: PathBuf,
    /// Current signature database version (atomic for lock-free reads).
    current_version: AtomicU64,
}

impl SignatureStorage {
    /// Initialize storage at the given directory.
    ///
    /// Creates the directory structure if it does not exist and reads the
    /// current version from the `version` file (defaulting to 0).
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create directory structure.
        std::fs::create_dir_all(base_dir.join("deltas")).context("failed to create deltas directory")?;
        std::fs::create_dir_all(base_dir.join("full")).context("failed to create full directory")?;

        // Read current version.
        let version_file = base_dir.join("version");
        let version = if version_file.exists() {
            let text = std::fs::read_to_string(&version_file).context("failed to read version file")?;
            text.trim()
                .parse::<u64>()
                .context("invalid version number in version file")?
        } else {
            std::fs::write(&version_file, "0").context("failed to create version file")?;
            0
        };

        info!(version, base_dir = %base_dir.display(), "signature storage initialized");

        Ok(Self {
            base_dir,
            current_version: AtomicU64::new(version),
        })
    }

    /// Return the current signature database version.
    pub fn current_version(&self) -> u64 {
        self.current_version.load(Ordering::Relaxed)
    }

    /// Read a stored delta patch file for the given version range.
    ///
    /// The returned bytes are the signed, compressed payload ready to serve
    /// directly to clients.
    pub fn get_delta(&self, from: u64, to: u64) -> Result<Vec<u8>> {
        let path = self.delta_path(from, to);

        if !path.exists() {
            bail!("delta {from}..{to} not found at {}", path.display());
        }

        std::fs::read(&path).with_context(|| format!("failed to read delta file {}", path.display()))
    }

    /// Read the latest full database snapshot.
    ///
    /// Returns the signed, compressed payload.
    pub fn get_full(&self) -> Result<Vec<u8>> {
        let path = self.base_dir.join("full").join("latest.bin");

        if !path.exists() {
            bail!("full database snapshot not found");
        }

        std::fs::read(&path).context("failed to read full database snapshot")
    }

    /// Publish a new delta patch.
    ///
    /// Serializes and compresses the patch, signs it with the provided key,
    /// writes it to disk, and bumps the current version. Returns the new
    /// version number.
    pub fn publish(&self, patch: &DeltaPatch, signing_key: &SigningKey) -> Result<u64> {
        let current = self.current_version();
        let new_version = patch.version;

        if new_version <= current {
            bail!("cannot publish version {new_version}: current version is {current}");
        }

        // Encode (serialize + zstd compress) the delta.
        let compressed = encode_delta(patch).context("failed to encode delta patch")?;

        // Sign the compressed payload: [64-byte sig][compressed data].
        let signed = prx_sd_updater::sign_payload(signing_key, &compressed);

        // Write delta file.
        let delta_path = self.delta_path(current, new_version);
        std::fs::write(&delta_path, &signed)
            .with_context(|| format!("failed to write delta to {}", delta_path.display()))?;

        // Update version file and atomic counter.
        let version_file = self.base_dir.join("version");
        std::fs::write(&version_file, new_version.to_string()).context("failed to update version file")?;
        self.current_version.store(new_version, Ordering::Relaxed);

        info!(
            from = current,
            to = new_version,
            delta_size = signed.len(),
            "published new delta patch"
        );

        Ok(new_version)
    }

    /// Build the file path for a delta covering `from..to`.
    fn delta_path(&self, from: u64, to: u64) -> PathBuf {
        self.base_dir.join("deltas").join(format!("{from}..{to}.bin"))
    }
}
