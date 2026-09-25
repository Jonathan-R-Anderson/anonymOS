use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Unique identifier for a quarantined file.
pub type QuarantineId = Uuid;

/// Metadata stored alongside each quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMeta {
    /// Original path of the file before quarantine.
    pub original_path: PathBuf,
    /// Name of the detected threat.
    pub threat_name: String,
    /// Timestamp when the file was quarantined.
    pub quarantine_time: DateTime<Utc>,
    /// SHA-256 hash of the original (unencrypted) file contents.
    pub sha256: String,
    /// Size of the original file in bytes.
    pub file_size: u64,
    /// AES-GCM nonce used for encryption.
    pub nonce: [u8; 12],
}

/// Summary statistics for the quarantine vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineStats {
    /// Number of files currently quarantined.
    pub count: usize,
    /// Total size of all original files (before encryption).
    pub total_size: u64,
}

/// Encrypted quarantine vault for malicious files.
///
/// Files are encrypted with AES-256-GCM using a vault-level key,
/// each with a unique random nonce. Metadata is stored as JSON sidecar files.
pub struct Quarantine {
    vault_dir: PathBuf,
    key: [u8; 32],
    meta_dir: PathBuf,
}

impl Quarantine {
    /// Create or open a quarantine vault at the given directory.
    ///
    /// Creates the vault directory structure if it does not exist.
    /// Loads an existing encryption key or generates a new one.
    pub fn new(vault_dir: PathBuf) -> Result<Self> {
        let meta_dir = vault_dir.join("meta");
        fs::create_dir_all(&vault_dir)
            .with_context(|| format!("failed to create vault dir: {}", vault_dir.display()))?;
        fs::create_dir_all(&meta_dir).with_context(|| format!("failed to create meta dir: {}", meta_dir.display()))?;

        let key = load_or_create_key(&vault_dir)?;

        Ok(Self {
            vault_dir,
            key,
            meta_dir,
        })
    }

    /// Quarantine a file: encrypt it, store metadata, and delete the original.
    ///
    /// Returns the unique [`QuarantineId`] assigned to the quarantined file.
    pub fn quarantine(&self, path: &Path, threat_name: &str) -> Result<QuarantineId> {
        let id = Uuid::new_v4();
        let data = fs::read(path).with_context(|| format!("failed to read file: {}", path.display()))?;

        // Compute SHA-256 of original contents.
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = format!("{:x}", hasher.finalize());

        let file_size = data.len() as u64;

        // Generate a random nonce.
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt the file contents.
        let cipher = Aes256Gcm::new_from_slice(&self.key).context("failed to create AES-256-GCM cipher")?;
        let ciphertext = cipher
            .encrypt(&nonce, data.as_ref())
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        // Write encrypted data.
        let encrypted_path = self.vault_dir.join(format!("{id}.enc"));
        fs::write(&encrypted_path, &ciphertext)
            .with_context(|| format!("failed to write encrypted file: {}", encrypted_path.display()))?;

        // Write metadata.
        let meta = QuarantineMeta {
            original_path: path.to_path_buf(),
            threat_name: threat_name.to_string(),
            quarantine_time: Utc::now(),
            sha256,
            file_size,
            nonce: nonce_bytes,
        };

        let meta_path = self.meta_dir.join(format!("{id}.json"));
        let meta_json = serde_json::to_string_pretty(&meta).context("failed to serialize quarantine metadata")?;
        fs::write(&meta_path, meta_json)
            .with_context(|| format!("failed to write metadata: {}", meta_path.display()))?;

        // Delete the original file.
        fs::remove_file(path).with_context(|| format!("failed to delete original file: {}", path.display()))?;

        tracing::info!(
            id = %id,
            path = %path.display(),
            threat = threat_name,
            "file quarantined"
        );

        Ok(id)
    }

    /// Restore a quarantined file to the specified path.
    ///
    /// Decrypts the file and writes it to `to`. The quarantine entry
    /// is **not** removed; call [`delete`] separately if desired.
    ///
    /// The restore path is validated to prevent path traversal attacks:
    /// - Paths containing `..` components are rejected.
    /// - Restoring to system-critical directories is denied.
    pub fn restore(&self, id: QuarantineId, to: &Path) -> Result<()> {
        // Path traversal protection: reject `..` components.
        for component in to.components() {
            if matches!(component, std::path::Component::ParentDir) {
                anyhow::bail!(
                    "restore path contains '..' component, which is not allowed: {}",
                    to.display()
                );
            }
        }

        // Resolve symlinks to prevent bypass via symbolic links.
        // If the path doesn't exist yet, canonicalize the parent directory.
        let resolved = if to.exists() {
            to.canonicalize()
                .with_context(|| format!("failed to resolve restore path: {}", to.display()))?
        } else if let Some(parent) = to.parent() {
            if parent.exists() {
                let resolved_parent = parent
                    .canonicalize()
                    .with_context(|| format!("failed to resolve parent of restore path: {}", parent.display()))?;
                resolved_parent.join(to.file_name().unwrap_or_default())
            } else {
                to.to_path_buf()
            }
        } else {
            to.to_path_buf()
        };

        // Deny restoring to system-critical directories (check resolved path).
        let denied_prefixes: &[&str] = &[
            "/etc",
            "/usr",
            "/bin",
            "/sbin",
            "/boot",
            "/proc",
            "/sys",
            "/lib",
            "/lib64",
            "/dev",
            "/run/systemd",
        ];
        let path_str = resolved.to_string_lossy();
        for prefix in denied_prefixes {
            if path_str.starts_with(prefix) {
                anyhow::bail!("restoring to system directory is denied: {}", resolved.display());
            }
        }

        let meta = self.load_meta(id)?;

        let encrypted_path = self.vault_dir.join(format!("{id}.enc"));
        let ciphertext = fs::read(&encrypted_path)
            .with_context(|| format!("failed to read encrypted file: {}", encrypted_path.display()))?;

        let nonce = Nonce::from(meta.nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key).context("failed to create AES-256-GCM cipher")?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

        // Ensure parent directory exists (use resolved path to prevent symlink bypass).
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).with_context(|| format!("failed to create parent dir: {}", parent.display()))?;
        }

        fs::write(&resolved, &plaintext)
            .with_context(|| format!("failed to write restored file: {}", resolved.display()))?;

        tracing::info!(id = %id, to = %resolved.display(), "file restored from quarantine");
        Ok(())
    }

    /// Permanently delete a quarantined file and its metadata.
    pub fn delete(&self, id: QuarantineId) -> Result<()> {
        let encrypted_path = self.vault_dir.join(format!("{id}.enc"));
        let meta_path = self.meta_dir.join(format!("{id}.json"));

        if encrypted_path.exists() {
            fs::remove_file(&encrypted_path)
                .with_context(|| format!("failed to delete: {}", encrypted_path.display()))?;
        }

        if meta_path.exists() {
            fs::remove_file(&meta_path).with_context(|| format!("failed to delete: {}", meta_path.display()))?;
        }

        tracing::info!(id = %id, "quarantine entry deleted");
        Ok(())
    }

    /// List all quarantined files and their metadata.
    pub fn list(&self) -> Result<Vec<(QuarantineId, QuarantineMeta)>> {
        let mut entries = Vec::new();

        for entry in fs::read_dir(&self.meta_dir).context("failed to read meta directory")? {
            let entry = entry.context("failed to read directory entry")?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            let id: QuarantineId = match stem.parse() {
                Ok(id) => id,
                Err(_) => continue,
            };

            match self.load_meta(id) {
                Ok(meta) => entries.push((id, meta)),
                Err(e) => {
                    tracing::warn!(id = %id, error = %e, "failed to load quarantine metadata");
                }
            }
        }

        // Sort by quarantine time (newest first).
        entries.sort_by(|a, b| b.1.quarantine_time.cmp(&a.1.quarantine_time));
        Ok(entries)
    }

    /// Get summary statistics for the quarantine vault.
    pub fn stats(&self) -> Result<QuarantineStats> {
        let entries = self.list()?;
        let count = entries.len();
        let total_size: u64 = entries.iter().map(|(_, m)| m.file_size).sum();
        Ok(QuarantineStats { count, total_size })
    }

    /// Load metadata for a specific quarantine ID.
    fn load_meta(&self, id: QuarantineId) -> Result<QuarantineMeta> {
        let meta_path = self.meta_dir.join(format!("{id}.json"));
        let data = fs::read_to_string(&meta_path)
            .with_context(|| format!("failed to read metadata: {}", meta_path.display()))?;
        let meta: QuarantineMeta = serde_json::from_str(&data).context("failed to parse quarantine metadata")?;
        Ok(meta)
    }
}

/// Load an existing vault encryption key or create a new one.
///
/// The key is stored as raw bytes in `vault_dir/.key`. Uses atomic
/// file creation (`create_new`) to eliminate TOCTOU race conditions.
/// On Unix, the key file is created with mode 0o600 to restrict access.
fn load_or_create_key(vault_dir: &Path) -> Result<[u8; 32]> {
    use std::io::Write;
    let key_path = vault_dir.join(".key");

    // Try to read existing key first.
    match fs::read(&key_path) {
        Ok(data) => {
            if data.len() != 32 {
                anyhow::bail!("invalid vault key length: expected 32 bytes, got {}", data.len());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            tracing::debug!("loaded existing vault key");
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Key does not exist -- generate and write atomically.
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);

            // Use create_new (O_CREAT | O_EXCL) to atomically create the file
            // and fail if it was created by another process in the meantime.
            let open_result = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&key_path)
                }
                #[cfg(not(unix))]
                {
                    fs::OpenOptions::new().write(true).create_new(true).open(&key_path)
                }
            };

            match open_result {
                Ok(mut file) => {
                    file.write_all(&key).context("failed to write vault key")?;
                    file.sync_all().context("failed to sync vault key to disk")?;
                    tracing::info!("generated new vault encryption key");
                    Ok(key)
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Another process created the key between our read attempt
                    // and our create attempt -- read the key it wrote.
                    let data = fs::read(&key_path).context("failed to read vault key")?;
                    if data.len() != 32 {
                        anyhow::bail!("invalid vault key length: expected 32 bytes, got {}", data.len());
                    }
                    let mut existing = [0u8; 32];
                    existing.copy_from_slice(&data);
                    tracing::debug!("loaded vault key created by concurrent process");
                    Ok(existing)
                }
                Err(e) => Err(anyhow::anyhow!("failed to create vault key file: {e}")),
            }
        }
        Err(e) => Err(anyhow::anyhow!("failed to read vault key: {e}")),
    }
}
