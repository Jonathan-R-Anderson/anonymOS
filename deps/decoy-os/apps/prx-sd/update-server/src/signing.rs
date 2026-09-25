//! Ed25519 key management and payload signing utilities for the update server.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::info;

use prx_sd_updater::sign_payload;

/// Load an Ed25519 keypair from a file, or generate and save a new one.
///
/// The key file stores the 32-byte Ed25519 seed (private key material).
/// If the file does not exist, a fresh keypair is generated, the seed is
/// written to disk, and the pair is returned. If it exists, the seed is
/// read and the keypair is reconstructed.
pub fn load_or_create_keypair(path: &Path) -> Result<(SigningKey, VerifyingKey)> {
    use std::io::Write as IoWrite;

    // Try to read existing key first (avoids TOCTOU with exists() check).
    match std::fs::read(path) {
        Ok(seed_bytes) => {
            if seed_bytes.len() != 32 {
                anyhow::bail!(
                    "signing key file has invalid length: expected 32 bytes, got {}",
                    seed_bytes.len()
                );
            }

            let seed: [u8; 32] = seed_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key seed conversion failed despite length check"))?;

            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();

            info!(
                path = %path.display(),
                public_key = hex::encode(verifying_key.as_bytes()),
                "loaded existing signing keypair"
            );

            Ok((signing_key, verifying_key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Generate a new keypair.
            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let verifying_key = signing_key.verifying_key();

            // Ensure parent directory exists.
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory for signing key: {}", parent.display()))?;
            }

            // Use create_new (O_CREAT | O_EXCL) for atomic creation.
            // On Unix, set mode 0o600 at creation time to prevent
            // any window where the key is world-readable.
            let open_result = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                }
                #[cfg(not(unix))]
                {
                    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
                }
            };

            match open_result {
                Ok(mut file) => {
                    file.write_all(&signing_key.to_bytes())
                        .with_context(|| format!("failed to write signing key to {}", path.display()))?;
                    file.sync_all()
                        .with_context(|| format!("failed to sync signing key to {}", path.display()))?;

                    info!(
                        path = %path.display(),
                        public_key = hex::encode(verifying_key.as_bytes()),
                        "generated and saved new signing keypair"
                    );

                    Ok((signing_key, verifying_key))
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Another process created the key concurrently -- load it.
                    let seed_bytes = std::fs::read(path)
                        .with_context(|| format!("failed to read signing key from {}", path.display()))?;

                    if seed_bytes.len() != 32 {
                        anyhow::bail!(
                            "signing key file has invalid length: expected 32 bytes, got {}",
                            seed_bytes.len()
                        );
                    }

                    let seed: [u8; 32] = seed_bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("signing key seed conversion failed"))?;

                    let sk = SigningKey::from_bytes(&seed);
                    let vk = sk.verifying_key();

                    info!(
                        path = %path.display(),
                        "loaded signing key created by concurrent process"
                    );

                    Ok((sk, vk))
                }
                Err(e) => Err(anyhow::anyhow!(
                    "failed to create signing key file {}: {e}",
                    path.display()
                )),
            }
        }
        Err(e) => Err(anyhow::anyhow!(
            "failed to read signing key from {}: {e}",
            path.display()
        )),
    }
}

/// Sign data with the given key and compress with zstd.
///
/// Used when generating full database snapshots.
///
/// The output format is `[64-byte Ed25519 signature][zstd-compressed data]`.
/// This is the wire format used for delta and full-database downloads.
#[allow(dead_code)]
pub fn sign_and_compress(data: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    let compressed = zstd::encode_all(data, 3).context("failed to compress payload with zstd")?;

    Ok(sign_payload(key, &compressed))
}

/// Hex-encode bytes into a lowercase string.
///
/// Used for logging public keys; kept private to this module.
mod hex {
    use std::fmt::Write;

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}
