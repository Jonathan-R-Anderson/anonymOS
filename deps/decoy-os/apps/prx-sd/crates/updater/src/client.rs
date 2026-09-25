//! HTTP update client for fetching and applying signature database updates.
//!
//! Connects to the prx-sd update server, checks for new versions, downloads
//! delta patches, verifies their Ed25519 signatures, and applies them to the
//! local signature database.

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use tracing::info;

use crate::delta::{DeltaPatch, decode_delta};
use crate::verify::verify_payload;

/// HTTP client for the prx-sd signature update protocol.
pub struct UpdateClient {
    /// Base URL of the update server (e.g. `http://localhost:8080`).
    server_url: String,
    /// Ed25519 public key used to verify signed payloads from the server.
    verify_key: VerifyingKey,
    /// Underlying HTTP client (with connection pooling).
    http: reqwest::Client,
}

/// Version information returned by the update server.
#[derive(Debug, serde::Deserialize)]
struct VersionInfo {
    current: u64,
    #[allow(dead_code)]
    min_delta: u64,
}

impl UpdateClient {
    /// Create a new update client.
    ///
    /// # Arguments
    /// * `server_url` - Base URL of the update server (no trailing slash).
    /// * `public_key_bytes` - 32-byte Ed25519 public key for signature verification.
    pub fn new(server_url: &str, public_key_bytes: &[u8; 32]) -> Result<Self> {
        let verify_key = VerifyingKey::from_bytes(public_key_bytes).context("invalid Ed25519 public key bytes")?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent("prx-sd-updater/0.1")
            .build()
            .context("failed to build HTTP client")?;

        let server_url = server_url.trim_end_matches('/').to_string();

        Ok(Self {
            server_url,
            verify_key,
            http,
        })
    }

    /// Check whether a newer version is available on the server.
    ///
    /// Returns `Some(latest_version)` if the server has a version newer than
    /// `current_version`, or `None` if already up-to-date.
    pub async fn check_update(&self, current_version: u64) -> Result<Option<u64>> {
        let latest = self.fetch_latest_version().await?;
        if latest > current_version {
            Ok(Some(latest))
        } else {
            Ok(None)
        }
    }

    /// Perform a full update cycle: check for updates and apply them.
    ///
    /// Returns `true` if the database was updated, `false` if already current.
    pub async fn update(&self, db: &prx_sd_signatures::SignatureDatabase) -> Result<bool> {
        let current_version = db.get_version()?;
        let latest = self.fetch_latest_version().await?;

        if latest <= current_version {
            info!(current_version, latest, "signature database is already up-to-date");
            return Ok(false);
        }

        info!(
            current_version,
            latest, "new signature version available, downloading delta"
        );

        let delta_data = self.fetch_delta(current_version, latest).await?;
        self.apply_delta(db, &delta_data, latest)?;

        info!(new_version = latest, "signature database updated successfully");
        Ok(true)
    }

    /// Fetch the latest version number from the server.
    async fn fetch_latest_version(&self) -> Result<u64> {
        let url = format!("{}/version", self.server_url);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("failed to connect to update server")?;

        let status = resp.status();
        if !status.is_success() {
            bail!("update server returned HTTP {status} for GET /version");
        }

        let info: VersionInfo = resp.json().await.context("failed to parse version response")?;

        Ok(info.current)
    }

    /// Fetch a signed, compressed delta patch from the server.
    async fn fetch_delta(&self, from: u64, to: u64) -> Result<Vec<u8>> {
        let url = format!("{}/delta/{}..{}", self.server_url, from, to);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to fetch delta {from}..{to}"))?;

        let status = resp.status();
        if !status.is_success() {
            bail!("update server returned HTTP {status} for GET /delta/{from}..{to}");
        }

        let bytes = resp.bytes().await.context("failed to read delta response body")?;

        Ok(bytes.to_vec())
    }

    /// Verify, decompress, and apply a delta patch to the signature database.
    fn apply_delta(&self, db: &prx_sd_signatures::SignatureDatabase, delta_data: &[u8], new_ver: u64) -> Result<()> {
        // Verify the Ed25519 signature and extract the compressed payload.
        let compressed =
            verify_payload(&self.verify_key, delta_data).context("delta payload signature verification failed")?;

        // Decompress and deserialize the delta patch.
        let patch: DeltaPatch = decode_delta(&compressed).context("failed to decode delta patch")?;

        // Sanity check: the patch version should match what we expect.
        if patch.version != new_ver {
            bail!(
                "delta patch version mismatch: expected {new_ver}, got {}",
                patch.version
            );
        }

        // Apply removals first, then additions.
        if !patch.remove_hashes.is_empty() {
            let removed = db.remove_hashes(&patch.remove_hashes)?;
            info!(
                requested = patch.remove_hashes.len(),
                removed, "removed obsolete hash entries"
            );
        }

        if !patch.add_hashes.is_empty() {
            let added = db.import_hashes(&patch.add_hashes)?;
            info!(added, "imported new hash entries");
        }

        // YARA rule changes are logged but not applied here because the
        // YaraEngine is managed separately from the hash database. The caller
        // should reload YARA rules from the rules directory after update.
        for rule in &patch.yara_rules {
            match rule.action {
                crate::delta::RuleAction::Add => {
                    info!(rule = %rule.name, "YARA rule to add (write to rules dir)");
                }
                crate::delta::RuleAction::Remove => {
                    info!(rule = %rule.name, "YARA rule to remove");
                }
                crate::delta::RuleAction::Update => {
                    info!(rule = %rule.name, "YARA rule to update");
                }
            }
        }

        // Bump the database version.
        db.set_version(new_ver)?;

        Ok(())
    }
}
