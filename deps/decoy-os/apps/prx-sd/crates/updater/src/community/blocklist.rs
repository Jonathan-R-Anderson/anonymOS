//! Community blocklist synchronisation.
//!
//! Pulls the community-maintained blocklist of malicious SHA-256 hashes and
//! merges them into a local in-memory set for fast lookup during scans.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::config::CommunityConfig;
use super::enroll::build_http_client;

/// Version metadata returned by the blocklist version endpoint.
#[derive(Debug, Deserialize)]
struct BlocklistVersion {
    version: u64,
}

/// Full blocklist payload returned by the server.
#[derive(Debug, Deserialize)]
struct BlocklistPayload {
    version: u64,
    hashes: Vec<String>,
}

/// Community blocklist synchroniser.
///
/// Maintains an in-memory set of SHA-256 hex digests pulled from the
/// community API. The set is behind an `RwLock` so scanners can read
/// concurrently while sync updates it.
pub struct CommunityBlocklistSync {
    config: CommunityConfig,
    http: reqwest::Client,
    /// Current blocklist version (0 = never synced).
    current_version: RwLock<u64>,
    /// Set of lowercase SHA-256 hex digests from the community blocklist.
    hashes: RwLock<HashSet<String>>,
}

impl CommunityBlocklistSync {
    /// Create a new blocklist syncer.
    ///
    /// Returns `None` if community sharing is disabled or not enrolled.
    pub fn new(config: &CommunityConfig) -> Result<Option<Arc<Self>>> {
        if !config.enabled || !config.is_enrolled() {
            return Ok(None);
        }
        let http = build_http_client()?;
        Ok(Some(Arc::new(Self {
            config: config.clone(),
            http,
            current_version: RwLock::new(0),
            hashes: RwLock::new(HashSet::new()),
        })))
    }

    /// Check whether a SHA-256 hex digest is in the community blocklist.
    pub async fn contains(&self, sha256_hex: &str) -> bool {
        let set = self.hashes.read().await;
        set.contains(&sha256_hex.to_ascii_lowercase())
    }

    /// Number of hashes currently in the blocklist.
    pub async fn len(&self) -> usize {
        let set = self.hashes.read().await;
        set.len()
    }

    /// Returns `true` if the blocklist contains no hashes.
    pub async fn is_empty(&self) -> bool {
        let set = self.hashes.read().await;
        set.is_empty()
    }

    /// Current blocklist version.
    pub async fn version(&self) -> u64 {
        *self.current_version.read().await
    }

    /// Perform a single sync cycle: check version, pull full if newer.
    pub async fn sync_once(&self) -> Result<bool> {
        let api_key = match &self.config.api_key {
            Some(k) => k.clone(),
            None => bail!("cannot sync blocklist: no api_key configured"),
        };

        let base = self.config.server_url.trim_end_matches('/');

        // 1. Check remote version.
        let version_url = format!("{base}/api/v1/sd/blocklist/version");
        let resp = self
            .http
            .get(&version_url)
            .bearer_auth(&api_key)
            .send()
            .await
            .context("failed to check blocklist version")?;

        let status = resp.status();
        if !status.is_success() {
            bail!("blocklist version check failed: HTTP {status}");
        }

        let ver: BlocklistVersion = resp.json().await.context("failed to parse blocklist version")?;

        let local = *self.current_version.read().await;
        if ver.version <= local {
            debug!(
                local_version = local,
                remote_version = ver.version,
                "community blocklist is up to date"
            );
            return Ok(false);
        }

        // 2. Pull full blocklist.
        let full_url = format!("{base}/api/v1/sd/blocklist/decoded");
        let resp = self
            .http
            .get(&full_url)
            .bearer_auth(&api_key)
            .send()
            .await
            .context("failed to fetch full blocklist")?;

        let status = resp.status();
        if !status.is_success() {
            bail!("blocklist fetch failed: HTTP {status}");
        }

        // Enforce response size limit (8 MiB) before parsing.
        let bytes = resp.bytes().await.context("failed to read blocklist response")?;
        if bytes.len() > 8 * 1024 * 1024 {
            bail!("blocklist response too large ({} bytes), max 8 MiB", bytes.len());
        }
        let payload: BlocklistPayload = serde_json::from_slice(&bytes).context("failed to parse blocklist payload")?;

        let count = payload.hashes.len();
        let new_set: HashSet<String> = payload.hashes.into_iter().map(|h| h.to_ascii_lowercase()).collect();

        // 3. Swap in the new set.
        {
            let mut set = self.hashes.write().await;
            *set = new_set;
        }
        {
            let mut v = self.current_version.write().await;
            *v = payload.version;
        }

        info!(version = payload.version, count, "community blocklist synced");
        Ok(true)
    }

    /// Run a periodic sync loop. Spawned as a background tokio task.
    pub async fn run_sync_loop(self: Arc<Self>, cancel: tokio::sync::watch::Receiver<bool>) {
        // Initial full pull.
        if let Err(e) = self.sync_once().await {
            warn!(error = %e, "initial community blocklist sync failed");
        }

        let interval = std::time::Duration::from_secs(self.config.sync_interval_secs.max(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip immediate first tick

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.sync_once().await {
                        warn!(error = %e, "periodic community blocklist sync failed");
                    }
                }
                () = cancel_notified(&cancel) => {
                    break;
                }
            }
        }
    }
}

/// Wait until the cancellation watch channel signals `true`.
async fn cancel_notified(rx: &tokio::sync::watch::Receiver<bool>) {
    let mut rx = rx.clone();
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrolled_config() -> CommunityConfig {
        CommunityConfig {
            enabled: true,
            server_url: "http://localhost:9999".to_string(),
            api_key: Some("test-key".to_string()),
            machine_id: Some("test-machine".to_string()),
            batch_size: 50,
            flush_interval_secs: 30,
            sync_interval_secs: 60,
        }
    }

    #[test]
    fn new_returns_none_when_disabled() {
        let cfg = CommunityConfig::default();
        let sync = CommunityBlocklistSync::new(&cfg).unwrap();
        assert!(sync.is_none());
    }

    #[tokio::test]
    async fn new_returns_some_when_enrolled() {
        let cfg = enrolled_config();
        let sync = CommunityBlocklistSync::new(&cfg).unwrap();
        assert!(sync.is_some());
    }

    #[tokio::test]
    async fn empty_blocklist_contains_nothing() {
        let cfg = enrolled_config();
        let sync = CommunityBlocklistSync::new(&cfg).unwrap().unwrap();
        assert!(!sync.contains("deadbeef").await);
        assert_eq!(sync.len().await, 0);
        assert_eq!(sync.version().await, 0);
    }
}
