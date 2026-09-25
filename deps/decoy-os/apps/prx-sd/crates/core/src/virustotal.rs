//! `VirusTotal` API v3 client for hash-based cloud lookups.
//!
//! Queries the free `VirusTotal` API (500 requests/day) when a file hash is
//! not found in the local signature database. Results are cached in LMDB so
//! the same file is never queried twice.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result, bail};
use prx_sd_signatures::SignatureDatabase;
use serde::Deserialize;

/// `VirusTotal` cloud lookup client.
pub struct VtClient {
    api_key: String,
    http: reqwest::Client,
    /// Shared reference to the signature database for caching results.
    db: Arc<SignatureDatabase>,
    /// Daily request counter (best-effort, not persisted across restarts).
    requests_today: AtomicU32,
    /// Maximum requests per day (free tier = 500).
    daily_limit: u32,
}

/// Subset of the VT API v3 file report we care about.
#[derive(Debug, Deserialize)]
struct VtResponse {
    data: Option<VtData>,
}

#[derive(Debug, Deserialize)]
struct VtData {
    attributes: Option<VtAttributes>,
}

#[derive(Debug, Deserialize)]
struct VtAttributes {
    /// Number of engines that flagged the file as malicious.
    #[serde(default)]
    last_analysis_stats: VtStats,
    /// Suggested threat label from VT.
    #[serde(default)]
    popular_threat_classification: Option<VtThreatClassification>,
}

#[derive(Debug, Default, Deserialize)]
struct VtStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
}

#[derive(Debug, Deserialize)]
struct VtThreatClassification {
    suggested_threat_label: Option<String>,
}

/// Result of a `VirusTotal` lookup.
#[derive(Debug, Clone)]
pub enum VtVerdict {
    /// Known malicious by VT consensus.
    Malicious {
        /// The threat classification name.
        threat_name: String,
        /// Number of engines that detected the threat.
        detections: u32,
        /// Total number of engines that scanned the file.
        total: u32,
    },
    /// Not enough detections to classify as malicious.
    Clean,
    /// Rate limit reached; query skipped.
    RateLimited,
    /// VT has no record of this hash.
    NotFound,
}

impl VtClient {
    /// Create a new `VirusTotal` client. Returns `None` if `api_key` is empty.
    pub fn new(api_key: &str, db: Arc<SignatureDatabase>) -> Option<Self> {
        let key = api_key.trim();
        if key.is_empty() {
            return None;
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?;

        Some(Self {
            api_key: key.to_string(),
            http,
            db,
            requests_today: AtomicU32::new(0),
            daily_limit: 500,
        })
    }

    /// Query VT for a SHA-256 hash (hex-encoded, 64 chars).
    ///
    /// If the hash is found to be malicious, the result is cached in LMDB
    /// so future scans of the same file are instant.
    #[allow(clippy::similar_names)] // `stats` vs `status` are semantically distinct
    pub async fn lookup_sha256(&self, sha256_hex: &str) -> Result<VtVerdict> {
        // Rate-limit check.
        let count = self.requests_today.fetch_add(1, Ordering::Relaxed);
        if count >= self.daily_limit {
            self.requests_today.fetch_sub(1, Ordering::Relaxed);
            tracing::warn!(count, limit = self.daily_limit, "VirusTotal daily rate limit reached");
            return Ok(VtVerdict::RateLimited);
        }

        let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256_hex.to_lowercase());

        let resp = self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .context("VT API request failed")?;

        let status = resp.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(VtVerdict::NotFound);
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Ok(VtVerdict::RateLimited);
        }

        if !status.is_success() {
            bail!("VT API returned status {status}");
        }

        let body: VtResponse = resp.json().await.context("failed to parse VT response")?;

        let Some(data) = body.data else {
            return Ok(VtVerdict::NotFound);
        };

        let Some(attrs) = data.attributes else {
            return Ok(VtVerdict::NotFound);
        };

        let stats = &attrs.last_analysis_stats;
        let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
        let detections = stats.malicious;

        // Threshold: at least 5 engines flagging malicious, or >25% detection rate.
        let is_malicious = detections >= 5 || (total > 0 && detections * 100 / total > 25);

        if is_malicious {
            let threat_name = attrs
                .popular_threat_classification
                .and_then(|c| c.suggested_threat_label)
                .unwrap_or_else(|| format!("VT.Malicious.{detections}/{total}"));

            // Cache the result in LMDB so we don't query again.
            if let Some(hash_bytes) = hex_decode(sha256_hex) {
                let cache_name = format!("VT:{threat_name}");
                if let Err(e) = self.db.import_hashes(&[(hash_bytes, cache_name)]) {
                    tracing::warn!("failed to cache VT result in LMDB: {e}");
                }
            }

            Ok(VtVerdict::Malicious {
                threat_name,
                detections,
                total,
            })
        } else {
            Ok(VtVerdict::Clean)
        }
    }

    /// Return how many requests have been made today (approximate).
    pub fn requests_used(&self) -> u32 {
        self.requests_today.load(Ordering::Relaxed)
    }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = hex.get(i..i + 2)?;
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("4d5a"), Some(vec![0x4d, 0x5a]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert!(hex_decode("4d5").is_none());
    }

    #[test]
    fn test_vt_client_none_for_empty_key() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = Arc::new(SignatureDatabase::open(dir.path()).expect("db open"));
        assert!(VtClient::new("", db.clone()).is_none());
        assert!(VtClient::new("   ", db).is_none());
    }

    #[test]
    fn test_vt_client_some_for_valid_key() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = Arc::new(SignatureDatabase::open(dir.path()).expect("db open"));
        assert!(VtClient::new("test_api_key_123", db).is_some());
    }
}
