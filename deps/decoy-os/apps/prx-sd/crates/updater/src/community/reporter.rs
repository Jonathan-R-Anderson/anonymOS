//! Batched threat signal reporter for the community API.
//!
//! `SdCommunityReporter` buffers non-clean scan results and flushes them
//! to `POST /api/v1/sd/signals` in batches.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use super::config::CommunityConfig;
use super::enroll::build_http_client;

/// A single threat signal sent to the community API.
///
/// The four required fields (`file_sha256`, `threat_level`, `detection_type`,
/// `threat_name`) are always present. Optional fields are omitted from the
/// JSON payload when `None` or zero, matching the backend's `serde(default)`
/// contract.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatSignal {
    /// SHA-256 hex digest of the file.
    pub file_sha256: String,
    /// Threat level string: "Suspicious" or "Malicious".
    pub threat_level: String,
    /// Detection method: "Hash", "`YaraRule`", "Heuristic", "Behavioral".
    pub detection_type: String,
    /// Human-readable threat name.
    pub threat_name: String,
    /// MD5 hex digest (optional, for backward-compat lookups).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_md5: Option<String>,
    /// Original file name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// File size in bytes.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub file_size: i64,
    /// YARA rule that matched (empty string if not a YARA detection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara_rule: Option<String>,
    /// Heuristic analysis score (0.0 if not applicable).
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub heuristic_score: f64,
    /// Confidence score (0.0–1.0).
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub confidence: f64,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

/// Request body for signal batch upload.
///
/// The backend extracts `machine_id` from the Bearer token (via
/// `MachineContext`), so it is not included in the payload.
#[derive(Debug, Serialize)]
struct SignalBatch {
    signals: Vec<ThreatSignal>,
}

/// Batched threat signal reporter.
///
/// Thread-safe: the inner buffer is protected by a tokio `Mutex` and the
/// struct is wrapped in `Arc` for sharing across tasks.
pub struct SdCommunityReporter {
    config: CommunityConfig,
    buffer: Mutex<Vec<ThreatSignal>>,
    http: reqwest::Client,
}

impl SdCommunityReporter {
    /// Create a new reporter from the given community config.
    ///
    /// Returns `None` if the config is not enrolled or not enabled.
    pub fn new(config: &CommunityConfig) -> Result<Option<Arc<Self>>> {
        if !config.enabled || !config.is_enrolled() {
            return Ok(None);
        }
        let http = build_http_client()?;
        Ok(Some(Arc::new(Self {
            config: config.clone(),
            buffer: Mutex::new(Vec::with_capacity(config.batch_size)),
            http,
        })))
    }

    /// Push a threat signal into the buffer.
    ///
    /// If the buffer reaches `batch_size`, a flush is triggered automatically.
    pub async fn push_signal(self: &Arc<Self>, signal: ThreatSignal) {
        let should_flush = {
            let mut buf = self.buffer.lock().await;
            buf.push(signal);
            buf.len() >= self.config.batch_size
        };

        if should_flush {
            if let Err(e) = self.flush().await {
                error!(error = %e, "failed to flush signal batch");
            }
        }
    }

    /// Flush all buffered signals to the community API.
    pub async fn flush(&self) -> Result<()> {
        let signals = {
            let mut buf = self.buffer.lock().await;
            if buf.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *buf)
        };

        let count = signals.len();
        debug!(count, "flushing signal batch");

        let api_key = match &self.config.api_key {
            Some(k) => k.clone(),
            None => bail!("cannot flush signals: no api_key configured"),
        };

        let url = format!("{}/api/v1/sd/signals", self.config.server_url.trim_end_matches('/'));

        let batch = SignalBatch { signals };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&api_key)
            .json(&batch)
            .send()
            .await
            .context("failed to send signal batch")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(status = %status, "signal upload returned non-success: {body}");
            bail!("signal upload failed: HTTP {status}");
        }

        info!(count, "signal batch uploaded successfully");
        Ok(())
    }

    /// Run a periodic flush loop. This should be spawned as a background
    /// tokio task.
    ///
    /// The loop runs until the provided cancellation token is notified.
    pub async fn run_flush_loop(self: Arc<Self>, cancel: tokio::sync::watch::Receiver<bool>) {
        let interval = std::time::Duration::from_secs(self.config.flush_interval_secs.max(1));
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.flush().await {
                        warn!(error = %e, "periodic signal flush failed");
                    }
                }
                () = cancel_notified(&cancel) => {
                    // Final flush before shutdown.
                    if let Err(e) = self.flush().await {
                        warn!(error = %e, "final signal flush on shutdown failed");
                    }
                    break;
                }
            }
        }
    }
}

/// Wait until the cancellation watch channel signals `true`.
async fn cancel_notified(rx: &tokio::sync::watch::Receiver<bool>) {
    let mut rx = rx.clone();
    // Wait until the value becomes true.
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            // Sender dropped — treat as cancellation.
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
            batch_size: 3,
            flush_interval_secs: 5,
            sync_interval_secs: 60,
        }
    }

    #[test]
    fn new_returns_none_when_disabled() {
        let cfg = CommunityConfig::default();
        let reporter = SdCommunityReporter::new(&cfg).unwrap();
        assert!(reporter.is_none());
    }

    #[tokio::test]
    async fn new_returns_some_when_enrolled() {
        let cfg = enrolled_config();
        let reporter = SdCommunityReporter::new(&cfg).unwrap();
        assert!(reporter.is_some());
    }

    #[tokio::test]
    async fn flush_empty_buffer_is_noop() {
        let cfg = enrolled_config();
        let reporter = SdCommunityReporter::new(&cfg).unwrap().unwrap();
        // Should succeed with no signals buffered.
        let result = reporter.flush().await;
        assert!(result.is_ok());
    }
}
