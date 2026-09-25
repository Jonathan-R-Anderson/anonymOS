//! Machine enrollment against the community API.
//!
//! Calls `POST /api/v1/machines/enroll` and returns credentials that are
//! persisted in [`CommunityConfig`].

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::config::CommunityConfig;

/// Request body for machine enrollment.
#[derive(Debug, Serialize)]
struct EnrollRequest {
    machine_name: String,
    os_info: String,
    version: String,
    product_type: String,
}

/// Successful enrollment response from the server.
#[derive(Debug, Deserialize)]
pub struct EnrollResponse {
    pub machine_id: String,
    pub api_key: String,
}

/// Build an HTTP client for community API calls.
pub(crate) fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(format!("prx-sd/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}

/// Collect basic OS information for the enrollment payload.
fn os_info_string() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Collect hostname, falling back to "unknown" on failure.
fn hostname() -> String {
    #[cfg(unix)]
    {
        // Read /etc/hostname directly; no unwrap.
        std::fs::read_to_string("/etc/hostname").map_or_else(|_| "unknown".to_string(), |s| s.trim().to_string())
    }
    #[cfg(not(unix))]
    {
        "unknown".to_string()
    }
}

/// Enroll this machine with the community API.
///
/// On success the returned [`EnrollResponse`] credentials should be persisted
/// into `CommunityConfig`.
pub async fn enroll_machine(config: &CommunityConfig) -> Result<EnrollResponse> {
    let client = build_http_client()?;

    let url = format!("{}/api/v1/machines/enroll", config.server_url.trim_end_matches('/'));

    let body = EnrollRequest {
        machine_name: hostname(),
        os_info: os_info_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        product_type: "sd".to_string(),
    };

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("failed to reach community API for enrollment")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("enrollment failed: HTTP {status} — {text}");
    }

    let enrollment: EnrollResponse = resp.json().await.context("failed to parse enrollment response")?;

    info!(
        machine_id = %enrollment.machine_id,
        "successfully enrolled with community API"
    );

    Ok(enrollment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_info_is_non_empty() {
        let info = os_info_string();
        assert!(!info.is_empty());
    }

    #[test]
    fn hostname_returns_something() {
        let name = hostname();
        assert!(!name.is_empty());
    }
}
