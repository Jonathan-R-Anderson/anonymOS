//! Axum route handlers for the prx-sd update server.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use tracing::{error, info, warn};

use prx_sd_updater::delta::DeltaPatch;

use crate::storage::SignatureStorage;

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    /// Signature delta/full storage backend.
    pub storage: Arc<SignatureStorage>,
    /// Ed25519 signing key for authenticating payloads.
    pub signing_key: Arc<SigningKey>,
    /// Admin authentication token (required; publish endpoint always requires auth).
    pub admin_token: String,
}

/// Response body for `GET /version`.
#[derive(Debug, Serialize)]
pub struct VersionInfo {
    /// Current latest version on the server.
    pub current: u64,
    /// Minimum version that can receive delta updates (older clients need
    /// a full download).
    pub min_delta: u64,
}

/// Application-level error type that implements `IntoResponse`.
pub struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }

    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
        }
    }

    fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.message,
        });
        (self.status, Json(body)).into_response()
    }
}

/// `GET /version` - Return the current signature database version.
pub async fn get_version(State(state): State<AppState>) -> Json<VersionInfo> {
    let current = state.storage.current_version();
    // min_delta is 0 for now; in production this would be set based on
    // how many delta files are retained.
    Json(VersionInfo { current, min_delta: 0 })
}

/// `GET /delta/:range` - Return a signed delta patch.
///
/// The `:range` path parameter should be in the format `{from}..{to}`,
/// e.g. `/delta/5..10`.
pub async fn get_delta(
    State(state): State<AppState>,
    Path(range): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (from, to) = parse_range(&range)
        .ok_or_else(|| AppError::bad_request(format!("invalid range format '{range}': expected 'FROM..TO'")))?;

    if from >= to {
        return Err(AppError::bad_request(format!(
            "invalid range: 'from' ({from}) must be less than 'to' ({to})"
        )));
    }

    let data = state.storage.get_delta(from, to).map_err(|e| {
        warn!(from, to, error = %e, "delta not found");
        AppError::not_found(format!("delta {from}..{to} not available"))
    })?;

    info!(from, to, size = data.len(), "serving delta patch");

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        data,
    ))
}

/// `GET /full` - Return the full signed database snapshot.
pub async fn get_full(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let data = state.storage.get_full().map_err(|e| {
        warn!(error = %e, "full snapshot not available");
        AppError::not_found("full database snapshot not available")
    })?;

    info!(size = data.len(), "serving full database snapshot");

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        data,
    ))
}

/// `POST /admin/publish` - Publish a new delta patch.
///
/// Expects the request body to contain a bincode-serialized, zstd-compressed
/// `DeltaPatch`. The server will sign it and store it.
///
/// Requires an `Authorization: Bearer <token>` header if an admin token is
/// configured.
pub async fn publish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    // Always check authorization -- ADMIN_TOKEN is required at startup.
    {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");

        let expected_bytes = state.admin_token.as_bytes();
        let provided_bytes = provided.as_bytes();

        // Constant-time comparison to prevent timing attacks.
        // Length difference is checked first (this leaks length but not content).
        let is_valid = provided_bytes.len() == expected_bytes.len() && {
            let mut diff = 0u8;
            for (a, b) in provided_bytes.iter().zip(expected_bytes.iter()) {
                diff |= a ^ b;
            }
            diff == 0
        };

        if !is_valid {
            return Err(AppError::unauthorized("invalid or missing admin token"));
        }
    }

    if body.is_empty() {
        return Err(AppError::bad_request("request body is empty"));
    }

    // Decompress and deserialize the patch from the raw body.
    let patch: DeltaPatch = prx_sd_updater::delta::decode_delta(&body).map_err(|e| {
        error!(error = %e, "failed to decode published delta patch");
        AppError::bad_request(format!("invalid delta patch: {e}"))
    })?;

    let new_version = patch.version;

    // Publish (sign, write to disk, bump version).
    state.storage.publish(&patch, &state.signing_key).map_err(|e| {
        error!(error = %e, "failed to publish delta patch");
        AppError::internal(format!("publish failed: {e}"))
    })?;

    info!(new_version, "delta patch published successfully");

    let resp = serde_json::json!({
        "published": true,
        "version": new_version,
    });
    Ok((StatusCode::OK, Json(resp)))
}

/// Parse a `"FROM..TO"` range string into `(from, to)`.
fn parse_range(range: &str) -> Option<(u64, u64)> {
    let mut parts = range.splitn(2, "..");
    let from = parts.next()?.parse::<u64>().ok()?;
    let to = parts.next()?.parse::<u64>().ok()?;
    Some((from, to))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_range_valid() {
        assert_eq!(parse_range("0..5"), Some((0, 5)));
        assert_eq!(parse_range("10..20"), Some((10, 20)));
        assert_eq!(parse_range("0..1"), Some((0, 1)));
    }

    #[test]
    fn test_parse_range_invalid() {
        assert_eq!(parse_range("abc"), None);
        assert_eq!(parse_range("1-2"), None);
        assert_eq!(parse_range("..5"), None);
        assert_eq!(parse_range("5.."), None);
        assert_eq!(parse_range(""), None);
    }
}
