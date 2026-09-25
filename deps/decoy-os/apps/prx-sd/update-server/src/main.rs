//! prx-sd update server.
//!
//! Serves signature database updates over HTTP. Clients fetch version info,
//! delta patches, and full snapshots, all signed with Ed25519.
//!
//! # Configuration (environment variables)
//!
//! - `LISTEN_ADDR` - Address to bind to (default: `0.0.0.0:8080`)
//! - `STORAGE_DIR` - Directory for delta/full storage (default: `./data`)
//! - `KEY_FILE` - Path to Ed25519 signing key (default: `./data/signing.key`)
//! - `ADMIN_TOKEN` - Bearer token required for `POST /admin/publish` (optional)

mod routes;
mod signing;
mod storage;

use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use axum::Router;
use axum::http::header;
use axum::routing::{get, post};
use tower_http::cors::{AllowHeaders, AllowMethods, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use routes::AppState;
use signing::load_or_create_keypair;
use storage::SignatureStorage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (respects RUST_LOG env var).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    // Read configuration from environment.
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("LISTEN_ADDR must be a valid socket address")?;

    let storage_dir = PathBuf::from(std::env::var("STORAGE_DIR").unwrap_or_else(|_| "./data".to_string()));

    let key_file = PathBuf::from(
        std::env::var("KEY_FILE").unwrap_or_else(|_| storage_dir.join("signing.key").to_string_lossy().to_string()),
    );

    let admin_token = std::env::var("ADMIN_TOKEN").map_err(|_| {
        anyhow::anyhow!(
            "ADMIN_TOKEN environment variable must be set. \
             The /admin/publish endpoint requires authentication to prevent \
             unauthorized signature updates. Set ADMIN_TOKEN to a strong secret."
        )
    })?;

    // Load or generate Ed25519 signing keypair.
    let (signing_key, verifying_key) = load_or_create_keypair(&key_file)?;

    info!(
        public_key = %hex_encode(verifying_key.as_bytes()),
        "update server public key (distribute to clients)"
    );

    // Initialize storage.
    let storage = SignatureStorage::new(storage_dir)?;

    // Build shared state.
    let state = AppState {
        storage: Arc::new(storage),
        signing_key: Arc::new(signing_key),
        admin_token,
    };

    // Build the router.
    let app = Router::new()
        .route("/version", get(routes::get_version))
        .route("/delta/{range}", get(routes::get_delta))
        .route("/full", get(routes::get_full))
        .route("/admin/publish", post(routes::publish))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_methods(AllowMethods::list([axum::http::Method::GET, axum::http::Method::POST]))
                .allow_headers(AllowHeaders::list([header::CONTENT_TYPE, header::AUTHORIZATION])),
        )
        .with_state(state);

    info!(%listen_addr, "starting prx-sd update server");

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Hex-encode bytes for logging.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
