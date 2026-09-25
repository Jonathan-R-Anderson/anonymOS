use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use prx_sd_heuristic::HeuristicEngine;
use prx_sd_signatures::{SignatureDatabase, YaraEngine};

use crate::config::ScanConfig;
use crate::virustotal::VtClient;

/// Central scan engine that owns shared handles to every detection sub-system.
///
/// Instances are cheap to clone (all inner state is `Arc`-wrapped) and safe to
/// share across threads.
#[derive(Clone)]
pub struct ScanEngine {
    /// Hash-based signature database (SHA-256 / MD5 lookups).
    pub signatures: Arc<SignatureDatabase>,
    /// Compiled YARA rule-set.
    pub yara: Arc<YaraEngine>,
    /// Heuristic / scoring engine.
    pub heuristic: Arc<HeuristicEngine>,
    /// `VirusTotal` cloud lookup client (enabled when API key is configured).
    pub vt_client: Option<Arc<VtClient>>,
    /// Active configuration snapshot.
    pub config: ScanConfig,
}

impl ScanEngine {
    /// Initialise the engine, loading signatures and YARA rules from the paths
    /// specified in `config`.
    ///
    /// Returns an error if any sub-engine fails to initialise (e.g. corrupt
    /// signature database, invalid YARA rules).
    pub fn new(config: ScanConfig) -> Result<Self> {
        info!(
            signatures_dir = %config.signatures_dir.display(),
            yara_rules_dir = %config.yara_rules_dir.display(),
            "initialising scan engine"
        );

        let signatures =
            SignatureDatabase::open(&config.signatures_dir).context("failed to open signature database")?;

        let yara = YaraEngine::load_rules(&config.yara_rules_dir).context("failed to initialise YARA engine")?;

        let heuristic = HeuristicEngine::new();

        let sig_arc = Arc::new(signatures);
        let vt_client = VtClient::new(&config.vt_api_key, Arc::clone(&sig_arc)).map(Arc::new);

        if vt_client.is_some() {
            info!("VirusTotal cloud lookup enabled");
        }

        Ok(Self {
            signatures: sig_arc,
            yara: Arc::new(yara),
            heuristic: Arc::new(heuristic),
            vt_client,
            config,
        })
    }

    /// Hot-reload signatures and YARA rules from disk without restarting.
    ///
    /// This acquires new `Arc` instances so in-flight scans continue using the
    /// previous data until they finish.
    pub fn reload_signatures(&mut self) -> Result<()> {
        info!("reloading signatures and YARA rules");

        let signatures =
            SignatureDatabase::open(&self.config.signatures_dir).context("failed to reload signature database")?;

        let yara = YaraEngine::load_rules(&self.config.yara_rules_dir).context("failed to reload YARA engine")?;

        let sig_arc = Arc::new(signatures);
        self.vt_client = VtClient::new(&self.config.vt_api_key, Arc::clone(&sig_arc)).map(Arc::new);
        self.signatures = sig_arc;
        self.yara = Arc::new(yara);

        info!("signature reload complete");
        Ok(())
    }

    /// Returns a reference to the current configuration.
    pub const fn config(&self) -> &ScanConfig {
        &self.config
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;

    /// Helper to create a valid config backed by temp directories.
    fn temp_config() -> (tempfile::TempDir, ScanConfig) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let sig_dir = dir.path().join("signatures");
        let yara_dir = dir.path().join("yara");
        std::fs::create_dir_all(&sig_dir).expect("failed to create sig dir");
        std::fs::create_dir_all(&yara_dir).expect("failed to create yara dir");

        let config = ScanConfig::default()
            .with_signatures_dir(sig_dir)
            .with_yara_rules_dir(yara_dir)
            .with_quarantine_dir(dir.path().join("quarantine"));
        (dir, config)
    }

    #[test]
    fn new_succeeds_with_valid_config() {
        let (_dir, config) = temp_config();
        let engine = ScanEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn new_fails_with_nonexistent_yara_dir() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let sig_dir = dir.path().join("signatures");
        std::fs::create_dir_all(&sig_dir).expect("failed to create sig dir");
        // Deliberately do NOT create the yara dir.
        let config = ScanConfig::default()
            .with_signatures_dir(sig_dir)
            .with_yara_rules_dir(dir.path().join("no_such_yara_dir"))
            .with_quarantine_dir(dir.path().join("quarantine"));
        let result = ScanEngine::new(config);
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.err().expect("expected an error"));
        assert!(err_msg.contains("YARA"), "expected YARA error, got: {err_msg}");
    }

    #[test]
    fn reload_signatures_succeeds() {
        let (_dir, config) = temp_config();
        let mut engine = ScanEngine::new(config).expect("engine init");
        let result = engine.reload_signatures();
        assert!(result.is_ok());
    }

    #[test]
    fn config_returns_correct_reference() {
        let (_dir, config) = temp_config();
        let max_size = config.max_file_size;
        let threads = config.scan_threads;
        let engine = ScanEngine::new(config).expect("engine init");

        assert_eq!(engine.config().max_file_size, max_size);
        assert_eq!(engine.config().scan_threads, threads);
    }

    #[test]
    fn engine_is_clone() {
        let (_dir, config) = temp_config();
        let engine = ScanEngine::new(config).expect("engine init");
        let cloned = engine.clone();
        assert_eq!(cloned.config().max_file_size, engine.config().max_file_size);
    }

    #[test]
    fn vt_client_is_none_without_api_key() {
        let (_dir, config) = temp_config();
        let engine = ScanEngine::new(config).expect("engine init");
        assert!(engine.vt_client.is_none());
    }
}
