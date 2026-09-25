//! Configuration for community threat intelligence sharing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default community API server URL.
const DEFAULT_COMMUNITY_URL: &str = "https://community.openprx.dev";

/// Configuration for community threat intelligence sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityConfig {
    /// Whether community sharing is enabled.
    pub enabled: bool,
    /// Base URL of the community API server.
    pub server_url: String,
    /// API key obtained during enrollment.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Machine ID assigned by the server during enrollment.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Maximum number of signals to buffer before flushing.
    pub batch_size: usize,
    /// How often (seconds) to flush buffered signals.
    pub flush_interval_secs: u64,
    /// How often (seconds) to check for blocklist updates.
    pub sync_interval_secs: u64,
}

impl Default for CommunityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: DEFAULT_COMMUNITY_URL.to_string(),
            api_key: None,
            machine_id: None,
            batch_size: 50,
            flush_interval_secs: 30,
            sync_interval_secs: 300,
        }
    }
}

impl CommunityConfig {
    /// Canonical path to the community config file inside the data directory.
    pub fn config_path(data_dir: &Path) -> PathBuf {
        data_dir.join("community.json")
    }

    /// Load community config from the data directory.
    ///
    /// Returns the default (disabled) config if the file does not exist.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = Self::config_path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let cfg: Self = serde_json::from_str(&data).with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(cfg)
    }

    /// Persist the config to the data directory.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = Self::config_path(data_dir);
        let json = serde_json::to_string_pretty(self).context("failed to serialize community config")?;
        std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    /// Returns `true` when the config has valid enrollment credentials.
    pub const fn is_enrolled(&self) -> bool {
        self.machine_id.is_some() && self.api_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled() {
        let cfg = CommunityConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.is_enrolled());
        assert_eq!(cfg.batch_size, 50);
        assert_eq!(cfg.flush_interval_secs, 30);
        assert_eq!(cfg.sync_interval_secs, 300);
    }

    #[test]
    fn load_returns_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CommunityConfig::load(dir.path()).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CommunityConfig {
            enabled: true,
            machine_id: Some("m-123".to_string()),
            api_key: Some("key-abc".to_string()),
            ..Default::default()
        };
        cfg.save(dir.path()).unwrap();

        let loaded = CommunityConfig::load(dir.path()).unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.machine_id.as_deref(), Some("m-123"));
        assert_eq!(loaded.api_key.as_deref(), Some("key-abc"));
        assert!(loaded.is_enrolled());
    }
}
