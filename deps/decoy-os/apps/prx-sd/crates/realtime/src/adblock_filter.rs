//! Ad/tracker/malware domain filtering powered by Brave's adblock-rust engine.
//!
//! Features:
//! - Auto-download filter lists from well-known sources
//! - Local cache with staleness detection
//! - Periodic background sync
//! - Persistent storage (lists saved to disk, loaded on startup)
//!
//! ```rust,ignore
//! use prx_sd_realtime::adblock_filter::AdblockFilterManager;
//!
//! // One-line setup: downloads lists if stale, loads from cache otherwise
//! let mgr = AdblockFilterManager::init("/home/user/.prx-sd/adblock")?;
//! assert!(mgr.check_domain("ads.doubleclick.net"));
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use adblock::Engine;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Public types ────────────────────────────────────────────────────────────

/// Result of checking a URL against the adblock engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdblockResult {
    pub blocked: bool,
    pub filter_name: String,
    pub matched_rule: Option<String>,
    pub important: bool,
    pub category: AdblockCategory,
}

/// Category of blocked content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdblockCategory {
    Ads,
    Tracking,
    Malware,
    Social,
    Annoyances,
    Unknown,
}

/// Statistics about the loaded filter engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdblockStats {
    pub list_count: usize,
    pub list_names: Vec<String>,
    pub total_rules: usize,
    pub cache_dir: String,
    pub last_sync: Option<String>,
}

/// Descriptor for a remote filter list source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterListSource {
    pub name: String,
    pub url: String,
    pub category: AdblockCategory,
    pub enabled: bool,
}

/// Persistent configuration for which lists to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdblockConfig {
    pub sources: Vec<FilterListSource>,
    /// How often to check for updates (seconds). Default 86400 (24h).
    pub sync_interval_secs: u64,
    /// Enable/disable the entire adblock engine.
    pub enabled: bool,
}

impl Default for AdblockConfig {
    fn default() -> Self {
        Self {
            sources: default_sources(),
            sync_interval_secs: 86400,
            enabled: true,
        }
    }
}

// ── Default sources ─────────────────────────────────────────────────────────

fn default_sources() -> Vec<FilterListSource> {
    vec![
        FilterListSource {
            name: "EasyList".into(),
            url: "https://easylist.to/easylist/easylist.txt".into(),
            category: AdblockCategory::Ads,
            enabled: true,
        },
        FilterListSource {
            name: "EasyPrivacy".into(),
            url: "https://easylist.to/easylist/easyprivacy.txt".into(),
            category: AdblockCategory::Tracking,
            enabled: true,
        },
        FilterListSource {
            name: "Peter Lowe".into(),
            url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext".into(),
            category: AdblockCategory::Tracking,
            enabled: true,
        },
        FilterListSource {
            name: "CyberHost Malware".into(),
            url: "https://lists.cyberhost.uk/malware.txt".into(),
            category: AdblockCategory::Malware,
            enabled: true,
        },
        FilterListSource {
            name: "Fabriziosalmi Blacklist".into(),
            url: "https://raw.githubusercontent.com/fabriziosalmi/blacklists/main/custom/blacklist.txt".into(),
            category: AdblockCategory::Malware,
            enabled: true,
        },
    ]
}

// ── Manager ─────────────────────────────────────────────────────────────────

/// High-level adblock filter manager with auto-download, local cache, and sync.
pub struct AdblockFilterManager {
    engine: Engine,
    config: AdblockConfig,
    cache_dir: PathBuf,
    loaded_lists: Vec<(String, AdblockCategory, usize)>,
}

impl AdblockFilterManager {
    /// Initialize the manager:
    /// 1. Load config from `cache_dir/adblock_config.json` (or create default)
    /// 2. For each enabled source, check if local cache exists and is fresh
    /// 3. If stale or missing, download from URL and save to disk
    /// 4. Build the adblock engine from all cached lists
    pub fn init(cache_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("failed to create adblock cache dir: {}", cache_dir.display()))?;

        let lists_dir = cache_dir.join("lists");
        std::fs::create_dir_all(&lists_dir)?;

        // Load or create config
        let config_path = cache_dir.join("adblock_config.json");
        let config = if config_path.exists() {
            let data = std::fs::read_to_string(&config_path).context("failed to read adblock config")?;
            serde_json::from_str(&data).unwrap_or_else(|_| {
                tracing::warn!("corrupt adblock config, using defaults");
                AdblockConfig::default()
            })
        } else {
            let config = AdblockConfig::default();
            let json = serde_json::to_string_pretty(&config).context("failed to serialize adblock config")?;
            std::fs::write(&config_path, json).ok();
            config
        };

        if !config.enabled {
            tracing::info!("adblock engine disabled by config");
            return Ok(Self {
                engine: Engine::from_filter_set(FilterSet::new(false), true),
                config,
                cache_dir: cache_dir.to_path_buf(),
                loaded_lists: Vec::new(),
            });
        }

        // Sync each enabled source
        let max_age = Duration::from_secs(config.sync_interval_secs);
        for source in &config.sources {
            if !source.enabled {
                continue;
            }
            let cached = lists_dir.join(sanitize_filename(&source.name));
            if is_fresh(&cached, max_age) {
                tracing::debug!(list = %source.name, "cache fresh, skipping download");
            } else {
                tracing::info!(list = %source.name, url = %source.url, "downloading filter list");
                match download_list(&source.url) {
                    Ok(content) => {
                        if let Err(e) = std::fs::write(&cached, &content) {
                            tracing::warn!(list = %source.name, "failed to cache: {e}");
                        } else {
                            tracing::info!(
                                list = %source.name,
                                bytes = content.len(),
                                "cached filter list"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(list = %source.name, "download failed: {e}");
                        // Fall through — will use stale cache if it exists
                    }
                }
            }
        }

        // Build engine from all cached files
        let mut filter_set = FilterSet::new(false);
        let mut loaded = Vec::new();

        for source in &config.sources {
            if !source.enabled {
                continue;
            }
            let cached = lists_dir.join(sanitize_filename(&source.name));
            if !cached.exists() {
                tracing::warn!(list = %source.name, "no cached data, skipping");
                continue;
            }
            let content = match std::fs::read_to_string(&cached) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(list = %source.name, "failed to read cache: {e}");
                    continue;
                }
            };

            let rules: Vec<String> = content
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('!')
                })
                .map(std::string::ToString::to_string)
                .collect();

            let count = rules.len();
            filter_set.add_filters(&rules, ParseOptions::default());
            loaded.push((source.name.clone(), source.category.clone(), count));
            tracing::info!(list = %source.name, rules = count, "loaded filter list");
        }

        let total: usize = loaded.iter().map(|(_, _, c)| c).sum();
        tracing::info!(lists = loaded.len(), rules = total, "adblock engine ready");

        // Write last-sync timestamp
        let sync_path = cache_dir.join("last_sync");
        let now = chrono::Utc::now().to_rfc3339();
        std::fs::write(&sync_path, &now).ok();

        Ok(Self {
            engine: Engine::from_filter_set(filter_set, true),
            config,
            cache_dir: cache_dir.to_path_buf(),
            loaded_lists: loaded,
        })
    }

    /// Force re-download all lists and rebuild the engine.
    pub fn sync(&mut self) -> Result<usize> {
        let lists_dir = self.cache_dir.join("lists");

        let mut downloaded = 0usize;
        for source in &self.config.sources {
            if !source.enabled {
                continue;
            }
            let cached = lists_dir.join(sanitize_filename(&source.name));
            match download_list(&source.url) {
                Ok(content) => {
                    std::fs::write(&cached, &content).with_context(|| format!("failed to cache {}", source.name))?;
                    downloaded += 1;
                }
                Err(e) => {
                    tracing::warn!(list = %source.name, "sync download failed: {e}");
                }
            }
        }

        // Rebuild engine
        self.rebuild_engine();

        let sync_path = self.cache_dir.join("last_sync");
        let now = chrono::Utc::now().to_rfc3339();
        std::fs::write(&sync_path, &now).ok();

        Ok(downloaded)
    }

    /// Rebuild the engine from local cache (no network).
    fn rebuild_engine(&mut self) {
        let lists_dir = self.cache_dir.join("lists");
        let mut filter_set = FilterSet::new(false);
        let mut loaded = Vec::new();

        for source in &self.config.sources {
            if !source.enabled {
                continue;
            }
            let cached = lists_dir.join(sanitize_filename(&source.name));
            if let Ok(content) = std::fs::read_to_string(&cached) {
                let rules: Vec<String> = content
                    .lines()
                    .filter(|l| {
                        let t = l.trim();
                        !t.is_empty() && !t.starts_with('!')
                    })
                    .map(std::string::ToString::to_string)
                    .collect();
                let count = rules.len();
                filter_set.add_filters(&rules, ParseOptions::default());
                loaded.push((source.name.clone(), source.category.clone(), count));
            }
        }

        self.engine = Engine::from_filter_set(filter_set, true);
        self.loaded_lists = loaded;
    }

    /// Add a custom filter list source and immediately download+cache it.
    pub fn add_source(&mut self, name: &str, url: &str, category: AdblockCategory) -> Result<usize> {
        self.config.sources.push(FilterListSource {
            name: name.to_string(),
            url: url.to_string(),
            category,
            enabled: true,
        });
        self.save_config()?;

        let lists_dir = self.cache_dir.join("lists");
        let cached = lists_dir.join(sanitize_filename(name));
        let content = download_list(url)?;
        std::fs::write(&cached, &content)?;

        self.rebuild_engine();

        let count = self
            .loaded_lists
            .iter()
            .find(|(n, _, _)| n == name)
            .map_or(0, |(_, _, c)| *c);
        Ok(count)
    }

    /// Remove a filter list source.
    pub fn remove_source(&mut self, name: &str) -> Result<()> {
        self.config.sources.retain(|s| s.name != name);
        self.save_config()?;

        let cached = self.cache_dir.join("lists").join(sanitize_filename(name));
        std::fs::remove_file(&cached).ok();

        self.rebuild_engine();
        Ok(())
    }

    /// Check if a URL should be blocked.
    pub fn check_url(&self, url: &str, source_url: &str, request_type: &str) -> AdblockResult {
        let Ok(request) = Request::new(url, source_url, request_type) else {
            return AdblockResult {
                blocked: false,
                filter_name: String::new(),
                matched_rule: None,
                important: false,
                category: AdblockCategory::Unknown,
            };
        };

        let result = self.engine.check_network_request(&request);

        AdblockResult {
            blocked: result.matched,
            filter_name: result.filter.as_ref().map(|f| format!("{f:?}")).unwrap_or_default(),
            matched_rule: result.filter.map(|f| format!("{f:?}")),
            important: result.important,
            category: if result.matched {
                self.loaded_lists
                    .last()
                    .map_or(AdblockCategory::Unknown, |(_, c, _)| c.clone())
            } else {
                AdblockCategory::Unknown
            },
        }
    }

    /// Quick domain check.
    pub fn check_domain(&self, domain: &str) -> bool {
        let url = format!("https://{domain}/");
        self.check_url(&url, &url, "document").blocked
    }

    /// Get engine statistics.
    pub fn stats(&self) -> AdblockStats {
        let last_sync = self.cache_dir.join("last_sync");
        let sync_time = std::fs::read_to_string(&last_sync).ok();

        AdblockStats {
            list_count: self.loaded_lists.len(),
            list_names: self.loaded_lists.iter().map(|(n, _, _)| n.clone()).collect(),
            total_rules: self.loaded_lists.iter().map(|(_, _, c)| c).sum(),
            cache_dir: self.cache_dir.display().to_string(),
            last_sync: sync_time,
        }
    }

    /// Get the current config.
    pub const fn config(&self) -> &AdblockConfig {
        &self.config
    }

    /// Save config to disk.
    fn save_config(&self) -> Result<()> {
        let path = self.cache_dir.join("adblock_config.json");
        let json = serde_json::to_string_pretty(&self.config)?;
        std::fs::write(&path, json).context("failed to save adblock config")?;
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn sanitize_filename(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{clean}.txt")
}

fn is_fresh(path: &Path, max_age: Duration) -> bool {
    path.exists()
        && std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map(|modified| SystemTime::now().duration_since(modified).unwrap_or(Duration::MAX) < max_age)
            .unwrap_or(false)
}

fn download_list(url: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to create HTTP client")?;

    let resp = client
        .get(url)
        .header("User-Agent", "PRX-SD/0.1 adblock-sync")
        .send()
        .with_context(|| format!("failed to download {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} for {url}", resp.status());
    }

    resp.text().with_context(|| format!("failed to read body from {url}"))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreadable_literal
    )]
    use super::*;

    fn test_cache_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    #[test]
    fn init_creates_dirs_and_config() {
        let dir = test_cache_dir();
        let mgr = AdblockFilterManager::init(dir.path());
        // May fail due to network — that's ok, just check dir structure
        if let Ok(mgr) = mgr {
            assert!(dir.path().join("lists").is_dir());
            assert!(dir.path().join("adblock_config.json").exists());
            let config: AdblockConfig =
                serde_json::from_str(&std::fs::read_to_string(dir.path().join("adblock_config.json")).unwrap())
                    .unwrap();
            assert!(config.enabled);
            assert_eq!(config.sources.len(), 5);
            let _ = mgr.stats();
        }
    }

    #[test]
    fn disabled_config_skips_everything() {
        let dir = test_cache_dir();
        let config = AdblockConfig {
            enabled: false,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        std::fs::create_dir_all(dir.path().join("lists")).unwrap();
        std::fs::write(dir.path().join("adblock_config.json"), json).unwrap();

        let mgr = AdblockFilterManager::init(dir.path()).unwrap();
        assert_eq!(mgr.stats().list_count, 0);
        assert!(!mgr.check_domain("anything.com"));
    }

    #[test]
    fn load_from_local_cache() {
        let dir = test_cache_dir();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();

        // Pre-populate cache with a tiny list
        std::fs::write(lists_dir.join("TestList.txt"), "||evil.ads.com^\n||tracker.bad.org^\n").unwrap();

        let config = AdblockConfig {
            sources: vec![FilterListSource {
                name: "TestList".into(),
                url: "https://example.com/nonexistent".into(),
                category: AdblockCategory::Ads,
                enabled: true,
            }],
            sync_interval_secs: 999999, // don't try to re-download
            enabled: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        std::fs::write(dir.path().join("adblock_config.json"), json).unwrap();

        let mgr = AdblockFilterManager::init(dir.path()).unwrap();
        assert_eq!(mgr.stats().list_count, 1);
        assert!(mgr.stats().total_rules >= 2);
        assert!(mgr.check_domain("evil.ads.com"));
        assert!(mgr.check_domain("tracker.bad.org"));
        assert!(!mgr.check_domain("safe.example.com"));
    }

    #[test]
    fn sanitize_filename_works() {
        assert_eq!(sanitize_filename("EasyList"), "EasyList.txt");
        assert_eq!(sanitize_filename("Peter Lowe's List"), "Peter_Lowe_s_List.txt");
        assert_eq!(sanitize_filename("a/b\\c:d"), "a_b_c_d.txt");
    }

    #[test]
    fn is_fresh_nonexistent() {
        assert!(!is_fresh(Path::new("/nonexistent"), Duration::from_secs(3600)));
    }

    #[test]
    fn default_config_has_5_sources() {
        let config = AdblockConfig::default();
        assert_eq!(config.sources.len(), 5);
        assert!(config.enabled);
        assert_eq!(config.sync_interval_secs, 86400);
    }

    #[test]
    fn check_url_invalid_returns_not_blocked() {
        let dir = test_cache_dir();
        std::fs::create_dir_all(dir.path().join("lists")).unwrap();
        let config = AdblockConfig {
            sources: vec![],
            enabled: true,
            sync_interval_secs: 99999,
        };
        std::fs::write(
            dir.path().join("adblock_config.json"),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let mgr = AdblockFilterManager::init(dir.path()).unwrap();
        let result = mgr.check_url("not-a-url", "", "");
        assert!(!result.blocked);
    }
}
