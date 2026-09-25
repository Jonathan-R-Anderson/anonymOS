//! Registry that discovers, loads, and dispatches to all installed plugins.

use crate::host::PluginHost;
use crate::{PluginFinding, PluginInfo};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Manages every loaded plugin and dispatches scan requests to them.
pub struct PluginRegistry {
    plugins_dir: PathBuf,
    plugins: Vec<PluginHost>,
}

impl PluginRegistry {
    /// Create an empty registry rooted at `plugins_dir`.
    ///
    /// Call [`load_all`](Self::load_all) afterwards to discover and compile
    /// every plugin found in that directory tree.
    pub fn new(plugins_dir: &Path) -> Result<Self> {
        if !plugins_dir.is_dir() {
            std::fs::create_dir_all(plugins_dir)
                .with_context(|| format!("failed to create plugins directory: {}", plugins_dir.display()))?;
        }
        Ok(Self {
            plugins_dir: plugins_dir.to_path_buf(),
            plugins: Vec::new(),
        })
    }

    /// Walk the plugins directory, loading every sub-directory that contains a
    /// `plugin.json`.  Returns the number of successfully loaded plugins.
    pub fn load_all(&mut self) -> Result<usize> {
        let mut loaded = 0usize;

        for entry in WalkDir::new(&self.plugins_dir)
            .min_depth(1)
            .max_depth(2)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if entry.file_name() == "plugin.json" {
                let Some(plugin_dir) = entry.path().parent() else {
                    continue;
                };

                match PluginHost::load(plugin_dir) {
                    Ok(host) => {
                        if !host.manifest().matches_platform() {
                            tracing::info!(
                                plugin = %host.info().name,
                                "skipping plugin (platform mismatch)"
                            );
                            continue;
                        }
                        tracing::info!(
                            plugin = %host.info().name,
                            version = %host.info().version,
                            "registered plugin"
                        );
                        self.plugins.push(host);
                        loaded += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            dir = %plugin_dir.display(),
                            "failed to load plugin: {e:#}"
                        );
                    }
                }
            }
        }

        tracing::info!(count = loaded, "plugin loading complete");
        Ok(loaded)
    }

    /// Run every applicable plugin against the given file and collect
    /// findings.  Plugins whose manifest does not match `file_type` are
    /// silently skipped.
    pub fn scan_with_plugins(&self, file_data: &[u8], file_path: &str, file_type: &str) -> Vec<PluginFinding> {
        let mut all_findings = Vec::new();

        for plugin in &self.plugins {
            if !plugin.manifest().matches_file_type(file_type) {
                continue;
            }

            match plugin.scan(file_data, file_path, file_type) {
                Ok(findings) => {
                    if !findings.is_empty() {
                        tracing::info!(
                            plugin = %plugin.info().name,
                            findings = findings.len(),
                            "plugin reported findings"
                        );
                    }
                    all_findings.extend(findings);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = %plugin.info().name,
                        "plugin scan error: {e:#}"
                    );
                }
            }
        }

        all_findings
    }

    /// List metadata for every loaded plugin.
    pub fn list(&self) -> Vec<&PluginInfo> {
        self.plugins.iter().map(PluginHost::info).collect()
    }

    /// Drop all plugins and re-load from disk (hot reload).
    pub fn reload(&mut self) -> Result<usize> {
        tracing::info!("reloading plugins");
        self.plugins.clear();
        self.load_all()
    }

    /// Number of currently loaded plugins.
    pub const fn count(&self) -> usize {
        self.plugins.len()
    }
}
