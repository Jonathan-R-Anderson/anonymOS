//! Plugin manifest (`plugin.json`) that lives alongside a `.wasm` file.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Describes a plugin and its sandbox constraints.
///
/// Every plugin directory must contain a `plugin.json` that deserialises to
/// this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    /// File name of the compiled WASM module (e.g. `"scanner.wasm"`).
    pub wasm_file: String,
    /// Target platforms: `"linux"`, `"macos"`, `"windows"`, `"all"`.
    pub platforms: Vec<String>,
    /// File types the plugin cares about: `"pe"`, `"elf"`, `"all"`, etc.
    pub file_types: Vec<String>,
    /// Minimum engine version required to load this plugin.
    pub min_engine_version: String,
    /// Sandbox / resource permissions.
    #[serde(default)]
    pub permissions: PluginPermissions,
}

/// Resource and capability limits enforced on the WASM sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPermissions {
    /// Whether the plugin may access the network.
    pub network: bool,
    /// Whether the plugin may access the host filesystem via WASI.
    pub filesystem: bool,
    /// Maximum linear memory the plugin may allocate (MiB).
    pub max_memory_mb: u32,
    /// Maximum wall-clock execution time (ms) before the plugin is killed.
    pub max_exec_ms: u64,
}

impl Default for PluginPermissions {
    fn default() -> Self {
        Self {
            network: false,
            filesystem: false,
            max_memory_mb: 64,
            max_exec_ms: 5000,
        }
    }
}

impl PluginManifest {
    /// Load a manifest from a `plugin.json` file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("failed to read manifest at {}", path.display()))?;
        let manifest: Self = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse manifest at {}", path.display()))?;
        Ok(manifest)
    }

    /// Returns `true` when the plugin declares support for the current OS
    /// (or declares `"all"`).
    pub fn matches_platform(&self) -> bool {
        let current = current_platform();
        self.platforms
            .iter()
            .any(|p| p.eq_ignore_ascii_case("all") || p.eq_ignore_ascii_case(current))
    }

    /// Returns `true` when the plugin declares interest in `file_type`
    /// (or declares `"all"`).
    pub fn matches_file_type(&self, file_type: &str) -> bool {
        self.file_types
            .iter()
            .any(|ft| ft.eq_ignore_ascii_case("all") || ft.eq_ignore_ascii_case(file_type))
    }
}

const fn current_platform() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> PluginManifest {
        PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            author: "tester".into(),
            description: "unit test".into(),
            wasm_file: "test.wasm".into(),
            platforms: vec!["all".into()],
            file_types: vec!["pe".into(), "elf".into()],
            min_engine_version: "0.1.0".into(),
            permissions: PluginPermissions::default(),
        }
    }

    #[test]
    fn matches_platform_all() {
        let m = sample_manifest();
        assert!(m.matches_platform());
    }

    #[test]
    fn matches_file_type_specific() {
        let m = sample_manifest();
        assert!(m.matches_file_type("pe"));
        assert!(m.matches_file_type("ELF"));
        assert!(!m.matches_file_type("macho"));
    }

    #[test]
    fn default_permissions() {
        let p = PluginPermissions::default();
        assert!(!p.network);
        assert!(!p.filesystem);
        assert_eq!(p.max_memory_mb, 64);
        assert_eq!(p.max_exec_ms, 5000);
    }
}
