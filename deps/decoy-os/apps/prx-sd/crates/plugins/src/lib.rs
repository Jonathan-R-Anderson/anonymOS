//! WASM plugin system for the prx-sd antivirus engine.
//!
//! Allows users to write custom detection/remediation plugins in any language
//! that compiles to WASM (Rust, Go, C, `AssemblyScript`, etc.).
//!
//! When compiled without the `wasm-runtime` feature the host and registry
//! are still available but every scan returns an empty result set and a
//! warning is logged.

pub mod host;
pub mod manifest;
pub mod registry;

pub use host::PluginHost;
pub use manifest::PluginManifest;
pub use registry::PluginRegistry;

use serde::{Deserialize, Serialize};

/// A single finding reported by a plugin during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    /// Name of the plugin that produced this finding.
    pub plugin_name: String,
    /// Threat identifier, e.g. `"Trojan.Marker"`.
    pub threat_name: String,
    /// Threat score in the range 0-100.
    pub score: u32,
    /// Free-form detail string.
    pub detail: String,
}

/// Metadata about a loaded plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    /// Target platforms: `"linux"`, `"macos"`, `"windows"`, or `"all"`.
    pub platforms: Vec<String>,
    /// File types this plugin wants to inspect: `"pe"`, `"elf"`, `"all"`, etc.
    pub file_types: Vec<String>,
}
