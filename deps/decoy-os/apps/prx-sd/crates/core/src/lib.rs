// This crate uses unsafe for libc::kill in rootkit detection.
// All unsafe blocks have SAFETY comments.
#![allow(unsafe_code)]

//! `prx-sd-core` -- Scan coordination engine for the prx-sd antivirus toolkit.
//!
//! This crate glues together signature matching, YARA rules, format parsing,
//! and heuristic analysis into a single, thread-safe [`ScanEngine`] that
//! exposes file, directory, and in-memory scanning.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use prx_sd_core::{ScanConfig, ScanEngine};
//!
//! let config = ScanConfig::default();
//! let engine = ScanEngine::new(config).expect("engine init");
//! let results = engine.scan_directory(std::path::Path::new("/tmp/suspect"));
//! for r in &results {
//!     if r.is_threat() {
//!         println!("{}: {} ({:?})", r.path.display(), r.threat_level, r.detection_type);
//!     }
//! }
//! ```

pub mod config;
pub mod engine;
pub mod magic;
#[cfg(target_os = "linux")]
pub mod memscan;
pub mod result;
#[cfg(target_os = "linux")]
pub mod rootkit;
pub mod scanner;
pub mod virustotal;

// Re-export the primary public API at the crate root for convenience.
pub use config::ScanConfig;
pub use engine::ScanEngine;
pub use magic::{FileType, detect_magic};
pub use result::{DetectionType, ScanResult, ThreatLevel};
