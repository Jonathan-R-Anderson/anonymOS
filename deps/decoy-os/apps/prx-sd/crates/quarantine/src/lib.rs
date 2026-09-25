//! Quarantine vault for the prx-sd antivirus engine.
//!
//! Provides encrypted storage for malicious files with metadata tracking,
//! restoration capabilities, and batch management operations.
//!
//! Files are encrypted with AES-256-GCM using a per-vault key, each with
//! a unique random nonce. Metadata (original path, threat name, timestamp,
//! SHA-256 hash) is stored as JSON sidecar files.

pub mod restore;
pub mod vault;

pub use restore::{batch_delete, batch_restore, cleanup_expired};
pub use vault::{Quarantine, QuarantineId, QuarantineMeta, QuarantineStats};
