// This crate uses unsafe for Linux syscalls (fanotify, libc). All unsafe blocks
// have SAFETY comments. The workspace-level `unsafe_code = "deny"` is relaxed
// here; `undocumented_unsafe_blocks = "deny"` still enforces documentation.
#![allow(unsafe_code)]

//! Real-time file system monitoring for the prx-sd antivirus engine.
//!
//! This crate provides a unified [`FileSystemMonitor`] trait with
//! platform-specific implementations:
//!
//! - **Linux**: `FanotifyMonitor` — kernel-level monitoring with permission
//!   (blocking) event support via fanotify.
//! - **macOS**: `MacOSMonitor` — FSEvents-based monitoring via the `notify` crate
//!   with macOS-specific event conversion and rename handling.
//! - **Windows**: `WindowsMonitor` — `ReadDirectoryChangesW`-based monitoring via
//!   the `notify` crate. Also includes [`RegistryMonitor`] for watching
//!   persistence-related registry keys.
//! - **All platforms**: `NotifyMonitor` — cross-platform fallback using the
//!   `notify` crate (non-blocking only).
//!
//! Use [`create_monitor`] to obtain the best available monitor for the
//! current platform.

pub mod adblock_filter;
pub mod dns_filter;
pub mod dns_proxy;
pub mod event;
pub mod ioc_filter;
pub mod monitor;
pub mod notify_fallback;
pub mod protected_dirs;
pub mod ransomware;
pub mod registry_monitor;
pub mod url_scanner;

#[cfg(target_os = "linux")]
pub mod behavior_monitor;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

// ── Re-exports ──────────────────────────────────────────────────────────────

pub use adblock_filter::{AdblockCategory, AdblockConfig, AdblockFilterManager, AdblockResult, AdblockStats};
pub use dns_filter::{DnsFilter, DnsVerdict};
pub use dns_proxy::{DnsProxy, DnsProxyConfig};
pub use event::{FileEvent, FileEventAction};
pub use ioc_filter::{IocFilter, IocStats, IocVerdict};
pub use monitor::FileSystemMonitor;
pub use notify_fallback::NotifyMonitor;
pub use protected_dirs::{ProtectedDirsConfig, ProtectedDirsEnforcer, ProtectionVerdict};
pub use ransomware::{RansomwareConfig, RansomwareDetector, RansomwareVerdict};
pub use registry_monitor::{RegistryEvent, RegistryEventType, RegistryMonitor};
pub use url_scanner::{MaliciousUrl, UrlScanResult, UrlScanner};

#[cfg(target_os = "linux")]
pub use behavior_monitor::{BehaviorConfig, BehaviorMonitor, BehaviorVerdict, ProcessBehaviorScore};

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub use ebpf::{EbpfMetrics, EbpfPipeline, EbpfRuntime, PipelineOutput, RuntimeEvent, RuntimeEventKind};

#[cfg(target_os = "linux")]
pub use linux::FanotifyMonitor;

#[cfg(target_os = "windows")]
pub use windows::WindowsMonitor;

#[cfg(target_os = "macos")]
pub use macos::MacOSMonitor;

// ── Factory ─────────────────────────────────────────────────────────────────

/// Create the best available file system monitor for the current platform.
///
/// On Linux this returns a [`FanotifyMonitor`] which supports blocking
/// (permission) events. On other platforms it returns the cross-platform
/// [`NotifyMonitor`] fallback.
pub fn create_monitor() -> Box<dyn FileSystemMonitor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(FanotifyMonitor::default())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsMonitor::default())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSMonitor::default())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(NotifyMonitor::default())
    }
}
