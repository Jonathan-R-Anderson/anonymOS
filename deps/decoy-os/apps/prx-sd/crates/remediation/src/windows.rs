//! Windows-specific remediation stubs.
//!
//! These functions provide the same interface as the Linux and macOS modules
//! but return errors since Windows remediation is not yet implemented.
//! This allows the crate to compile on all platforms.

use std::path::Path;

use anyhow::Result;

use crate::PersistenceType;

/// Kill a process by PID (not yet implemented on Windows).
pub fn kill_process(_pid: u32) -> Result<()> {
    anyhow::bail!("Windows process killing not yet implemented")
}

/// Clean scheduled tasks referencing the given path (not yet implemented).
pub fn clean_scheduled_tasks(_path: &Path) -> Result<Vec<String>> {
    anyhow::bail!("Windows scheduled task cleaning not yet implemented")
}

/// Clean registry Run keys referencing the given path (not yet implemented).
pub fn clean_registry_run(_path: &Path) -> Result<Vec<String>> {
    anyhow::bail!("Windows registry Run key cleaning not yet implemented")
}

/// Clean Windows services referencing the given path (not yet implemented).
pub fn clean_services(_path: &Path) -> Result<Vec<String>> {
    anyhow::bail!("Windows service cleaning not yet implemented")
}

/// Clean startup folder entries referencing the given path (not yet implemented).
pub fn clean_startup_folder(_path: &Path) -> Result<Vec<String>> {
    anyhow::bail!("Windows startup folder cleaning not yet implemented")
}

/// Clean shell profiles on Windows (not yet implemented).
pub fn clean_shell_profiles(_path: &Path) -> Result<Vec<String>> {
    anyhow::bail!("Windows shell profile cleaning not yet implemented")
}

/// Network isolation via Windows Firewall (not yet implemented).
pub fn isolate_network_firewall() -> Result<()> {
    anyhow::bail!("Windows network isolation not yet implemented")
}

/// Restore network after isolation (not yet implemented).
pub fn restore_network_firewall() -> Result<()> {
    anyhow::bail!("Windows network restore not yet implemented")
}

/// Scan all Windows persistence mechanisms (not yet implemented).
///
/// Returns an empty list since Windows remediation is not implemented.
pub fn scan_all_persistence(_path: &Path) -> Vec<(PersistenceType, String)> {
    Vec::new()
}
