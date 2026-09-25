//! Self-update — download and replace the sd binary from GitHub releases.

use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

/// Return the compile-time version of this binary.
const fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Build the expected asset name for the current platform and architecture.
fn platform_asset_name(version: &str) -> String {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };
    format!("sd-{version}-{os}-{arch}")
}

/// Represents a GitHub release asset.
#[derive(serde::Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Represents a GitHub release.
#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

/// Strip a leading 'v' from a tag name (e.g. "v0.2.0" -> "0.2.0").
fn strip_v_prefix(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Compare two semver-like version strings. Returns true if `remote` is newer
/// than `local`. Falls back to lexicographic comparison if parsing fails.
fn is_newer(local: &str, remote: &str) -> bool {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let mut iter = s.splitn(3, '.');
        let major = iter.next()?.parse().ok()?;
        let minor = iter.next()?.parse().ok()?;
        let patch = iter.next()?.parse().ok()?;
        Some((major, minor, patch))
    };

    match (parse(local), parse(remote)) {
        (Some(l), Some(r)) => r > l,
        _ => remote > local,
    }
}

/// Entry point for the `self-update` command.
pub async fn run(check_only: bool, _data_dir: &Path) -> Result<()> {
    let current = current_version();
    println!("{} current version: v{}", "self-update:".cyan().bold(), current);
    println!("  Checking for updates...");

    let client = reqwest::Client::builder()
        .user_agent(format!("prx-sd/{current}"))
        .build()
        .context("failed to build HTTP client")?;

    let release: Release = client
        .get("https://api.github.com/repos/openprx/prx-sd/releases/latest")
        .send()
        .await
        .context("failed to query GitHub releases")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .await
        .context("failed to parse release JSON")?;

    let remote_version = strip_v_prefix(&release.tag_name);

    if !is_newer(current, remote_version) {
        println!("  {} already up to date (v{current})", "OK:".green().bold());
        return Ok(());
    }

    println!(
        "  {} v{current} -> v{remote_version}",
        "Update available:".yellow().bold()
    );

    if check_only {
        println!("  Run `sd self-update` (without --check-only) to apply.");
        return Ok(());
    }

    // Find the matching asset for this platform.
    let wanted = platform_asset_name(remote_version);
    let asset = release.assets.iter().find(|a| a.name == wanted).with_context(|| {
        format!(
            "no release asset matching '{wanted}' found (available: {})",
            release
                .assets
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    println!("  Downloading {}...", asset.name);

    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release asset")?
        .error_for_status()
        .context("download returned an error status")?
        .bytes()
        .await
        .context("failed to read release asset bytes")?;

    // Determine the path to the currently running binary.
    let current_exe = std::env::current_exe().context("failed to determine current executable path")?;

    let backup_path = current_exe.with_extension("old");
    let new_path = current_exe.with_extension("new");

    // Write the downloaded binary to a temporary file next to the current one.
    std::fs::write(&new_path, &bytes)
        .with_context(|| format!("failed to write new binary to {}", new_path.display()))?;

    // Make the new binary executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&new_path, perms).context("failed to set executable permissions on new binary")?;
    }

    // Rename dance: current -> backup, new -> current.
    // If the final rename fails, attempt to restore the backup.
    std::fs::rename(&current_exe, &backup_path).with_context(|| {
        format!(
            "failed to back up current binary from {} to {}",
            current_exe.display(),
            backup_path.display()
        )
    })?;

    if let Err(e) = std::fs::rename(&new_path, &current_exe) {
        // Attempt to restore the backup so the user isn't left without a binary.
        let _ = std::fs::rename(&backup_path, &current_exe);
        return Err(e).with_context(|| format!("failed to move new binary into place at {}", current_exe.display()));
    }

    // Clean up the backup (non-fatal).
    let _ = std::fs::remove_file(&backup_path);

    println!("  {} updated to v{remote_version}", "Success:".green().bold());

    Ok(())
}
