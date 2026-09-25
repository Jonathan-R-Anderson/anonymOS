use std::path::Path;

use anyhow::{Context, Result};

/// File manager integration asset files, embedded at compile time.
#[cfg(target_os = "linux")]
mod assets {
    pub const NAUTILUS_SCRIPT: &str = include_str!("../../../../packaging/filemanager/nautilus/prx-sd-scan");
    pub const DOLPHIN_DESKTOP: &str = include_str!("../../../../packaging/filemanager/dolphin/prx-sd-scan.desktop");
    pub const NEMO_ACTION: &str = include_str!("../../../../packaging/filemanager/nemo/prx-sd-scan.nemo_action");
}

/// Install file manager right-click scan integration for the current platform.
pub fn run(_data_dir: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        install_linux()?;
    }

    #[cfg(target_os = "macos")]
    {
        install_macos()?;
    }

    #[cfg(target_os = "windows")]
    {
        eprintln!("Windows file manager integration is not yet supported.");
        eprintln!("Please check future releases for Windows Explorer context menu integration.");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        eprintln!("File manager integration is not supported on this platform.");
    }

    Ok(())
}

/// Install integrations for Linux file managers (Nautilus, Dolphin, Nemo).
#[cfg(target_os = "linux")]
fn install_linux() -> Result<()> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let home = Path::new(&home);
    let mut installed_any = false;

    // Nautilus (GNOME Files)
    let nautilus_dir = home.join(".local/share/nautilus/scripts");
    if let Err(e) = install_file(&nautilus_dir, "Scan with PRX-SD", assets::NAUTILUS_SCRIPT, true) {
        tracing::debug!("Skipping Nautilus integration: {e:#}");
    } else {
        eprintln!("  Installed Nautilus (GNOME Files) integration");
        installed_any = true;
    }

    // Dolphin (KDE)
    let dolphin_dir = home.join(".local/share/kservices5/ServiceMenus");
    if let Err(e) = install_file(&dolphin_dir, "prx-sd-scan.desktop", assets::DOLPHIN_DESKTOP, false) {
        tracing::debug!("Skipping Dolphin integration: {e:#}");
    } else {
        eprintln!("  Installed Dolphin (KDE) integration");
        installed_any = true;
    }

    // Nemo (Cinnamon)
    let nemo_dir = home.join(".local/share/nemo/actions");
    if let Err(e) = install_file(&nemo_dir, "prx-sd-scan.nemo_action", assets::NEMO_ACTION, false) {
        tracing::debug!("Skipping Nemo integration: {e:#}");
    } else {
        eprintln!("  Installed Nemo (Cinnamon) integration");
        installed_any = true;
    }

    if installed_any {
        eprintln!();
        eprintln!("File manager integration installed successfully.");
        eprintln!("You may need to restart your file manager for changes to take effect.");
    } else {
        eprintln!("No file manager integration directories could be created.");
        eprintln!("Please ensure your HOME directory is writable.");
    }

    // Thunar hint
    eprintln!();
    eprintln!("Note: Thunar (XFCE) requires manual setup via Edit > Configure custom actions.");
    eprintln!("  Name: Scan with PRX-SD");
    eprintln!("  Command: sd scan %F");

    Ok(())
}

/// Install the macOS Finder Quick Action workflow.
#[cfg(target_os = "macos")]
fn install_macos() -> Result<()> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let services_dir = Path::new(&home).join("Library/Services");
    let workflow_dir = services_dir.join("Scan with PRX-SD.workflow/Contents");

    std::fs::create_dir_all(&workflow_dir).context("failed to create workflow directory in ~/Library/Services")?;

    // Write Info.plist
    let info_plist =
        include_str!("../../../../packaging/filemanager/macos/Scan with PRX-SD.workflow/Contents/Info.plist");
    std::fs::write(workflow_dir.join("Info.plist"), info_plist).context("failed to write Info.plist")?;

    // Write document.wflow
    let document_wflow =
        include_str!("../../../../packaging/filemanager/macos/Scan with PRX-SD.workflow/Contents/document.wflow");
    std::fs::write(workflow_dir.join("document.wflow"), document_wflow).context("failed to write document.wflow")?;

    eprintln!("  Installed Finder Quick Action: \"Scan with PRX-SD\"");
    eprintln!();
    eprintln!("The action is now available in Finder's right-click menu under Quick Actions.");
    eprintln!("You can also find it in System Settings > Extensions > Finder.");

    Ok(())
}

/// Write a file into the given directory, creating the directory if needed.
#[cfg(target_os = "linux")]
fn install_file(dir: &Path, filename: &str, content: &str, executable: bool) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create directory {}", dir.display()))?;

    let dest = dir.join(filename);
    std::fs::write(&dest, content).with_context(|| format!("failed to write {}", dest.display()))?;

    if executable {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&dest, perms)
                .with_context(|| format!("failed to set permissions on {}", dest.display()))?;
        }
    }

    Ok(())
}
