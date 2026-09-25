//! Scheduled scan management — register/remove systemd timers or cron jobs.

use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::Colorize;

/// Sanitize a path for safe inclusion in shell commands and config files.
/// Rejects paths containing shell metacharacters, newlines, or null bytes.
fn sanitize_path(path: &str) -> Result<&str> {
    let forbidden = [
        ';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '!', '\n', '\r', '\0', '\'', '"', '\\',
    ];
    for ch in forbidden {
        if path.contains(ch) {
            let display = match ch {
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\0' => "\\0".to_string(),
                other => other.to_string(),
            };
            bail!("scan path contains forbidden character '{display}'. Use a simple absolute path like /home.");
        }
    }
    if path.is_empty() {
        bail!("scan path cannot be empty");
    }
    // Must be an absolute path
    if !path.starts_with('/') && !path.starts_with("C:\\") && !path.starts_with("D:\\") {
        bail!("scan path must be an absolute path");
    }
    Ok(path)
}

/// Which scheduler backend to use.
#[derive(Debug, Clone, Copy)]
enum Backend {
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    SystemdTimer,
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Cron,
    #[cfg(target_os = "macos")]
    Launchd,
    #[cfg(target_os = "windows")]
    TaskScheduler,
}

fn detect_backend() -> Backend {
    #[cfg(target_os = "windows")]
    {
        return Backend::TaskScheduler;
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: prefer launchd (always available), fall back to cron
        return Backend::Launchd;
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // Linux/Unix: prefer systemd if available, fall back to cron
        if std::process::Command::new("systemctl")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            Backend::SystemdTimer
        } else {
            Backend::Cron
        }
    }
}

/// Convert a frequency string like "daily", "weekly", "hourly", or "4h" into
/// a systemd calendar expression and a cron expression.
fn parse_frequency(freq: &str) -> Result<(&'static str, &'static str)> {
    match freq.to_lowercase().as_str() {
        "hourly" | "1h" => Ok(("hourly", "0 * * * *")),
        "daily" | "24h" => Ok(("daily", "0 2 * * *")),
        "weekly" | "7d" => Ok(("weekly", "0 2 * * 0")),
        "4h" => Ok(("*-*-* 0/4:00:00", "0 */4 * * *")),
        "12h" => Ok(("*-*-* 0/12:00:00", "0 */12 * * *")),
        _ => bail!("unsupported frequency '{freq}'. Use: hourly, 4h, 12h, daily, weekly"),
    }
}

fn sd_binary_path() -> String {
    std::env::current_exe().map_or_else(|_| "sd".to_string(), |p| p.to_string_lossy().to_string())
}

// ─── systemd timer ──────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn systemd_unit_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    std::path::PathBuf::from(home).join(".config/systemd/user")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn install_systemd_timer(scan_path: &str, frequency: &str, data_dir: &Path) -> Result<()> {
    let scan_path = sanitize_path(scan_path)?;
    let (calendar, _) = parse_frequency(frequency)?;
    let unit_dir = systemd_unit_dir();
    std::fs::create_dir_all(&unit_dir).context("failed to create systemd user unit directory")?;

    let sd_bin = sd_binary_path();
    let data_dir_str = data_dir.to_string_lossy();

    // Service unit.
    let service_content = format!(
        "[Unit]\n\
         Description=PRX-SD scheduled scan of {scan_path}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={sd_bin} --data-dir {data_dir_str} --log-level warn scan {scan_path} --recursive\n\
         Nice=19\n\
         IOSchedulingClass=idle\n"
    );

    // Timer unit.
    let timer_content = format!(
        "[Unit]\n\
         Description=PRX-SD scheduled scan timer\n\
         \n\
         [Timer]\n\
         OnCalendar={calendar}\n\
         Persistent=true\n\
         RandomizedDelaySec=300\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    );

    let service_path = unit_dir.join("prx-sd-scan.service");
    let timer_path = unit_dir.join("prx-sd-scan.timer");

    std::fs::write(&service_path, service_content).context("failed to write systemd service unit")?;
    std::fs::write(&timer_path, timer_content).context("failed to write systemd timer unit")?;

    // Reload and enable.
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    if let Ok(s) = reload {
        if s.success() {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "enable", "--now", "prx-sd-scan.timer"])
                .status();
        }
    }

    println!("{} systemd timer installed", "success:".green().bold());
    println!("  Service: {}", service_path.display());
    println!("  Timer:   {}", timer_path.display());
    println!("  Schedule: {calendar}");
    println!("  Scan path: {scan_path}");
    println!();
    println!("  Check status: systemctl --user status prx-sd-scan.timer");
    println!("  View logs:    journalctl --user -u prx-sd-scan.service");

    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[allow(clippy::unnecessary_wraps)]
fn remove_systemd_timer() -> Result<()> {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "prx-sd-scan.timer"])
        .status();

    let unit_dir = systemd_unit_dir();
    let service_path = unit_dir.join("prx-sd-scan.service");
    let timer_path = unit_dir.join("prx-sd-scan.timer");

    if service_path.exists() {
        std::fs::remove_file(&service_path).ok();
    }
    if timer_path.exists() {
        std::fs::remove_file(&timer_path).ok();
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!("{} systemd timer removed", "success:".green().bold());
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[allow(clippy::unnecessary_wraps)]
fn show_systemd_status() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["--user", "status", "prx-sd-scan.timer"])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stdout.is_empty() {
                println!("{stdout}");
            }
            if !stderr.is_empty() && !o.status.success() {
                println!("{}", "No scheduled scan configured (systemd timer not found)".yellow());
            }
        }
        Err(_) => {
            println!("{}", "systemctl not available".yellow());
        }
    }
    Ok(())
}

// ─── cron ───────────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn install_cron_job(scan_path: &str, frequency: &str, data_dir: &Path) -> Result<()> {
    let scan_path = sanitize_path(scan_path)?;
    let (_, cron_expr) = parse_frequency(frequency)?;
    let sd_bin = sd_binary_path();
    let data_dir_str = data_dir.to_string_lossy();

    let cron_line = format!(
        "{cron_expr} {sd_bin} --data-dir {data_dir_str} --log-level warn scan {scan_path} --recursive # prx-sd-scheduled-scan"
    );

    // Read existing crontab, filter out old prx-sd entries, add new one.
    let existing = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut lines: Vec<&str> = existing
        .lines()
        .filter(|l| !l.contains("prx-sd-scheduled-scan"))
        .collect();
    lines.push(&cron_line);

    let new_crontab = lines.join("\n") + "\n";

    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn crontab")?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin
            .write_all(new_crontab.as_bytes())
            .context("failed to write crontab")?;
    }

    let status = child.wait().context("crontab failed")?;
    if !status.success() {
        bail!("crontab returned non-zero exit code");
    }

    println!("{} cron job installed", "success:".green().bold());
    println!("  Cron expression: {cron_expr}");
    println!("  Scan path: {scan_path}");
    println!("  View: crontab -l | grep prx-sd");

    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn remove_cron_job() -> Result<()> {
    let existing = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let lines: Vec<&str> = existing
        .lines()
        .filter(|l| !l.contains("prx-sd-scheduled-scan"))
        .collect();

    let new_crontab = lines.join("\n") + "\n";

    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn crontab")?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(new_crontab.as_bytes()).ok();
    }

    let _ = child.wait();

    println!("{} cron job removed", "success:".green().bold());
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[allow(clippy::unnecessary_wraps)]
fn show_cron_status() -> Result<()> {
    let output = std::process::Command::new("crontab").arg("-l").output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let found: Vec<&str> = stdout.lines().filter(|l| l.contains("prx-sd-scheduled-scan")).collect();
            if found.is_empty() {
                println!("{}", "No scheduled scan configured (no cron job found)".yellow());
            } else {
                println!("{}", "Scheduled scan cron jobs:".cyan().bold());
                for line in found {
                    println!("  {line}");
                }
            }
        }
        Err(_) => {
            println!("{}", "crontab not available".yellow());
        }
    }
    Ok(())
}

// ─── macOS launchd ──────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn launchd_plist_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join("Library/LaunchAgents")
}

#[cfg(target_os = "macos")]
fn install_launchd_job(scan_path: &str, frequency: &str, data_dir: &Path) -> Result<()> {
    let scan_path = sanitize_path(scan_path)?;
    let (_, _) = parse_frequency(frequency)?; // validate frequency
    let plist_dir = launchd_plist_dir();
    std::fs::create_dir_all(&plist_dir).context("failed to create LaunchAgents directory")?;

    let sd_bin = sd_binary_path();
    let data_dir_str = data_dir.to_string_lossy();

    // Convert frequency to launchd interval in seconds.
    let interval_secs: u64 = match frequency.to_lowercase().as_str() {
        "hourly" | "1h" => 3600,
        "4h" => 4 * 3600,
        "12h" => 12 * 3600,
        "daily" | "24h" => 86400,
        "weekly" | "7d" => 7 * 86400,
        _ => 86400,
    };

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.prx-sd.scheduled-scan</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sd_bin}</string>
        <string>--data-dir</string>
        <string>{data_dir_str}</string>
        <string>--log-level</string>
        <string>warn</string>
        <string>scan</string>
        <string>{scan_path}</string>
        <string>--recursive</string>
    </array>
    <key>StartInterval</key>
    <integer>{interval_secs}</integer>
    <key>Nice</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>"#
    );

    let plist_path = plist_dir.join("dev.prx-sd.scheduled-scan.plist");
    std::fs::write(&plist_path, plist).context("failed to write launchd plist")?;

    let _ = std::process::Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .status();

    println!("{} launchd job installed", "success:".green().bold());
    println!("  Plist: {}", plist_path.display());
    println!("  Interval: every {interval_secs} seconds");
    println!("  Scan path: {scan_path}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_launchd_job() -> Result<()> {
    let plist_path = launchd_plist_dir().join("dev.prx-sd.scheduled-scan.plist");
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload"])
            .arg(&plist_path)
            .status();
        std::fs::remove_file(&plist_path).ok();
    }
    println!("{} launchd job removed", "success:".green().bold());
    Ok(())
}

#[cfg(target_os = "macos")]
fn show_launchd_status() -> Result<()> {
    let output = std::process::Command::new("launchctl")
        .args(["list", "dev.prx-sd.scheduled-scan"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            println!("{}", "Scheduled scan (launchd):".cyan().bold());
            println!("{}", String::from_utf8_lossy(&o.stdout));
        }
        _ => {
            println!("{}", "No scheduled scan configured (launchd job not found)".yellow());
        }
    }
    Ok(())
}

// ─── Windows Task Scheduler ────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_task_scheduler(scan_path: &str, frequency: &str, data_dir: &Path) -> Result<()> {
    let scan_path = sanitize_path(scan_path)?;
    let (_, _) = parse_frequency(frequency)?;
    let sd_bin = sd_binary_path();
    let data_dir_str = data_dir.to_string_lossy();

    let schtasks_freq = match frequency.to_lowercase().as_str() {
        "hourly" | "1h" => "HOURLY",
        "4h" => "HOURLY /MO 4",
        "12h" => "HOURLY /MO 12",
        "daily" | "24h" => "DAILY",
        "weekly" | "7d" => "WEEKLY",
        _ => "DAILY",
    };

    let status = std::process::Command::new("schtasks")
        .args([
            "/Create",
            "/F",
            "/TN",
            "PRX-SD Scheduled Scan",
            "/SC",
            schtasks_freq,
            "/TR",
            &format!("\"{sd_bin}\" --data-dir \"{data_dir_str}\" --log-level warn scan \"{scan_path}\" --recursive"),
            "/RL",
            "HIGHEST",
        ])
        .status()
        .context("failed to run schtasks")?;

    if !status.success() {
        bail!("schtasks /Create failed");
    }

    println!("{} Windows scheduled task created", "success:".green().bold());
    println!("  Task name: PRX-SD Scheduled Scan");
    println!("  Frequency: {frequency}");
    println!("  Scan path: {scan_path}");
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_task_scheduler() -> Result<()> {
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", "PRX-SD Scheduled Scan"])
        .status();
    println!("{} Windows scheduled task removed", "success:".green().bold());
    Ok(())
}

#[cfg(target_os = "windows")]
fn show_task_scheduler_status() -> Result<()> {
    let output = std::process::Command::new("schtasks")
        .args(["/Query", "/TN", "PRX-SD Scheduled Scan", "/V", "/FO", "LIST"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            println!("{}", "Scheduled scan (Task Scheduler):".cyan().bold());
            println!("{}", String::from_utf8_lossy(&o.stdout));
        }
        _ => {
            println!("{}", "No scheduled scan configured (task not found)".yellow());
        }
    }
    Ok(())
}

// ─── public API ─────────────────────────────────────────────────────────────

pub fn run_add(scan_path: &str, frequency: &str, data_dir: &Path) -> Result<()> {
    let backend = detect_backend();
    match backend {
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Backend::SystemdTimer => install_systemd_timer(scan_path, frequency, data_dir),
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Backend::Cron => install_cron_job(scan_path, frequency, data_dir),
        #[cfg(target_os = "macos")]
        Backend::Launchd => install_launchd_job(scan_path, frequency, data_dir),
        #[cfg(target_os = "windows")]
        Backend::TaskScheduler => install_task_scheduler(scan_path, frequency, data_dir),
    }
}

pub fn run_remove() -> Result<()> {
    let backend = detect_backend();
    match backend {
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Backend::SystemdTimer => remove_systemd_timer(),
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Backend::Cron => remove_cron_job(),
        #[cfg(target_os = "macos")]
        Backend::Launchd => remove_launchd_job(),
        #[cfg(target_os = "windows")]
        Backend::TaskScheduler => remove_task_scheduler(),
    }
}

pub fn run_status() -> Result<()> {
    let backend = detect_backend();
    match backend {
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Backend::SystemdTimer => show_systemd_status(),
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Backend::Cron => show_cron_status(),
        #[cfg(target_os = "macos")]
        Backend::Launchd => show_launchd_status(),
        #[cfg(target_os = "windows")]
        Backend::TaskScheduler => show_task_scheduler_status(),
    }
}
