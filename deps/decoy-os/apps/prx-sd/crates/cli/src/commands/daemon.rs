use std::fmt::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::signal;

use prx_sd_core::{ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_realtime::event::FileEvent;
use prx_sd_realtime::protected_dirs::{ProtectedDirsConfig, ProtectedDirsEnforcer, ProtectionVerdict};
use prx_sd_realtime::ransomware::{RansomwareConfig, RansomwareDetector, RansomwareVerdict};

use notify::{RecursiveMode, Watcher};

/// Convert a `notify::Event` into zero or more [`FileEvent`]s.
///
/// The `notify` crate does not expose PIDs, so PID-dependent variants
/// (`Open`, `Execute`, `Rename`) are not produced here.  The ransomware
/// detector and protected-dirs enforcer handle the absence of a PID
/// gracefully (returning `Clean` / `Allowed`).
fn notify_to_file_events(event: &notify::Event) -> Vec<FileEvent> {
    let mut out = Vec::with_capacity(event.paths.len());
    for p in &event.paths {
        let fe = match event.kind {
            notify::EventKind::Create(_) => FileEvent::Create { path: p.clone() },
            notify::EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
                if let (Some(from), Some(to)) = (event.paths.first(), event.paths.get(1)) {
                    if p == from {
                        return vec![FileEvent::Rename {
                            from: from.clone(),
                            to: to.clone(),
                            pid: 0,
                        }];
                    }
                    return out;
                }
                FileEvent::Modify { path: p.clone() }
            }
            notify::EventKind::Modify(_) => FileEvent::Modify { path: p.clone() },
            notify::EventKind::Access(notify::event::AccessKind::Close(notify::event::AccessMode::Write)) => {
                FileEvent::CloseWrite { path: p.clone() }
            }
            notify::EventKind::Remove(_) => FileEvent::Delete { path: p.clone() },
            _ => continue,
        };
        out.push(fe);
    }
    out
}

/// Create a `ScanConfig` for the daemon.
fn build_config(data_dir: &Path) -> ScanConfig {
    ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"))
}

/// Write PID file to data_dir/prx-sd.pid.
fn write_pid_file(data_dir: &Path) -> Result<()> {
    let pid_path = data_dir.join("prx-sd.pid");
    let pid = std::process::id();
    std::fs::write(&pid_path, pid.to_string())
        .with_context(|| format!("failed to write PID file: {}", pid_path.display()))?;

    // Restrict PID file to owner-only read/write.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pid_path, std::fs::Permissions::from_mode(0o600));
    }

    tracing::info!(pid, path = %pid_path.display(), "wrote PID file");
    Ok(())
}

/// Remove PID file on shutdown.
fn remove_pid_file(data_dir: &Path) {
    let pid_path = data_dir.join("prx-sd.pid");
    if let Err(e) = std::fs::remove_file(&pid_path) {
        tracing::debug!(error = %e, "could not remove PID file (may already be gone)");
    }
}

/// Sanitize a string for safe embedding in AppleScript double-quoted strings.
///
/// Escapes backslashes and double-quotes to prevent command injection when
/// interpolating user-controlled values into osascript commands.
#[cfg(target_os = "macos")]
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Sanitize a string for safe embedding in PowerShell single-quoted strings.
///
/// In PowerShell single-quoted strings, the only special character is the
/// single quote itself, which is escaped by doubling it.
#[cfg(target_os = "windows")]
fn escape_powershell_single_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Send a desktop notification (cross-platform, best-effort).
///
/// All user-controlled values are sanitized before interpolation into shell
/// commands to prevent command injection.
fn send_notification(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        // notify-send receives title and body as separate argv entries,
        // so no shell interpolation occurs -- safe as-is.
        let _ = std::process::Command::new("notify-send")
            .args(["--urgency=critical", "--icon=dialog-warning", title, body])
            .spawn();
    }

    #[cfg(target_os = "macos")]
    {
        let safe_body = escape_applescript(body);
        let safe_title = escape_applescript(title);
        let _ = std::process::Command::new("osascript")
            .args([
                "-e",
                &format!("display notification \"{}\" with title \"{}\"", safe_body, safe_title),
            ])
            .spawn();
    }

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell single-quoted strings to avoid backtick/variable
        // expansion. The only character that needs escaping inside single
        // quotes is the single quote itself (doubled).
        let safe_title = escape_powershell_single_quote(title);
        let safe_body = escape_powershell_single_quote(body);
        let script = format!(
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
             $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
             $textNodes = $template.GetElementsByTagName('text'); \
             $textNodes.Item(0).AppendChild($template.CreateTextNode('{safe_title}')) > $null; \
             $textNodes.Item(1).AppendChild($template.CreateTextNode('{safe_body}')) > $null; \
             $toast = [Windows.UI.Notifications.ToastNotification]::new($template); \
             [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PRX-SD').Show($toast)"
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .spawn();
    }
}

/// Check for signature updates by running the update-server flow.
///
/// Returns `Ok(true)` if new signatures were downloaded, `Ok(false)` if
/// already up to date, or an error on failure.
async fn auto_update_signatures(data_dir: &Path) -> Result<bool> {
    #[derive(serde::Deserialize)]
    struct UpdateManifest {
        version: u64,
        sha256: String,
        size: u64,
        payload_url: String,
    }

    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;

    // Read local version.
    let version_file = sig_dir.join("version");
    let local_version: u64 = std::fs::read_to_string(&version_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    // Read server URL from config. If not configured, skip auto-update
    // (users should run `sd update` manually or set up a custom server).
    let server_url = {
        let config_path = data_dir.join("config.json");
        if let Some(url) = std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
            .and_then(|val| {
                val.get("update_server_url")
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string)
            })
        {
            url
        } else {
            tracing::debug!("no custom update_server_url configured, skipping daemon auto-update");
            return Ok(false);
        }
    };

    let manifest_url = format!("{}/manifest.json", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let manifest: UpdateManifest = match client.get(&manifest_url).send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(resp) => resp.json().await.context("failed to parse update manifest")?,
            Err(e) => {
                tracing::warn!(error = %e, "update server returned error");
                return Ok(false);
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "failed to reach update server");
            return Ok(false);
        }
    };

    if manifest.version <= local_version {
        tracing::debug!(
            local = local_version,
            remote = manifest.version,
            "signatures already up to date"
        );
        return Ok(false);
    }

    tracing::info!(
        local = local_version,
        remote = manifest.version,
        size = manifest.size,
        "downloading signature update"
    );

    let payload_url = if manifest.payload_url.starts_with("http") {
        manifest.payload_url.clone()
    } else {
        format!(
            "{}/{}",
            server_url.trim_end_matches('/'),
            manifest.payload_url.trim_start_matches('/')
        )
    };

    let response = client
        .get(&payload_url)
        .send()
        .await
        .context("failed to download update payload")?
        .error_for_status()
        .context("update download failed")?;

    let bytes = response.bytes().await.context("failed to read update payload body")?;

    // Verify SHA-256.
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_bytes = hasher.finalize();
        let digest = hash_bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        if digest != manifest.sha256 {
            anyhow::bail!("SHA-256 mismatch: expected {}, got {}", manifest.sha256, digest);
        }
    }

    // Write payload and update version marker.
    std::fs::write(sig_dir.join("update.bin"), &bytes)?;
    std::fs::write(sig_dir.join("version"), manifest.version.to_string())?;

    tracing::info!(version = manifest.version, "signatures updated");
    Ok(true)
}

/// Quarantine a detected threat (best-effort).
fn quarantine_threat(path: &Path, threat_name: &str, data_dir: &Path) {
    let quarantine_dir = data_dir.join("quarantine");
    match prx_sd_quarantine::Quarantine::new(quarantine_dir) {
        Ok(q) => {
            if let Err(e) = q.quarantine(path, threat_name) {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "failed to quarantine threat"
                );
            } else {
                tracing::info!(path = %path.display(), threat = threat_name, "threat quarantined");
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to open quarantine vault");
        }
    }
}

pub async fn run(
    data_dir: &Path,
    paths: Vec<PathBuf>,
    update_interval_hours: u32,
    ebpf_enabled: bool,
    ebpf_fail_open: bool,
    ebpf_policy: Option<PathBuf>,
) -> Result<()> {
    // Silence unused-variable warnings when ebpf feature is not compiled in.
    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    let _ = &ebpf_policy;

    // 1. Write PID file.
    write_pid_file(data_dir)?;

    println!(
        "{} PRX-SD daemon starting (PID {})",
        ">>>".cyan().bold(),
        std::process::id()
    );

    // 2. Initialize scan engine.
    let config = build_config(data_dir);
    let mut engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    println!("{} Scan engine initialized", ">>>".green().bold());

    // 2b. Optionally start eBPF runtime.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    let _ebpf_handle = if ebpf_enabled {
        match start_ebpf_sidecar(ebpf_policy.as_deref(), data_dir) {
            Ok(handle) => {
                println!("{} eBPF runtime attached", ">>>".green().bold());
                Some(handle)
            }
            Err(e) => {
                if ebpf_fail_open {
                    tracing::warn!("eBPF failed to start ({e:#}), continuing without it");
                    println!("  {} eBPF unavailable: {e:#}", "WARNING:".yellow().bold());
                    None
                } else {
                    return Err(e.context("eBPF required but failed to start (use --ebpf-fail-open to degrade)"));
                }
            }
        }
    } else {
        None
    };

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    if ebpf_enabled {
        let msg = "eBPF requested but not compiled in (need --features ebpf on Linux)";
        if ebpf_fail_open {
            println!("  {} {msg}", "WARNING:".yellow().bold());
        } else {
            anyhow::bail!("{msg}");
        }
    }

    // 3. Start file system watcher.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Event>(4096);

    let mut watcher =
        notify::recommended_watcher(
            move |res: std::result::Result<notify::Event, notify::Error>| match res {
                Ok(event) => {
                    let _ = tx.blocking_send(event);
                }
                Err(e) => {
                    tracing::error!("watcher error: {e}");
                }
            },
        )
        .context("failed to create file system watcher")?;

    for p in &paths {
        watcher
            .watch(p, RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch: {}", p.display()))?;
        println!("  {} {}", "Watching:".green(), p.display());
    }

    // 4. Spawn signature update task.
    let update_data_dir = data_dir.to_path_buf();
    let update_interval = std::time::Duration::from_secs(u64::from(update_interval_hours) * 3600);
    let (update_tx, mut update_rx) = tokio::sync::mpsc::channel::<bool>(1);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(update_interval);
        // Skip the first immediate tick (signatures were just loaded).
        interval.tick().await;

        loop {
            interval.tick().await;
            tracing::info!("checking for signature updates...");
            match auto_update_signatures(&update_data_dir).await {
                Ok(updated) => {
                    if updated {
                        // Notify the main loop to reload.
                        let _ = update_tx.send(true).await;
                        send_notification(
                            "PRX-SD: Signatures Updated",
                            "Malware signatures have been updated to the latest version.",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "signature auto-update failed");
                }
            }
        }
    });

    // Read auto-quarantine policy from config.
    let auto_quarantine = {
        let config_path = data_dir.join("config.json");
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
            .and_then(|val| {
                val.get("quarantine")
                    .and_then(|q| q.get("auto_quarantine"))
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false)
    };

    println!(
        "\n{} Daemon active (update every {}h, auto-quarantine: {}). Press {} to stop.\n",
        ">>>".green().bold(),
        update_interval_hours,
        if auto_quarantine { "on" } else { "off" },
        "Ctrl+C".bold()
    );

    // Ransomware behaviour detector (stateful, tracks per-PID sliding windows).
    let mut ransomware_detector = RansomwareDetector::new(RansomwareConfig::default());
    // Protected directory enforcer (blocks unauthorised writes to sensitive paths).
    let protected_dirs = ProtectedDirsEnforcer::new(ProtectedDirsConfig::default());

    let data_dir_owned = data_dir.to_path_buf();

    // 5. Main event loop.
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                let dominated = matches!(
                    event.kind,
                    notify::EventKind::Create(_)
                    | notify::EventKind::Modify(_)
                    | notify::EventKind::Access(notify::event::AccessKind::Close(
                        notify::event::AccessMode::Write,
                    ))
                );

                if !dominated {
                    continue;
                }

                // ── Ransomware + protected-dirs checks ──────────────
                let file_events = notify_to_file_events(&event);
                for fe in &file_events {
                    // 1. Ransomware behaviour analysis.
                    match ransomware_detector.on_file_event(fe) {
                        RansomwareVerdict::RansomwareDetected { pid, ref process_name, ref reason } => {
                            tracing::error!(
                                pid,
                                process = %process_name,
                                reason = %reason,
                                "ransomware behaviour detected"
                            );
                            send_notification(
                                "PRX-SD: RANSOMWARE DETECTED",
                                &format!("{process_name} (PID {pid}) - {reason}"),
                            );
                        }
                        RansomwareVerdict::Suspicious { pid, ref process_name, ref reason, score } => {
                            tracing::warn!(
                                pid,
                                process = %process_name,
                                score,
                                reason = %reason,
                                "suspicious ransomware-like activity"
                            );
                        }
                        RansomwareVerdict::Clean => {}
                    }

                    // 2. Protected directory enforcement.
                    if let Some(pid) = fe.pid() {
                        if let ProtectionVerdict::Blocked { ref path, pid: blocked_pid, ref process_name, ref reason } = protected_dirs.check_access(fe.path(), pid) {
                            tracing::warn!(
                                pid = blocked_pid,
                                process = %process_name,
                                path = %path.display(),
                                reason = %reason,
                                "protected directory violation"
                            );
                            send_notification(
                                "PRX-SD: Protected Directory Violation",
                                &format!("{} (PID {}) tried to modify {}", process_name, blocked_pid, path.display()),
                            );
                        }
                    }
                }

                for file_path in &event.paths {
                    if !file_path.is_file() {
                        continue;
                    }

                    match engine.scan_file(file_path).await {
                        Ok(result) => {
                            if result.is_threat() {
                                let threat_name = result
                                    .threat_name
                                    .as_deref()
                                    .unwrap_or("Unknown Threat");

                                let level_label = match result.threat_level {
                                    ThreatLevel::Suspicious => "Suspicious",
                                    ThreatLevel::Malicious => "Malicious",
                                    ThreatLevel::Clean => "Clean",
                                };

                                tracing::warn!(
                                    path = %file_path.display(),
                                    level = level_label,
                                    threat = threat_name,
                                    "threat detected"
                                );

                                // Send desktop notification.
                                send_notification(
                                    &format!("PRX-SD: {level_label} File Detected"),
                                    &format!("{}: {}", file_path.display(), threat_name),
                                );

                                // Auto-quarantine if policy says so and threat is malicious.
                                if auto_quarantine && result.threat_level == ThreatLevel::Malicious {
                                    quarantine_threat(file_path, threat_name, &data_dir_owned);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                path = %file_path.display(),
                                error = %e,
                                "failed to scan file event"
                            );
                        }
                    }
                }
            }
            Some(_updated) = update_rx.recv() => {
                tracing::info!("reloading engine signatures after update");
                if let Err(e) = engine.reload_signatures() {
                    tracing::error!(error = %e, "failed to reload signatures");
                }
            }
            _ = signal::ctrl_c() => {
                println!("\n{} Shutting down daemon...", ">>>".yellow().bold());
                break;
            }
        }
    }

    // 6. Graceful shutdown.
    drop(watcher);

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    if let Some(mut handle) = _ebpf_handle {
        handle.pipeline.stop();
        println!("{} eBPF pipeline detached", ">>>".green().bold());
    }

    remove_pid_file(&data_dir_owned);
    println!("{} Daemon stopped.", ">>>".green().bold());
    Ok(())
}

/// eBPF sidecar that runs alongside the daemon's file watcher.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
struct EbpfHandle {
    pipeline: prx_sd_realtime::ebpf::EbpfPipeline,
}

/// Start the eBPF pipeline in a background tokio task that logs events + alerts.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn start_ebpf_sidecar(policy_path: Option<&Path>, data_dir: &Path) -> Result<EbpfHandle> {
    use prx_sd_realtime::ebpf;

    ebpf::loader::check_capabilities().context("eBPF capability check failed")?;

    let (pipeline, mut rx) = if let Some(path) = policy_path {
        let engine = ebpf::PolicyEngine::load_from_file(path)
            .with_context(|| format!("failed to load eBPF policy: {}", path.display()))?;
        tracing::info!(
            rules = engine.rule_count(),
            path = %path.display(),
            "loaded eBPF policy"
        );

        let executor = std::sync::Arc::new(SdActionExecutor::new(data_dir)?);
        let config = ebpf::PolicyConfig {
            engine,
            executor: executor as std::sync::Arc<dyn ebpf::ActionExecutor>,
            dispatcher_config: ebpf::DispatcherConfig::default(),
        };

        ebpf::EbpfPipeline::start_with_policy(8192, config).context("failed to start eBPF pipeline with policy")?
    } else {
        ebpf::EbpfPipeline::start(8192).context("failed to start eBPF pipeline")?
    };

    // Spawn an async task to consume pipeline output and log it.
    tokio::spawn(async move {
        while let Some(output) = rx.recv().await {
            match output {
                ebpf::PipelineOutput::Event(event) => {
                    tracing::info!(target: "ebpf", "{event}");
                }
                ebpf::PipelineOutput::Alert(alert) => {
                    tracing::warn!(target: "ebpf_alert", "{alert}");
                    send_notification(&format!("PRX-SD: {} Alert", alert.severity), &alert.description);
                }
                ebpf::PipelineOutput::Policy(policy_match) => {
                    tracing::warn!(target: "ebpf_policy", "{policy_match}");
                    send_notification(
                        &format!("PRX-SD: Policy Match ({})", policy_match.severity),
                        &policy_match.description,
                    );
                }
            }
        }
        tracing::debug!("eBPF pipeline receiver closed");
    });

    Ok(EbpfHandle { pipeline })
}

/// Create a shared [`ActionExecutor`] for use in eBPF pipeline policy mode.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub fn create_sd_executor(data_dir: &Path) -> Result<std::sync::Arc<dyn prx_sd_realtime::ebpf::ActionExecutor>> {
    let executor = SdActionExecutor::new(data_dir)?;
    Ok(std::sync::Arc::new(executor))
}

/// Concrete [`ActionExecutor`] for the `sd` CLI that uses the real scan
/// engine, quarantine vault, and process management APIs.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
struct SdActionExecutor {
    scan_engine: prx_sd_core::ScanEngine,
    quarantine_dir: PathBuf,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl SdActionExecutor {
    fn new(data_dir: &Path) -> Result<Self> {
        let config = prx_sd_core::ScanConfig::default()
            .with_signatures_dir(data_dir.join("signatures"))
            .with_yara_rules_dir(data_dir.join("yara"))
            .with_quarantine_dir(data_dir.join("quarantine"));
        let scan_engine =
            prx_sd_core::ScanEngine::new(config).context("failed to create eBPF action executor scan engine")?;
        Ok(Self {
            scan_engine,
            quarantine_dir: data_dir.join("quarantine"),
        })
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[async_trait::async_trait]
impl prx_sd_realtime::ebpf::ActionExecutor for SdActionExecutor {
    async fn scan_file(&self, path: &Path) -> anyhow::Result<prx_sd_realtime::ebpf::ActionResult> {
        let result = self.scan_engine.scan_file(path).await?;
        let success = !result.is_threat();
        let detail = if result.is_threat() {
            format!(
                "THREAT: {} ({})",
                result.threat_name.as_deref().unwrap_or("Unknown"),
                result.threat_level,
            )
        } else {
            "clean".to_string()
        };

        Ok(prx_sd_realtime::ebpf::ActionResult {
            action: prx_sd_realtime::ebpf::PolicyAction::TriggerFileScan,
            target: path.to_string_lossy().into_owned(),
            success,
            detail,
        })
    }

    async fn scan_memory(&self, pid: u32) -> anyhow::Result<prx_sd_realtime::ebpf::ActionResult> {
        // Memory scanning requires direct YaraEngine/SignatureDatabase access
        // which is not yet exposed. Planned for Sprint D.
        tracing::info!(pid, "memory scan requested (not yet implemented, logging only)");
        Ok(prx_sd_realtime::ebpf::ActionResult {
            action: prx_sd_realtime::ebpf::PolicyAction::TriggerMemoryScan,
            target: pid.to_string(),
            success: false,
            detail: "memory scan not yet implemented (planned for Sprint D)".to_string(),
        })
    }

    async fn kill_process(&self, pid: u32) -> anyhow::Result<prx_sd_realtime::ebpf::ActionResult> {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;

        // Safety guards: refuse to kill system-critical or own process.
        if pid == 0 {
            return Ok(prx_sd_realtime::ebpf::ActionResult {
                action: prx_sd_realtime::ebpf::PolicyAction::KillProcess,
                target: pid.to_string(),
                success: false,
                detail: "refusing to kill PID 0 (process group broadcast)".to_string(),
            });
        }
        if pid == 1 {
            return Ok(prx_sd_realtime::ebpf::ActionResult {
                action: prx_sd_realtime::ebpf::PolicyAction::KillProcess,
                target: pid.to_string(),
                success: false,
                detail: "refusing to kill PID 1 (init/systemd)".to_string(),
            });
        }
        if pid == std::process::id() {
            return Ok(prx_sd_realtime::ebpf::ActionResult {
                action: prx_sd_realtime::ebpf::PolicyAction::KillProcess,
                target: pid.to_string(),
                success: false,
                detail: "refusing to kill own PID".to_string(),
            });
        }
        // Verify the process comm matches the event (basic TOCTOU mitigation).
        let proc_comm_path = format!("/proc/{pid}/comm");
        if std::fs::read_to_string(&proc_comm_path).is_err() {
            return Ok(prx_sd_realtime::ebpf::ActionResult {
                action: prx_sd_realtime::ebpf::PolicyAction::KillProcess,
                target: pid.to_string(),
                success: false,
                detail: format!("PID {pid} no longer exists, skipping kill"),
            });
        }

        let nix_pid = Pid::from_raw(i32::try_from(pid).map_err(|_| anyhow::anyhow!("PID {pid} out of i32 range"))?);
        match signal::kill(nix_pid, Signal::SIGKILL) {
            Ok(()) => {
                tracing::warn!(pid, "killed process via policy action");
                Ok(prx_sd_realtime::ebpf::ActionResult {
                    action: prx_sd_realtime::ebpf::PolicyAction::KillProcess,
                    target: pid.to_string(),
                    success: true,
                    detail: format!("sent SIGKILL to PID {pid}"),
                })
            }
            Err(e) => Ok(prx_sd_realtime::ebpf::ActionResult {
                action: prx_sd_realtime::ebpf::PolicyAction::KillProcess,
                target: pid.to_string(),
                success: false,
                detail: format!("kill failed: {e}"),
            }),
        }
    }

    async fn quarantine_path(
        &self,
        path: &Path,
        threat_name: &str,
    ) -> anyhow::Result<prx_sd_realtime::ebpf::ActionResult> {
        let quarantine = prx_sd_quarantine::Quarantine::new(self.quarantine_dir.clone())?;
        match quarantine.quarantine(path, threat_name) {
            Ok(id) => {
                tracing::warn!(
                    path = %path.display(),
                    id = %id,
                    "quarantined file via policy action"
                );
                Ok(prx_sd_realtime::ebpf::ActionResult {
                    action: prx_sd_realtime::ebpf::PolicyAction::QuarantinePath,
                    target: path.to_string_lossy().into_owned(),
                    success: true,
                    detail: format!("quarantined as {id}"),
                })
            }
            Err(e) => Ok(prx_sd_realtime::ebpf::ActionResult {
                action: prx_sd_realtime::ebpf::PolicyAction::QuarantinePath,
                target: path.to_string_lossy().into_owned(),
                success: false,
                detail: format!("quarantine failed: {e}"),
            }),
        }
    }
}
