use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::signal;

use prx_sd_core::{ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_realtime::event::FileEvent;
use prx_sd_realtime::protected_dirs::{ProtectedDirsConfig, ProtectedDirsEnforcer, ProtectionVerdict};
use prx_sd_realtime::ransomware::{RansomwareConfig, RansomwareDetector, RansomwareVerdict};

use notify::{RecursiveMode, Watcher};

use crate::MonitorBackend;

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
                // notify rename events carry two paths (from, to).  When
                // both are present we emit a Rename; otherwise treat as a
                // plain Modify so the ransomware detector still sees it.
                if let (Some(from), Some(to)) = (event.paths.first(), event.paths.get(1)) {
                    if p == from {
                        return vec![FileEvent::Rename {
                            from: from.clone(),
                            to: to.clone(),
                            pid: 0,
                        }];
                    }
                    // Second path of the rename pair – already handled.
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

/// Create a `ScanConfig` for the real-time monitor.
fn build_config(data_dir: &Path) -> ScanConfig {
    ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"))
}

pub async fn run(
    paths: Vec<PathBuf>,
    block_mode: bool,
    daemon: bool,
    backend: MonitorBackend,
    ebpf_policy: Option<PathBuf>,
    data_dir: &Path,
) -> Result<()> {
    // Silence unused-variable warnings when ebpf feature is not compiled in.
    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    let _ = (&ebpf_policy, data_dir);

    // ── eBPF backend (Linux only) ─────────────────────────────────────
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    if matches!(backend, MonitorBackend::Ebpf | MonitorBackend::Auto) {
        if let Some(result) = try_ebpf_monitor(&backend, ebpf_policy.as_deref(), data_dir).await {
            return result;
        }
        // Auto mode: eBPF unavailable, fall through to fanotify backend.
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    if matches!(backend, MonitorBackend::Ebpf) {
        anyhow::bail!(
            "eBPF backend not available. Compile with --features ebpf on Linux, \
             or use --backend auto"
        );
    }

    // ── fanotify backend (Linux only, pre-execution blocking) ─────────
    #[cfg(target_os = "linux")]
    if matches!(backend, MonitorBackend::Fanotify | MonitorBackend::Auto) {
        match try_fanotify_monitor(&paths, block_mode, data_dir).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if matches!(backend, MonitorBackend::Fanotify) {
                    return Err(e.context("fanotify backend failed (requires CAP_SYS_ADMIN)"));
                }
                tracing::info!("fanotify unavailable ({e:#}), falling back to notify backend");
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    if matches!(backend, MonitorBackend::Fanotify) {
        anyhow::bail!("fanotify backend is only available on Linux");
    }

    // Warn when block mode falls through to notify (best-effort only).
    if block_mode {
        tracing::warn!(
            "--block in notify backend is best-effort (post-hoc deletion). \
             True pre-execution blocking requires fanotify or eBPF."
        );
    }

    // ── notify backend (default / fallback) ───────────────────────────
    let config = build_config(data_dir);
    let engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    println!(
        "{} Starting real-time monitor on {} path(s)",
        ">>>".cyan().bold(),
        paths.len()
    );
    for p in &paths {
        println!("  {} {}", "Watching:".green(), p.display());
    }

    if block_mode {
        println!(
            "  {} blocking mode enabled (requires root + fanotify on Linux)",
            "Mode:".yellow().bold()
        );
    }

    if daemon {
        println!(
            "  {} running in foreground (daemon fork not implemented)",
            "Note:".yellow()
        );
    }

    // Use the notify-based cross-platform watcher.
    // The prx-sd-realtime crate is a placeholder, so we use `notify` directly.
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
    }

    // Ransomware behaviour detector (stateful, tracks per-PID sliding windows).
    let mut ransomware_detector = RansomwareDetector::new(RansomwareConfig::default());
    // Protected directory enforcer (blocks unauthorised writes to sensitive paths).
    let protected_dirs = ProtectedDirsEnforcer::new(ProtectedDirsConfig::default());

    println!(
        "\n{} Monitoring active. Press {} to stop.\n",
        ">>>".green().bold(),
        "Ctrl+C".bold()
    );

    // Event processing loop.
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                // Only scan on file creation, modification, or close-write.
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
                            println!(
                                "  {} {} (PID {}) - {}",
                                "RANSOMWARE DETECTED:".red().bold(),
                                process_name,
                                pid,
                                reason,
                            );
                            tracing::error!(
                                pid,
                                process = %process_name,
                                reason = %reason,
                                "ransomware behaviour detected"
                            );
                        }
                        RansomwareVerdict::Suspicious { pid, ref process_name, ref reason, score } => {
                            println!(
                                "  {} {} (PID {}) score={} - {}",
                                "SUSPICIOUS ACTIVITY:".yellow().bold(),
                                process_name,
                                pid,
                                score,
                                reason,
                            );
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
                            println!(
                                "  {} {} (PID {}) tried to modify {}",
                                "PROTECTED DIR VIOLATION:".red().bold(),
                                process_name,
                                blocked_pid,
                                path.display(),
                            );
                            tracing::warn!(
                                pid = blocked_pid,
                                process = %process_name,
                                path = %path.display(),
                                reason = %reason,
                                "protected directory violation"
                            );
                        }
                    }
                }

                for file_path in &event.paths {
                    if !file_path.is_file() {
                        continue;
                    }

                    let kind_label = match event.kind {
                        notify::EventKind::Create(_) => "CREATE",
                        notify::EventKind::Modify(_) => "MODIFY",
                        _ => "WRITE",
                    };

                    match engine.scan_file(file_path).await {
                        Ok(result) => {
                            let level_str = match result.threat_level {
                                ThreatLevel::Clean => format!("{}", "CLEAN".green()),
                                ThreatLevel::Suspicious => format!("{}", "SUSPICIOUS".yellow().bold()),
                                ThreatLevel::Malicious => format!("{}", "MALICIOUS".red().bold()),
                            };

                            let threat_info = result
                                .threat_name
                                .as_deref()
                                .map(|n| format!(" ({n})"))
                                .unwrap_or_default();

                            println!(
                                "[{}] {} {} → {}{}",
                                kind_label.dimmed(),
                                chrono::Local::now().format("%H:%M:%S"),
                                file_path.display(),
                                level_str,
                                threat_info,
                            );

                            // In block mode, attempt to remove malicious files immediately.
                            if block_mode && result.threat_level == ThreatLevel::Malicious {
                                println!(
                                    "  {} blocking access to {}",
                                    "BLOCKED:".red().bold(),
                                    file_path.display()
                                );
                                // Best-effort removal -- true blocking requires fanotify.
                                if let Err(e) = std::fs::remove_file(file_path) {
                                    tracing::warn!(
                                        path = %file_path.display(),
                                        error = %e,
                                        "could not remove malicious file"
                                    );
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
            _ = signal::ctrl_c() => {
                println!("\n{} Shutting down monitor...", ">>>".yellow().bold());
                break;
            }
        }
    }

    drop(watcher);
    println!("{} Monitor stopped.", ">>>".green().bold());
    Ok(())
}

/// Try to start the fanotify-based monitor with pre-execution blocking support.
///
/// Returns `Ok(())` if fanotify started and ran until Ctrl+C.
/// Returns `Err` if fanotify is unavailable (no `CAP_SYS_ADMIN`, etc.).
#[cfg(target_os = "linux")]
async fn try_fanotify_monitor(paths: &[PathBuf], block_mode: bool, data_dir: &Path) -> Result<()> {
    use prx_sd_realtime::linux::FanotifyMonitor;
    use prx_sd_realtime::monitor::FileSystemMonitor;

    let config = build_config(data_dir);
    let engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    // When block_mode is enabled, set up a hash checker for pre-execution blocking.
    let mut monitor = if block_mode {
        let sigs_db = prx_sd_signatures::SignatureDatabase::open(&data_dir.join("signatures"))
            .context("failed to open signature database for fanotify blocking")?;
        let checker: prx_sd_realtime::linux::HashChecker = std::sync::Arc::new(move |hash: &[u8]| {
            match sigs_db.sha256_lookup_raw(hash) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    // Fail-open: DB errors allow execution to proceed.
                    // This prevents a DB outage from blocking all file access.
                    tracing::warn!("signature DB lookup failed, defaulting to allow: {e:#}");
                    false
                }
            }
        });
        FanotifyMonitor::with_hash_checker(4096, checker)
    } else {
        FanotifyMonitor::new(4096)
    };

    monitor.start(paths).await.context("failed to start fanotify monitor")?;

    println!(
        "{} fanotify monitor started on {} path(s) (block={})",
        ">>>".green().bold(),
        paths.len(),
        block_mode,
    );
    for p in paths {
        println!("  {} {}", "Watching:".green(), p.display());
    }

    println!(
        "\n{} Monitoring active. Press {} to stop.\n",
        ">>>".green().bold(),
        "Ctrl+C".bold()
    );

    // Drain events from the fanotify receiver.
    let rx = monitor.event_receiver_mut();
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                // For fanotify, blocking is handled inside the kernel event loop.
                // Here we just log the events for visibility.
                let file_path = event.path();
                if file_path.is_file() {
                    match engine.scan_file(file_path).await {
                        Ok(result) => {
                            let level_str = match result.threat_level {
                                ThreatLevel::Clean => format!("{}", "CLEAN".green()),
                                ThreatLevel::Suspicious => {
                                    format!("{}", "SUSPICIOUS".yellow().bold())
                                }
                                ThreatLevel::Malicious => {
                                    format!("{}", "MALICIOUS".red().bold())
                                }
                            };
                            let threat_info = result
                                .threat_name
                                .as_deref()
                                .map(|n| format!(" ({n})"))
                                .unwrap_or_default();
                            println!(
                                "[FANOTIFY] {} {} → {}{}",
                                chrono::Local::now().format("%H:%M:%S"),
                                file_path.display(),
                                level_str,
                                threat_info,
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                path = %file_path.display(),
                                error = %e,
                                "failed to scan fanotify event"
                            );
                        }
                    }
                }
            }
            _ = signal::ctrl_c() => {
                println!("\n{} Shutting down fanotify monitor...", ">>>".yellow().bold());
                break;
            }
        }
    }

    monitor.stop().await.ok();
    println!("{} fanotify monitor stopped.", ">>>".green().bold());
    Ok(())
}

/// Try to start the eBPF event monitor. Returns `Some(Result)` if eBPF was
/// explicitly requested or successfully started; `None` if auto-detect should
/// fall through to the notify backend.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn try_ebpf_monitor(backend: &MonitorBackend, policy_path: Option<&Path>, data_dir: &Path) -> Option<Result<()>> {
    use prx_sd_realtime::ebpf;

    // Capability pre-check.
    if let Err(e) = ebpf::loader::check_capabilities() {
        if matches!(backend, MonitorBackend::Ebpf) {
            return Some(Err(e.context("eBPF capability check failed")));
        }
        tracing::info!("eBPF unavailable ({e:#}), falling back to notify backend");
        return None;
    }

    let pipeline_result = if let Some(path) = policy_path {
        let engine = match ebpf::PolicyEngine::load_from_file(path) {
            Ok(e) => e,
            Err(e) => {
                return Some(Err(e.context(format!("failed to load eBPF policy: {}", path.display()))));
            }
        };

        println!(
            "  {} loaded {} rules from {}",
            "Policy:".cyan().bold(),
            engine.rule_count(),
            path.display(),
        );

        let executor: std::sync::Arc<dyn ebpf::ActionExecutor> = match super::daemon::create_sd_executor(data_dir) {
            Ok(e) => e,
            Err(e) => {
                return Some(Err(e.context("failed to create action executor")));
            }
        };

        let config = ebpf::PolicyConfig {
            engine,
            executor,
            dispatcher_config: ebpf::DispatcherConfig::default(),
        };

        ebpf::EbpfPipeline::start_with_policy(8192, config)
    } else {
        ebpf::EbpfPipeline::start(8192)
    };

    let (mut pipeline, mut rx) = match pipeline_result {
        Ok(pair) => pair,
        Err(e) => {
            if matches!(backend, MonitorBackend::Ebpf) {
                return Some(Err(e.context("failed to start eBPF pipeline")));
            }
            tracing::info!("eBPF start failed ({e:#}), falling back to notify backend");
            return None;
        }
    };

    println!(
        "{} eBPF pipeline started — streaming events + correlation (Ctrl+C to stop)",
        ">>>".green().bold()
    );

    // Stream events + alerts until Ctrl+C.
    let result: Result<()> = async {
        loop {
            tokio::select! {
                Some(output) = rx.recv() => {
                    match &output {
                        ebpf::PipelineOutput::Event(event) => {
                            println!(
                                "[{}] {}",
                                chrono::Local::now().format("%H:%M:%S"),
                                event,
                            );
                        }
                        ebpf::PipelineOutput::Alert(alert) => {
                            println!(
                                "[{}] {}",
                                chrono::Local::now().format("%H:%M:%S"),
                                format!("{alert}").red().bold(),
                            );
                        }
                        ebpf::PipelineOutput::Policy(policy_match) => {
                            println!(
                                "[{}] {}",
                                chrono::Local::now().format("%H:%M:%S"),
                                format!("{policy_match}").yellow().bold(),
                            );
                        }
                    }
                }
                _ = signal::ctrl_c() => {
                    println!("\n{} Shutting down eBPF monitor...", ">>>".yellow().bold());
                    break;
                }
            }
        }

        let snap = pipeline.metrics().snapshot();
        println!();
        println!("{snap}");
        pipeline.stop();
        println!("{} eBPF monitor stopped.", ">>>".green().bold());
        Ok(())
    }
    .await;

    Some(result)
}
