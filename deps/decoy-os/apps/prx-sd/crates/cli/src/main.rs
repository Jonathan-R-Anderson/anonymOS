// CLI binary — printing to stdout/stderr is the primary interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod commands;
mod embedded_rules;
mod output;

/// Subcommands for quarantine management.
#[derive(Subcommand)]
pub enum QuarantineAction {
    /// List all quarantined files.
    List,
    /// Restore a quarantined file to its original location.
    Restore {
        /// Quarantine entry ID.
        id: String,
        /// Restore to an alternate path instead of the original location.
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Permanently delete a quarantined file.
    Delete {
        /// Quarantine entry ID.
        id: String,
    },
    /// Permanently delete all quarantined files.
    DeleteAll {
        /// Skip confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Show quarantine statistics.
    Stats,
}

/// Subcommands for configuration management.
#[derive(Subcommand)]
pub enum ConfigAction {
    /// Display the current configuration.
    Show,
    /// Set a configuration key to a value.
    Set {
        /// Configuration key (dot-separated, e.g. "`scan.max_file_size`").
        key: String,
        /// New value for the key.
        value: String,
    },
    /// Reset configuration to defaults.
    Reset,
}

/// Subcommands for webhook alert management.
#[derive(Subcommand)]
pub enum WebhookAction {
    /// List configured webhook endpoints.
    List,
    /// Add a new webhook endpoint.
    Add {
        /// Webhook name (e.g., "my-slack").
        name: String,
        /// Webhook URL.
        url: String,
        /// Payload format: slack, discord, or generic.
        #[arg(long, default_value = "generic")]
        format: String,
    },
    /// Remove a webhook endpoint by name.
    Remove {
        /// Name of the webhook to remove.
        name: String,
    },
    /// Send a test alert to all enabled webhooks.
    Test,
}

/// Subcommands for email alert management.
#[derive(Subcommand)]
pub enum EmailAlertAction {
    /// Create or show the email alert configuration.
    Configure,
    /// Send a test alert email.
    Test,
    /// Send a custom alert email.
    Send {
        /// Threat name.
        threat_name: String,
        /// Threat level (e.g., Malicious, Suspicious).
        threat_level: String,
        /// File path that triggered the alert.
        file_path: String,
    },
}

/// Subcommands for adblock filter management.
#[derive(Subcommand)]
pub enum AdblockAction {
    /// Enable adblock: download lists + install DNS blocking (/etc/hosts).
    Enable,
    /// Disable adblock: remove DNS blocking entries.
    Disable,
    /// Force re-download all filter lists.
    Sync,
    /// Show engine statistics and status.
    Stats,
    /// Check if a URL/domain is blocked.
    Check {
        /// URL or domain to check.
        url: String,
    },
    /// Show recent blocked entries from log.
    Log {
        /// Number of entries to show.
        #[arg(short, long, default_value = "50")]
        count: usize,
    },
    /// Add a custom filter list source.
    Add {
        /// List name.
        name: String,
        /// URL to download from.
        url: String,
        /// Category: ads, tracking, malware, social.
        #[arg(long, default_value = "unknown")]
        category: String,
    },
    /// Remove a filter list source.
    Remove {
        /// List name to remove.
        name: String,
    },
}

/// Subcommands for scheduled scan management.
#[derive(Subcommand)]
pub enum ScheduleAction {
    /// Register a recurring scheduled scan.
    Add {
        /// Path to scan (e.g., /home).
        scan_path: String,
        /// Frequency: hourly, 4h, 12h, daily, weekly.
        #[arg(long, default_value = "weekly")]
        frequency: String,
    },
    /// Remove the scheduled scan.
    Remove,
    /// Show current schedule status.
    Status,
}

/// Subcommands for eBPF runtime management.
#[derive(Subcommand)]
pub enum RuntimeAction {
    /// Show eBPF runtime status, capabilities, and event metrics.
    Status,
}

/// Monitoring backend selection.
#[derive(Clone, Debug, Default)]
pub enum MonitorBackend {
    /// Automatically pick the best backend (ebpf → fanotify → notify).
    #[default]
    Auto,
    /// Cross-platform `notify` crate (inotify on Linux, `FSEvents` on macOS).
    Notify,
    /// eBPF-based kernel telemetry (Linux only, requires `--features ebpf`).
    Ebpf,
    /// Linux fanotify with permission-event blocking (requires `CAP_SYS_ADMIN`).
    Fanotify,
}

impl std::str::FromStr for MonitorBackend {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "notify" => Ok(Self::Notify),
            "ebpf" => Ok(Self::Ebpf),
            "fanotify" => Ok(Self::Fanotify),
            other => Err(format!(
                "unknown backend '{other}', expected: auto, notify, ebpf, fanotify"
            )),
        }
    }
}

/// Subcommands for community threat intelligence sharing.
#[derive(Subcommand)]
pub enum CommunityAction {
    /// Show community sharing configuration and enrollment status.
    Status,
    /// Enroll this machine with the community threat sharing API.
    Enroll,
    /// Disable community threat intelligence sharing.
    Disable,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory for threats.
    Scan {
        /// Path to scan (file or directory).
        path: PathBuf,
        /// Recurse into subdirectories (default for directories).
        #[arg(short, long, default_value_t = true)]
        recursive: bool,
        /// Output results as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// Number of scanner threads (defaults to CPU count).
        #[arg(short, long)]
        threads: Option<usize>,
        /// Automatically quarantine detected threats.
        #[arg(long)]
        auto_quarantine: bool,
        /// Auto-remediate threats (kill process, quarantine, clean persistence).
        #[arg(long)]
        remediate: bool,
        /// Glob patterns to exclude from scanning.
        #[arg(short, long)]
        exclude: Vec<String>,
        /// Export results as HTML report to this path.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Start real-time file system monitoring.
    Monitor {
        /// Paths to monitor for file system events.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Block malicious files before access completes (requires root + fanotify).
        #[arg(long)]
        block: bool,
        /// Run as a background daemon.
        #[arg(long)]
        daemon: bool,
        /// Monitoring backend: auto, notify, or ebpf.
        #[arg(long, default_value = "auto")]
        backend: MonitorBackend,
        /// Path to an eBPF policy TOML file for runtime response rules.
        #[arg(long)]
        ebpf_policy: Option<PathBuf>,
    },
    /// Manage quarantined files.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Check for and apply signature database updates.
    Update {
        /// Only check whether an update is available; do not download.
        #[arg(long)]
        check_only: bool,
        /// Force re-download even if signatures are already up to date.
        #[arg(long)]
        force: bool,
        /// Override the update server URL.
        #[arg(long)]
        server_url: Option<String>,
    },
    /// Manage engine configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Display engine version, signature database status, and system info.
    Info,
    /// Import hash signatures from a blocklist file into the signature database.
    Import {
        /// Path to the blocklist file (one "`hex_hash` `malware_name`" per line).
        path: PathBuf,
    },
    /// Import `ClamAV` signature files (.cvd, .hdb, .hsb) into the database.
    ImportClamav {
        /// Paths to `ClamAV` signature files (main.cvd, daily.cvd, .hdb, .hsb).
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Manage scheduled scans (add, remove, status).
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
    },
    /// Manage remediation policy (show, set, reset).
    Policy {
        /// Action: show, set, reset.
        action: String,
        /// Key to set (for 'set' action).
        key: Option<String>,
        /// Value to set (for 'set' action).
        value: Option<String>,
    },
    /// Run as a background daemon with real-time monitoring and auto-updates.
    Daemon {
        /// Paths to monitor for file system events (default: /home, /tmp).
        #[arg(default_values_os_t = vec![
            PathBuf::from("/home"),
            PathBuf::from("/tmp"),
        ])]
        paths: Vec<PathBuf>,
        /// Interval in hours between automatic signature updates.
        #[arg(long, default_value = "4")]
        update_hours: u32,
        /// Enable eBPF-based runtime behaviour monitoring (Linux only).
        #[arg(long)]
        ebpf: bool,
        /// If eBPF fails to start, continue with file-only monitoring instead of aborting.
        #[arg(long)]
        ebpf_fail_open: bool,
        /// Path to an eBPF policy TOML file for runtime response rules.
        #[arg(long)]
        ebpf_policy: Option<PathBuf>,
    },
    /// Scan USB/removable devices.
    ScanUsb {
        /// Device path (e.g., /dev/sdb1). Scans all USB devices if omitted.
        device: Option<String>,
        /// Automatically quarantine detected threats.
        #[arg(long)]
        auto_quarantine: bool,
    },
    /// Scan process memory for threats (Linux only, requires root).
    #[cfg(target_os = "linux")]
    ScanMemory {
        /// Scan a specific process by PID. Scans all if omitted.
        #[arg(long)]
        pid: Option<u32>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check for rootkit indicators (kernel modules, hidden processes).
    #[cfg(target_os = "linux")]
    CheckRootkit {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Manage webhook alert endpoints.
    Webhook {
        #[command(subcommand)]
        action: WebhookAction,
    },
    /// Manage email alert configuration and send alerts via SMTP.
    EmailAlert {
        #[command(subcommand)]
        action: EmailAlertAction,
    },
    /// Generate HTML report from JSON scan results.
    Report {
        /// Output HTML file path.
        output: PathBuf,
        /// Input JSON file (or - for stdin).
        #[arg(long, default_value = "-")]
        input: String,
    },
    /// Show daemon status (running/stopped, PID, signature version, threats blocked).
    Status,
    /// Check for and apply engine updates (binary + signatures).
    SelfUpdate {
        /// Only check if an update is available, don't download.
        #[arg(long)]
        check_only: bool,
    },
    /// Install file manager right-click scan integration.
    InstallIntegration,
    /// Manage adblock/malware domain filter lists.
    Adblock {
        #[command(subcommand)]
        action: AdblockAction,
    },
    /// Manage community threat intelligence sharing.
    Community {
        #[command(subcommand)]
        action: CommunityAction,
    },
    /// Manage eBPF runtime (status, diagnostics).
    Runtime {
        #[command(subcommand)]
        action: RuntimeAction,
    },
    /// Start local DNS proxy with adblock + IOC + custom blocklist filtering.
    DnsProxy {
        /// Listen address (default: 127.0.0.1:53).
        #[arg(long, default_value = "127.0.0.1:53")]
        listen: String,
        /// Upstream DNS server (default: 8.8.8.8:53).
        #[arg(long, default_value = "8.8.8.8:53")]
        upstream: String,
        /// Path for the JSONL query log.
        #[arg(long, default_value = "/tmp/prx-sd-dns.log")]
        log_path: String,
    },
}

#[derive(Parser)]
#[command(name = "sd", version, about = "PRX-SD: Open-source Rust antivirus engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Logging level: trace, debug, info, warn, error.
    #[arg(long, default_value = "warn", global = true)]
    log_level: String,

    /// Base data directory (signatures, quarantine, config). Defaults to ~/.prx-sd/.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
}

impl Cli {
    /// Resolve the data directory, creating it if it does not exist.
    fn resolve_data_dir(&self) -> Result<PathBuf> {
        let dir = self.data_dir.as_ref().map_or_else(
            || {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".prx-sd")
            },
            Clone::clone,
        );
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

/// Perform first-run initialization when the data directory is missing
/// essential subdirectories. This ensures that the engine is usable
/// immediately after installation, even without a network connection.
fn first_run_setup(data_dir: &Path) -> Result<()> {
    let signatures_dir = data_dir.join("signatures");
    let yara_dir = data_dir.join("yara");
    let quarantine_dir = data_dir.join("quarantine");

    // If both signature and YARA directories exist with content, assume
    // setup has already been completed.
    if signatures_dir.exists() && yara_dir.exists() {
        let has_yara_files = std::fs::read_dir(&yara_dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        if has_yara_files {
            return Ok(());
        }
    }

    eprintln!("Welcome to PRX-SD! Setting up for first use...");

    // 1. Create directory structure.
    std::fs::create_dir_all(&signatures_dir).context("failed to create signatures directory")?;
    std::fs::create_dir_all(&yara_dir).context("failed to create yara directory")?;
    std::fs::create_dir_all(&quarantine_dir).context("failed to create quarantine directory")?;
    eprintln!("  Created data directories at {}", data_dir.display());

    // 2. Write embedded YARA rules so basic detection works offline.
    embedded_rules::write_embedded_rules(&yara_dir).context("failed to write embedded YARA rules")?;
    eprintln!("  Installed built-in detection rules");

    // 3. Import embedded hash signatures (EICAR, WannaCry, etc.) into LMDB.
    match embedded_rules::import_embedded_hashes(&signatures_dir) {
        Ok(0) => {} // already populated or empty
        Ok(n) => eprintln!("  Imported {n} built-in hash signatures"),
        Err(e) => eprintln!("  Warning: failed to import embedded hashes: {e:#}"),
    }

    // 3. Create default configuration if none exists.
    let config_path = data_dir.join("config.json");
    if !config_path.exists() {
        let config = prx_sd_core::ScanConfig::default()
            .with_signatures_dir(signatures_dir)
            .with_yara_rules_dir(yara_dir)
            .with_quarantine_dir(quarantine_dir);
        let json = serde_json::to_string_pretty(&config).context("failed to serialize default config")?;
        std::fs::write(&config_path, json).context("failed to write default config")?;
        eprintln!("  Created default configuration");
    }

    // 4. Attempt to download the latest signatures. This is non-fatal
    //    so that offline installation still works.
    eprintln!("  Downloading latest threat signatures...");
    // We print a hint rather than actually running the async update here,
    // since first_run_setup is called synchronously before the tokio
    // runtime dispatches the user's chosen command. The `update` command
    // is the canonical way to fetch signatures.
    eprintln!("  (Run 'sd update' to download the latest signature database)");

    eprintln!("  Setup complete! Run 'sd scan <path>' to start scanning.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise tracing with the requested log level.
    let filter = tracing_subscriber::EnvFilter::try_new(&cli.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let data_dir = cli.resolve_data_dir()?;

    // Run first-time initialization if the data directory is empty or
    // missing essential subdirectories.
    if let Err(e) = first_run_setup(&data_dir) {
        tracing::warn!("First-run setup encountered an error: {e:#}");
        eprintln!("Warning: first-run setup incomplete ({e:#}). Some features may be limited.");
    }

    match cli.command {
        Commands::Scan {
            path,
            recursive,
            json,
            threads,
            auto_quarantine,
            remediate,
            exclude,
            report,
        } => {
            commands::scan::run(
                path,
                recursive,
                json,
                threads,
                auto_quarantine,
                remediate,
                exclude,
                report,
                &data_dir,
            )
            .await
        }
        Commands::Monitor {
            paths,
            block,
            daemon,
            backend,
            ebpf_policy,
        } => commands::realtime::run(paths, block, daemon, backend, ebpf_policy, &data_dir).await,
        Commands::Quarantine { action } => commands::quarantine::run(action, &data_dir),
        Commands::Update {
            check_only,
            force,
            server_url,
        } => commands::update::run(check_only, force, server_url, &data_dir).await,
        Commands::Config { action } => commands::config::run(action, &data_dir),
        Commands::Info => commands::info::run(&data_dir),
        Commands::Import { path } => commands::import::run(&path, &data_dir),
        Commands::ImportClamav { paths } => commands::import_clamav::run(&paths, &data_dir),
        Commands::Schedule { action } => match action {
            ScheduleAction::Add { scan_path, frequency } => {
                commands::schedule::run_add(&scan_path, &frequency, &data_dir)
            }
            ScheduleAction::Remove => commands::schedule::run_remove(),
            ScheduleAction::Status => commands::schedule::run_status(),
        },
        Commands::Policy { action, key, value } => {
            commands::policy::run(&action, key.as_deref(), value.as_deref(), &data_dir)
        }
        Commands::ScanUsb {
            device,
            auto_quarantine,
        } => commands::scan_usb::run(device.as_deref(), auto_quarantine, &data_dir).await,
        Commands::Daemon {
            paths,
            update_hours,
            ebpf,
            ebpf_fail_open,
            ebpf_policy,
        } => commands::daemon::run(&data_dir, paths, update_hours, ebpf, ebpf_fail_open, ebpf_policy).await,
        #[cfg(target_os = "linux")]
        Commands::ScanMemory { pid, json } => commands::memscan::run(pid, json, &data_dir),
        #[cfg(target_os = "linux")]
        Commands::CheckRootkit { json } => commands::rootkit::run(json, &data_dir),
        Commands::Webhook { action } => match action {
            WebhookAction::List => commands::webhook::run_list(&data_dir),
            WebhookAction::Add { name, url, format } => commands::webhook::run_add(&name, &url, &format, &data_dir),
            WebhookAction::Remove { name } => commands::webhook::run_remove(&name, &data_dir),
            WebhookAction::Test => commands::webhook::run_test(&data_dir).await,
        },
        Commands::EmailAlert { action } => match action {
            EmailAlertAction::Configure => commands::email_alert::run_configure(&data_dir),
            EmailAlertAction::Test => commands::email_alert::run_test(&data_dir).await,
            EmailAlertAction::Send {
                threat_name,
                threat_level,
                file_path,
            } => commands::email_alert::run_send(&threat_name, &threat_level, &file_path, &data_dir).await,
        },
        Commands::Report { output, input } => commands::report::run(&output, &input),
        Commands::Status => commands::status::run(&data_dir),
        Commands::SelfUpdate { check_only } => commands::self_update::run(check_only, &data_dir).await,
        Commands::InstallIntegration => commands::integration::run(&data_dir),
        Commands::Adblock { action } => match action {
            AdblockAction::Enable => commands::adblock::run_enable(&data_dir),
            AdblockAction::Disable => commands::adblock::run_disable(&data_dir),
            AdblockAction::Sync => commands::adblock::run_sync(&data_dir),
            AdblockAction::Stats => commands::adblock::run_stats(&data_dir),
            AdblockAction::Check { url } => commands::adblock::run_check(&url, &data_dir),
            AdblockAction::Log { count } => commands::adblock::run_log(&data_dir, count),
            AdblockAction::Add { name, url, category } => commands::adblock::run_add(&name, &url, &category, &data_dir),
            AdblockAction::Remove { name } => commands::adblock::run_remove(&name, &data_dir),
        },
        Commands::Community { action } => match action {
            CommunityAction::Status => commands::community::run_status(&data_dir),
            CommunityAction::Enroll => commands::community::run_enroll(&data_dir).await,
            CommunityAction::Disable => commands::community::run_disable(&data_dir),
        },
        Commands::Runtime { action } => match action {
            RuntimeAction::Status => commands::runtime::run_status().await,
        },
        Commands::DnsProxy {
            listen,
            upstream,
            log_path,
        } => commands::dns_proxy::run(&listen, &upstream, &log_path, &data_dir).await,
    }
}
