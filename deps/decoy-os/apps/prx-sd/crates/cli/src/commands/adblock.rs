//! CLI commands for the adblock domain filter engine.
//!
//! `sd adblock enable`  — download lists + install DNS blocking (hosts file)
//! `sd adblock disable` — remove DNS blocking
//! `sd adblock sync`    — force re-download all lists
//! `sd adblock stats`   — show engine statistics
//! `sd adblock check`   — check a single URL/domain
//! `sd adblock log`     — show recent blocked entries
//! `sd adblock add/remove` — manage custom lists

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use prx_sd_realtime::adblock_filter::{AdblockCategory, AdblockFilterManager};

/// Returns the platform-specific hosts file path for display purposes.
const fn hosts_file_display() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        r"C:\Windows\System32\drivers\etc\hosts"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "/etc/hosts"
    }
}

/// Returns the platform-specific hint for running with elevated privileges.
const fn elevate_hint() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Try running as Administrator"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "Try: sudo sd adblock enable"
    }
}

fn adblock_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("adblock")
}

fn init_manager(data_dir: &Path) -> Result<AdblockFilterManager> {
    AdblockFilterManager::init(&adblock_dir(data_dir)).context("failed to init adblock engine")
}

fn log_path(data_dir: &Path) -> std::path::PathBuf {
    adblock_dir(data_dir).join("blocked_log.jsonl")
}

/// Write a block record to the persistent log.
pub fn log_blocked(data_dir: &Path, domain: &str, url: &str, category: &str, source: &str) {
    let path = log_path(data_dir);
    let record = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "domain": domain,
        "url": url,
        "category": category,
        "source": source,
        "action": "blocked",
    });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{record}");
    }
}

/// `sd adblock enable` — download lists + install hosts file blocking.
pub fn run_enable(data_dir: &Path) -> Result<()> {
    println!("{} Enabling adblock protection...", ">>>".cyan().bold());

    // 1. Init and sync lists
    let mgr = init_manager(data_dir)?;
    let stats = mgr.stats();
    println!("  Loaded {} lists ({} rules)", stats.list_count, stats.total_rules);

    // 2. Generate hosts file entries from adblock engine
    // We use the dns_filter module to write entries to /etc/hosts
    let mut dns = prx_sd_realtime::DnsFilter::new();

    // Load all domains from cached lists and add to DNS filter
    let lists_dir = adblock_dir(data_dir).join("lists");
    if lists_dir.is_dir() {
        for entry in std::fs::read_dir(&lists_dir)? {
            let entry = entry?;
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
                        continue;
                    }
                    // Extract domain from ABP rule "||domain.com^"
                    if let Some(domain) = line.strip_prefix("||").and_then(|rest| rest.strip_suffix('^')) {
                        dns.add_domain(domain);
                    }
                    // Extract domain from hosts line "0.0.0.0 domain.com"
                    let is_hosts_entry = line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ");
                    if let Some(domain) = is_hosts_entry.then(|| line.split_whitespace().nth(1)).flatten() {
                        dns.add_domain(domain);
                    }
                }
            }
        }
    }

    let domain_count = dns.domain_count();

    // 3. Install to /etc/hosts (requires root)
    match dns.install_hosts_blocking() {
        Ok(()) => {
            println!(
                "{} Adblock enabled: {} domains blocked via {}",
                "success:".green().bold(),
                domain_count,
                hosts_file_display(),
            );
            println!("  Lists: {:?}", stats.list_names);
            println!("  Log: {}", log_path(data_dir).display());

            // Write enabled flag
            let flag = adblock_dir(data_dir).join("enabled");
            std::fs::write(&flag, "true").ok();
        }
        Err(e) => {
            eprintln!(
                "{} Failed to write {} (insufficient privileges?): {e}",
                "error:".red().bold(),
                hosts_file_display(),
            );
            eprintln!("  {}", elevate_hint());
            return Err(e);
        }
    }

    Ok(())
}

/// `sd adblock disable` — remove hosts file blocking entries.
pub fn run_disable(data_dir: &Path) -> Result<()> {
    let mut dns = prx_sd_realtime::DnsFilter::new();
    dns.remove_hosts_blocking()?;
    let flag = adblock_dir(data_dir).join("enabled");
    std::fs::remove_file(&flag).ok();
    println!("{} Adblock protection disabled", "success:".green().bold());
    Ok(())
}

/// `sd adblock sync` — force re-download all lists.
pub fn run_sync(data_dir: &Path) -> Result<()> {
    println!("{} Syncing adblock filter lists...", ">>>".cyan().bold());
    let mut mgr = init_manager(data_dir)?;
    let downloaded = mgr.sync()?;
    let stats = mgr.stats();
    println!(
        "{} Synced {} lists ({} rules total)",
        "success:".green().bold(),
        downloaded,
        stats.total_rules,
    );
    for name in &stats.list_names {
        println!("  - {name}");
    }

    // If enabled, re-apply hosts blocking with new lists
    let flag = adblock_dir(data_dir).join("enabled");
    if flag.exists() {
        println!("  Re-applying DNS blocking with updated lists...");
        run_enable(data_dir).ok();
    }

    Ok(())
}

/// `sd adblock stats` — show engine statistics.
pub fn run_stats(data_dir: &Path) -> Result<()> {
    let mgr = init_manager(data_dir)?;
    let stats = mgr.stats();
    let enabled = adblock_dir(data_dir).join("enabled").exists();

    println!("{}", "Adblock Engine Statistics".cyan().bold());
    println!(
        "  Status:        {}",
        if enabled {
            "ENABLED".green().bold().to_string()
        } else {
            "DISABLED".yellow().to_string()
        }
    );
    println!("  Lists loaded:  {}", stats.list_count);
    println!("  Total rules:   {}", stats.total_rules);
    println!("  Cache dir:     {}", stats.cache_dir);
    println!("  Last sync:     {}", stats.last_sync.as_deref().unwrap_or("never"));

    // Show log stats
    let log = log_path(data_dir);
    if log.exists() {
        let count = std::fs::read_to_string(&log).map(|c| c.lines().count()).unwrap_or(0);
        println!("  Blocked log:   {count} entries");
    }

    println!();
    for name in &stats.list_names {
        println!("  - {name}");
    }
    Ok(())
}

/// `sd adblock check <url>` — check if a URL/domain is blocked.
pub fn run_check(url: &str, data_dir: &Path) -> Result<()> {
    let mgr = init_manager(data_dir)?;

    let full_url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}/")
    };

    let result = mgr.check_url(&full_url, &full_url, "document");

    if result.blocked {
        println!("{} {} → {:?}", "BLOCKED".red().bold(), url, result.category,);
        // Log it
        log_blocked(
            data_dir,
            url,
            &full_url,
            &format!("{:?}", result.category),
            "manual_check",
        );
    } else {
        println!("{} {}", "ALLOWED".green().bold(), url);
    }
    Ok(())
}

/// `sd adblock log` — show recent blocked entries.
pub fn run_log(data_dir: &Path, count: usize) -> Result<()> {
    let log = log_path(data_dir);
    if !log.exists() {
        println!("No adblock log entries yet.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&log).context("failed to read adblock log")?;

    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let start = total.saturating_sub(count);

    println!(
        "{} (showing last {} of {})",
        "Adblock Block Log".cyan().bold(),
        count.min(total),
        total
    );
    println!();

    for line in lines.get(start..).unwrap_or_default() {
        if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
            let ts = record.get("timestamp").and_then(|v| v.as_str()).unwrap_or("?");
            let domain = record.get("domain").and_then(|v| v.as_str()).unwrap_or("?");
            let cat = record.get("category").and_then(|v| v.as_str()).unwrap_or("?");
            let source = record.get("source").and_then(|v| v.as_str()).unwrap_or("?");
            println!(
                "  {} {} {:30} [{}] ({})",
                "🚫".red(),
                ts.get(..19.min(ts.len())).unwrap_or(ts),
                domain,
                cat,
                source,
            );
        }
    }

    Ok(())
}

/// `sd adblock add <name> <url>` — add a custom filter list.
pub fn run_add(name: &str, url: &str, category: &str, data_dir: &Path) -> Result<()> {
    let cat = match category.to_lowercase().as_str() {
        "ads" => AdblockCategory::Ads,
        "tracking" => AdblockCategory::Tracking,
        "malware" => AdblockCategory::Malware,
        "social" => AdblockCategory::Social,
        _ => AdblockCategory::Unknown,
    };

    let mut mgr = init_manager(data_dir)?;
    let rules = mgr.add_source(name, url, cat)?;
    println!("{} Added '{}': {} rules loaded", "success:".green().bold(), name, rules,);
    Ok(())
}

/// `sd adblock remove <name>` — remove a filter list.
pub fn run_remove(name: &str, data_dir: &Path) -> Result<()> {
    let mut mgr = init_manager(data_dir)?;
    mgr.remove_source(name)?;
    println!("{} Removed '{}'", "success:".green().bold(), name);
    Ok(())
}
