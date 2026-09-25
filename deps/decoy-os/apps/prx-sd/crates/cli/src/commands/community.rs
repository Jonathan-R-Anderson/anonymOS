//! CLI handlers for the `sd community` subcommand family.

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use prx_sd_updater::community::config::CommunityConfig;
use prx_sd_updater::community::enroll;

/// `sd community status` -- display current community config and enrollment.
pub fn run_status(data_dir: &Path) -> Result<()> {
    let cfg = CommunityConfig::load(data_dir)?;

    println!("{}", "Community Threat Intelligence".cyan().bold());
    println!();
    println!(
        "  {:<20} {}",
        "Enabled:".bold(),
        if cfg.enabled {
            "yes".green().to_string()
        } else {
            "no".yellow().to_string()
        }
    );
    println!("  {:<20} {}", "Server URL:".bold(), cfg.server_url);

    if let Some(ref mid) = cfg.machine_id {
        println!("  {:<20} {}", "Machine ID:".bold(), mid);
    } else {
        println!("  {:<20} {}", "Machine ID:".bold(), "not enrolled".dimmed());
    }

    println!(
        "  {:<20} {}",
        "API key:".bold(),
        if cfg.api_key.is_some() {
            "configured".green().to_string()
        } else {
            "none".dimmed().to_string()
        }
    );
    println!("  {:<20} {}", "Batch size:".bold(), cfg.batch_size);
    println!("  {:<20} {} s", "Flush interval:".bold(), cfg.flush_interval_secs);
    println!("  {:<20} {} s", "Sync interval:".bold(), cfg.sync_interval_secs);

    Ok(())
}

/// `sd community enroll` -- register this machine with the community API.
pub async fn run_enroll(data_dir: &Path) -> Result<()> {
    let mut cfg = CommunityConfig::load(data_dir)?;

    if cfg.is_enrolled() {
        println!(
            "{} Already enrolled as machine {}",
            "OK".green().bold(),
            cfg.machine_id.as_deref().unwrap_or("?")
        );
        return Ok(());
    }

    println!(
        "{} Enrolling with community API at {}...",
        ">>>".cyan().bold(),
        cfg.server_url
    );

    let resp = enroll::enroll_machine(&cfg).await?;

    cfg.machine_id = Some(resp.machine_id.clone());
    cfg.api_key = Some(resp.api_key);
    cfg.enabled = true;
    cfg.save(data_dir)?;

    println!(
        "{} Enrolled successfully. Machine ID: {}",
        "OK".green().bold(),
        resp.machine_id
    );
    println!("  Community sharing is now {}", "enabled".green().bold());

    Ok(())
}

/// `sd community disable` -- turn off community sharing.
pub fn run_disable(data_dir: &Path) -> Result<()> {
    let mut cfg = CommunityConfig::load(data_dir)?;

    if !cfg.enabled {
        println!("{} Community sharing is already disabled.", "OK".green());
        return Ok(());
    }

    cfg.enabled = false;
    cfg.save(data_dir)?;

    println!(
        "{} Community sharing {}.",
        "OK".green().bold(),
        "disabled".yellow().bold()
    );
    println!("  Enrollment credentials are preserved. Run 'sd community enroll' to re-enable.");

    Ok(())
}
