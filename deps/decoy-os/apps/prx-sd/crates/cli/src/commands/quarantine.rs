use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::QuarantineAction;
use crate::output;

/// Open the real AES-256-GCM quarantine vault.
fn open_quarantine(data_dir: &Path) -> Result<prx_sd_quarantine::Quarantine> {
    let vault_dir = data_dir.join("quarantine");
    prx_sd_quarantine::Quarantine::new(vault_dir).context("failed to open quarantine vault")
}

/// Prompt the user for a yes/no confirmation. Returns `true` for yes.
fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N] ");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

pub fn run(action: QuarantineAction, data_dir: &Path) -> Result<()> {
    match action {
        QuarantineAction::List => cmd_list(data_dir),
        QuarantineAction::Restore { id, to } => cmd_restore(data_dir, &id, to.as_deref()),
        QuarantineAction::Delete { id } => cmd_delete(data_dir, &id),
        QuarantineAction::DeleteAll { yes } => cmd_delete_all(data_dir, yes),
        QuarantineAction::Stats => cmd_stats(data_dir),
    }
}

fn cmd_list(data_dir: &Path) -> Result<()> {
    let q = open_quarantine(data_dir)?;
    let entries = q.list()?;

    if entries.is_empty() {
        println!("{}", "No quarantined files.".dimmed());
        return Ok(());
    }

    let headers = &["ID", "Original Path", "Threat", "Date", "Size"];
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|(id, meta)| {
            vec![
                id.to_string().chars().take(8).collect::<String>(),
                meta.original_path.display().to_string(),
                meta.threat_name.clone(),
                meta.quarantine_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
                output::format_bytes(meta.file_size),
            ]
        })
        .collect();

    output::print_table(headers, &rows);
    println!("\n{} quarantined file(s)", entries.len());
    Ok(())
}

fn cmd_restore(data_dir: &Path, id: &str, dest: Option<&Path>) -> Result<()> {
    let q = open_quarantine(data_dir)?;
    let entries = q.list()?;

    let (full_id, meta) = entries
        .iter()
        .find(|(eid, _)| eid.to_string().starts_with(id))
        .with_context(|| format!("no quarantine entry matching id '{id}'"))?;

    let restore_to = dest.map_or_else(|| meta.original_path.clone(), std::path::Path::to_path_buf);

    // Security: reject restore to sensitive system paths
    let blocked_prefixes = ["/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/root/.ssh/"];
    let restore_str = restore_to.to_string_lossy();
    for prefix in &blocked_prefixes {
        if restore_str.starts_with(prefix) {
            anyhow::bail!(
                "refusing to restore to sensitive path '{}' — use a safe destination",
                restore_to.display()
            );
        }
    }

    if let Some(parent) = restore_to.parent() {
        std::fs::create_dir_all(parent)?;
    }

    q.restore(*full_id, &restore_to)
        .with_context(|| format!("failed to restore {full_id}"))?;

    // Delete from quarantine after successful restore
    q.delete(*full_id).ok();

    println!("{} Restored {} -> {}", "OK".green().bold(), id, restore_to.display());
    Ok(())
}

fn cmd_delete(data_dir: &Path, id: &str) -> Result<()> {
    let q = open_quarantine(data_dir)?;
    let entries = q.list()?;

    let (full_id, meta) = entries
        .iter()
        .find(|(eid, _)| eid.to_string().starts_with(id))
        .with_context(|| format!("no quarantine entry matching id '{id}'"))?;

    if !confirm(&format!(
        "Permanently delete quarantined file {} ({})?",
        id,
        meta.original_path.display(),
    )) {
        println!("Aborted.");
        return Ok(());
    }

    q.delete(*full_id)?;
    println!("{} Deleted quarantine entry {}", "OK".green().bold(), id);
    Ok(())
}

fn cmd_delete_all(data_dir: &Path, skip_confirm: bool) -> Result<()> {
    let q = open_quarantine(data_dir)?;
    let entries = q.list()?;

    if entries.is_empty() {
        println!("{}", "No quarantined files to delete.".dimmed());
        return Ok(());
    }

    if !skip_confirm
        && !confirm(&format!(
            "Permanently delete ALL {} quarantined file(s)?",
            entries.len()
        ))
    {
        println!("Aborted.");
        return Ok(());
    }

    let mut deleted = 0u64;
    for (id, _) in &entries {
        if q.delete(*id).is_ok() {
            deleted += 1;
        }
    }

    println!("{} Deleted {} quarantine entries", "OK".green().bold(), deleted);
    Ok(())
}

fn cmd_stats(data_dir: &Path) -> Result<()> {
    let q = open_quarantine(data_dir)?;
    let stats = q.stats()?;

    println!("{}", "Quarantine Statistics".cyan().bold());
    println!("  Total files:  {}", stats.count);
    println!("  Total size:   {}", output::format_bytes(stats.total_size));

    let entries = q.list()?;
    if let Some((_, newest)) = entries.first() {
        println!("  Newest entry: {}", newest.quarantine_time);
    }
    if let Some((_, oldest)) = entries.last() {
        println!("  Oldest entry: {}", oldest.quarantine_time);
    }

    Ok(())
}
