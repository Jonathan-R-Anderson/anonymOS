//! Manage remediation policy configuration.

use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use prx_sd_remediation::policy::RemediationPolicy;

/// Show the current remediation policy.
fn show_policy(data_dir: &Path) -> Result<()> {
    let policy_path = data_dir.join("remediation_policy.json");
    let policy = if policy_path.exists() {
        RemediationPolicy::load(&policy_path)?
    } else {
        println!("{} no custom policy found, showing defaults", "info:".cyan().bold());
        RemediationPolicy::default()
    };

    let json = serde_json::to_string_pretty(&policy).context("failed to serialize policy")?;
    println!("{json}");
    Ok(())
}

/// Reset the policy to defaults.
fn reset_policy(data_dir: &Path) -> Result<()> {
    let policy_path = data_dir.join("remediation_policy.json");
    let policy = RemediationPolicy::default();
    policy.save(&policy_path)?;
    println!(
        "{} policy reset to defaults at {}",
        "success:".green().bold(),
        policy_path.display()
    );
    Ok(())
}

/// Set a specific policy field.
fn set_policy(data_dir: &Path, key: &str, value: &str) -> Result<()> {
    let policy_path = data_dir.join("remediation_policy.json");
    let mut policy = if policy_path.exists() {
        RemediationPolicy::load(&policy_path)?
    } else {
        RemediationPolicy::default()
    };

    match key {
        "on_malicious" | "policy.on_malicious" => {
            policy.on_malicious = parse_action_list(value)?;
        }
        "on_suspicious" | "policy.on_suspicious" => {
            policy.on_suspicious = parse_action_list(value)?;
        }
        "kill_processes" | "policy.kill_processes" => {
            policy.kill_processes = value.parse::<bool>().context("expected true or false")?;
        }
        "clean_persistence" | "policy.clean_persistence" => {
            policy.clean_persistence = value.parse::<bool>().context("expected true or false")?;
        }
        "network_isolation" | "policy.network_isolation" => {
            policy.network_isolation = value.parse::<bool>().context("expected true or false")?;
        }
        "audit_logging" | "policy.audit_logging" => {
            policy.audit_logging = value.parse::<bool>().context("expected true or false")?;
        }
        _ => {
            anyhow::bail!(
                "unknown policy key '{key}'. Valid keys: on_malicious, on_suspicious, \
                 kill_processes, clean_persistence, network_isolation, audit_logging"
            );
        }
    }

    policy.save(&policy_path)?;
    println!("{} policy updated: {} = {}", "success:".green().bold(), key, value);
    Ok(())
}

/// Parse a comma-separated action list like "kill,quarantine,clean".
fn parse_action_list(value: &str) -> Result<Vec<prx_sd_remediation::policy::ActionType>> {
    use prx_sd_remediation::policy::ActionType;

    let mut actions = Vec::new();
    for token in value.split(',') {
        let action = match token.trim().to_lowercase().as_str() {
            "report" => ActionType::Report,
            "quarantine" => ActionType::Quarantine,
            "block" => ActionType::Block,
            "kill" | "killprocess" | "kill_process" => ActionType::KillProcess,
            "clean" | "cleanpersistence" | "clean_persistence" => ActionType::CleanPersistence,
            "delete" => ActionType::Delete,
            "isolate" | "networkisolate" | "network_isolate" => ActionType::NetworkIsolate,
            "blocklist" | "addtoblocklist" | "add_to_blocklist" => ActionType::AddToBlocklist,
            other => anyhow::bail!(
                "unknown action '{other}'. Valid: report, quarantine, block, kill, clean, delete, isolate, blocklist"
            ),
        };
        actions.push(action);
    }
    Ok(actions)
}

pub fn run(action: &str, key: Option<&str>, value: Option<&str>, data_dir: &Path) -> Result<()> {
    match action {
        "show" => show_policy(data_dir),
        "reset" => reset_policy(data_dir),
        "set" => {
            let k = key.context("missing key for 'policy set'")?;
            let v = value.context("missing value for 'policy set'")?;
            set_policy(data_dir, k, v)
        }
        other => anyhow::bail!("unknown policy action '{other}'. Use: show, set, reset"),
    }
}
