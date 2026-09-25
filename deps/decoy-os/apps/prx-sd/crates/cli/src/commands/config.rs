use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::Value;

use crate::ConfigAction;

/// Default configuration as a JSON value.
fn default_config() -> Value {
    serde_json::json!({
        "scan": {
            "max_file_size": 104_857_600_u64,
            "threads": null,
            "timeout_per_file_ms": 30_000,
            "scan_archives": true,
            "max_archive_depth": 3,
            "heuristic_threshold": 60,
            "exclude_paths": []
        },
        "monitor": {
            "block_mode": false,
            "channel_capacity": 4096
        },
        "update_server_url": null,
        "quarantine": {
            "auto_quarantine": false,
            "max_vault_size_mb": 1024
        }
    })
}

/// Path to the config file.
fn config_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("config.json")
}

/// Load existing config or return defaults.
fn load_config(data_dir: &Path) -> Value {
    let path = config_path(data_dir);
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(default_config)
    } else {
        default_config()
    }
}

/// Persist config to disk.
fn save_config(data_dir: &Path, config: &Value) -> Result<()> {
    let path = config_path(data_dir);
    std::fs::create_dir_all(data_dir)?;
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, json).context("failed to write config file")?;
    Ok(())
}

/// Navigate into a nested JSON value using a dot-separated key path, returning
/// a mutable reference to the target value. Creates intermediate objects as needed.
fn navigate_mut<'a>(root: &'a mut Value, key: &str) -> &'a mut Value {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = root;

    for part in &parts {
        if !current.is_object() {
            *current = Value::Object(serde_json::Map::new());
        }
        // Indexing a serde_json::Value with a string key on an Object
        // auto-creates the entry as Null if missing. This avoids the
        // borrow-checker issues with as_object_mut() + re-assignment.
        current = &mut current[*part];
    }
    current
}

/// Parse a string value into the most appropriate JSON type.
fn parse_value(s: &str) -> Value {
    // Try boolean.
    if s == "true" {
        return Value::Bool(true);
    }
    if s == "false" {
        return Value::Bool(false);
    }
    // Try null.
    if s == "null" {
        return Value::Null;
    }
    // Try integer.
    if let Ok(n) = s.parse::<i64>() {
        return Value::Number(n.into());
    }
    // Try float.
    if let Ok(n) = s.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(n) {
            return Value::Number(num);
        }
    }
    // Try JSON array/object.
    if (s.starts_with('[') && s.ends_with(']')) || (s.starts_with('{') && s.ends_with('}')) {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            return v;
        }
    }
    // Fall back to string.
    Value::String(s.to_string())
}

pub fn run(action: ConfigAction, data_dir: &Path) -> Result<()> {
    match action {
        ConfigAction::Show => {
            let config = load_config(data_dir);
            let path = config_path(data_dir);

            println!("{}", "Current Configuration".cyan().bold());
            println!("  File: {}", path.display());
            println!();
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        ConfigAction::Set { key, value } => {
            let mut config = load_config(data_dir);
            let target = navigate_mut(&mut config, &key);
            let parsed = parse_value(&value);

            let old = target.clone();
            *target = parsed.clone();

            save_config(data_dir, &config)?;

            println!(
                "{} Set {} = {} (was {})",
                "OK".green().bold(),
                key.bold(),
                serde_json::to_string(&parsed)?,
                serde_json::to_string(&old)?,
            );
            Ok(())
        }
        ConfigAction::Reset => {
            let config = default_config();
            save_config(data_dir, &config)?;
            println!("{} Configuration reset to defaults.", "OK".green().bold());
            Ok(())
        }
    }
}
