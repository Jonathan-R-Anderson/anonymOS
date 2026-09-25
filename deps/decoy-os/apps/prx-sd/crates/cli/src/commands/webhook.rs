//! Webhook alert system for sending threat notifications to external services.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Configuration holding all webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub webhooks: Vec<WebhookEndpoint>,
}

/// A single webhook endpoint definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub name: String,
    pub url: String,
    pub format: WebhookFormat,
    pub enabled: bool,
}

/// Supported webhook payload formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookFormat {
    Slack,
    Discord,
    Generic,
}

/// A threat alert to be sent via webhooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub timestamp: String,
    pub hostname: String,
    pub file_path: String,
    pub threat_name: String,
    pub threat_level: String,
    pub detection_type: String,
    pub action_taken: String,
}

const WEBHOOK_FILE: &str = "webhooks.json";

impl WebhookConfig {
    /// Load webhook configuration from `data_dir/webhooks.json`.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(WEBHOOK_FILE);
        if !path.exists() {
            return Ok(Self { webhooks: Vec::new() });
        }
        let content = std::fs::read_to_string(&path).context("failed to read webhooks.json")?;
        let config: Self = serde_json::from_str(&content).context("failed to parse webhooks.json")?;
        Ok(config)
    }

    /// Persist webhook configuration to `data_dir/webhooks.json`.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join(WEBHOOK_FILE);
        let json = serde_json::to_string_pretty(self).context("failed to serialize webhook config")?;
        std::fs::write(&path, json).context("failed to write webhooks.json")?;
        Ok(())
    }
}

/// Format a Slack Block Kit payload for the given alert.
pub fn format_slack_payload(alert: &ThreatAlert) -> serde_json::Value {
    serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "\u{1f6a8} PRX-SD Threat Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    { "type": "mrkdwn", "text": format!("*Threat:*\n{}", alert.threat_name) },
                    { "type": "mrkdwn", "text": format!("*Level:*\n{}", alert.threat_level) },
                    { "type": "mrkdwn", "text": format!("*File:*\n{}", alert.file_path) },
                    { "type": "mrkdwn", "text": format!("*Action:*\n{}", alert.action_taken) }
                ]
            },
            {
                "type": "context",
                "elements": [
                    { "type": "mrkdwn", "text": format!("Host: {} | Detection: {} | {}", alert.hostname, alert.detection_type, alert.timestamp) }
                ]
            }
        ]
    })
}

/// Format a Discord embed payload for the given alert.
pub fn format_discord_payload(alert: &ThreatAlert) -> serde_json::Value {
    serde_json::json!({
        "embeds": [{
            "title": "\u{1f6a8} PRX-SD Threat Alert",
            "color": 16_711_680,
            "fields": [
                { "name": "Threat", "value": &alert.threat_name, "inline": true },
                { "name": "Level", "value": &alert.threat_level, "inline": true },
                { "name": "File", "value": &alert.file_path },
                { "name": "Host", "value": &alert.hostname, "inline": true },
                { "name": "Detection", "value": &alert.detection_type, "inline": true },
                { "name": "Action", "value": &alert.action_taken, "inline": true }
            ],
            "footer": { "text": "PRX-SD Antivirus" },
            "timestamp": &alert.timestamp
        }]
    })
}

/// Format a generic JSON payload for the given alert.
pub fn format_generic_payload(alert: &ThreatAlert) -> serde_json::Value {
    serde_json::json!({
        "source": "prx-sd",
        "timestamp": &alert.timestamp,
        "hostname": &alert.hostname,
        "threat": {
            "name": &alert.threat_name,
            "level": &alert.threat_level,
            "detection_type": &alert.detection_type
        },
        "file": &alert.file_path,
        "action_taken": &alert.action_taken
    })
}

/// Send a threat alert to all enabled webhook endpoints.
pub async fn send_alert(config: &WebhookConfig, alert: &ThreatAlert) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    let mut errors: Vec<String> = Vec::new();

    for endpoint in &config.webhooks {
        if !endpoint.enabled {
            continue;
        }

        let payload = match endpoint.format {
            WebhookFormat::Slack => format_slack_payload(alert),
            WebhookFormat::Discord => format_discord_payload(alert),
            WebhookFormat::Generic => format_generic_payload(alert),
        };

        match client.post(&endpoint.url).json(&payload).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    errors.push(format!("webhook '{}': HTTP {} — {}", endpoint.name, status, body));
                }
            }
            Err(e) => {
                errors.push(format!("webhook '{}': {}", endpoint.name, e));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("some webhooks failed:\n{}", errors.join("\n")))
    }
}

/// Parse a format string into a `WebhookFormat`.
fn parse_format(s: &str) -> Result<WebhookFormat> {
    match s.to_lowercase().as_str() {
        "slack" => Ok(WebhookFormat::Slack),
        "discord" => Ok(WebhookFormat::Discord),
        "generic" | "json" => Ok(WebhookFormat::Generic),
        other => Err(anyhow::anyhow!(
            "unknown webhook format '{other}'. Expected: slack, discord, generic"
        )),
    }
}

/// Get the current hostname.
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map_or_else(|_| "unknown".to_string(), |s| s.trim().to_string())
}

// ── CLI handlers ──────────────────────────────────────────────────────

/// List all configured webhook endpoints.
pub fn run_list(data_dir: &Path) -> Result<()> {
    let config = WebhookConfig::load(data_dir)?;

    if config.webhooks.is_empty() {
        println!("No webhook endpoints configured.");
        println!("Use 'sd webhook add <name> <url>' to add one.");
        return Ok(());
    }

    println!("{:<20} {:<10} {:<10} URL", "NAME", "FORMAT", "ENABLED");
    println!("{}", "-".repeat(72));

    for ep in &config.webhooks {
        let fmt = match ep.format {
            WebhookFormat::Slack => "slack",
            WebhookFormat::Discord => "discord",
            WebhookFormat::Generic => "generic",
        };
        let enabled = if ep.enabled { "yes" } else { "no" };
        println!("{:<20} {:<10} {:<10} {}", ep.name, fmt, enabled, ep.url);
    }

    Ok(())
}

/// Add a new webhook endpoint.
pub fn run_add(name: &str, url: &str, format: &str, data_dir: &Path) -> Result<()> {
    let fmt = parse_format(format)?;
    let mut config = WebhookConfig::load(data_dir)?;

    // Check for duplicate names.
    if config.webhooks.iter().any(|w| w.name == name) {
        return Err(anyhow::anyhow!("a webhook named '{name}' already exists"));
    }

    config.webhooks.push(WebhookEndpoint {
        name: name.to_string(),
        url: url.to_string(),
        format: fmt,
        enabled: true,
    });

    config.save(data_dir)?;
    println!("Added webhook '{name}'.");
    Ok(())
}

/// Remove a webhook endpoint by name.
pub fn run_remove(name: &str, data_dir: &Path) -> Result<()> {
    let mut config = WebhookConfig::load(data_dir)?;
    let before = config.webhooks.len();
    config.webhooks.retain(|w| w.name != name);

    if config.webhooks.len() == before {
        return Err(anyhow::anyhow!("no webhook named '{name}' found"));
    }

    config.save(data_dir)?;
    println!("Removed webhook '{name}'.");
    Ok(())
}

/// Send a test alert to all enabled webhook endpoints.
pub async fn run_test(data_dir: &Path) -> Result<()> {
    let config = WebhookConfig::load(data_dir)?;

    let enabled_count = config.webhooks.iter().filter(|w| w.enabled).count();
    if enabled_count == 0 {
        println!("No enabled webhook endpoints. Nothing to test.");
        return Ok(());
    }

    let alert = ThreatAlert {
        timestamp: chrono::Utc::now().to_rfc3339(),
        hostname: get_hostname(),
        file_path: "/tmp/test-threat-sample.exe".to_string(),
        threat_name: "EICAR-Test-File".to_string(),
        threat_level: "Malicious".to_string(),
        detection_type: "hash_match".to_string(),
        action_taken: "Test — no action taken".to_string(),
    };

    println!("Sending test alert to {enabled_count} enabled endpoint(s)...");

    match send_alert(&config, &alert).await {
        Ok(()) => {
            println!("Test alert sent successfully.");
            Ok(())
        }
        Err(e) => {
            eprintln!("Some endpoints failed: {e:#}");
            Err(e)
        }
    }
}
