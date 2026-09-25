//! Email alert system for sending threat notifications via SMTP.
//!
//! Configuration is stored in `data_dir/email_config.json`.
//! Uses the `lettre` crate for SMTP transport.

use std::path::Path;

use anyhow::{Context, Result};
use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};

use super::webhook::ThreatAlert;

const EMAIL_CONFIG_FILE: &str = "email_config.json";

/// SMTP email configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (typically 587 for STARTTLS, 465 for implicit TLS).
    pub smtp_port: u16,
    /// SMTP username for authentication.
    pub username: String,
    /// SMTP password for authentication.
    pub password: String,
    /// Sender email address (RFC 5322 "From" header).
    pub from: String,
    /// List of recipient email addresses.
    pub to: Vec<String>,
    /// Whether to use TLS (STARTTLS on port 587, or implicit TLS on port 465).
    pub use_tls: bool,
    /// Whether email alerts are enabled.
    pub enabled: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_host: "smtp.example.com".to_owned(),
            smtp_port: 587,
            username: String::new(),
            password: String::new(),
            from: "prx-sd@example.com".to_owned(),
            to: Vec::new(),
            use_tls: true,
            enabled: false,
        }
    }
}

impl EmailConfig {
    /// Load email configuration from `data_dir/email_config.json`.
    ///
    /// Returns the default (disabled) configuration if the file does not exist.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(EMAIL_CONFIG_FILE);
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path).context("failed to read email_config.json")?;
        let config: Self = serde_json::from_str(&content).context("failed to parse email_config.json")?;
        Ok(config)
    }

    /// Persist email configuration to `data_dir/email_config.json`.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join(EMAIL_CONFIG_FILE);
        let json = serde_json::to_string_pretty(self).context("failed to serialize email config")?;
        std::fs::write(&path, json).context("failed to write email_config.json")?;
        Ok(())
    }

    /// Validate that the configuration has the minimum required fields.
    pub fn validate(&self) -> Result<()> {
        if self.smtp_host.is_empty() {
            return Err(anyhow::anyhow!("smtp_host is required"));
        }
        if self.from.is_empty() {
            return Err(anyhow::anyhow!("from address is required"));
        }
        if self.to.is_empty() {
            return Err(anyhow::anyhow!("at least one recipient (to) is required"));
        }
        Ok(())
    }
}

/// Build an HTML email body for a threat alert.
fn build_html_body(alert: &ThreatAlert) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
  <div style="background: #dc3545; color: white; padding: 16px 24px;">
    <h2 style="margin: 0;">PRX-SD Threat Alert</h2>
  </div>
  <div style="padding: 24px;">
    <table style="width: 100%; border-collapse: collapse;">
      <tr><td style="padding: 8px 0; font-weight: bold; width: 140px;">Threat:</td><td style="padding: 8px 0;">{threat_name}</td></tr>
      <tr><td style="padding: 8px 0; font-weight: bold;">Level:</td><td style="padding: 8px 0; color: #dc3545; font-weight: bold;">{threat_level}</td></tr>
      <tr><td style="padding: 8px 0; font-weight: bold;">File:</td><td style="padding: 8px 0; font-family: monospace; font-size: 13px;">{file_path}</td></tr>
      <tr><td style="padding: 8px 0; font-weight: bold;">Detection:</td><td style="padding: 8px 0;">{detection_type}</td></tr>
      <tr><td style="padding: 8px 0; font-weight: bold;">Action:</td><td style="padding: 8px 0;">{action_taken}</td></tr>
      <tr><td style="padding: 8px 0; font-weight: bold;">Host:</td><td style="padding: 8px 0;">{hostname}</td></tr>
      <tr><td style="padding: 8px 0; font-weight: bold;">Time:</td><td style="padding: 8px 0;">{timestamp}</td></tr>
    </table>
  </div>
  <div style="padding: 12px 24px; background: #f8f9fa; font-size: 12px; color: #6c757d;">
    Sent by PRX-SD Antivirus Engine
  </div>
</div>
</body>
</html>"#,
        threat_name = alert.threat_name,
        threat_level = alert.threat_level,
        file_path = alert.file_path,
        detection_type = alert.detection_type,
        action_taken = alert.action_taken,
        hostname = alert.hostname,
        timestamp = alert.timestamp,
    )
}

/// Send a threat alert email using the given SMTP configuration.
pub async fn send_threat_alert(config: &EmailConfig, alert: &ThreatAlert) -> Result<()> {
    config.validate()?;

    let from_mailbox: Mailbox = config
        .from
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid from address '{}': {}", config.from, e))?;

    let html_body = build_html_body(alert);
    let subject = format!("[PRX-SD ALERT] {} — {}", alert.threat_level, alert.threat_name);

    let creds = Credentials::new(config.username.clone(), config.password.clone());

    let mailer = if config.use_tls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
            .map_err(|e| anyhow::anyhow!("failed to create SMTP transport: {e}"))?
            .port(config.smtp_port)
            .credentials(creds)
            .build()
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
            .port(config.smtp_port)
            .credentials(creds)
            .build()
    };

    let mut errors: Vec<String> = Vec::new();

    for recipient in &config.to {
        let to_mailbox: Mailbox = match recipient.parse() {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("invalid recipient '{recipient}': {e}"));
                continue;
            }
        };

        let email = match Message::builder()
            .from(from_mailbox.clone())
            .to(to_mailbox)
            .subject(&subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.clone())
        {
            Ok(msg) => msg,
            Err(e) => {
                errors.push(format!("failed to build email for '{recipient}': {e}"));
                continue;
            }
        };

        if let Err(e) = mailer.send(email).await {
            errors.push(format!("failed to send to '{recipient}': {e}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("some emails failed:\n{}", errors.join("\n")))
    }
}

// ── CLI handlers ──────────────────────────────────────────────────────

/// Get the current hostname.
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map_or_else(|_| "unknown".to_owned(), |s| s.trim().to_owned())
}

/// Interactive-style configuration: write a default config for the user to edit.
pub fn run_configure(data_dir: &Path) -> Result<()> {
    let config_path = data_dir.join(EMAIL_CONFIG_FILE);
    if config_path.exists() {
        println!("Email configuration already exists at: {}", config_path.display());
        println!("Edit the file directly or delete it and re-run this command.");
        let config = EmailConfig::load(data_dir)?;
        println!("\nCurrent settings:");
        println!("  SMTP host:    {}", config.smtp_host);
        println!("  SMTP port:    {}", config.smtp_port);
        println!("  Username:     {}", config.username);
        println!("  From:         {}", config.from);
        println!("  Recipients:   {:?}", config.to);
        println!("  TLS:          {}", config.use_tls);
        println!("  Enabled:      {}", config.enabled);
        return Ok(());
    }

    let config = EmailConfig::default();
    config.save(data_dir)?;
    println!("Created default email configuration at: {}", config_path.display());
    println!("Edit the file to set your SMTP credentials and recipients.");
    println!("Then run 'sd email-alert test' to verify connectivity.");
    Ok(())
}

/// Send a test alert email.
pub async fn run_test(data_dir: &Path) -> Result<()> {
    let config = EmailConfig::load(data_dir)?;

    if !config.enabled {
        println!("Email alerts are disabled. Set \"enabled\": true in email_config.json.");
        return Ok(());
    }

    config.validate()?;

    let alert = ThreatAlert {
        timestamp: chrono::Utc::now().to_rfc3339(),
        hostname: get_hostname(),
        file_path: "/tmp/test-threat-sample.exe".to_owned(),
        threat_name: "EICAR-Test-File".to_owned(),
        threat_level: "Malicious".to_owned(),
        detection_type: "hash_match".to_owned(),
        action_taken: "Test - no action taken".to_owned(),
    };

    println!("Sending test alert to {} recipient(s)...", config.to.len());

    send_threat_alert(&config, &alert).await?;
    println!("Test email sent successfully.");
    Ok(())
}

/// Send an alert with custom parameters (for programmatic use).
pub async fn run_send(threat_name: &str, threat_level: &str, file_path: &str, data_dir: &Path) -> Result<()> {
    let config = EmailConfig::load(data_dir)?;

    if !config.enabled {
        return Err(anyhow::anyhow!(
            "email alerts are disabled. Set \"enabled\": true in email_config.json"
        ));
    }

    config.validate()?;

    let alert = ThreatAlert {
        timestamp: chrono::Utc::now().to_rfc3339(),
        hostname: get_hostname(),
        file_path: file_path.to_owned(),
        threat_name: threat_name.to_owned(),
        threat_level: threat_level.to_owned(),
        detection_type: "manual".to_owned(),
        action_taken: "alert sent".to_owned(),
    };

    send_threat_alert(&config, &alert).await?;
    println!("Alert email sent.");
    Ok(())
}
