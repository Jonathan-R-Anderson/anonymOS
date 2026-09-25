//! Scan report export — generates self-contained HTML reports from scan results.

use std::fmt::Write;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use prx_sd_core::{ScanResult, ThreatLevel};

/// Generate a self-contained HTML scan report from scan results.
pub fn generate_html_report(results: &[ScanResult], scan_path: &str, elapsed_ms: u64) -> String {
    let total = results.len();
    let clean = results.iter().filter(|r| r.threat_level == ThreatLevel::Clean).count();
    let suspicious = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Suspicious)
        .count();
    let malicious = results
        .iter()
        .filter(|r| r.threat_level == ThreatLevel::Malicious)
        .count();

    let now = chrono::Local::now();
    let scan_date = now.format("%Y-%m-%d %H:%M:%S").to_string();

    let hostname = get_hostname();

    let elapsed_display = crate::output::format_duration(elapsed_ms);

    // Build threat table rows (only non-clean results).
    let mut threat_rows = String::new();
    for r in results {
        if r.threat_level == ThreatLevel::Clean {
            continue;
        }

        let level_class = match r.threat_level {
            ThreatLevel::Clean => "clean",
            ThreatLevel::Suspicious => "suspicious",
            ThreatLevel::Malicious => "malicious",
        };
        let level_text = match r.threat_level {
            ThreatLevel::Clean => "Clean",
            ThreatLevel::Suspicious => "Suspicious",
            ThreatLevel::Malicious => "Malicious",
        };
        let threat_name = r.threat_name.as_deref().unwrap_or("-");
        let detection = r
            .detection_type
            .as_ref()
            .map_or_else(|| "-".to_string(), |d| format!("{d}"));
        let path_display = html_escape(r.path.display().to_string().as_str());
        let threat_name_escaped = html_escape(threat_name);

        let _ = writeln!(
            threat_rows,
            "<tr>\
                <td title=\"{path_display}\">{path_display}</td>\
                <td class=\"{level_class}\">{level_text}</td>\
                <td>{threat_name_escaped}</td>\
                <td>{detection}</td>\
                <td>{} ms</td>\
            </tr>",
            r.scan_time_ms,
        );
    }

    let no_threats_row = if threat_rows.is_empty() {
        "<tr><td colspan=\"5\" style=\"text-align:center;color:#4caf50;padding:20px;\">No threats detected</td></tr>"
    } else {
        ""
    };

    let scan_path_escaped = html_escape(scan_path);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PRX-SD Scan Report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0; color: #00d4ff; font-size: 1.8em; }}
  .header .meta {{ text-align: right; font-size: 0.9em; color: #999; }}
  .scan-target {{ background: #16213e; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.95em; }}
  .scan-target strong {{ color: #00d4ff; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
  .stat {{ background: #16213e; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat .label {{ font-size: 0.85em; color: #999; margin-bottom: 4px; }}
  .stat .value {{ font-size: 2em; font-weight: bold; }}
  .clean {{ color: #4caf50; }}
  .suspicious {{ color: #ff9800; }}
  .malicious {{ color: #f44336; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
  th {{ background: #0f3460; padding: 12px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #16213e; word-break: break-all; }}
  tr:hover {{ background: #16213e; }}
  .footer {{ margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }}
  @media (max-width: 600px) {{
    .header {{ flex-direction: column; align-items: flex-start; }}
    .header .meta {{ text-align: left; }}
    .summary {{ grid-template-columns: 1fr 1fr; }}
    table {{ font-size: 0.85em; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>PRX-SD Scan Report</h1>
    <div class="meta">
      <div>{scan_date}</div>
      <div>{hostname}</div>
    </div>
  </div>

  <div class="scan-target">
    <strong>Scan path:</strong> {scan_path_escaped}
  </div>

  <div class="summary">
    <div class="stat">
      <div class="label">Total Files</div>
      <div class="value">{total}</div>
    </div>
    <div class="stat">
      <div class="label">Clean</div>
      <div class="value clean">{clean}</div>
    </div>
    <div class="stat">
      <div class="label">Suspicious</div>
      <div class="value suspicious">{suspicious}</div>
    </div>
    <div class="stat">
      <div class="label">Malicious</div>
      <div class="value malicious">{malicious}</div>
    </div>
    <div class="stat">
      <div class="label">Scan Time</div>
      <div class="value" style="font-size:1.2em;">{elapsed_display}</div>
    </div>
  </div>

  <h2 style="color:#00d4ff;">Detections</h2>
  <table>
    <thead>
      <tr>
        <th>File Path</th>
        <th>Threat Level</th>
        <th>Threat Name</th>
        <th>Detection Type</th>
        <th>Scan Time</th>
      </tr>
    </thead>
    <tbody>
      {threat_rows}{no_threats_row}
    </tbody>
  </table>

  <div class="footer">
    Generated by PRX-SD v{version} &mdash; open-source antivirus engine
  </div>
</div>
</body>
</html>"#,
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Retrieve the system hostname, falling back to "unknown" on error.
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map_or_else(|_| "unknown".to_string(), |s| s.trim().to_string())
}

/// Minimal HTML entity escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Write an HTML report to disk.
pub fn write_report(path: &Path, html: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    std::fs::write(path, html).with_context(|| format!("failed to write report to {}", path.display()))?;
    Ok(())
}

/// Run the standalone `sd report` command: read JSON scan results and produce HTML.
pub fn run(output: &Path, input: &str) -> Result<()> {
    let json_str = if input == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read from stdin")?;
        buf
    } else {
        std::fs::read_to_string(input).with_context(|| format!("failed to read input file: {input}"))?
    };

    let results: Vec<ScanResult> = serde_json::from_str(&json_str).context("failed to parse JSON scan results")?;

    let html = generate_html_report(&results, "(from JSON input)", 0);
    write_report(output, &html)?;

    eprintln!("Report saved to {}", output.display());
    Ok(())
}
