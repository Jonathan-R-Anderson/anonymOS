use colored::Colorize;
use prx_sd_core::{ScanResult, ThreatLevel};

/// Print a single scan result to stdout with optional ANSI colour.
pub fn print_scan_result(result: &ScanResult, colored: bool) {
    let level_str = match result.threat_level {
        ThreatLevel::Clean => {
            if colored {
                "CLEAN".green().to_string()
            } else {
                "CLEAN".to_string()
            }
        }
        ThreatLevel::Suspicious => {
            if colored {
                "SUSPICIOUS".yellow().bold().to_string()
            } else {
                "SUSPICIOUS".to_string()
            }
        }
        ThreatLevel::Malicious => {
            if colored {
                "MALICIOUS".red().bold().to_string()
            } else {
                "MALICIOUS".to_string()
            }
        }
    };

    let threat_info = result.threat_name.as_deref().unwrap_or("-");

    let detection = result
        .detection_type
        .as_ref()
        .map_or_else(|| "-".to_string(), std::string::ToString::to_string);

    println!(
        "  [{level_str}] {} | {threat_info} ({detection}) [{} ms]",
        result.path.display(),
        result.scan_time_ms,
    );

    for detail in &result.details {
        println!("         {}", detail.dimmed());
    }
}

/// Print a summary line for a batch of scan results.
pub fn print_scan_summary(results: &[ScanResult], elapsed_ms: u64) {
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

    println!("{}", "Scan Summary".cyan().bold());
    println!("  Total scanned: {total}");
    println!("  Clean:         {}", format!("{clean}").green());
    if suspicious > 0 {
        println!("  Suspicious:    {}", format!("{suspicious}").yellow().bold());
    } else {
        println!("  Suspicious:    {suspicious}");
    }
    if malicious > 0 {
        println!("  Malicious:     {}", format!("{malicious}").red().bold());
    } else {
        println!("  Malicious:     {malicious}");
    }
    println!("  Time elapsed:  {}", format_duration(elapsed_ms));
}

/// Print a simple ASCII table to stdout.
///
/// Columns are auto-sized to the widest value in each column (including the
/// header). Padding of two spaces is added between columns.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }

    // Determine column widths.
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.len());
            }
        }
    }

    // Header line.
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let w = widths.get(i).copied().unwrap_or(0);
            format!("{h:<w$}")
        })
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", header_line.bold());

    // Separator.
    let sep: String = widths.iter().map(|&w| "-".repeat(w)).collect::<Vec<_>>().join("  ");
    println!("{sep}");

    // Rows.
    for row in rows {
        let line: String = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(0);
                format!("{cell:<w$}")
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("{line}");
    }
}

/// Format a byte count into a human-readable string (B, KB, MB, GB, TB).
#[allow(clippy::cast_precision_loss)] // Precision loss is acceptable for display formatting.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Format a duration in milliseconds into a human-readable string.
#[allow(clippy::cast_precision_loss)] // Precision loss is acceptable for display formatting.
pub fn format_duration(ms: u64) -> String {
    if ms < 1_000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        let secs = ms as f64 / 1_000.0;
        format!("{secs:.2} s")
    } else if ms < 3_600_000 {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1_000;
        format!("{mins}m {secs}s")
    } else {
        let hours = ms / 3_600_000;
        let mins = (ms % 3_600_000) / 60_000;
        format!("{hours}h {mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1_048_576), "1.00 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.00 GB");
        assert_eq!(format_bytes(1_099_511_627_776), "1.00 TB");
    }

    #[test]
    fn format_duration_units() {
        assert_eq!(format_duration(50), "50 ms");
        assert_eq!(format_duration(1_500), "1.50 s");
        assert_eq!(format_duration(90_000), "1m 30s");
        assert_eq!(format_duration(3_660_000), "1h 1m");
    }
}
