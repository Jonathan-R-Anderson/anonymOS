//! Audit logging for remediation actions.
//!
//! Stores threat audit records in JSON Lines format (.jsonl), with one
//! record per line, rotated by date. Supports querying records by date
//! range and generating summary statistics.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::{RemediationAction, ThreatAuditRecord};

/// Audit logger that writes threat records to date-partitioned JSONL files.
pub struct AuditLogger {
    log_dir: PathBuf,
}

/// Summary statistics from the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_threats: u64,
    pub total_quarantined: u64,
    pub total_processes_killed: u64,
    pub total_persistence_cleaned: u64,
    pub by_threat_level: HashMap<String, u64>,
}

impl AuditLogger {
    /// Create a new audit logger writing to the given directory.
    ///
    /// Creates the directory if it does not exist.
    pub fn new(log_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("failed to create audit log dir: {}", log_dir.display()))?;
        Ok(Self { log_dir })
    }

    /// Write a threat audit record to the date-appropriate log file.
    ///
    /// Appends a single JSON line to `audit-YYYY-MM-DD.jsonl`.
    pub fn log(&self, record: &ThreatAuditRecord) -> Result<()> {
        let date = record.timestamp.format("%Y-%m-%d");
        let filename = format!("audit-{date}.jsonl");
        let filepath = self.log_dir.join(filename);

        let json_line = serde_json::to_string(record).context("failed to serialize audit record")?;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filepath)
            .with_context(|| format!("failed to open audit log: {}", filepath.display()))?;

        writeln!(file, "{json_line}")
            .with_context(|| format!("failed to write to audit log: {}", filepath.display()))?;

        tracing::debug!(
            id = record.id.as_str(),
            file = %filepath.display(),
            "wrote audit record"
        );

        Ok(())
    }

    /// Read audit records for a date range (inclusive on both ends).
    ///
    /// Reads all `.jsonl` files whose dates fall within `[from, to]` and
    /// returns the deserialized records.
    pub fn query(&self, from: NaiveDate, to: NaiveDate) -> Result<Vec<ThreatAuditRecord>> {
        let mut records = Vec::new();
        let mut current = from;

        while current <= to {
            let filename = format!("audit-{current}.jsonl");
            let filepath = self.log_dir.join(&filename);

            if filepath.exists() {
                let file =
                    fs::File::open(&filepath).with_context(|| format!("failed to open: {}", filepath.display()))?;
                let reader = BufReader::new(file);

                for line_result in reader.lines() {
                    let line = match line_result {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::warn!(
                                file = %filepath.display(),
                                error = %e,
                                "failed to read line from audit log"
                            );
                            continue;
                        }
                    };
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<ThreatAuditRecord>(&line) {
                        Ok(record) => records.push(record),
                        Err(e) => {
                            tracing::warn!(
                                file = %filepath.display(),
                                error = %e,
                                "failed to parse audit record"
                            );
                        }
                    }
                }
            }

            current = match current.succ_opt() {
                Some(d) => d,
                None => break,
            };
        }

        Ok(records)
    }

    /// Generate summary statistics from all audit log files in the directory.
    pub fn summary(&self) -> Result<AuditSummary> {
        let mut total_threats: u64 = 0;
        let mut total_quarantined: u64 = 0;
        let mut total_processes_killed: u64 = 0;
        let mut total_persistence_cleaned: u64 = 0;
        let mut by_threat_level: HashMap<String, u64> = HashMap::new();

        let dir_entries = fs::read_dir(&self.log_dir)
            .with_context(|| format!("failed to read audit dir: {}", self.log_dir.display()))?;

        for entry in dir_entries {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().to_string());

            let is_jsonl = std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            if !name.starts_with("audit-") || !is_jsonl {
                continue;
            }

            let Ok(file) = fs::File::open(&path) else {
                continue;
            };
            let reader = BufReader::new(file);

            for line_result in reader.lines() {
                let Ok(line) = line_result else {
                    continue;
                };
                if line.trim().is_empty() {
                    continue;
                }
                let record: ThreatAuditRecord = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                total_threats += 1;
                *by_threat_level.entry(record.threat_level.clone()).or_insert(0) += 1;

                for action_result in &record.actions_taken {
                    if !action_result.success {
                        continue;
                    }
                    match &action_result.action {
                        RemediationAction::Quarantined { .. } => {
                            total_quarantined += 1;
                        }
                        RemediationAction::ProcessKilled { .. } => {
                            total_processes_killed += 1;
                        }
                        RemediationAction::PersistenceCleaned { .. } => {
                            total_persistence_cleaned += 1;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(AuditSummary {
            total_threats,
            total_quarantined,
            total_processes_killed,
            total_persistence_cleaned,
            by_threat_level,
        })
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::items_after_statements)]
mod tests {
    use super::*;
    use crate::{RemediationAction, RemediationResult};

    fn make_record(threat_level: &str, actions: Vec<RemediationResult>, date: &str) -> ThreatAuditRecord {
        let timestamp = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .expect("parse date")
            .and_hms_opt(12, 0, 0)
            .expect("hms")
            .and_utc();
        ThreatAuditRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            file_path: "/tmp/malware.exe".to_string(),
            threat_name: "TestThreat".to_string(),
            threat_level: threat_level.to_string(),
            detection_type: "hash".to_string(),
            actions_taken: actions,
            platform: "linux".to_string(),
            hostname: "testhost".to_string(),
        }
    }

    #[test]
    fn new_creates_log_directory() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let log_dir = dir.path().join("audit_logs");
        assert!(!log_dir.exists());

        let _logger = AuditLogger::new(log_dir.clone()).expect("create logger");
        assert!(log_dir.exists());
        assert!(log_dir.is_dir());
    }

    #[test]
    fn log_writes_jsonl_to_date_partitioned_file() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let logger = AuditLogger::new(dir.path().to_path_buf()).expect("create logger");

        let record = make_record(
            "malicious",
            vec![RemediationResult::success(RemediationAction::ReportOnly)],
            "2025-06-15",
        );
        logger.log(&record).expect("log record");

        let log_file = dir.path().join("audit-2025-06-15.jsonl");
        assert!(log_file.exists());

        let content = std::fs::read_to_string(&log_file).expect("read log");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: ThreatAuditRecord = serde_json::from_str(lines[0]).expect("parse record");
        assert_eq!(parsed.threat_name, "TestThreat");
        assert_eq!(parsed.threat_level, "malicious");
    }

    #[test]
    fn query_with_date_range_returns_correct_records() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let logger = AuditLogger::new(dir.path().to_path_buf()).expect("create logger");

        let r1 = make_record(
            "malicious",
            vec![RemediationResult::success(RemediationAction::ReportOnly)],
            "2025-06-10",
        );
        let r2 = make_record(
            "suspicious",
            vec![RemediationResult::success(RemediationAction::Blocked)],
            "2025-06-12",
        );
        let r3 = make_record(
            "malicious",
            vec![RemediationResult::success(RemediationAction::Deleted)],
            "2025-06-15",
        );

        logger.log(&r1).expect("log r1");
        logger.log(&r2).expect("log r2");
        logger.log(&r3).expect("log r3");

        // Query only 10th to 12th
        let from = NaiveDate::from_ymd_opt(2025, 6, 10).expect("from date");
        let to = NaiveDate::from_ymd_opt(2025, 6, 12).expect("to date");
        let results = logger.query(from, to).expect("query");
        assert_eq!(results.len(), 2);

        // Query all three
        let to_all = NaiveDate::from_ymd_opt(2025, 6, 15).expect("to date");
        let all = logger.query(from, to_all).expect("query all");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn summary_aggregates_counts_correctly() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let logger = AuditLogger::new(dir.path().to_path_buf()).expect("create logger");

        let r1 = make_record(
            "malicious",
            vec![
                RemediationResult::success(RemediationAction::Quarantined {
                    quarantine_id: "q1".to_string(),
                }),
                RemediationResult::success(RemediationAction::ProcessKilled {
                    pid: 1234,
                    name: "evil".to_string(),
                }),
            ],
            "2025-06-10",
        );
        let r2 = make_record(
            "suspicious",
            vec![RemediationResult::success(RemediationAction::ReportOnly)],
            "2025-06-10",
        );
        let r3 = make_record(
            "malicious",
            vec![RemediationResult::success(RemediationAction::PersistenceCleaned {
                persistence_type: crate::PersistenceType::Crontab,
                detail: "removed cron entry".to_string(),
            })],
            "2025-06-11",
        );

        logger.log(&r1).expect("log r1");
        logger.log(&r2).expect("log r2");
        logger.log(&r3).expect("log r3");

        let summary = logger.summary().expect("summary");
        assert_eq!(summary.total_threats, 3);
        assert_eq!(summary.total_quarantined, 1);
        assert_eq!(summary.total_processes_killed, 1);
        assert_eq!(summary.total_persistence_cleaned, 1);
        assert_eq!(*summary.by_threat_level.get("malicious").unwrap_or(&0), 2);
        assert_eq!(*summary.by_threat_level.get("suspicious").unwrap_or(&0), 1);
    }

    #[test]
    fn empty_log_directory_returns_empty_results() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let logger = AuditLogger::new(dir.path().to_path_buf()).expect("create logger");

        let from = NaiveDate::from_ymd_opt(2025, 1, 1).expect("from");
        let to = NaiveDate::from_ymd_opt(2025, 12, 31).expect("to");
        let results = logger.query(from, to).expect("query");
        assert!(results.is_empty());

        let summary = logger.summary().expect("summary");
        assert_eq!(summary.total_threats, 0);
    }

    #[test]
    fn corrupted_jsonl_line_is_skipped_gracefully() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let logger = AuditLogger::new(dir.path().to_path_buf()).expect("create logger");

        // Write a valid record first
        let record = make_record(
            "malicious",
            vec![RemediationResult::success(RemediationAction::ReportOnly)],
            "2025-06-10",
        );
        logger.log(&record).expect("log record");

        // Append a corrupted line to the same file
        let log_file = dir.path().join("audit-2025-06-10.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_file)
            .expect("open log");
        use std::io::Write;
        writeln!(file, "{{this is not valid json}}").expect("write bad line");
        // Write another valid record line manually
        writeln!(file, "{}", serde_json::to_string(&record).expect("serialize")).expect("write good line");

        let from = NaiveDate::from_ymd_opt(2025, 6, 10).expect("from");
        let to = NaiveDate::from_ymd_opt(2025, 6, 10).expect("to");
        let results = logger.query(from, to).expect("query");
        // Should get 2 valid records, skipping the corrupted line
        assert_eq!(results.len(), 2);

        let summary = logger.summary().expect("summary");
        assert_eq!(summary.total_threats, 2);
    }
}
