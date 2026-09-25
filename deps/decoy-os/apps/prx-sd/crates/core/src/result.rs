use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The category of detection that flagged a file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionType {
    /// Matched a known-bad hash (SHA-256 / MD5).
    Hash,
    /// Matched a YARA rule.
    YaraRule,
    /// Exceeded the heuristic scoring threshold.
    Heuristic,
    /// Flagged by behavioral analysis (sandbox / runtime monitor).
    Behavioral,
}

/// Threat severity derived from a numeric score or explicit classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// No threat detected.
    Clean,
    /// Indicators present but below the malicious threshold.
    Suspicious,
    /// Confirmed malicious.
    Malicious,
}

impl ThreatLevel {
    /// Map a heuristic / aggregate score to a threat level.
    ///
    /// * 0 ..= 29  → `Clean`
    /// * 30 ..= 59 → `Suspicious`
    /// * 60 ..     → `Malicious`
    pub const fn from_score(score: u32) -> Self {
        match score {
            0..=29 => Self::Clean,
            30..=59 => Self::Suspicious,
            _ => Self::Malicious,
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Suspicious => write!(f, "Suspicious"),
            Self::Malicious => write!(f, "Malicious"),
        }
    }
}

impl std::fmt::Display for DetectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hash => write!(f, "Hash"),
            Self::YaraRule => write!(f, "YaraRule"),
            Self::Heuristic => write!(f, "Heuristic"),
            Self::Behavioral => write!(f, "Behavioral"),
        }
    }
}

/// The outcome of scanning a single file (or byte buffer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Absolute path of the scanned file (may be synthetic for in-memory scans).
    pub path: PathBuf,
    /// Overall threat classification.
    pub threat_level: ThreatLevel,
    /// Which detection method(s) triggered, if any.
    pub detection_type: Option<DetectionType>,
    /// Human-readable threat name, e.g. `"Trojan.GenericKD.12345"`.
    pub threat_name: Option<String>,
    /// Detailed notes from each scanning phase.
    pub details: Vec<String>,
    /// Wall-clock time spent scanning this file, in milliseconds.
    pub scan_time_ms: u64,
}

impl ScanResult {
    /// Produce a clean (no-threat) result for the given path.
    pub fn clean(path: impl AsRef<Path>, scan_time_ms: u64) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            threat_level: ThreatLevel::Clean,
            detection_type: None,
            threat_name: None,
            details: Vec::new(),
            scan_time_ms,
        }
    }

    /// Produce a result that records a positive detection.
    pub fn detected(
        path: impl AsRef<Path>,
        threat_level: ThreatLevel,
        detection_type: DetectionType,
        threat_name: impl Into<String>,
        details: Vec<String>,
        scan_time_ms: u64,
    ) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            threat_level,
            detection_type: Some(detection_type),
            threat_name: Some(threat_name.into()),
            details,
            scan_time_ms,
        }
    }

    /// Merge multiple results for the same path (e.g. different engines) into
    /// one, keeping the highest threat level and collecting all details.
    pub fn aggregate(path: impl AsRef<Path>, results: &[Self]) -> Self {
        let threat_level = results
            .iter()
            .map(|r| r.threat_level)
            .max()
            .unwrap_or(ThreatLevel::Clean);

        // Pick the detection type from the highest-severity sub-result,
        // using explicit priority: Hash(0) > YaraRule(1) > Heuristic(2) > Behavioral(3).
        let detection_type = results
            .iter()
            .filter(|r| r.threat_level == threat_level)
            .filter_map(|r| r.detection_type.clone())
            .min_by_key(|dt| match dt {
                DetectionType::Hash => 0,
                DetectionType::YaraRule => 1,
                DetectionType::Heuristic => 2,
                DetectionType::Behavioral => 3,
            });

        // Pick the threat name from the sub-result that matches the chosen detection type.
        let threat_name = results
            .iter()
            .filter(|r| r.threat_level == threat_level)
            .filter(|r| r.detection_type == detection_type)
            .find_map(|r| r.threat_name.clone());

        let details: Vec<String> = results.iter().flat_map(|r| r.details.iter().cloned()).collect();

        let scan_time_ms = results.iter().map(|r| r.scan_time_ms).sum();

        Self {
            path: path.as_ref().to_path_buf(),
            threat_level,
            detection_type,
            threat_name,
            details,
            scan_time_ms,
        }
    }

    /// Returns `true` when the file is not clean.
    pub fn is_threat(&self) -> bool {
        self.threat_level != ThreatLevel::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(29), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(59), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(60), ThreatLevel::Malicious);
        assert_eq!(ThreatLevel::from_score(100), ThreatLevel::Malicious);
    }

    #[test]
    fn clean_result() {
        let r = ScanResult::clean("/tmp/safe.txt", 5);
        assert!(!r.is_threat());
        assert_eq!(r.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn aggregate_picks_highest() {
        let a = ScanResult::clean("/tmp/x", 2);
        let b = ScanResult::detected(
            "/tmp/x",
            ThreatLevel::Malicious,
            DetectionType::YaraRule,
            "Trojan.Test",
            vec!["matched rule X".into()],
            3,
        );
        let agg = ScanResult::aggregate("/tmp/x", &[a, b]);
        assert_eq!(agg.threat_level, ThreatLevel::Malicious);
        assert_eq!(agg.scan_time_ms, 5);
        assert_eq!(agg.details.len(), 1);
    }
}
