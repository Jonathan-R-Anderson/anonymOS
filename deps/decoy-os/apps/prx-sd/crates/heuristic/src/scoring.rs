//! Score aggregation and threat-level classification.
//!
//! Each heuristic finding contributes a weighted score. The aggregate score is
//! capped at 100 and mapped to a [`ThreatLevel`](crate::ThreatLevel).

use serde::{Deserialize, Serialize};

use crate::{Finding, ThreatLevel};

/// Configurable weights for each class of heuristic finding.
///
/// Weights represent the maximum score contribution for a single occurrence of
/// the corresponding finding type. Multiple findings of the same type may each
/// contribute their full weight (the total is capped at 100).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub high_entropy: u32,
    pub packed_section: u32,
    pub suspicious_api: u32,
    pub anti_debug: u32,
    pub zero_timestamp: u32,
    pub writable_code: u32,
    pub no_imports: u32,
    pub packer_detected: u32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            high_entropy: 30,
            packed_section: 25,
            suspicious_api: 20,
            anti_debug: 20,
            zero_timestamp: 10,
            writable_code: 20,
            no_imports: 25,
            packer_detected: 20,
        }
    }
}

impl ScoringWeights {
    /// Return the weight for a single [`Finding`].
    #[allow(clippy::match_same_arms)] // Intentional: each finding type has its own weight for independent tuning
    const fn weight_for(&self, finding: &Finding) -> u32 {
        match finding {
            Finding::HighEntropy(_) => self.high_entropy,
            Finding::PackedSection { .. } => self.packed_section,
            Finding::SuspiciousApi(_) => self.suspicious_api,
            Finding::AntiDebug => self.anti_debug,
            Finding::ZeroTimestamp => self.zero_timestamp,
            Finding::WritableCodeSection => self.writable_code,
            Finding::NoImports => self.no_imports,
            Finding::PackerDetected(_) => self.packer_detected,
            // Secondary indicators contribute a modest fixed amount.
            Finding::SelfModifying => 15,
            Finding::UPXPacked => self.packer_detected,
            Finding::HighImportCount => 5,
            Finding::SuspiciousSection(_) => 10,
            Finding::ResourceAnomaly(_) => 10,
            // Office macro findings
            Finding::OfficeMacros => 5,
            Finding::OfficeAutoExecMacro(_) => 20,
            Finding::OfficeShellExecution => 30,
            Finding::OfficeNetworkAccess => 25,
            Finding::OfficeDde => 25,
            Finding::OfficeObfuscation(_) => 15,
            // OfficeMacroThreatScore carries its own value directly
            Finding::OfficeMacroThreatScore(s) => *s,
            // PDF exploit findings
            Finding::PdfJavaScript => 20,
            Finding::PdfLaunchAction => 30,
            Finding::PdfAutoExecJavaScript => 40,
            Finding::PdfCvePattern(_) => 50,
            // PdfThreatScore carries its own value directly
            Finding::PdfThreatScore(s) => *s,
        }
    }
}

/// Compute an aggregate heuristic score from a list of findings and return the
/// corresponding [`ThreatLevel`].
///
/// The raw sum of finding weights is capped at 100. Duplicate finding types
/// each contribute independently (e.g. three `SuspiciousApi` findings yield
/// `3 * suspicious_api` weight before capping).
pub fn aggregate_score(findings: &[Finding]) -> (u32, ThreatLevel) {
    aggregate_score_with_weights(findings, &ScoringWeights::default())
}

/// Like [`aggregate_score`] but with caller-supplied weights.
pub fn aggregate_score_with_weights(findings: &[Finding], weights: &ScoringWeights) -> (u32, ThreatLevel) {
    let raw: u32 = findings.iter().map(|f| weights.weight_for(f)).sum();

    // Bonus for multiple suspicious API findings: 3+ co-occurring suspicious
    // APIs is a strong indicator of injection/evasion toolkits.
    let api_count = findings
        .iter()
        .filter(|f| matches!(f, Finding::SuspiciousApi(_)))
        .count();
    let bonus = if api_count >= 3 { 15u32 } else { 0 };

    let score = (raw + bonus).min(100);
    let level = ThreatLevel::from_score(score);
    (score, level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_findings_are_clean() {
        let (score, level) = aggregate_score(&[]);
        assert_eq!(score, 0);
        assert_eq!(level, ThreatLevel::Clean);
    }

    #[test]
    fn single_high_entropy() {
        let (score, level) = aggregate_score(&[Finding::HighEntropy(7.8)]);
        assert_eq!(score, 30);
        assert_eq!(level, ThreatLevel::Suspicious);
    }

    #[test]
    fn combined_findings_suspicious() {
        let findings = vec![
            Finding::ZeroTimestamp,             // 10
            Finding::SuspiciousApi("X".into()), // 20
        ];
        let (score, level) = aggregate_score(&findings);
        assert_eq!(score, 30);
        assert_eq!(level, ThreatLevel::Suspicious);
    }

    #[test]
    fn combined_findings_malicious() {
        let findings = vec![
            Finding::HighEntropy(7.9),             // 30
            Finding::PackerDetected("UPX".into()), // 20
            Finding::AntiDebug,                    // 20
        ];
        let (score, level) = aggregate_score(&findings);
        assert_eq!(score, 70);
        assert_eq!(level, ThreatLevel::Malicious);
    }

    #[test]
    fn score_capped_at_100() {
        let findings = vec![
            Finding::HighEntropy(7.9),
            Finding::PackedSection {
                name: "s".into(),
                entropy: 7.8,
            },
            Finding::PackerDetected("UPX".into()),
            Finding::AntiDebug,
            Finding::WritableCodeSection,
            Finding::NoImports,
            Finding::ZeroTimestamp,
        ];
        let (score, _) = aggregate_score(&findings);
        assert!(score <= 100, "score should be capped at 100, got {score}");
    }

    #[test]
    fn custom_weights() {
        let weights = ScoringWeights {
            high_entropy: 50,
            ..Default::default()
        };
        let findings = vec![Finding::HighEntropy(7.5)];
        let (score, level) = aggregate_score_with_weights(&findings, &weights);
        assert_eq!(score, 50);
        assert_eq!(level, ThreatLevel::Suspicious);
    }

    #[test]
    fn threat_level_boundaries() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(29), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(59), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(60), ThreatLevel::Malicious);
        assert_eq!(ThreatLevel::from_score(100), ThreatLevel::Malicious);
    }
}
