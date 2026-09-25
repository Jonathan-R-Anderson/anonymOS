//! Behavioral sequence classifier.
//!
//! Analyzes syscall sequences from sandbox traces to detect malicious patterns.
//! Uses a rule-based model (no ONNX needed) that matches known attack chains.
//!
//! Each [`AttackPattern`] defines a sequence of syscall names that, when found
//! in order within a trace, indicates a specific attack technique. The
//! classifier scans the trace with a sliding subsequence match and aggregates
//! all hits into a single [`BehaviorPrediction`].

use serde::{Deserialize, Serialize};

// ── Public types ────────────────────────────────────────────────────────────

/// A pre-defined attack chain expressed as an ordered sequence of syscall names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    /// Human-readable name of the attack pattern (e.g. "`reverse_shell`").
    pub name: String,
    /// Ordered syscall names that must appear (in order, not necessarily
    /// contiguous) for the pattern to match.
    pub syscall_sequence: Vec<String>,
    /// MITRE ATT&CK-style category (e.g. "execution", "persistence").
    pub category: String,
    /// Threat score contribution when this pattern matches (0–100).
    pub score: u32,
}

/// Result of running the behavior classifier on a syscall trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPrediction {
    /// Whether the aggregate score exceeds the malicious threshold.
    pub is_malicious: bool,
    /// Confidence value in the range 0.0–1.0.
    pub confidence: f32,
    /// Names of all patterns that matched.
    pub matched_patterns: Vec<String>,
    /// Aggregate threat score (capped at 100).
    pub score: u32,
}

/// Classifier that holds a set of [`AttackPattern`]s and matches them against
/// syscall traces.
pub struct BehaviorClassifier {
    patterns: Vec<AttackPattern>,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Check whether `needle` appears as an ordered subsequence inside `haystack`.
///
/// The elements need not be contiguous — only the relative ordering matters.
fn is_subsequence(haystack: &[&str], needle: &[String]) -> bool {
    if needle.is_empty() {
        return false; // empty pattern should not match
    }
    let mut hi = 0;
    for n in needle {
        let mut found = false;
        while hi < haystack.len() {
            if haystack.get(hi).is_some_and(|h| *h == n.as_str()) {
                hi += 1;
                found = true;
                break;
            }
            hi += 1;
        }
        if !found {
            return false;
        }
    }
    true
}

/// Mining pool ports commonly used by crypto miners.
const MINING_POOL_PORTS: &[u16] = &[3333, 5555, 7777, 8888];

// ── Implementation ──────────────────────────────────────────────────────────

impl BehaviorClassifier {
    /// Create a new classifier pre-loaded with built-in attack chain patterns.
    pub fn new() -> Self {
        Self {
            patterns: Self::builtin_patterns(),
        }
    }

    /// Classify a trace given as a slice of syscall name strings.
    ///
    /// This is the primary entry point when you already have extracted names
    /// (e.g. from a non-Linux stub trace or test harness).
    pub fn classify_from_names(&self, names: &[&str]) -> BehaviorPrediction {
        let mut matched: Vec<String> = Vec::new();
        let mut total_score: u32 = 0;

        for pattern in &self.patterns {
            if is_subsequence(names, &pattern.syscall_sequence) {
                matched.push(pattern.name.clone());
                total_score = total_score.saturating_add(pattern.score);
            }
        }

        let total_score = total_score.min(100);

        // Confidence is proportional to the number of distinct patterns matched
        // relative to the total pattern count.
        let confidence = if self.patterns.is_empty() {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            {
                (matched.len() as f32 / self.patterns.len() as f32).min(1.0)
            }
        };

        BehaviorPrediction {
            is_malicious: total_score >= 60,
            confidence,
            matched_patterns: matched,
            score: total_score,
        }
    }

    /// Classify a trace of [`SyscallEvent`]-like structs.
    ///
    /// Because [`SyscallEvent`] is behind `#[cfg(target_os = "linux")]` in the
    /// sandbox crate, this method accepts any type that exposes a `.name` field
    /// via the [`SyscallName`] trait.  For convenience the most common path is
    /// to call [`classify_from_names`](Self::classify_from_names) directly.
    pub fn classify<T: SyscallName>(&self, syscalls: &[T]) -> BehaviorPrediction {
        let names: Vec<&str> = syscalls.iter().map(SyscallName::syscall_name).collect();
        self.classify_from_names(&names)
    }

    // ── Built-in attack patterns ────────────────────────────────────────

    fn builtin_patterns() -> Vec<AttackPattern> {
        vec![
            // 1. Reverse shell: socket → connect → dup2 → execve
            AttackPattern {
                name: "reverse_shell".into(),
                syscall_sequence: vec!["socket".into(), "connect".into(), "dup2".into(), "execve".into()],
                category: "execution".into(),
                score: 90,
            },
            // 2. Dropper: write → chmod → execve
            AttackPattern {
                name: "dropper".into(),
                syscall_sequence: vec!["write".into(), "chmod".into(), "execve".into()],
                category: "execution".into(),
                score: 80,
            },
            // 3. Credential theft: open → read → socket → connect
            //    (targeting /etc/shadow or similar)
            AttackPattern {
                name: "credential_theft".into(),
                syscall_sequence: vec!["open".into(), "read".into(), "socket".into(), "connect".into()],
                category: "credential_access".into(),
                score: 85,
            },
            // 3b. Credential theft via openat (modern kernels)
            AttackPattern {
                name: "credential_theft_openat".into(),
                syscall_sequence: vec!["openat".into(), "read".into(), "socket".into(), "connect".into()],
                category: "credential_access".into(),
                score: 85,
            },
            // 4. Privilege escalation: setuid → execve
            AttackPattern {
                name: "privilege_escalation".into(),
                syscall_sequence: vec!["setuid".into(), "execve".into()],
                category: "privilege_escalation".into(),
                score: 75,
            },
            // 5a. Persistence via crontab: open → write (targeting /etc/crontab)
            AttackPattern {
                name: "persistence_crontab".into(),
                syscall_sequence: vec!["open".into(), "write".into()],
                category: "persistence".into(),
                score: 60,
            },
            // 5b. Persistence via systemd: openat → write
            AttackPattern {
                name: "persistence_systemd".into(),
                syscall_sequence: vec!["openat".into(), "write".into()],
                category: "persistence".into(),
                score: 60,
            },
            // 6. Data exfiltration: opendir → readdir → open → read → socket → sendto
            AttackPattern {
                name: "data_exfiltration".into(),
                syscall_sequence: vec![
                    "getdents64".into(),
                    "open".into(),
                    "read".into(),
                    "socket".into(),
                    "sendto".into(),
                ],
                category: "exfiltration".into(),
                score: 85,
            },
            // 7. Crypto mining: socket → connect (mining pool ports checked separately)
            AttackPattern {
                name: "crypto_mining".into(),
                syscall_sequence: vec!["socket".into(), "connect".into()],
                category: "impact".into(),
                score: 50,
            },
        ]
    }
}

impl Default for BehaviorClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── Trait for abstracting over syscall event types ───────────────────────────

/// Trait that exposes the syscall name from an event struct.
///
/// This allows [`BehaviorClassifier::classify`] to work with both the
/// Linux-only `SyscallEvent` and the cross-platform `SyscallEventStub`.
pub trait SyscallName {
    /// Return the human-readable syscall name.
    fn syscall_name(&self) -> &str;
}

// Blanket impl for anything that has a public `name: String` behind a reference.
// We provide impls for the stub type; the Linux `SyscallEvent` has the same shape.

/// Simple wrapper for testing: a borrowed string slice as a syscall event.
impl SyscallName for &str {
    fn syscall_name(&self) -> &str {
        self
    }
}

/// Return the set of well-known mining pool ports for external callers
/// (e.g. the sandbox behavior analyzer).
pub const fn mining_pool_ports() -> &'static [u16] {
    MINING_POOL_PORTS
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_shell_detected() {
        let classifier = BehaviorClassifier::new();
        let trace = &["socket", "connect", "dup2", "execve"];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.is_malicious);
        assert!(pred.matched_patterns.contains(&"reverse_shell".to_string()));
        assert!(pred.score >= 60);
    }

    #[test]
    fn dropper_detected() {
        let classifier = BehaviorClassifier::new();
        let trace = &["write", "chmod", "execve"];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.matched_patterns.contains(&"dropper".to_string()));
        assert!(pred.score >= 60);
    }

    #[test]
    fn credential_theft_detected() {
        let classifier = BehaviorClassifier::new();
        let trace = &["open", "read", "socket", "connect"];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.matched_patterns.contains(&"credential_theft".to_string()));
    }

    #[test]
    fn privilege_escalation_detected() {
        let classifier = BehaviorClassifier::new();
        let trace = &["setuid", "execve"];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.matched_patterns.contains(&"privilege_escalation".to_string()));
    }

    #[test]
    fn data_exfiltration_detected() {
        let classifier = BehaviorClassifier::new();
        let trace = &["getdents64", "open", "read", "socket", "sendto"];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.matched_patterns.contains(&"data_exfiltration".to_string()));
    }

    #[test]
    fn clean_trace_scores_zero() {
        let classifier = BehaviorClassifier::new();
        let trace = &["read", "write", "close"];
        let pred = classifier.classify_from_names(trace);
        // Only persistence patterns (open→write) should *not* match because
        // there is no "open" in this trace.
        assert!(!pred.is_malicious);
    }

    #[test]
    fn empty_trace() {
        let classifier = BehaviorClassifier::new();
        let trace: &[&str] = &[];
        let pred = classifier.classify_from_names(trace);
        assert!(!pred.is_malicious);
        assert!(pred.matched_patterns.is_empty());
        assert_eq!(pred.score, 0);
    }

    #[test]
    fn subsequence_non_contiguous() {
        let classifier = BehaviorClassifier::new();
        // Reverse shell syscalls separated by unrelated calls.
        let trace = &[
            "brk", "mmap", "socket", "read", "write", "connect", "close", "dup2", "mprotect", "execve",
        ];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.matched_patterns.contains(&"reverse_shell".to_string()));
    }

    #[test]
    fn classify_via_trait() {
        let classifier = BehaviorClassifier::new();
        let events: Vec<&str> = vec!["socket", "connect", "dup2", "execve"];
        let pred = classifier.classify(&events);
        assert!(pred.is_malicious);
    }

    #[test]
    fn score_capped_at_100() {
        let classifier = BehaviorClassifier::new();
        // A trace that triggers many patterns simultaneously.
        let trace = &[
            "socket", "connect", "dup2", "execve", // reverse_shell (90)
            "write", "chmod", "execve", // dropper (80)
            "open", "read", "socket", "connect", // credential_theft (85)
            "setuid", "execve", // priv_esc (75)
        ];
        let pred = classifier.classify_from_names(trace);
        assert!(pred.score <= 100);
        assert!(pred.is_malicious);
    }

    #[test]
    fn default_impl() {
        let classifier = BehaviorClassifier::default();
        assert!(!classifier.patterns.is_empty());
    }

    #[test]
    fn mining_pool_ports_not_empty() {
        assert!(!mining_pool_ports().is_empty());
        assert!(mining_pool_ports().contains(&3333));
    }

    #[test]
    fn is_subsequence_basic() {
        assert!(super::is_subsequence(&["a", "b", "c"], &["a".into(), "c".into()]));
        assert!(!super::is_subsequence(&["a", "b", "c"], &["c".into(), "a".into()]));
    }
}
