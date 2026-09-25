//! DNS filtering — blocks resolution of malicious domains.
//!
//! Two approaches:
//! 1. Hosts file injection: adds malicious domains to `/etc/hosts` pointing to `0.0.0.0`.
//! 2. Runtime check: provides a lookup function for the realtime monitor.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Platform-specific default path to the hosts file.
const fn default_hosts_path() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        r"C:\Windows\System32\drivers\etc\hosts"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "/etc/hosts"
    }
}

// ── Marker comment used to identify prx-sd entries in /etc/hosts ─────────────

const HOSTS_MARKER: &str = "# prx-sd-dns-filter";

// ── Public types ─────────────────────────────────────────────────────────────

/// Verdict returned after checking a domain against the blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsVerdict {
    /// Domain is safe (not in the blocklist).
    Allow,
    /// Domain is blocked.
    Blocked { domain: String, reason: String },
}

/// DNS filter that checks domain resolutions against a blocklist.
///
/// Domains are stored lowercase and without trailing dots.
pub struct DnsFilter {
    /// Blocked domains (lowercase, no trailing dot).
    blocked_domains: HashSet<String>,
    /// Whether hosts-file blocking is currently active.
    hosts_active: bool,
    /// Path to the hosts file (configurable for testing).
    hosts_path: PathBuf,
}

impl DnsFilter {
    /// Create a new, empty DNS filter.
    pub fn new() -> Self {
        Self {
            blocked_domains: HashSet::new(),
            hosts_active: false,
            hosts_path: PathBuf::from(default_hosts_path()),
        }
    }

    /// Load a blocklist from a text file.
    ///
    /// The file should contain one domain per line. Lines starting with `#`
    /// and empty lines are ignored. Domains are normalised to lowercase with
    /// trailing dots removed.
    pub fn load_blocklist(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read blocklist from {}", path.display()))?;

        let mut filter = Self::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            filter.add_domain(trimmed);
        }

        Ok(filter)
    }

    /// Add a domain to the blocklist.
    ///
    /// The domain is normalised: lowercased and trailing dots stripped.
    pub fn add_domain(&mut self, domain: &str) {
        let normalised = normalise_domain(domain);
        if !normalised.is_empty() {
            self.blocked_domains.insert(normalised);
        }
    }

    /// Remove a domain from the blocklist.
    pub fn remove_domain(&mut self, domain: &str) {
        let normalised = normalise_domain(domain);
        self.blocked_domains.remove(&normalised);
    }

    /// Check whether a domain should be blocked.
    ///
    /// Returns [`DnsVerdict::Blocked`] if the domain itself **or any parent
    /// domain** is in the blocklist.  For example, if `evil.com` is blocked,
    /// `sub.evil.com` will also be blocked.
    pub fn check(&self, domain: &str) -> DnsVerdict {
        let normalised = normalise_domain(domain);

        // Walk the domain and its parents: e.g. a.b.evil.com → b.evil.com → evil.com → com
        let mut candidate = normalised.as_str();
        loop {
            if self.blocked_domains.contains(candidate) {
                let reason = format!("matched blocklist entry: {candidate}");
                return DnsVerdict::Blocked {
                    domain: normalised,
                    reason,
                };
            }
            // Move to the parent domain.
            match candidate.find('.') {
                Some(pos) => candidate = &candidate[pos + 1..],
                None => break,
            }
        }

        DnsVerdict::Allow
    }

    /// Install hosts-file blocking by appending blocked domains to the hosts
    /// file as `0.0.0.0 <domain>`.
    ///
    /// Existing prx-sd entries (identified by [`HOSTS_MARKER`]) are removed
    /// first. **Requires root/admin privileges.**
    pub fn install_hosts_blocking(&mut self) -> Result<()> {
        self.install_hosts_blocking_at(&self.hosts_path.clone())
    }

    /// Internal implementation that accepts an explicit path (for testing).
    fn install_hosts_blocking_at(&mut self, hosts_path: &Path) -> Result<()> {
        let content =
            std::fs::read_to_string(hosts_path).with_context(|| format!("failed to read {}", hosts_path.display()))?;

        let mut lines: Vec<String> = content
            .lines()
            .filter(|line| !line.contains(HOSTS_MARKER))
            .map(String::from)
            .collect();

        // Append blocked domains.
        let mut sorted_domains: Vec<&String> = self.blocked_domains.iter().collect();
        sorted_domains.sort();

        for domain in sorted_domains {
            lines.push(format!("0.0.0.0 {domain} {HOSTS_MARKER}"));
        }

        // Ensure the file ends with a newline.
        let mut output = lines.join("\n");
        if !output.ends_with('\n') {
            output.push('\n');
        }

        std::fs::write(hosts_path, &output).with_context(|| format!("failed to write {}", hosts_path.display()))?;

        self.hosts_active = true;
        Ok(())
    }

    /// Remove all prx-sd entries from the hosts file.
    ///
    /// **Requires root/admin privileges.**
    pub fn remove_hosts_blocking(&mut self) -> Result<()> {
        self.remove_hosts_blocking_at(&self.hosts_path.clone())
    }

    /// Internal implementation with explicit path (for testing).
    fn remove_hosts_blocking_at(&mut self, hosts_path: &Path) -> Result<()> {
        let content =
            std::fs::read_to_string(hosts_path).with_context(|| format!("failed to read {}", hosts_path.display()))?;

        let lines: Vec<&str> = content.lines().filter(|line| !line.contains(HOSTS_MARKER)).collect();

        let mut output = lines.join("\n");
        if !output.ends_with('\n') {
            output.push('\n');
        }

        std::fs::write(hosts_path, &output).with_context(|| format!("failed to write {}", hosts_path.display()))?;

        self.hosts_active = false;
        Ok(())
    }

    /// Return the number of domains in the blocklist.
    pub fn domain_count(&self) -> usize {
        self.blocked_domains.len()
    }

    /// Return whether hosts-file blocking is currently active.
    pub const fn is_hosts_active(&self) -> bool {
        self.hosts_active
    }
}

impl Default for DnsFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Normalise a domain: lowercase + strip trailing dot.
fn normalise_domain(domain: &str) -> String {
    let lower = domain.trim().to_ascii_lowercase();
    lower.strip_suffix('.').unwrap_or(&lower).to_string()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn exact_domain_is_blocked() {
        let mut filter = DnsFilter::new();
        filter.add_domain("evil.com");

        assert_eq!(
            filter.check("evil.com"),
            DnsVerdict::Blocked {
                domain: "evil.com".into(),
                reason: "matched blocklist entry: evil.com".into(),
            }
        );
    }

    #[test]
    fn subdomain_of_blocked_domain_is_blocked() {
        let mut filter = DnsFilter::new();
        filter.add_domain("evil.com");

        let verdict = filter.check("sub.evil.com");
        assert!(matches!(verdict, DnsVerdict::Blocked { .. }));

        let verdict = filter.check("deep.sub.evil.com");
        assert!(matches!(verdict, DnsVerdict::Blocked { .. }));
    }

    #[test]
    fn unrelated_domain_is_allowed() {
        let mut filter = DnsFilter::new();
        filter.add_domain("evil.com");

        assert_eq!(filter.check("good.com"), DnsVerdict::Allow);
        assert_eq!(filter.check("notevil.com"), DnsVerdict::Allow);
    }

    #[test]
    fn domain_normalisation() {
        let mut filter = DnsFilter::new();
        filter.add_domain("EVIL.COM.");

        // Should match regardless of case or trailing dot.
        assert!(matches!(filter.check("evil.com"), DnsVerdict::Blocked { .. }));
        assert!(matches!(filter.check("Evil.Com."), DnsVerdict::Blocked { .. }));
    }

    #[test]
    fn add_and_remove_domain() {
        let mut filter = DnsFilter::new();
        filter.add_domain("malware.net");
        assert_eq!(filter.domain_count(), 1);
        assert!(matches!(filter.check("malware.net"), DnsVerdict::Blocked { .. }));

        filter.remove_domain("malware.net");
        assert_eq!(filter.domain_count(), 0);
        assert_eq!(filter.check("malware.net"), DnsVerdict::Allow);
    }

    #[test]
    fn empty_domain_ignored() {
        let mut filter = DnsFilter::new();
        filter.add_domain("");
        filter.add_domain("   ");
        assert_eq!(filter.domain_count(), 0);
    }

    #[test]
    fn load_blocklist_from_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blocklist_path = dir.path().join("blocklist.txt");

        {
            let mut f = std::fs::File::create(&blocklist_path).expect("create");
            writeln!(f, "# comment line").expect("write");
            writeln!(f).expect("write");
            writeln!(f, "bad-domain.com").expect("write");
            writeln!(f, "ANOTHER-BAD.ORG").expect("write");
            writeln!(f, "  spaced.net  ").expect("write");
        }

        let filter = DnsFilter::load_blocklist(&blocklist_path).expect("load");
        assert_eq!(filter.domain_count(), 3);
        assert!(matches!(filter.check("bad-domain.com"), DnsVerdict::Blocked { .. }));
        assert!(matches!(filter.check("another-bad.org"), DnsVerdict::Blocked { .. }));
        assert!(matches!(filter.check("spaced.net"), DnsVerdict::Blocked { .. }));
        assert_eq!(filter.check("safe.com"), DnsVerdict::Allow);
    }

    #[test]
    fn load_blocklist_missing_file() {
        let result = DnsFilter::load_blocklist(Path::new("/nonexistent/blocklist.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn install_and_remove_hosts_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts_path = dir.path().join("hosts");

        // Write a minimal initial hosts file.
        std::fs::write(&hosts_path, "127.0.0.1 localhost\n::1 localhost\n").expect("write hosts");

        let mut filter = DnsFilter::new();
        filter.add_domain("evil.com");
        filter.add_domain("malware.net");

        // Install blocking.
        filter.install_hosts_blocking_at(&hosts_path).expect("install");
        assert!(filter.is_hosts_active());

        let content = std::fs::read_to_string(&hosts_path).expect("read");
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(content.contains("0.0.0.0 evil.com # prx-sd-dns-filter"));
        assert!(content.contains("0.0.0.0 malware.net # prx-sd-dns-filter"));

        // Remove blocking.
        filter.remove_hosts_blocking_at(&hosts_path).expect("remove");
        assert!(!filter.is_hosts_active());

        let content = std::fs::read_to_string(&hosts_path).expect("read");
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(!content.contains("prx-sd-dns-filter"));
    }

    #[test]
    fn install_hosts_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts_path = dir.path().join("hosts");

        std::fs::write(&hosts_path, "127.0.0.1 localhost\n").expect("write");

        let mut filter = DnsFilter::new();
        filter.add_domain("evil.com");

        // Install twice.
        filter.install_hosts_blocking_at(&hosts_path).expect("install 1");
        filter.install_hosts_blocking_at(&hosts_path).expect("install 2");

        let content = std::fs::read_to_string(&hosts_path).expect("read");
        // Should only have one entry for evil.com, not two.
        let count = content.matches("evil.com").count();
        assert_eq!(count, 1, "expected exactly one entry, found {count}");
    }

    #[test]
    fn default_trait() {
        let filter = DnsFilter::default();
        assert_eq!(filter.domain_count(), 0);
        assert!(!filter.is_hosts_active());
    }
}
