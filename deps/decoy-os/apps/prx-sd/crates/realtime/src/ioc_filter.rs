//! IOC (Indicators of Compromise) network filter.
//!
//! Uses hash sets for malicious IP and URL/domain lookup.
//! Designed for in-memory filtering of network connections.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Statistics about the loaded IOC data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocStats {
    pub ip_count: usize,
    pub domain_count: usize,
    pub url_count: usize,
}

/// Verdict returned after checking a network indicator.
#[derive(Debug, Clone)]
pub enum IocVerdict {
    /// The indicator is not in any blocklist.
    Clean,
    /// The IP address matched a blocklist entry.
    MaliciousIp { ip: IpAddr, reason: String },
    /// The domain matched a blocklist entry.
    MaliciousDomain { domain: String, reason: String },
    /// The URL matched a blocklist entry.
    MaliciousUrl { url: String, reason: String },
}

/// IOC network filter for checking IPs and domains against blocklists.
#[allow(clippy::struct_field_names)] // prefix `malicious_` clarifies intent for IOC data
pub struct IocFilter {
    /// Malicious IP addresses.
    malicious_ips: HashSet<IpAddr>,
    /// Malicious domains (lowercase).
    malicious_domains: HashSet<String>,
    /// Malicious URL patterns (lowercase).
    malicious_urls: HashSet<String>,
}

impl IocFilter {
    /// Create a new empty IOC filter.
    pub fn new() -> Self {
        Self {
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
            malicious_urls: HashSet::new(),
        }
    }

    /// Load IP addresses from a text file (one per line).
    ///
    /// Lines starting with `#` and empty lines are skipped.
    /// Returns a new `IocFilter` containing the loaded IPs.
    pub fn load_ip_blocklist(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read IP blocklist: {}", path.display()))?;

        let mut filter = Self::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                filter.malicious_ips.insert(ip);
            } else {
                tracing::warn!(line = trimmed, "skipping invalid IP address");
            }
        }
        Ok(filter)
    }

    /// Load domains from a text file (one per line).
    ///
    /// Lines starting with `#` and empty lines are skipped.
    /// Returns the number of domains loaded.
    pub fn load_domain_blocklist(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read domain blocklist: {}", path.display()))?;

        let mut count = 0usize;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.malicious_domains.insert(trimmed.to_lowercase());
            count += 1;
        }
        Ok(count)
    }

    /// Load URLs from a text file (one per line).
    ///
    /// Lines starting with `#` and empty lines are skipped.
    /// Returns the number of URLs loaded.
    pub fn load_url_blocklist(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read URL blocklist: {}", path.display()))?;

        let mut count = 0usize;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.malicious_urls.insert(trimmed.to_lowercase());
            count += 1;
        }
        Ok(count)
    }

    /// Check whether the given IP address is in the blocklist.
    pub fn check_ip(&self, ip: &IpAddr) -> bool {
        self.malicious_ips.contains(ip)
    }

    /// Check whether the given domain is in the blocklist.
    ///
    /// Also checks parent domains: if `evil.com` is blocked,
    /// `sub.evil.com` will also match.
    pub fn check_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.malicious_domains.contains(&lower) {
            return true;
        }
        // Walk parent domains: for "a.b.evil.com", check "b.evil.com", then "evil.com".
        let mut remaining = lower.as_str();
        while let Some(pos) = remaining.find('.') {
            remaining = &remaining[pos + 1..];
            if self.malicious_domains.contains(remaining) {
                return true;
            }
        }
        false
    }

    /// Check whether the given URL matches the blocklist.
    pub fn check_url(&self, url: &str) -> bool {
        let lower = url.to_lowercase();
        self.malicious_urls.contains(&lower)
    }

    /// Return a full verdict for an IP address.
    pub fn check_ip_verdict(&self, ip: &IpAddr) -> IocVerdict {
        if self.check_ip(ip) {
            IocVerdict::MaliciousIp {
                ip: *ip,
                reason: "IP found in IOC blocklist".to_owned(),
            }
        } else {
            IocVerdict::Clean
        }
    }

    /// Return a full verdict for a domain.
    pub fn check_domain_verdict(&self, domain: &str) -> IocVerdict {
        if self.check_domain(domain) {
            IocVerdict::MaliciousDomain {
                domain: domain.to_owned(),
                reason: "domain found in IOC blocklist".to_owned(),
            }
        } else {
            IocVerdict::Clean
        }
    }

    /// Return a full verdict for a URL.
    pub fn check_url_verdict(&self, url: &str) -> IocVerdict {
        if self.check_url(url) {
            IocVerdict::MaliciousUrl {
                url: url.to_owned(),
                reason: "URL found in IOC blocklist".to_owned(),
            }
        } else {
            IocVerdict::Clean
        }
    }

    /// Return statistics about the loaded IOC data.
    pub fn stats(&self) -> IocStats {
        IocStats {
            ip_count: self.malicious_ips.len(),
            domain_count: self.malicious_domains.len(),
            url_count: self.malicious_urls.len(),
        }
    }
}

impl Default for IocFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Create a temporary file with the given content and return its path.
    /// The caller is responsible for cleanup (tests are short-lived so this is fine).
    fn write_temp_file(content: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("prx_sd_ioc_test_{id}.txt"));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn empty_filter_returns_clean() {
        let filter = IocFilter::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!filter.check_ip(&ip));
        assert!(!filter.check_domain("example.com"));
        assert!(!filter.check_url("http://example.com/bad"));
        assert!(matches!(filter.check_ip_verdict(&ip), IocVerdict::Clean));
    }

    #[test]
    fn load_ip_blocklist_and_lookup() {
        let content = "# comment line\n\n192.168.1.1\n10.0.0.1\n::1\n";
        let tmp = write_temp_file(content);
        let filter = IocFilter::load_ip_blocklist(&tmp).unwrap();

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.1".parse().unwrap();
        let ip3: IpAddr = "::1".parse().unwrap();
        let ip_clean: IpAddr = "8.8.8.8".parse().unwrap();

        assert!(filter.check_ip(&ip1));
        assert!(filter.check_ip(&ip2));
        assert!(filter.check_ip(&ip3));
        assert!(!filter.check_ip(&ip_clean));

        let stats = filter.stats();
        assert_eq!(stats.ip_count, 3);
        assert_eq!(stats.domain_count, 0);
    }

    #[test]
    fn load_domain_blocklist_and_subdomain_matching() {
        let content = "# domains\nevil.com\nbad-site.org\n";
        let tmp = write_temp_file(content);
        let mut filter = IocFilter::new();
        let count = filter.load_domain_blocklist(&tmp).unwrap();
        assert_eq!(count, 2);

        // Exact match
        assert!(filter.check_domain("evil.com"));
        assert!(filter.check_domain("bad-site.org"));

        // Subdomain matching
        assert!(filter.check_domain("sub.evil.com"));
        assert!(filter.check_domain("deep.sub.evil.com"));

        // Non-match
        assert!(!filter.check_domain("notevil.com"));
        assert!(!filter.check_domain("example.com"));

        // Case insensitive
        assert!(filter.check_domain("Evil.COM"));
        assert!(filter.check_domain("SUB.EVIL.COM"));
    }

    #[test]
    fn load_url_blocklist_and_lookup() {
        let content = "# urls\nhttp://evil.com/malware.exe\nhttps://bad.org/payload\n";
        let tmp = write_temp_file(content);
        let mut filter = IocFilter::new();
        let count = filter.load_url_blocklist(&tmp).unwrap();
        assert_eq!(count, 2);

        assert!(filter.check_url("http://evil.com/malware.exe"));
        assert!(filter.check_url("HTTP://EVIL.COM/MALWARE.EXE")); // case insensitive
        assert!(!filter.check_url("http://evil.com/other"));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let content = "# this is a comment\n\n  # another comment\n  \n192.168.0.1\n";
        let tmp = write_temp_file(content);
        let filter = IocFilter::load_ip_blocklist(&tmp).unwrap();
        assert_eq!(filter.stats().ip_count, 1);
    }

    #[test]
    fn invalid_ips_are_skipped() {
        let content = "192.168.0.1\nnot-an-ip\n10.0.0.1\n";
        let tmp = write_temp_file(content);
        let filter = IocFilter::load_ip_blocklist(&tmp).unwrap();
        assert_eq!(filter.stats().ip_count, 2);
    }

    #[test]
    fn verdict_types() {
        let mut filter = IocFilter::new();
        filter.malicious_ips.insert("1.2.3.4".parse().unwrap());
        filter.malicious_domains.insert("evil.com".to_owned());
        filter.malicious_urls.insert("http://evil.com/bad".to_owned());

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(matches!(filter.check_ip_verdict(&ip), IocVerdict::MaliciousIp { .. }));
        assert!(matches!(
            filter.check_domain_verdict("evil.com"),
            IocVerdict::MaliciousDomain { .. }
        ));
        assert!(matches!(
            filter.check_url_verdict("http://evil.com/bad"),
            IocVerdict::MaliciousUrl { .. }
        ));

        let clean_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(matches!(filter.check_ip_verdict(&clean_ip), IocVerdict::Clean));
        assert!(matches!(filter.check_domain_verdict("safe.com"), IocVerdict::Clean));
        assert!(matches!(filter.check_url_verdict("http://safe.com"), IocVerdict::Clean));
    }
}
