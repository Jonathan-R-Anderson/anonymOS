//! URL scanner — extracts URLs from file content and checks them against IOC blocklists.
//!
//! Detects:
//! - HTTP/HTTPS URLs embedded in binary or text data
//! - Bare IP addresses (IPv4)
//! - Suspicious TLDs (.tk, .ml, .ga, etc.)
//! - URL shortener services (bit.ly, tinyurl.com, etc.)
//! - IOC-matched malicious URLs

use std::collections::HashSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::ioc_filter::IocFilter;

/// A single malicious URL finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousUrl {
    /// The URL that was flagged.
    pub url: String,
    /// Human-readable reason for flagging.
    pub reason: String,
}

/// Result of scanning file content for URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlScanResult {
    /// All URLs extracted from the content.
    pub urls_found: Vec<String>,
    /// URLs that were flagged as malicious or suspicious.
    pub malicious_urls: Vec<MaliciousUrl>,
    /// Heuristic score (0 = clean, higher = more suspicious).
    pub score: u32,
}

/// Scanner that extracts URLs from file content and checks them against
/// IOC blocklists and suspicious-pattern heuristics.
pub struct UrlScanner {
    /// TLDs considered suspicious (e.g. free/abused registrars).
    suspicious_tlds: HashSet<String>,
    /// Known URL shortener domains.
    url_shorteners: HashSet<String>,
}

impl UrlScanner {
    /// Create a new `UrlScanner` with the default suspicious TLD and shortener lists.
    pub fn new() -> Self {
        let suspicious_tlds: HashSet<String> = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();

        let url_shorteners: HashSet<String> = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();

        Self {
            suspicious_tlds,
            url_shorteners,
        }
    }

    /// Create a `UrlScanner` with custom suspicious TLD and shortener lists.
    pub const fn with_lists(suspicious_tlds: HashSet<String>, url_shorteners: HashSet<String>) -> Self {
        Self {
            suspicious_tlds,
            url_shorteners,
        }
    }

    /// Extract HTTP/HTTPS URLs and bare IPv4 addresses from raw byte content.
    ///
    /// Non-UTF-8 bytes are replaced with the Unicode replacement character,
    /// so this works on binary files as well.
    pub fn extract_urls(data: &[u8]) -> Vec<String> {
        let text = String::from_utf8_lossy(data);
        let mut urls: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Match http:// and https:// URLs.
        // The regex is intentionally permissive to catch obfuscated URLs in binaries.
        if let Ok(re) = Regex::new(r#"https?://[^\s<>"'`\x00-\x1f\x7f]{4,256}"#) {
            for m in re.find_iter(&text) {
                let url = m.as_str().trim_end_matches(['.', ',', ';', ')', ']', '}', '>', '\'']);
                let url_string = url.to_owned();
                if seen.insert(url_string.clone()) {
                    urls.push(url_string);
                }
            }
        }

        // Match bare IPv4 addresses (not already part of a URL above).
        if let Ok(re_ip) = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b") {
            for cap in re_ip.captures_iter(&text) {
                let Some(m) = cap.get(1) else { continue };
                let ip_str = m.as_str();
                // Validate that octets are in range.
                let valid = ip_str
                    .split('.')
                    .filter_map(|octet| octet.parse::<u16>().ok())
                    .filter(|&v| v <= 255)
                    .count()
                    == 4;
                if valid {
                    let ip_string = ip_str.to_owned();
                    if seen.insert(ip_string.clone()) {
                        urls.push(ip_string);
                    }
                }
            }
        }

        urls
    }

    /// Scan file content for malicious URLs.
    ///
    /// Checks extracted URLs against:
    /// 1. The IOC blocklist (if provided)
    /// 2. Suspicious TLD patterns
    /// 3. URL shortener services
    /// 4. IP-based URLs (e.g. `http://1.2.3.4/payload`)
    pub fn scan_urls(&self, data: &[u8], ioc: Option<&IocFilter>) -> UrlScanResult {
        let urls_found = Self::extract_urls(data);
        let mut malicious_urls: Vec<MaliciousUrl> = Vec::new();
        let mut score: u32 = 0;

        for url in &urls_found {
            let lower = url.to_lowercase();

            // 1. IOC blocklist check.
            if let Some(filter) = ioc {
                if filter.check_url(&lower) {
                    malicious_urls.push(MaliciousUrl {
                        url: url.clone(),
                        reason: "URL found in IOC blocklist".to_owned(),
                    });
                    score = score.saturating_add(30);
                    continue;
                }
                // Also check domain extraction from the URL against the IOC domain list.
                if let Some(domain) = extract_domain_from_url(&lower) {
                    if filter.check_domain(&domain) {
                        malicious_urls.push(MaliciousUrl {
                            url: url.clone(),
                            reason: format!("domain '{domain}' found in IOC blocklist"),
                        });
                        score = score.saturating_add(25);
                        continue;
                    }
                }
            }

            // 2. IP-based URL detection (e.g. http://1.2.3.4/something).
            if is_ip_based_url(&lower) {
                malicious_urls.push(MaliciousUrl {
                    url: url.clone(),
                    reason: "IP-based URL (no domain name)".to_owned(),
                });
                score = score.saturating_add(10);
                continue;
            }

            // 3. URL shortener detection.
            if let Some(domain) = extract_domain_from_url(&lower) {
                if self.url_shorteners.contains(domain.as_str()) {
                    malicious_urls.push(MaliciousUrl {
                        url: url.clone(),
                        reason: format!("URL shortener service: {domain}"),
                    });
                    score = score.saturating_add(10);
                    continue;
                }

                // 4. Suspicious TLD detection.
                for tld in &self.suspicious_tlds {
                    if domain.ends_with(tld.as_str()) {
                        malicious_urls.push(MaliciousUrl {
                            url: url.clone(),
                            reason: format!("suspicious TLD: {tld}"),
                        });
                        score = score.saturating_add(5);
                        break;
                    }
                }
            }
        }

        // Cap score at 100.
        if score > 100 {
            score = 100;
        }

        UrlScanResult {
            urls_found,
            malicious_urls,
            score,
        }
    }
}

impl Default for UrlScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the domain (host) portion from a URL string.
///
/// Returns `None` if the URL does not contain a recognisable host.
fn extract_domain_from_url(url: &str) -> Option<String> {
    // Strip scheme.
    let after_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;

    // Take everything before the first `/`, `?`, `#`, or `:` (port).
    let host = after_scheme.split(['/', '?', '#', ':']).next()?;

    if host.is_empty() {
        return None;
    }

    Some(host.to_owned())
}

/// Check whether a URL uses a bare IP address instead of a domain name.
fn is_ip_based_url(url: &str) -> bool {
    extract_domain_from_url(url).is_some_and(|domain| domain.parse::<std::net::Ipv4Addr>().is_ok())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn extract_http_urls() {
        let data = b"Visit http://example.com and https://secure.example.org/path?q=1 for info.";
        let urls = UrlScanner::extract_urls(data);
        assert!(urls.iter().any(|u| u.contains("example.com")));
        assert!(urls.iter().any(|u| u.contains("secure.example.org")));
    }

    #[test]
    fn extract_bare_ip() {
        let data = b"Connect to 192.168.1.100 for the payload";
        let urls = UrlScanner::extract_urls(data);
        assert!(urls.iter().any(|u| u == "192.168.1.100"));
    }

    #[test]
    fn invalid_ip_ignored() {
        let data = b"version 999.999.999.999 is not an IP";
        let urls = UrlScanner::extract_urls(data);
        assert!(!urls.iter().any(|u| u == "999.999.999.999"));
    }

    #[test]
    fn deduplicate_urls() {
        let data = b"http://dup.com http://dup.com http://dup.com";
        let urls = UrlScanner::extract_urls(data);
        assert_eq!(urls.iter().filter(|u| u.as_str() == "http://dup.com").count(), 1);
    }

    #[test]
    fn scan_detects_ip_based_url() {
        let scanner = UrlScanner::new();
        let data = b"download from http://1.2.3.4/malware.exe now";
        let result = scanner.scan_urls(data, None);
        assert!(!result.malicious_urls.is_empty());
        assert!(result.malicious_urls[0].reason.contains("IP-based"));
        assert!(result.score > 0);
    }

    #[test]
    fn scan_detects_url_shortener() {
        let scanner = UrlScanner::new();
        let data = b"click http://bit.ly/abc123 for prize";
        let result = scanner.scan_urls(data, None);
        assert!(result.malicious_urls.iter().any(|m| m.reason.contains("shortener")));
    }

    #[test]
    fn scan_detects_suspicious_tld() {
        let scanner = UrlScanner::new();
        let data = b"visit http://evil-dropper.tk/payload for updates";
        let result = scanner.scan_urls(data, None);
        assert!(result.malicious_urls.iter().any(|m| m.reason.contains(".tk")));
    }

    #[test]
    fn scan_with_ioc_filter() {
        let mut ioc = IocFilter::new();
        // We can't directly insert into private fields in non-test module,
        // but load_url_blocklist works. Let's use a temp file approach.
        let dir = std::env::temp_dir();
        let path = dir.join("prx_sd_url_scanner_test_ioc.txt");
        std::fs::write(&path, "http://malware.evil.com/dropper\n").unwrap();
        ioc.load_url_blocklist(&path).unwrap();

        let scanner = UrlScanner::new();
        let data = b"get http://malware.evil.com/dropper for the goods";
        let result = scanner.scan_urls(data, Some(&ioc));
        assert!(result.malicious_urls.iter().any(|m| m.reason.contains("IOC blocklist")));
        assert!(result.score >= 30);
    }

    #[test]
    fn scan_clean_urls() {
        let scanner = UrlScanner::new();
        let data = b"visit https://www.google.com for search";
        let result = scanner.scan_urls(data, None);
        assert!(result.malicious_urls.is_empty());
        assert_eq!(result.score, 0);
    }

    #[test]
    fn score_capped_at_100() {
        let scanner = UrlScanner::new();
        // Many IP-based URLs to push score high.
        let mut data = Vec::new();
        for i in 1..=20 {
            data.extend_from_slice(format!("http://10.0.0.{i}/bad ").as_bytes());
        }
        let result = scanner.scan_urls(&data, None);
        assert!(result.score <= 100);
    }

    #[test]
    fn extract_domain_from_url_works() {
        assert_eq!(
            extract_domain_from_url("https://example.com/path"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            extract_domain_from_url("http://host:8080/path"),
            Some("host".to_owned())
        );
        assert_eq!(extract_domain_from_url("not-a-url"), None);
    }

    #[test]
    fn default_trait() {
        let scanner = UrlScanner::default();
        assert!(!scanner.suspicious_tlds.is_empty());
        assert!(!scanner.url_shorteners.is_empty());
    }
}
