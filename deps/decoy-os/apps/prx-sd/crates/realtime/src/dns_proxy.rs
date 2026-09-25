//! Local DNS proxy server with adblock + IOC + custom blocklist filtering.
//!
//! Listens on UDP port 53, checks each DNS query against multiple filter
//! engines, and either blocks (returns 0.0.0.0) or forwards to upstream DNS.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use super::adblock_filter::AdblockFilterManager;
use super::dns_filter::DnsFilter;
use super::ioc_filter::IocFilter;

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the DNS proxy server.
pub struct DnsProxyConfig {
    /// Address and port to listen on.
    pub listen_addr: SocketAddr,
    /// Upstream DNS server to forward allowed queries to.
    pub upstream_dns: SocketAddr,
    /// Path to write the JSONL query log.
    pub log_path: PathBuf,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 53)),
            upstream_dns: SocketAddr::from(([8, 8, 8, 8], 53)),
            log_path: PathBuf::from("/tmp/prx-sd-dns.log"),
        }
    }
}

// ── Blocking reason ──────────────────────────────────────────────────────────

/// Why a query was blocked (for logging).
#[derive(Debug, Clone, Serialize)]
pub enum BlockReason {
    Adblock,
    DnsBlocklist,
    IocMalicious,
}

/// A single log entry written as JSONL.
#[derive(Debug, Serialize)]
struct QueryLogEntry {
    timestamp: String,
    domain: String,
    blocked: bool,
    reason: Option<BlockReason>,
    client: String,
}

// ── DNS proxy ────────────────────────────────────────────────────────────────

/// Local DNS proxy that wires together adblock, `dns_filter`, and `ioc_filter`.
pub struct DnsProxy {
    config: DnsProxyConfig,
    adblock: Option<AdblockFilterManager>,
    dns_filter: DnsFilter,
    ioc_filter: IocFilter,
}

impl DnsProxy {
    /// Create a new DNS proxy, loading filter data from `data_dir`.
    ///
    /// Missing filter files are tolerated: the corresponding engine simply
    /// starts empty and will not block anything.
    pub fn new(config: DnsProxyConfig, data_dir: &Path) -> Result<Self> {
        // Adblock engine
        let adblock_dir = data_dir.join("adblock");
        let adblock = match AdblockFilterManager::init(&adblock_dir) {
            Ok(mgr) => {
                tracing::info!("adblock filter engine loaded");
                Some(mgr)
            }
            Err(e) => {
                tracing::warn!(error = %e, "adblock filter unavailable, continuing without it");
                None
            }
        };

        // DNS custom blocklist
        let dns_blocklist_path = data_dir.join("dns_blocklist.txt");
        let dns_filter = if dns_blocklist_path.exists() {
            match DnsFilter::load_blocklist(&dns_blocklist_path) {
                Ok(f) => {
                    tracing::info!(path = %dns_blocklist_path.display(), "dns blocklist loaded");
                    f
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load dns blocklist, using empty");
                    DnsFilter::new()
                }
            }
        } else {
            tracing::debug!("no dns_blocklist.txt found, dns_filter starts empty");
            DnsFilter::new()
        };

        // IOC domain blocklist
        let ioc_domains_path = data_dir.join("ioc_domains.txt");
        let mut ioc_filter = IocFilter::new();
        if ioc_domains_path.exists() {
            match ioc_filter.load_domain_blocklist(&ioc_domains_path) {
                Ok(n) => tracing::info!(count = n, "ioc domain blocklist loaded"),
                Err(e) => tracing::warn!(error = %e, "failed to load ioc domains"),
            }
        }

        Ok(Self {
            config,
            adblock,
            dns_filter,
            ioc_filter,
        })
    }

    /// Run the DNS proxy event loop (blocking).
    ///
    /// Binds to the configured listen address and processes queries until
    /// an unrecoverable error occurs.
    pub fn run(&self) -> Result<()> {
        let socket = UdpSocket::bind(self.config.listen_addr)
            .with_context(|| format!("failed to bind UDP {}", self.config.listen_addr))?;

        tracing::info!(
            listen = %self.config.listen_addr,
            upstream = %self.config.upstream_dns,
            "DNS proxy started"
        );

        let mut buf = [0u8; 4096];

        loop {
            let (len, src) = match socket.recv_from(&mut buf) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "recv_from failed, continuing");
                    continue;
                }
            };

            let Some(query) = buf.get(..len) else {
                continue;
            };
            let domain = extract_domain_from_query(query);

            let (blocked, reason) = domain.as_ref().map_or((false, None), |d| self.check_domain(d));

            let response = if blocked {
                build_blocked_response(query)
            } else {
                match forward_to_upstream(query, self.config.upstream_dns) {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            domain = domain.as_deref().unwrap_or("<unknown>"),
                            "upstream forward failed, returning SERVFAIL"
                        );
                        build_servfail_response(query)
                    }
                }
            };

            if !response.is_empty() {
                if let Err(e) = socket.send_to(&response, src) {
                    tracing::warn!(error = %e, "send_to failed");
                }
            }

            // Write log entry
            if let Some(ref d) = domain {
                log_query(d, blocked, reason, &src, &self.config.log_path);
            }
        }
    }

    /// Check a domain against all filter engines.
    ///
    /// Returns `(blocked, reason)`.
    fn check_domain(&self, domain: &str) -> (bool, Option<BlockReason>) {
        // 1. Adblock (fast, 173K rules)
        if let Some(ref adblock) = self.adblock {
            if adblock.check_domain(domain) {
                return (true, Some(BlockReason::Adblock));
            }
        }

        // 2. DNS custom blocklist
        if let super::dns_filter::DnsVerdict::Blocked { .. } = self.dns_filter.check(domain) {
            return (true, Some(BlockReason::DnsBlocklist));
        }

        // 3. IOC malicious domains
        if self.ioc_filter.check_domain(domain) {
            return (true, Some(BlockReason::IocMalicious));
        }

        (false, None)
    }
}

// ── DNS packet helpers ───────────────────────────────────────────────────────

/// Extract the queried domain name from a DNS query packet.
///
/// The DNS header is 12 bytes, followed by the question section whose QNAME
/// is encoded as a sequence of length-prefixed labels terminated by a zero
/// byte.
pub fn extract_domain_from_query(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }

    let mut pos = 12; // skip fixed header
    let mut labels: Vec<String> = Vec::new();

    loop {
        let &len_byte = packet.get(pos)?;
        let len = len_byte as usize;
        if len == 0 {
            break;
        }
        // Pointer compression (0xC0 mask) — not expected in queries but guard
        // against it anyway.
        if len & 0xC0 == 0xC0 {
            break;
        }
        pos += 1;
        let label_slice = packet.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label_slice).to_string());
        pos += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Build a DNS response that answers with `0.0.0.0` for A-record queries.
///
/// This crafts the minimal valid response: copy the query, flip the QR flag,
/// set ANCOUNT to 1, and append a single A record answer pointing to `0.0.0.0`.
pub fn build_blocked_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut resp = query.to_vec();
    // Indices 2,3,6,7 are guaranteed in-bounds: resp.len() >= 12 from the guard above.
    #[allow(clippy::indexing_slicing)]
    {
        // Set response flags: QR=1, RD=1
        resp[2] = 0x81;
        // RA=1, RCODE=0 (no error)
        resp[3] = 0x80;
        // Set ANCOUNT = 1
        resp[6] = 0x00;
        resp[7] = 0x01;
    }
    // Answer section: name pointer to QNAME at offset 12
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    resp.extend_from_slice(&[0x00, 0x01]); // type A
    resp.extend_from_slice(&[0x00, 0x01]); // class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60s
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 0.0.0.0
    resp
}

/// Build a SERVFAIL response when upstream forwarding fails.
fn build_servfail_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut resp = query.to_vec();
    // Indices 2,3 are guaranteed in-bounds: resp.len() >= 12 from the guard above.
    #[allow(clippy::indexing_slicing)]
    {
        // QR=1, RD=1
        resp[2] = 0x81;
        // RA=1, RCODE=2 (SERVFAIL)
        resp[3] = 0x82;
    }
    resp
}

/// Forward a DNS query to the upstream server and return the response.
fn forward_to_upstream(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").context("failed to bind ephemeral UDP socket")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .context("failed to set read timeout")?;
    sock.send_to(query, upstream)
        .context("failed to send query to upstream DNS")?;

    let mut buf = [0u8; 4096];
    let (len, _) = sock
        .recv_from(&mut buf)
        .context("upstream DNS did not respond in time")?;
    Ok(buf
        .get(..len)
        .context("upstream DNS response length exceeds buffer")?
        .to_vec())
}

/// Write a JSONL log entry for a DNS query.
fn log_query(domain: &str, blocked: bool, reason: Option<BlockReason>, client: &SocketAddr, log_path: &Path) {
    use std::io::Write;

    let entry = QueryLogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        domain: domain.to_owned(),
        blocked,
        reason,
        client: client.to_string(),
    };

    let line = match serde_json::to_string(&entry) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize log entry");
            return;
        }
    };

    let file = std::fs::OpenOptions::new().create(true).append(true).open(log_path);

    match file {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{line}") {
                tracing::warn!(error = %e, "failed to write DNS log");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %log_path.display(), "failed to open DNS log");
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation
    )]
    use super::*;

    /// Build a minimal DNS query packet for the given domain.
    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header: ID=0xABCD, flags=0x0100 (RD=1), QDCOUNT=1
        pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // QNAME
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // root label

        // QTYPE=A (1), QCLASS=IN (1)
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN

        pkt
    }

    #[test]
    fn test_extract_domain_simple() {
        let pkt = build_test_query("example.com");
        let domain = extract_domain_from_query(&pkt);
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_domain_subdomain() {
        let pkt = build_test_query("sub.domain.example.org");
        let domain = extract_domain_from_query(&pkt);
        assert_eq!(domain, Some("sub.domain.example.org".to_string()));
    }

    #[test]
    fn test_extract_domain_too_short() {
        let pkt = [0u8; 5];
        assert_eq!(extract_domain_from_query(&pkt), None);
    }

    #[test]
    fn test_extract_domain_empty_labels() {
        // Header + immediate zero label
        let mut pkt = vec![0u8; 12];
        pkt.push(0x00);
        assert_eq!(extract_domain_from_query(&pkt), None);
    }

    #[test]
    fn test_blocked_response_structure() {
        let query = build_test_query("ads.example.com");
        let resp = build_blocked_response(&query);

        // Response must be longer than the query (has answer section appended)
        assert!(resp.len() > query.len());

        // ID should match
        assert_eq!(resp[0], query[0]);
        assert_eq!(resp[1], query[1]);

        // QR=1
        assert_ne!(resp[2] & 0x80, 0);

        // ANCOUNT=1
        assert_eq!(resp[6], 0x00);
        assert_eq!(resp[7], 0x01);

        // Last 4 bytes should be 0.0.0.0
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_blocked_response_too_short() {
        let resp = build_blocked_response(&[0u8; 5]);
        assert!(resp.is_empty());
    }

    #[test]
    fn test_servfail_response() {
        let query = build_test_query("example.com");
        let resp = build_servfail_response(&query);

        // QR=1
        assert_ne!(resp[2] & 0x80, 0);
        // RCODE=2 (SERVFAIL)
        assert_eq!(resp[3] & 0x0F, 2);
    }
}
