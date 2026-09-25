# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# orin/collectors/dns_forensics.py
"""
orin.collectors.dns_forensics – Deep DNS Forensics & Tunneling Detection
=========================================================================
Tracks DNS queries/responses via multiple methods and detects DNS tunneling,
DGA (Domain Generation Algorithm) domains, and suspicious DNS patterns.

Features
--------
- DNS query/response logging via /proc/net/udp parsing (port 53)
- Entropy-based DGA detection using Shannon entropy calculation
- DNS tunneling heuristics (query length, subdomain depth, TXT record abuse)
- Statistical analysis of DNS patterns per process
- Integration with IOC matching for known-bad domains

Public API
----------
gather_dns_queries()        – Harvest DNS query patterns from active connections
detect_dga_domains()        – Identify algorithmically generated domains
detect_dns_tunneling()      – Detect DNS tunneling indicators
analyze_dns_patterns()      – Statistical analysis of DNS behavior
"""
import math
from collections import defaultdict
from typing import Dict, List, Optional, Any


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string to detect randomness.

    High entropy (>4.0 for domain names) often indicates DGA or encoded data.

    Parameters
    ----------
    text : str
        Input string to analyze (typically a domain name).

    Returns
    -------
    float
        Shannon entropy value. Higher values indicate more randomness.
        Typical English text: ~4.0-4.5
        Random strings: >4.5
        Normal domains: ~3.0-4.0
    """
    if not text:
        return 0.0

    # Calculate frequency of each character
    freq = defaultdict(int)
    for char in text.lower():
        freq[char] += 1

    # Calculate entropy
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def extract_domain_parts(domain: str) -> Dict[str, Any]:
    """Extract structural components of a domain name for analysis.

    Parameters
    ----------
    domain : str
        Full domain name (e.g., "sub.example.co.uk").

    Returns
    -------
    dict
        Contains:
        - labels: list of domain labels split by dots
        - label_count: number of labels
        - longest_label: length of longest single label
        - avg_label_length: average label length
        - has_numeric_labels: whether any label is mostly numeric
        - subdomain_depth: number of subdomains (labels - 2 for TLD handling)
    """
    if not domain:
        return {
            "labels": [],
            "label_count": 0,
            "longest_label": 0,
            "avg_label_length": 0,
            "has_numeric_labels": False,
            "subdomain_depth": 0
        }

    labels = domain.strip('.').split('.')
    label_lengths = [len(label) for label in labels if label]

    # Check for numeric-heavy labels (common in DGA)
    has_numeric = any(
        label and sum(c.isdigit() for c in label) / len(label) > 0.5
        for label in labels if label
    )

    return {
        "labels": labels,
        "label_count": len(labels),
        "longest_label": max(label_lengths) if label_lengths else 0,
        "avg_label_length": sum(label_lengths) / len(label_lengths) if label_lengths else 0,
        "has_numeric_labels": has_numeric,
        "subdomain_depth": max(0, len(labels) - 2)
    }


def is_likely_dga(domain: str, entropy_threshold: float = 4.2) -> Dict[str, Any]:
    """Analyze a domain for DGA (Domain Generation Algorithm) characteristics.

    DGA domains typically exhibit:
    - High entropy (randomness)
    - Unusual label lengths
    - Excessive numeric characters
    - Non-standard TLDs
    - Lack of recognizable words

    Parameters
    ----------
    domain : str
        Domain name to analyze.
    entropy_threshold : float
        Shannon entropy threshold above which domain is flagged (default: 4.2).

    Returns
    -------
    dict
        Analysis results including:
        - is_dga: boolean flag
        - confidence: 0.0-1.0 confidence score
        - indicators: list of detected suspicious patterns
        - entropy: calculated Shannon entropy
        - domain_parts: structural analysis from extract_domain_parts()
    """
    result = {
        "is_dga": False,
        "confidence": 0.0,
        "indicators": [],
        "entropy": 0.0,
        "domain_parts": extract_domain_parts(domain)
    }

    if not domain or len(domain) < 5:
        return result

    # Extract just the domain name without TLD for entropy calculation
    parts = domain.strip('.').split('.')
    if len(parts) >= 2:
        # Calculate entropy on second-level domain + subdomains
        domain_for_entropy = '.'.join(parts[:-1])
    else:
        domain_for_entropy = domain

    # Calculate entropy
    entropy = calculate_shannon_entropy(domain_for_entropy)
    result["entropy"] = entropy

    confidence_score = 0.0

    # Indicator 1: High entropy
    if entropy > entropy_threshold:
        result["indicators"].append(f"high_entropy:{entropy:.2f}")
        confidence_score += 0.35

    # Indicator 2: Very long labels (>20 chars)
    if result["domain_parts"]["longest_label"] > 20:
        result["indicators"].append(f"long_label:{result['domain_parts']['longest_label']}")
        confidence_score += 0.25

    # Indicator 3: Excessive subdomain depth (>4 levels)
    if result["domain_parts"]["subdomain_depth"] > 4:
        result["indicators"].append(f"deep_subdomains:{result['domain_parts']['subdomain_depth']}")
        confidence_score += 0.20

    # Indicator 4: Numeric-heavy labels
    if result["domain_parts"]["has_numeric_labels"]:
        result["indicators"].append("numeric_labels")
        confidence_score += 0.15

    # Indicator 5: Overall domain length (>50 chars)
    if len(domain) > 50:
        result["indicators"].append(f"long_domain:{len(domain)}")
        confidence_score += 0.15

    # Indicator 6: Consonant clusters (no vowels in long labels)
    vowels = set('aeiou')
    for label in parts:
        if len(label) > 8 and not any(v in label.lower() for v in vowels):
            result["indicators"].append(f"no_vowels:{label}")
            confidence_score += 0.20
            break

    # Normalize confidence to 0-1 range
    result["confidence"] = min(1.0, confidence_score)
    result["is_dga"] = result["confidence"] >= 0.35

    return result


def detect_dns_tunneling_indicators(dns_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze a collection of DNS queries for tunneling indicators.

    DNS tunneling typically exhibits:
    - High volume of TXT or NULL record queries
    - Unusually long query names (encoded data in subdomains)
    - High query rate to single domain
    - Base64/hex-like patterns in subdomains

    Parameters
    ----------
    dns_queries : list
        List of DNS query dictionaries with 'domain', 'query_type', 'timestamp' keys.

    Returns
    -------
    dict
        Analysis results including:
        - is_tunneling: boolean flag
        - confidence: 0.0-1.0 confidence score
        - indicators: list of detected patterns
        - suspicious_domains: list of domains exhibiting tunneling behavior
        - statistics: aggregate statistics about the query set
    """
    result = {
        "is_tunneling": False,
        "confidence": 0.0,
        "indicators": [],
        "suspicious_domains": [],
        "statistics": {
            "total_queries": len(dns_queries),
            "unique_domains": 0,
            "txt_query_ratio": 0.0,
            "avg_query_length": 0.0,
            "max_query_length": 0,
            "queries_per_domain": {}
        }
    }

    if not dns_queries:
        return result

    # Collect statistics
    domain_counts = defaultdict(int)
    txt_queries = 0
    total_length = 0
    max_length = 0
    long_queries = []

    for query in dns_queries:
        domain = query.get("domain", "")
        query_type = query.get("query_type", "A")

        domain_counts[domain] += 1
        total_length += len(domain)
        max_length = max(max_length, len(domain))

        if query_type.upper() == "TXT":
            txt_queries += 1

        # Flag unusually long queries (>50 chars)
        if len(domain) > 50:
            long_queries.append(domain)

    total_queries = len(dns_queries)
    unique_domains = len(domain_counts)

    result["statistics"]["unique_domains"] = unique_domains
    result["statistics"]["avg_query_length"] = total_length / total_queries if total_queries > 0 else 0
    result["statistics"]["max_query_length"] = max_length
    result["statistics"]["txt_query_ratio"] = txt_queries / total_queries if total_queries > 0 else 0
    result["statistics"]["queries_per_domain"] = dict(domain_counts)

    confidence_score = 0.0

    # Indicator 1: High TXT query ratio (>30%)
    txt_ratio = result["statistics"]["txt_query_ratio"]
    if txt_ratio > 0.30:
        result["indicators"].append(f"high_txt_ratio:{txt_ratio:.2f}")
        confidence_score += 0.30

    # Indicator 2: Very long average query length (>40 chars)
    avg_len = result["statistics"]["avg_query_length"]
    if avg_len > 40:
        result["indicators"].append(f"long_avg_query_length:{avg_len:.1f}")
        confidence_score += 0.25
        result["suspicious_domains"].extend(long_queries[:10])

    # Indicator 3: High query concentration (single domain >50% of queries)
    if domain_counts:
        max_domain_count = max(domain_counts.values())
        concentration = max_domain_count / total_queries
        if concentration > 0.50 and total_queries > 10:
            result["indicators"].append(f"query_concentration:{concentration:.2f}")
            confidence_score += 0.25

            # Find the concentrated domain
            for domain, count in domain_counts.items():
                if count / total_queries > 0.50:
                    result["suspicious_domains"].append(domain)
                    break

    # Indicator 4: Many long queries
    if len(long_queries) > total_queries * 0.20:
        result["indicators"].append(f"many_long_queries:{len(long_queries)}")
        confidence_score += 0.20

    # Normalize confidence
    result["confidence"] = min(1.0, confidence_score)
    result["is_tunneling"] = result["confidence"] >= 0.30

    return result


def gather_dns_queries() -> List[Dict[str, Any]]:
    """Harvest DNS query information from active network connections.

    This function identifies potential DNS traffic by looking for UDP connections
    to port 53 (standard DNS) and port 5353 (mDNS). For each connection, it
    attempts to correlate with process information.

    Note: This is a point-in-time snapshot. For real-time DNS query capture,
    eBPF uprobes on libc res_send()/res_query() would be required.

    Returns
    -------
    list
        List of DNS connection dictionaries containing:
        - local_ip: local source IP
        - local_port: local source port
        - remote_ip: DNS server IP
        - remote_port: DNS server port (53 or 5353)
        - process_name: owning process
        - protocol: UDP
        - state: connection state
        - dns_server_type: classification of DNS server
    """
    from .connections import gather_outbound_connections

    dns_connections = []
    all_connections = gather_outbound_connections()

    # Known DNS server ports
    dns_ports = {53, 5353}  # Standard DNS and mDNS

    for conn in all_connections:
        if conn.get("remote_port") in dns_ports:
            # Classify DNS server type
            remote_ip = conn.get("remote_ip", "")
            dns_type = "external"

            # Check if it's a local resolver
            if remote_ip.startswith("127.") or remote_ip == "::1":
                dns_type = "localhost"
            elif remote_ip.startswith("10.") or \
                 remote_ip.startswith("192.168.") or \
                 remote_ip.startswith("172."):
                dns_type = "internal"

            dns_connections.append({
                "local_ip": conn.get("local_ip"),
                "local_port": conn.get("local_port"),
                "remote_ip": remote_ip,
                "remote_port": conn.get("remote_port"),
                "process_name": conn.get("process_name", "unknown"),
                "protocol": "UDP",
                "state": conn.get("state", "ESTABLISHED"),
                "dns_server_type": dns_type,
                "timestamp": None  # Would need eBPF for actual timestamps
            })

    return dns_connections


def analyze_dns_patterns(dns_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Perform comprehensive statistical analysis of DNS query patterns.

    Provides aggregate metrics useful for detecting anomalous DNS behavior:
    - Query volume by process
    - Query distribution by DNS server
    - Temporal patterns (if timestamps available)
    - Domain diversity metrics

    Parameters
    ----------
    dns_queries : list
        List of DNS query/connection dictionaries.

    Returns
    -------
    dict
        Comprehensive analysis including:
        - summary: high-level statistics
        - by_process: breakdown by originating process
        - by_server: breakdown by DNS server
        - anomalies: list of detected anomalous patterns
    """
    result = {
        "summary": {
            "total_queries": len(dns_queries),
            "unique_processes": 0,
            "unique_servers": 0,
            "external_dns_count": 0,
            "localhost_dns_count": 0
        },
        "by_process": {},
        "by_server": {},
        "anomalies": []
    }

    if not dns_queries:
        return result

    process_counts = defaultdict(int)
    server_counts = defaultdict(int)

    for query in dns_queries:
        process = query.get("process_name", "unknown")
        server = query.get("remote_ip", "unknown")
        server_type = query.get("dns_server_type", "unknown")

        process_counts[process] += 1
        server_counts[server] += 1

        if server_type == "external":
            result["summary"]["external_dns_count"] += 1
        elif server_type == "localhost":
            result["summary"]["localhost_dns_count"] += 1

    result["summary"]["unique_processes"] = len(process_counts)
    result["summary"]["unique_servers"] = len(server_counts)
    result["by_process"] = dict(process_counts)
    result["by_server"] = dict(server_counts)

    # Detect anomalies

    # Anomaly 1: Single process making excessive DNS queries (>80% of total)
    total = len(dns_queries)
    for process, count in process_counts.items():
        ratio = count / total
        if ratio > 0.80 and total > 20:
            result["anomalies"].append({
                "type": "excessive_dns_by_process",
                "process": process,
                "count": count,
                "ratio": ratio,
                "severity": "high" if ratio > 0.95 else "medium"
            })

    # Anomaly 2: Using non-standard external DNS servers
    external_servers = [
        server for server, count in server_counts.items()
        if not server.startswith("127.") and
           not server.startswith("192.168.") and
           not server.startswith("10.") and
           not server.startswith("172.")
    ]

    if external_servers:
        result["anomalies"].append({
            "type": "external_dns_servers",
            "servers": external_servers,
            "severity": "low",
            "note": "External DNS usage detected - verify if authorized"
        })

    return result


def check_domain_against_iocs(domain: str, ioc_list: Optional[List[str]] = None) -> Dict[str, Any]:
    """Check a domain against a list of IOCs (Indicators of Compromise).

    Parameters
    ----------
    domain : str
        Domain to check.
    ioc_list : list, optional
        List of known-bad domains or patterns. If None, uses basic heuristics.

    Returns
    -------
    dict
        Match results including:
        - is_malicious: boolean flag
        - matched_ioc: the matched IOC if any
        - match_type: type of match (exact, substring, regex)
        - confidence: confidence level
    """
    result = {
        "is_malicious": False,
        "matched_ioc": None,
        "match_type": None,
        "confidence": 0.0
    }

    if not domain:
        return result

    # If custom IOC list provided, check against it
    if ioc_list:
        domain_lower = domain.lower()
        for ioc in ioc_list:
            ioc_lower = ioc.lower()

            # Exact match
            if domain_lower == ioc_lower:
                result["is_malicious"] = True
                result["matched_ioc"] = ioc
                result["match_type"] = "exact"
                result["confidence"] = 1.0
                return result

            # Subdomain match (IOC is parent domain)
            if domain_lower.endswith("." + ioc_lower):
                result["is_malicious"] = True
                result["matched_ioc"] = ioc
                result["match_type"] = "subdomain"
                result["confidence"] = 0.95
                return result

    # Basic heuristic checks even without IOC list

    # Check for known malicious TLDs (often abused)
    suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'}
    domain_lower = domain.lower()
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            result["is_malicious"] = True
            result["matched_ioc"] = f"suspicious_tld:{tld}"
            result["match_type"] = "heuristic"
            result["confidence"] = 0.3
            break

    return result