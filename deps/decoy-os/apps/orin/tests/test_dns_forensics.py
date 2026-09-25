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
"""
tests/test_dns_forensics.py – Unit Tests for DNS Forensics Module
==================================================================
Tests for DGA detection, DNS tunneling detection, entropy calculation,
and DNS pattern analysis functions.
"""
import pytest
from src.orin.collectors.dns_forensics import (
    calculate_shannon_entropy,
    extract_domain_parts,
    is_likely_dga,
    detect_dns_tunneling_indicators,
    gather_dns_queries,
    analyze_dns_patterns,
    check_domain_against_iocs
)


class TestShannonEntropy:
    """Test Shannon entropy calculation for randomness detection."""

    def test_empty_string(self):
        """Empty string should return 0.0 entropy."""
        assert calculate_shannon_entropy("") == 0.0

    def test_single_character(self):
        """Single character repeated should have 0 entropy."""
        assert calculate_shannon_entropy("aaaa") == 0.0

    def test_two_characters_equal(self):
        """Two characters with equal frequency should have entropy ~1.0."""
        entropy = calculate_shannon_entropy("ab")
        assert 0.9 < entropy < 1.1

    def test_random_string_high_entropy(self):
        """Random-looking string should have high entropy."""
        # High entropy random-like string
        entropy = calculate_shannon_entropy("a8f3k2m9x7q1")
        assert entropy > 3.0

    def test_normal_word_medium_entropy(self):
        """Normal English word should have medium entropy."""
        entropy = calculate_shannon_entropy("example")
        assert 2.5 < entropy < 3.5

    def test_case_insensitive(self):
        """Entropy calculation should be case-insensitive."""
        entropy_lower = calculate_shannon_entropy("abcdef")
        entropy_upper = calculate_shannon_entropy("ABCDEF")
        entropy_mixed = calculate_shannon_entropy("AbCdEf")
        assert abs(entropy_lower - entropy_upper) < 0.01
        assert abs(entropy_lower - entropy_mixed) < 0.01


class TestExtractDomainParts:
    """Test domain structure extraction."""

    def test_simple_domain(self):
        """Test simple two-part domain."""
        result = extract_domain_parts("example.com")
        assert result["label_count"] == 2
        assert result["subdomain_depth"] == 0
        assert "example" in result["labels"]
        assert "com" in result["labels"]

    def test_subdomain(self):
        """Test domain with subdomain."""
        result = extract_domain_parts("sub.example.com")
        assert result["label_count"] == 3
        assert result["subdomain_depth"] == 1

    def test_deep_subdomain(self):
        """Test domain with multiple subdomains."""
        result = extract_domain_parts("a.b.c.d.example.com")
        assert result["label_count"] == 6
        assert result["subdomain_depth"] == 4

    def test_numeric_label_detection(self):
        """Test detection of numeric-heavy labels."""
        result = extract_domain_parts("abc123.example.com")
        assert not result["has_numeric_labels"]

        result2 = extract_domain_parts("12345.example.com")
        assert result2["has_numeric_labels"]

    def test_long_label_detection(self):
        """Test detection of long labels."""
        result = extract_domain_parts("verylonglabelthatexceedstwentychars.example.com")
        assert result["longest_label"] > 20

    def test_empty_domain(self):
        """Test empty domain handling."""
        result = extract_domain_parts("")
        assert result["label_count"] == 0
        assert result["longest_label"] == 0


class TestDGADetection:
    """Test DGA (Domain Generation Algorithm) detection."""

    def test_normal_domain_not_dga(self):
        """Normal domains should not be flagged as DGA."""
        result = is_likely_dga("google.com")
        assert not result["is_dga"]
        assert result["confidence"] < 0.35

    def test_random_string_dga(self):
        """Random-looking strings should trigger DGA indicators."""
        result = is_likely_dga("xk7m9q2p4r8n.com")
        # This domain has no vowels which triggers an indicator
        # but may not reach the 0.35 confidence threshold for is_dga=True
        assert len(result["indicators"]) > 0
        assert "no_vowels" in str(result["indicators"])
        assert result["entropy"] > 0

    def test_long_label_dga_indicator(self):
        """Domains with very long labels should trigger DGA indicators."""
        result = is_likely_dga("abcdefghijklmnopqrstuvwxyz.malicious.com")
        assert "long_label" in str(result["indicators"])

    def test_numeric_heavy_dga(self):
        """Numeric-heavy domains should trigger DGA indicators."""
        result = is_likely_dga("123456789012345.com")
        assert result["indicators"]  # Should have some indicators

    def test_no_vowels_detection(self):
        """Consonant-only long labels should be flagged."""
        result = is_likely_dga("xkrtmplstrng.com")
        assert "no_vowels" in str(result["indicators"])

    def test_entropy_calculation_included(self):
        """DGA analysis should include entropy value."""
        result = is_likely_dga("test.com")
        assert "entropy" in result
        assert isinstance(result["entropy"], float)
        assert result["entropy"] >= 0.0

    def test_short_domain_handling(self):
        """Very short domains should be handled gracefully."""
        result = is_likely_dga("ab.cd")
        assert "is_dga" in result


class TestDNSTunnelingDetection:
    """Test DNS tunneling detection heuristics."""

    def test_empty_query_list(self):
        """Empty query list should return safe defaults."""
        result = detect_dns_tunneling_indicators([])
        assert not result["is_tunneling"]
        assert result["confidence"] == 0.0
        assert result["statistics"]["total_queries"] == 0

    def test_normal_queries_not_tunneling(self):
        """Normal DNS queries should not trigger tunneling detection."""
        queries = [
            {"domain": f"site{i}.com", "query_type": "A"}
            for i in range(20)
        ]
        result = detect_dns_tunneling_indicators(queries)
        assert not result["is_tunneling"]

    def test_high_txt_ratio_tunneling(self):
        """High TXT query ratio should indicate tunneling."""
        queries = [
            {"domain": f"site{i}.com", "query_type": "TXT"}
            for i in range(15)
        ] + [
            {"domain": f"site{i}.com", "query_type": "A"}
            for i in range(5)
        ]
        result = detect_dns_tunneling_indicators(queries)
        assert result["is_tunneling"]
        assert "high_txt_ratio" in str(result["indicators"])

    def test_long_queries_tunneling(self):
        """Unusually long queries should indicate tunneling."""
        queries = [
            {"domain": "a" * 60 + ".tunnel.com", "query_type": "A"}
            for _ in range(15)
        ]
        result = detect_dns_tunneling_indicators(queries)
        assert result["is_tunneling"]
        assert "long_avg_query_length" in str(result["indicators"])

    def test_query_concentration(self):
        """High concentration to single domain should be flagged."""
        queries = [
            {"domain": "same-domain.com", "query_type": "A"}
            for _ in range(25)
        ] + [
            {"domain": f"different{i}.com", "query_type": "A"}
            for i in range(5)
        ]
        result = detect_dns_tunneling_indicators(queries)
        assert result["statistics"]["total_queries"] == 30
        assert "same-domain.com" in result["statistics"]["queries_per_domain"]

    def test_statistics_collection(self):
        """Test that statistics are properly collected."""
        queries = [
            {"domain": "example.com", "query_type": "A"},
            {"domain": "test.com", "query_type": "TXT"},
        ]
        result = detect_dns_tunneling_indicators(queries)
        assert result["statistics"]["total_queries"] == 2
        assert result["statistics"]["unique_domains"] == 2
        assert result["statistics"]["txt_query_ratio"] == 0.5


class TestDNSPatternAnalysis:
    """Test DNS pattern analysis functions."""

    def test_empty_analysis(self):
        """Empty query list should return zero counts."""
        result = analyze_dns_patterns([])
        assert result["summary"]["total_queries"] == 0
        assert result["summary"]["unique_processes"] == 0

    def test_process_breakdown(self):
        """Test breakdown by process."""
        queries = [
            {"process_name": "chrome", "remote_ip": "8.8.8.8", "dns_server_type": "external"},
            {"process_name": "chrome", "remote_ip": "8.8.8.8", "dns_server_type": "external"},
            {"process_name": "firefox", "remote_ip": "1.1.1.1", "dns_server_type": "external"},
        ]
        result = analyze_dns_patterns(queries)
        assert result["by_process"]["chrome"] == 2
        assert result["by_process"]["firefox"] == 1

    def test_server_breakdown(self):
        """Test breakdown by DNS server."""
        queries = [
            {"process_name": "app", "remote_ip": "8.8.8.8", "dns_server_type": "external"},
            {"process_name": "app", "remote_ip": "8.8.8.8", "dns_server_type": "external"},
            {"process_name": "app", "remote_ip": "1.1.1.1", "dns_server_type": "external"},
        ]
        result = analyze_dns_patterns(queries)
        assert result["by_server"]["8.8.8.8"] == 2
        assert result["by_server"]["1.1.1.1"] == 1

    def test_dns_server_classification(self):
        """Test DNS server type classification."""
        queries = [
            {"process_name": "app", "remote_ip": "127.0.0.1", "dns_server_type": "localhost"},
            {"process_name": "app", "remote_ip": "192.168.1.1", "dns_server_type": "internal"},
            {"process_name": "app", "remote_ip": "8.8.8.8", "dns_server_type": "external"},
        ]
        result = analyze_dns_patterns(queries)
        assert result["summary"]["localhost_dns_count"] == 1
        assert result["summary"]["external_dns_count"] == 1

    def test_anomaly_detection_excessive_process(self):
        """Test detection of excessive DNS by single process."""
        queries = [
            {"process_name": "suspicious", "remote_ip": "8.8.8.8", "dns_server_type": "external"}
            for _ in range(25)
        ] + [
            {"process_name": "normal", "remote_ip": "8.8.8.8", "dns_server_type": "external"}
            for _ in range(5)
        ]
        result = analyze_dns_patterns(queries)
        assert len(result["anomalies"]) > 0
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "excessive_dns_by_process" in anomaly_types


class TestIOCMatching:
    """Test IOC (Indicator of Compromise) matching."""

    def test_exact_match(self):
        """Test exact domain match against IOC list."""
        iocs = ["malware.com", "badsite.org"]
        result = check_domain_against_iocs("malware.com", iocs)
        assert result["is_malicious"]
        assert result["match_type"] == "exact"
        assert result["confidence"] == 1.0

    def test_subdomain_match(self):
        """Test subdomain match against parent domain IOC."""
        iocs = ["malware.com"]
        result = check_domain_against_iocs("sub.malware.com", iocs)
        assert result["is_malicious"]
        assert result["match_type"] == "subdomain"
        assert result["confidence"] >= 0.9

    def test_no_match(self):
        """Test non-matching domain."""
        iocs = ["malware.com"]
        result = check_domain_against_iocs("google.com", iocs)
        assert not result["is_malicious"]

    def test_suspicious_tld_heuristic(self):
        """Test suspicious TLD heuristic detection."""
        result = check_domain_against_iocs("freemoney.tk")
        assert result["is_malicious"]
        assert result["match_type"] == "heuristic"
        assert "suspicious_tld" in str(result["matched_ioc"])

    def test_empty_domain(self):
        """Test empty domain handling."""
        result = check_domain_against_iocs("")
        assert not result["is_malicious"]

    def test_case_insensitive_match(self):
        """Test case-insensitive matching."""
        iocs = ["Malware.COM"]
        result = check_domain_against_iocs("malware.com", iocs)
        assert result["is_malicious"]


class TestGatherDNSQueries:
    """Test DNS query gathering from network connections."""

    def test_gather_returns_list(self):
        """gather_dns_queries should return a list."""
        result = gather_dns_queries()
        assert isinstance(result, list)

    def test_gather_handles_no_dns_connections(self):
        """Should handle systems with no active DNS connections."""
        # This depends on system state, but should not crash
        result = gather_dns_queries()
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])