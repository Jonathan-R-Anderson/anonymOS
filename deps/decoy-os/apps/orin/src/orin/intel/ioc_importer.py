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
# src/orin/intel/ioc_importer.py
"""
Orin Offline Threat Intelligence & IOC Importer
================================================
Enables security teams to import offline threat intelligence feeds in multiple formats:
- Simple IP/Domain/Hash blocklists (TXT)
- STIX 2.x JSON/XML
- TAXII 2.x collections (offline mode)
- CSV threat feeds

This module parses various threat intel formats and normalizes them into
a unified IOC format that can be used by the detection engine.
"""
import json
import csv
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Indicator:
    """Normalized IOC indicator from various threat intel formats."""
    id: str
    type: str  # ip-addr, domain, file-hash, url, email
    value: str
    confidence: int = 50  # 0-100
    severity: str = "medium"  # low, medium, high, critical
    source: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    created: str = ""
    expires: str = ""
    revoked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class IOCImporter:
    """
    Multi-format threat intelligence importer supporting:
    - Plain text blocklists (IPs, domains, hashes)
    - STIX 2.x JSON bundles
    - CSV threat feeds
    - TAXII 2.x collections (offline export format)
    """

    # Regex patterns for auto-detection
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$')
    DOMAIN_PATTERN = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    URL_PATTERN = re.compile(r'^https?://')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    def __init__(self, intel_dir: Path = None):
        """
        Initialize the IOC importer.

        Args:
            intel_dir: Directory containing threat intel files. Defaults to /var/lib/orin/intel/
        """
        self.intel_dir = intel_dir or Path("/var/lib/orin/intel")
        self.indicators: List[Indicator] = []
        self.ip_blocklist: Set[str] = set()
        self.domain_blocklist: Set[str] = set()
        self.hash_blocklist: Set[str] = set()
        self.url_blocklist: Set[str] = set()

    def detect_ioc_type(self, value: str) -> str:
        """Auto-detect the type of an IOC value."""
        value = value.strip()
        if self.IP_PATTERN.match(value):
            return "ip-addr"
        elif self.DOMAIN_PATTERN.match(value):
            return "domain"
        elif self.MD5_PATTERN.match(value):
            return "file-hash-md5"
        elif self.SHA1_PATTERN.match(value):
            return "file-hash-sha1"
        elif self.SHA256_PATTERN.match(value):
            return "file-hash-sha256"
        elif self.URL_PATTERN.match(value):
            return "url"
        elif self.EMAIL_PATTERN.match(value):
            return "email"
        return "unknown"

    def load_txt_blocklist(self, filepath: Path) -> List[Indicator]:
        """
        Load a plain text blocklist file.

        Format: One IOC per line, optionally with metadata after whitespace
        Example:
            192.168.1.100 # Known C2 server
            evil.com
            abc123...def  # Malware hash

        Args:
            filepath: Path to the text file

        Returns:
            List of parsed indicators
        """
        indicators = []
        if not filepath.exists():
            return indicators

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Extract value and optional comment
                    parts = line.split('#', 1)
                    value = parts[0].strip()
                    description = parts[1].strip() if len(parts) > 1 else ""

                    if not value:
                        continue

                    ioc_type = self.detect_ioc_type(value)
                    if ioc_type == "unknown":
                        print(f"[!] Warning: Could not detect IOC type for line {line_num}: {value}")
                        continue

                    indicator = Indicator(
                        id=f"txt-{filepath.name}-{line_num}",
                        type=ioc_type,
                        value=value,
                        confidence=70,
                        source=filepath.name,
                        description=description,
                        created=datetime.now().isoformat()
                    )
                    indicators.append(indicator)

        except Exception as e:
            print(f"[!] Error reading text blocklist {filepath}: {e}")

        return indicators

    def load_stix_json(self, filepath: Path) -> List[Indicator]:
        """
        Load STIX 2.x JSON bundle or collection.

        Supports:
        - STIX Bundle objects
        - Individual Indicator SDOs
        - TAXII 2.x collection exports

        Args:
            filepath: Path to the STIX JSON file

        Returns:
            List of parsed indicators
        """
        indicators = []
        if not filepath.exists():
            return indicators

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Handle STIX Bundle
            objects = []
            if isinstance(data, dict):
                if data.get("type") == "bundle":
                    objects = data.get("objects", [])
                elif data.get("type") == "indicator":
                    objects = [data]
                else:
                    # Might be a list of objects
                    objects = data.get("objects", [data] if "pattern" in data else [])
            elif isinstance(data, list):
                objects = data

            for obj in objects:
                if obj.get("type") != "indicator":
                    continue

                if obj.get("revoked", False):
                    continue

                # Parse STIX pattern (simplified - supports common patterns)
                pattern = obj.get("pattern", "")

                # Extract IOCs from STIX pattern
                extracted_iocs = self._parse_stix_pattern(pattern)

                for ioc_value, ioc_type in extracted_iocs:
                    # Map STIX confidence (0-100) to our scale
                    confidence = obj.get("confidence", 50)

                    # Map STIX labels to severity
                    labels = obj.get("labels", [])
                    severity = "medium"
                    if "critical" in [l.lower() for l in labels]:
                        severity = "critical"
                    elif "high" in [l.lower() for l in labels]:
                        severity = "high"
                    elif "low" in [l.lower() for l in labels]:
                        severity = "low"

                    indicator = Indicator(
                        id=obj.get("id", f"stix-{filepath.name}-{len(indicators)}"),
                        type=ioc_type,
                        value=ioc_value,
                        confidence=confidence,
                        severity=severity,
                        source=filepath.name,
                        description=obj.get("description", ""),
                        tags=obj.get("labels", []),
                        created=obj.get("created", datetime.now().isoformat()),
                        expires=obj.get("valid_until", ""),
                        revoked=False
                    )
                    indicators.append(indicator)

        except json.JSONDecodeError as e:
            print(f"[!] Error parsing STIX JSON {filepath}: {e}")
        except Exception as e:
            print(f"[!] Error reading STIX file {filepath}: {e}")

        return indicators

    def _parse_stix_pattern(self, pattern: str) -> List[tuple]:
        """
        Extract IOC values from a STIX 2.x pattern string.

        Supports common pattern types:
        - [ipv4:addr:value = '192.168.1.1']
        - [domain-name:value = 'evil.com']
        - [file:hashes.'SHA-256' = 'abc123...']
        - [url:value = 'http://evil.com/malware']

        Args:
            pattern: STIX pattern string

        Returns:
            List of (value, type) tuples
        """
        extracted = []

        # IPv4 pattern
        ipv4_matches = re.findall(r"\[ipv4:addr:value\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in ipv4_matches:
            extracted.append((match, "ip-addr"))

        # IPv6 pattern
        ipv6_matches = re.findall(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in ipv6_matches:
            extracted.append((match, "ip-addr"))

        # Domain pattern
        domain_matches = re.findall(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in domain_matches:
            extracted.append((match, "domain"))

        # File hash patterns (support quotes around hash type name)
        md5_matches = re.findall(r"\[file:hashes\.['\"]?(?:MD5|md5)['\"]?\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in md5_matches:
            extracted.append((match, "file-hash-md5"))

        sha1_matches = re.findall(r"\[file:hashes\.['\"]?(?:SHA1|sha1)['\"]?\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in sha1_matches:
            extracted.append((match, "file-hash-sha1"))

        sha256_matches = re.findall(r"\[file:hashes\.['\"]?(?:SHA-256|SHA256|sha256)['\"]?\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in sha256_matches:
            extracted.append((match, "file-hash-sha256"))

        # URL pattern
        url_matches = re.findall(r"\[url:value\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in url_matches:
            extracted.append((match, "url"))

        # Email pattern
        email_matches = re.findall(r"\[email-addr:value\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for match in email_matches:
            extracted.append((match, "email"))

        return extracted

    def load_csv_feed(self, filepath: Path, column_mapping: Dict[str, str] = None) -> List[Indicator]:
        """
        Load a CSV threat feed.

        Args:
            filepath: Path to the CSV file
            column_mapping: Optional mapping of column names to IOC types.
                           If not provided, attempts auto-detection.
                           Example: {"ip": "ip-addr", "domain": "domain", "hash": "file-hash-sha256"}

        Returns:
            List of parsed indicators
        """
        indicators = []
        if not filepath.exists():
            return indicators

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Try to detect delimiter
                sample = f.read(4096)
                f.seek(0)

                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
                except csv.Error:
                    dialect = csv.excel  # Default to comma

                reader = csv.DictReader(f, dialect=dialect)

                for row_num, row in enumerate(reader, 1):
                    if column_mapping:
                        # Use provided mapping
                        for col, ioc_type in column_mapping.items():
                            if col in row and row[col]:
                                value = row[col].strip()
                                if value:
                                    indicator = Indicator(
                                        id=f"csv-{filepath.name}-{row_num}-{col}",
                                        type=ioc_type,
                                        value=value,
                                        confidence=int(row.get('confidence', 50)),
                                        source=filepath.name,
                                        description=row.get('description', row.get('comment', '')),
                                        tags=[row.get('tag', '')] if row.get('tag') else [],
                                        created=row.get('created', datetime.now().isoformat())
                                    )
                                    indicators.append(indicator)
                    else:
                        # Auto-detect columns
                        for col, value in row.items():
                            if not value or not value.strip():
                                continue

                            value = value.strip()
                            ioc_type = self.detect_ioc_type(value)

                            if ioc_type != "unknown":
                                indicator = Indicator(
                                    id=f"csv-{filepath.name}-{row_num}-{col}",
                                    type=ioc_type,
                                    value=value,
                                    confidence=60,
                                    source=filepath.name,
                                    created=datetime.now().isoformat()
                                )
                                indicators.append(indicator)

        except Exception as e:
            print(f"[!] Error reading CSV feed {filepath}: {e}")

        return indicators

    def load_all_intel(self) -> List[Indicator]:
        """
        Load all threat intelligence files from the intel directory.

        Automatically detects file format based on extension and content.

        Returns:
            List of all parsed indicators
        """
        all_indicators = []

        if not self.intel_dir.exists():
            print(f"[!] Warning: Intel directory does not exist: {self.intel_dir}")
            return all_indicators

        # Process all files in intel directory
        for filepath in self.intel_dir.iterdir():
            if not filepath.is_file():
                continue

            indicators = []

            # Determine file type and load accordingly
            suffix = filepath.suffix.lower()

            if suffix in ['.txt', '.lst', '.blocklist']:
                indicators = self.load_txt_blocklist(filepath)
            elif suffix == '.json':
                # Try STIX first
                indicators = self.load_stix_json(filepath)
                # If no STIX indicators found, try as simple JSON list
                if not indicators:
                    indicators = self._load_json_list(filepath)
            elif suffix == '.xml':
                indicators = self._load_stix_xml(filepath)
            elif suffix == '.csv':
                indicators = self.load_csv_feed(filepath)

            if indicators:
                print(f"[+] Loaded {len(indicators)} indicators from {filepath.name}")
                all_indicators.extend(indicators)

        self.indicators = all_indicators
        self._build_blocklists()
        return all_indicators

    def _load_json_list(self, filepath: Path) -> List[Indicator]:
        """Load a simple JSON list of IOCs."""
        indicators = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, list):
                for idx, item in enumerate(data):
                    if isinstance(item, str):
                        value = item.strip()
                        ioc_type = self.detect_ioc_type(value)
                        if ioc_type != "unknown":
                            indicators.append(Indicator(
                                id=f"json-{filepath.name}-{idx}",
                                type=ioc_type,
                                value=value,
                                source=filepath.name,
                                created=datetime.now().isoformat()
                            ))
                    elif isinstance(item, dict):
                        # Try to extract value from dict
                        value = item.get('value') or item.get('ioc') or item.get('indicator')
                        ioc_type = item.get('type') or self.detect_ioc_type(str(value))
                        if value:
                            indicators.append(Indicator(
                                id=f"json-{filepath.name}-{idx}",
                                type=ioc_type,
                                value=str(value),
                                confidence=item.get('confidence', 50),
                                source=filepath.name,
                                description=item.get('description', ''),
                                created=datetime.now().isoformat()
                            ))
        except Exception as e:
            print(f"[!] Error reading JSON list {filepath}: {e}")

        return indicators

    def _load_stix_xml(self, filepath: Path) -> List[Indicator]:
        """Load STIX 1.x or 2.x XML format (basic support)."""
        indicators = []
        try:
            import xml.etree.ElementTree as ET

            tree = ET.parse(filepath)
            root = tree.getroot()

            # Remove namespace prefixes for easier parsing
            for elem in root.iter():
                if '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]

            # Look for Indicator elements (STIX 1.x style)
            for indicator_elem in root.iter('.//Indicator'):
                title = indicator_elem.findtext('Title', '')
                desc = indicator_elem.findtext('Description', '')

                # Look for observable values
                for observable in indicator_elem.iter('.//Observable'):
                    for obj in observable.iter('.//Object'):
                        props = obj.find('Properties')
                        if props is not None:
                            # IP Address
                            ip = props.get('address') or props.findtext('Address_Value')
                            if ip:
                                indicators.append(Indicator(
                                    id=f"stix-xml-{filepath.name}-{len(indicators)}",
                                    type="ip-addr",
                                    value=ip,
                                    source=filepath.name,
                                    description=title or desc,
                                    created=datetime.now().isoformat()
                                ))

                            # Domain
                            domain = props.get('name') or props.findtext('Value')
                            if domain and self.DOMAIN_PATTERN.match(domain):
                                indicators.append(Indicator(
                                    id=f"stix-xml-{filepath.name}-{len(indicators)}",
                                    type="domain",
                                    value=domain,
                                    source=filepath.name,
                                    description=title or desc,
                                    created=datetime.now().isoformat()
                                ))

                            # Hash
                            hash_val = props.get('md5') or props.get('sha1') or props.get('sha256')
                            if not hash_val:
                                for hash_elem in props.iter('Hash'):
                                    hash_val = hash_elem.text
                                    break
                            if hash_val:
                                hash_type = self.detect_ioc_type(hash_val)
                                if hash_type != "unknown":
                                    indicators.append(Indicator(
                                        id=f"stix-xml-{filepath.name}-{len(indicators)}",
                                        type=hash_type,
                                        value=hash_val,
                                        source=filepath.name,
                                        description=title or desc,
                                        created=datetime.now().isoformat()
                                    ))

        except Exception as e:
            print(f"[!] Error reading STIX XML {filepath}: {e}")

        return indicators

    def _build_blocklists(self):
        """Build optimized lookup sets from loaded indicators."""
        self.ip_blocklist.clear()
        self.domain_blocklist.clear()
        self.hash_blocklist.clear()
        self.url_blocklist.clear()

        for indicator in self.indicators:
            if indicator.revoked:
                continue

            if indicator.type == "ip-addr":
                # Extract base IP without CIDR notation for matching
                ip = indicator.value.split('/')[0]
                self.ip_blocklist.add(ip)
            elif indicator.type == "domain":
                self.domain_blocklist.add(indicator.value.lower())
            elif indicator.type.startswith("file-hash"):
                self.hash_blocklist.add(indicator.value.lower())
            elif indicator.type == "url":
                self.url_blocklist.add(indicator.value.lower())

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of loaded threat intelligence."""
        type_counts = {}
        severity_counts = {}

        for indicator in self.indicators:
            if indicator.revoked:
                continue
            type_counts[indicator.type] = type_counts.get(indicator.type, 0) + 1
            severity_counts[indicator.severity] = severity_counts.get(indicator.severity, 0) + 1

        return {
            "total_indicators": len(self.indicators),
            "active_indicators": sum(1 for i in self.indicators if not i.revoked),
            "by_type": type_counts,
            "by_severity": severity_counts,
            "ip_count": len(self.ip_blocklist),
            "domain_count": len(self.domain_blocklist),
            "hash_count": len(self.hash_blocklist),
            "url_count": len(self.url_blocklist),
            "sources": list(set(i.source for i in self.indicators if i.source))
        }

    def match_ip(self, ip: str) -> Optional[Indicator]:
        """Check if an IP matches any loaded indicator."""
        ip = ip.strip()
        if ip in self.ip_blocklist:
            for indicator in self.indicators:
                if indicator.type == "ip-addr" and indicator.value.split('/')[0] == ip:
                    return indicator
        return None

    def match_domain(self, domain: str) -> Optional[Indicator]:
        """Check if a domain matches any loaded indicator."""
        domain = domain.strip().lower()
        if domain in self.domain_blocklist:
            for indicator in self.indicators:
                if indicator.type == "domain" and indicator.value.lower() == domain:
                    return indicator
        return None

    def match_hash(self, file_hash: str) -> Optional[Indicator]:
        """Check if a file hash matches any loaded indicator."""
        file_hash = file_hash.strip().lower()
        if file_hash in self.hash_blocklist:
            for indicator in self.indicators:
                if indicator.type.startswith("file-hash") and indicator.value.lower() == file_hash:
                    return indicator
        return None

    def export_blocklist(self, output_path: Path, format: str = "txt"):
        """
        Export consolidated blocklist to a file.

        Args:
            output_path: Output file path
            format: Output format ('txt', 'json', 'csv')
        """
        if format == "txt":
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# Orin Threat Intelligence Blocklist\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Total Indicators: {len(self.indicators)}\n\n")

                for indicator in sorted(self.indicators, key=lambda x: x.type):
                    if not indicator.revoked:
                        f.write(f"{indicator.value} # {indicator.type} - {indicator.description}\n")

        elif format == "json":
            data = {
                "generated": datetime.now().isoformat(),
                "summary": self.get_summary(),
                "indicators": [i.to_dict() for i in self.indicators if not i.revoked]
            }
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        elif format == "csv":
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['type', 'value', 'confidence', 'severity', 'source', 'description', 'tags'])
                for indicator in sorted(self.indicators, key=lambda x: x.type):
                    if not indicator.revoked:
                        writer.writerow([
                            indicator.type,
                            indicator.value,
                            indicator.confidence,
                            indicator.severity,
                            indicator.source,
                            indicator.description,
                            '|'.join(indicator.tags)
                        ])

        print(f"[+] Exported blocklist to {output_path}")


def create_sample_intel_files(intel_dir: Path = None):
    """Create sample threat intelligence files for testing."""
    intel_dir = intel_dir or Path("/var/lib/orin/intel")
    intel_dir.mkdir(parents=True, exist_ok=True)

    # Sample TXT blocklist
    txt_file = intel_dir / "sample_blocklist.txt"
    with open(txt_file, 'w') as f:
        f.write("""# Sample Threat Intelligence Blocklist
# Format: IOC_VALUE # Optional description

# Known C2 Servers
192.168.100.50 # APT29 C2 infrastructure
10.0.0.99 # Ransomware payment portal
185.220.101.1 # Tor exit node (malicious)

# Malicious Domains
evil-malware.com # Malware distribution
phishing-site.net # Credential harvesting
c2-server.org # Command and control

# Malware Hashes (SHA256)
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 # Empty file test
""")

    # Sample STIX 2.x JSON
    stix_file = intel_dir / "sample_stix.json"
    stix_data = {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789012",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--12345678-1234-1234-1234-123456789012",
                "created": "2024-01-15T10:00:00Z",
                "modified": "2024-01-15T10:00:00Z",
                "name": "Malicious IP Address",
                "pattern": "[ipv4:addr:value = '203.0.113.50']",
                "pattern_type": "stix",
                "valid_from": "2024-01-15T10:00:00Z",
                "labels": ["malicious-activity", "high"],
                "confidence": 80,
                "description": "Known APT infrastructure"
            },
            {
                "type": "indicator",
                "id": "indicator--22345678-1234-1234-1234-123456789012",
                "created": "2024-01-15T11:00:00Z",
                "modified": "2024-01-15T11:00:00Z",
                "name": "Malicious Domain",
                "pattern": "[domain-name:value = 'bad-domain.com']",
                "pattern_type": "stix",
                "valid_from": "2024-01-15T11:00:00Z",
                "labels": ["phishing", "critical"],
                "confidence": 90,
                "description": "Active phishing campaign"
            },
            {
                "type": "indicator",
                "id": "indicator--32345678-1234-1234-1234-123456789012",
                "created": "2024-01-15T12:00:00Z",
                "modified": "2024-01-15T12:00:00Z",
                "name": "Ransomware Hash",
                "pattern": "[file:hashes.'SHA-256' = 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab']",
                "pattern_type": "stix",
                "valid_from": "2024-01-15T12:00:00Z",
                "labels": ["ransomware", "critical"],
                "confidence": 95,
                "description": "Known ransomware variant"
            }
        ]
    }
    with open(stix_file, 'w') as f:
        json.dump(stix_data, f, indent=2)

    # Sample CSV feed
    csv_file = intel_dir / "sample_feed.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['value', 'type', 'confidence', 'description'])
        writer.writerow(['198.51.100.23', 'ip-addr', '75', 'Botnet C2'])
        writer.writerow(['malware-download.net', 'domain', '85', 'Malware hosting'])
        writer.writerow(['deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678', 'file-hash-sha256', '90', 'Trojan downloader'])

    print(f"[+] Created sample threat intel files in {intel_dir}")
    return intel_dir


if __name__ == "__main__":
    # Demo usage
    import sys

    intel_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None

    # Create sample files if intel dir doesn't exist
    if not intel_dir or not intel_dir.exists():
        intel_dir = create_sample_intel_files()

    # Initialize importer
    importer = IOCImporter(intel_dir=intel_dir)

    # Load all threat intel
    print("[*] Loading threat intelligence...")
    indicators = importer.load_all_intel()

    # Print summary
    summary = importer.get_summary()
    print("\n=== Threat Intelligence Summary ===")
    print(f"Total Indicators: {summary['total_indicators']}")
    print(f"Active Indicators: {summary['active_indicators']}")
    print(f"By Type: {summary['by_type']}")
    print(f"By Severity: {summary['by_severity']}")
    print(f"Sources: {summary['sources']}")

    # Test matching
    print("\n=== Testing IOC Matching ===")
    test_ips = ["192.168.100.50", "203.0.113.50", "8.8.8.8"]
    for ip in test_ips:
        result = importer.match_ip(ip)
        if result:
            print(f"[!] MATCH: {ip} -> {result.type} (Confidence: {result.confidence}, Source: {result.source})")
        else:
            print(f"[+] CLEAN: {ip}")

    # Export consolidated blocklist
    output_file = intel_dir / "consolidated_blocklist.txt"
    importer.export_blocklist(output_file, format="txt")
    print(f"\n[+] Exported consolidated blocklist to {output_file}")