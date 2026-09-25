"""
Sigma Rule Parser for Spectre HIDS
Converts Sigma YAML rules to Spectre BehavioralRule objects
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SigmaRule:
    """Parsed Sigma rule structure"""

    title: str
    id: str
    description: str
    status: str
    author: str
    date: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    level: str
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    license: str = "MIT"


@dataclass
class SigmaCondition:
    """Parsed Sigma detection condition"""

    raw: str
    parsed: Any = None


class SigmaParser:
    """Parses Sigma YAML rules into structured objects"""

    # Field mappings from Sigma to Spectre
    FIELD_MAPPINGS = {
        # Process fields
        "Image": "name",
        "Image|endswith": "name",
        "CommandLine": "cmdline",
        "CommandLine|contains": "cmdline",
        "ParentImage": "parent_name",
        "ParentImage|endswith": "parent_name",
        "ParentCommandLine": "parent_cmdline",
        "ParentCommandLine|contains": "parent_cmdline",
        # File fields
        "TargetFilename": "file_path",
        "TargetFilename|endswith": "file_path",
        "TargetFilename|contains": "file_path",
        # Network fields
        "DestinationIp": "dest_ip",
        "DestinationPort": "dest_port",
        "SourceIp": "src_ip",
        "SourcePort": "src_port",
        # User fields
        "User": "user",
        "User|contains": "user",
    }

    # Sigma modifiers to Spectre operators
    MODIFIER_MAP = {
        "endswith": "endswith",
        "contains": "contains",
        "startswith": "startswith",
        "re": "regex",
        "cidr": "cidr",
        "all": "all",
    }

    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def parse_file(self, path: str | Path) -> SigmaRule:
        """Parse a Sigma rule from YAML file"""
        path = Path(path)
        with open(path) as f:
            content = f.read()
        return self.parse_string(content, source=str(path))

    def parse_string(self, content: str, source: str = "<string>") -> SigmaRule:
        """Parse a Sigma rule from YAML string"""
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {source}: {e}")

        if not isinstance(data, dict):
            raise ValueError(f"Sigma rule must be a YAML object in {source}")

        # Validate required fields
        required = ["title", "id", "detection"]
        for field in required:
            if field not in data:
                raise ValueError(f"Missing required field '{field}' in {source}")

        # Parse detection section
        detection = data.get("detection", {})
        if "condition" not in detection:
            raise ValueError(f"Missing 'condition' in detection section in {source}")

        # Create SigmaRule object
        return SigmaRule(
            title=data["title"],
            id=data["id"],
            description=data.get("description", ""),
            status=data.get("status", "experimental"),
            author=data.get("author", "unknown"),
            date=data.get("date", ""),
            logsource=data.get("logsource", {}),
            detection=detection,
            level=data.get("level", "medium"),
            tags=data.get("tags", []),
            references=data.get("references", []),
            falsepositives=data.get("falsepositives", []),
            license=data.get("license", "MIT"),
        )

    def parse_condition(self, condition: str) -> SigmaCondition:
        """Parse Sigma condition string into structured format"""
        # This is a simplified parser - full implementation would use a proper parser
        # For now, we return the raw condition and mark it for later processing
        return SigmaCondition(raw=condition)

    def get_field_mapping(self, sigma_field: str) -> str | None:
        """Map Sigma field name to Spectre field name"""
        # Handle modifiers (e.g., "Image|endswith")
        for sigma_key, spectre_field in self.FIELD_MAPPINGS.items():
            if sigma_field == sigma_key:
                return spectre_field
        return None

    def extract_field_conditions(
        self,
        detection: dict[str, Any],
        condition: str,
    ) -> dict[str, list[dict]]:
        """Extract field conditions from detection section based on condition"""
        # This is a placeholder for the full implementation
        # Full implementation would:
        # 1. Parse the condition (e.g., "selection1 and selection2")
        # 2. Extract each selection's field-value pairs
        # 3. Map to Spectre rule fields
        return {}


def parse_sigma_file(path: str | Path) -> SigmaRule:
    """Convenience function to parse a Sigma rule file"""
    parser = SigmaParser()
    return parser.parse_file(path)


def parse_sigma_string(content: str) -> SigmaRule:
    """Convenience function to parse a Sigma rule string"""
    parser = SigmaParser()
    return parser.parse_string(content)
