"""
Field Mapper - Maps Sigma fields to Spectre rule fields
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FieldMapping:
    """Mapping from Sigma field to Spectre rule field"""

    sigma_field: str
    spectre_field: str
    operator: str = "equals"  # equals, contains, startswith, endswith, regex, cidr
    modifier: str | None = None


# Comprehensive field mapping from Sigma to Spectre
SIGMA_TO_SPECTRE_FIELDS = {
    # Process creation (Windows Sysmon Event ID 1, Linux audit execve)
    "Image": FieldMapping("Image", "name", "endswith"),
    "Image|endswith": FieldMapping("Image|endswith", "name", "endswith"),
    "Image|contains": FieldMapping("Image|contains", "name", "contains"),
    "CommandLine": FieldMapping("CommandLine", "cmdline", "contains"),
    "CommandLine|contains": FieldMapping("CommandLine|contains", "cmdline", "contains"),
    "CommandLine|startswith": FieldMapping("CommandLine|startswith", "cmdline", "startswith"),
    "CommandLine|endswith": FieldMapping("CommandLine|endswith", "cmdline", "endswith"),
    "CommandLine|re": FieldMapping("CommandLine|re", "cmdline", "regex"),
    "ParentImage": FieldMapping("ParentImage", "parent_name", "endswith"),
    "ParentImage|endswith": FieldMapping("ParentImage|endswith", "parent_name", "endswith"),
    "ParentImage|contains": FieldMapping("ParentImage|contains", "parent_name", "contains"),
    "ParentCommandLine": FieldMapping("ParentCommandLine", "parent_cmdline", "contains"),
    "ParentCommandLine|contains": FieldMapping(
        "ParentCommandLine|contains",
        "parent_cmdline",
        "contains",
    ),
    "ParentCommandLine|re": FieldMapping("ParentCommandLine|re", "parent_cmdline", "regex"),
    # File operations (Windows Sysmon Event ID 11, Linux audit openat)
    "TargetFilename": FieldMapping("TargetFilename", "file_path", "equals"),
    "TargetFilename|endswith": FieldMapping("TargetFilename|endswith", "file_path", "endswith"),
    "TargetFilename|contains": FieldMapping("TargetFilename|contains", "file_path", "contains"),
    "TargetFilename|startswith": FieldMapping(
        "TargetFilename|startswith",
        "file_path",
        "startswith",
    ),
    "TargetFilename|re": FieldMapping("TargetFilename|re", "file_path", "regex"),
    # Network connections (Windows Sysmon Event ID 3, Linux audit connect)
    "DestinationIp": FieldMapping("DestinationIp", "dest_ip", "equals"),
    "DestinationIp|cidr": FieldMapping("DestinationIp|cidr", "dest_ip", "cidr"),
    "DestinationPort": FieldMapping("DestinationPort", "dest_port", "equals"),
    "DestinationPort|contains": FieldMapping("DestinationPort|contains", "dest_port", "contains"),
    "SourceIp": FieldMapping("SourceIp", "src_ip", "equals"),
    "SourceIp|cidr": FieldMapping("SourceIp|cidr", "src_ip", "cidr"),
    "SourcePort": FieldMapping("SourcePort", "src_port", "equals"),
    "Protocol": FieldMapping("Protocol", "protocol", "equals"),
    # User context
    "User": FieldMapping("User", "user", "equals"),
    "User|contains": FieldMapping("User|contains", "user", "contains"),
    "IntegrityLevel": FieldMapping("IntegrityLevel", "integrity_level", "equals"),
    # Hash values
    "Hashes": FieldMapping("Hashes", "hashes", "contains"),
    "Hashes|contains": FieldMapping("Hashes|contains", "hashes", "contains"),
    # Linux-specific
    "exe": FieldMapping("exe", "name", "endswith"),
    "exe|endswith": FieldMapping("exe|endswith", "name", "endswith"),
    "args": FieldMapping("args", "cmdline", "contains"),
    "args|contains": FieldMapping("args|contains", "cmdline", "contains"),
    "path": FieldMapping("path", "file_path", "equals"),
    "path|endswith": FieldMapping("path|endswith", "file_path", "endswith"),
    "path|contains": FieldMapping("path|contains", "file_path", "contains"),
}


# Spectre rule field categories
SPECTRE_RULE_FIELDS = {
    # Process ancestry matching
    "parent_names": ["parent_name", "parent_cmdline"],
    "child_names": ["name", "cmdline"],
    "ancestor_names": ["parent_name", "parent_cmdline"],
    "descendant_names": ["name", "cmdline"],
    # Process resource matching
    "process_names": ["name", "cmdline"],
    "file_paths": ["file_path"],
    "file_events": ["file_event"],  # READ, WRITE
    "socket_events": ["socket_event"],  # CONNECT, LISTEN
}


def map_sigma_field(sigma_field: str) -> FieldMapping | None:
    """Map a Sigma field to Spectre field mapping"""
    return SIGMA_TO_SPECTRE_FIELDS.get(sigma_field)


def get_spectre_fields_for_category(category: str) -> list[str]:
    """Get Sigma fields that map to a Spectre rule field category"""
    return SPECTRE_RULE_FIELDS.get(category, [])


def extract_mitre_from_tags(tags: list[str]) -> list[dict[str, str]]:
    """Extract MITRE ATT&CK techniques from Sigma tags"""
    mitre = []
    for tag in tags:
        # Match attack.tXXXX or attack.tXXXX.XXX
        match = re.search(r"attack\.t(\d{4})(?:\.(\d{3}))?", tag, re.IGNORECASE)
        if match:
            technique_id = f"T{match.group(1)}"
            if match.group(2):
                technique_id += f".{match.group(2).zfill(3)}"
            mitre.append(
                {
                    "technique_id": technique_id,
                    "tactic": "",  # Would need lookup
                    "technique_name": "",
                },
            )
    return mitre


import re
