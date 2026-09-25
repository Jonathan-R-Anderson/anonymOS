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
# src/orin/analysis/attck.py
"""
orin.analysis.attck – MITRE ATT&CK Reference Mapping
===================================================
Provides a static, zero-dependency lookup for mapping Orin forensic anomaly
indicators to their corresponding MITRE ATT&CK Technique ID, Tactic, and URL.
"""

#: Offline reference map mapping event types to (Technique ID, Tactic, URL).
ATTCK_MAP = {
    "unexpected_port": (
        "T1571",
        "Command and Control",
        "https://attack.mitre.org/techniques/T1571/"
    ),
    "outbound_c2_communication": (
        "T1071",
        "Command and Control",
        "https://attack.mitre.org/techniques/T1071/"
    ),
    "file_modification": (
        "T1565.001",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1565/001/"
    ),
    "new_ssh_authorized_key": (
        "T1098.004",
        "Persistence",
        "https://attack.mitre.org/techniques/T1098/004/"
    ),
    "new_cron_job": (
        "T1053.003",
        "Persistence",
        "https://attack.mitre.org/techniques/T1053/003/"
    ),
    "cron_volatile_execution": (
        "T1053.003",
        "Persistence",
        "https://attack.mitre.org/techniques/T1053/003/"
    ),
    "cron_suspicious_command": (
        "T1053.003",
        "Persistence",
        "https://attack.mitre.org/techniques/T1053/003/"
    ),
    "ssh_bruteforce": (
        "T1110.001",
        "Credential Access",
        "https://attack.mitre.org/techniques/T1110/001/"
    ),
    "new_user": (
        "T1136.001",
        "Persistence",
        "https://attack.mitre.org/techniques/T1136/001/"
    ),
    "unauthorized_user_created": (
        "T1136.001",
        "Persistence",
        "https://attack.mitre.org/techniques/T1136/001/"
    ),
    "privileged_group_escalation": (
        "T1098",
        "Persistence",
        "https://attack.mitre.org/techniques/T1098/"
    ),
    "auth_log_access_failure": (
        "T1562.001",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1562/001/"
    ),
    "untrusted_kernel_module": (
        "T1547.006",
        "Persistence",
        "https://attack.mitre.org/techniques/T1547/006/"
    ),
    "privilege_escalation_hijack": (
        "T1548",
        "Privilege Escalation",
        "https://attack.mitre.org/techniques/T1548/"
    ),
    "deleted_binary_execution": (
        "T1070.004",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1070/004/"
    ),
    "promiscuous_interface": (
        "T1040",
        "Credential Access",
        "https://attack.mitre.org/techniques/T1040/"
    ),
    "log_tampering": (
        "T1070.006",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1070/006/"
    ),
    "hidden_process": (
        "T1014",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1014/"
    ),
    "pkg_integrity_violation": (
        "T1574.002",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1574/002/"
    ),
    "new_suid_binary": (
        "T1548.001",
        "Privilege Escalation",
        "https://attack.mitre.org/techniques/T1548/001/"
    ),
    "modified_suid_binary": (
        "T1548.001",
        "Privilege Escalation",
        "https://attack.mitre.org/techniques/T1548/001/"
    ),
    "ld_preload_hijack": (
        "T1574.006",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1574/006/"
    ),
    "memfd_execution": (
        "T1620",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1620/"
    ),
    "ebpf_rootkit": (
        "T1547.006",
        "Persistence",
        "https://attack.mitre.org/techniques/T1547/006/"
    ),
    "relational_threat_chain": (
        "T1059",
        "Execution",
        "https://attack.mitre.org/techniques/T1059/"
    )
}

#: Default/fallback values when no exact mapping is matched
DEFAULT_ATTCK = (
    "T1059",
    "Execution",
    "https://attack.mitre.org/techniques/T1059/"
)


def get_attck_enrichment(event_type: str, description: str = "") -> tuple[str, str, str]:
    """Retrieve the MITRE ATT&CK enrichment parameters for a given security event.

    Parameters
    ----------
    event_type : str
        The classification type identifier of the security event.
    description : str, optional
        The contextual description string, used to sub-classify complex events
        like `suspicious_process_ancestry`.

    Returns
    -------
    tuple[str, str, str]
        A tuple containing:
        - str: Technique ID (e.g., "T1014")
        - str: Tactic Name (e.g., "Defense Evasion")
        - str: Reference URL (e.g., "https://attack.mitre.org/techniques/T1014/")
    """
    import re

    # Look for technique ID pattern in event_type or description
    tech_match = re.search(r'\b(T\d{4}(?:\.\d{3})?)\b', (event_type or "") + " " + (description or ""), re.IGNORECASE)
    if tech_match:
        tech_id = tech_match.group(1).upper()
        # Find if this technique or a base technique exists in ATTCK_MAP values
        for key, val in ATTCK_MAP.items():
            if val[0] == tech_id or val[0].split('.')[0] == tech_id.split('.')[0]:
                return (tech_id, val[1], f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/")

        # Determine tactic from technique prefix if not in map
        prefix = tech_id.split('.')[0]
        tactic = "Execution"
        if prefix in ("T1036", "T1070", "T1014", "T1562", "T1565", "T1574"):
            tactic = "Defense Evasion"
        elif prefix in ("T1098", "T1053", "T1136", "T1547"):
            tactic = "Persistence"
        elif prefix in ("T1548",):
            tactic = "Privilege Escalation"
        elif prefix in ("T1110",):
            tactic = "Credential Access"
        elif prefix in ("T1071", "T1571"):
            tactic = "Command and Control"

        return (tech_id, tactic, f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/")

    # Context-aware refinement for process execution anomalies
    if event_type == "suspicious_process_ancestry":
        desc_lower = (description or "").lower()
        if "masquerade" in desc_lower:
            return (
                "T1036.004",
                "Defense Evasion",
                "https://attack.mitre.org/techniques/T1036/004/"
            )
        elif "volatile" in desc_lower:
            return (
                "T1036",
                "Defense Evasion",
                "https://attack.mitre.org/techniques/T1036/"
            )
        else:
            return (
                "T1059.004",
                "Execution",
                "https://attack.mitre.org/techniques/T1059/004/"
            )

    return ATTCK_MAP.get(event_type, DEFAULT_ATTCK)