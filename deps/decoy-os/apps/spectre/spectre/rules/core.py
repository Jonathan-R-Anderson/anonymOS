"""
Core rule dataclasses for Spectre HIDS
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MitreMapping:
    tactic: str
    technique_id: str
    technique_name: str

    @classmethod
    def from_dict(cls, data: dict) -> MitreMapping:
        return cls(
            tactic=data["tactic"],
            technique_id=data["technique_id"],
            technique_name=data["technique_name"],
        )


@dataclass
class BehavioralRule:
    id: str
    name: str
    score: int
    description: str

    # Process ancestry matching criteria
    parent_names: list[str] | None = None
    child_names: list[str] | None = None
    ancestor_names: list[str] | None = None
    descendant_names: list[str] | None = None

    # Process resource matching criteria (V4)
    process_names: list[str] | None = None
    file_paths: list[str] | None = None
    file_events: list[str] | None = None  # e.g., ["READ", "WRITE"]
    socket_events: list[str] | None = None  # e.g., ["CONNECT", "LISTEN"]

    # MITRE ATT&CK mapping (V5)
    mitre_attack: list[MitreMapping] | None = None

    @classmethod
    def from_dict(cls, data: dict) -> BehavioralRule:
        mitre = None
        if "mitre_attack" in data and data["mitre_attack"]:
            mitre = [MitreMapping.from_dict(m) for m in data["mitre_attack"]]

        return cls(
            id=data["id"],
            name=data["name"],
            score=data["score"],
            description=data["description"],
            parent_names=data.get("parent_names"),
            child_names=data.get("child_names"),
            ancestor_names=data.get("ancestor_names"),
            descendant_names=data.get("descendant_names"),
            process_names=data.get("process_names"),
            file_paths=data.get("file_paths"),
            file_events=data.get("file_events"),
            socket_events=data.get("socket_events"),
            mitre_attack=mitre,
        )

    def get_mitre_str(self) -> str:
        """Returns a compact string representation of MITRE ATT&CK mappings."""
        if not self.mitre_attack:
            return ""
        parts = [f"{m.technique_id} ({m.tactic})" for m in self.mitre_attack]
        return " | ".join(parts)


# Default hardcoded fallback rules
DEFAULT_RULES: list[BehavioralRule] = [
    BehavioralRule(
        id="web_server_shell",
        name="Web Server Spawning Shell",
        score=20,
        description="A web server process spawned an interactive shell. This is a common pattern for web shells and remote code execution.",
        parent_names=["nginx", "apache2", "httpd", "lighttpd", "node", "tomcat"],
        child_names=["bash", "sh", "dash", "zsh", "ash"],
        mitre_attack=[
            MitreMapping("Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
            MitreMapping("Persistence", "T1505.003", "Server Software Component: Web Shell"),
        ],
    ),
    BehavioralRule(
        id="shell_network_tool",
        name="Shell Spawning Network Tool",
        score=15,
        description="A shell process spawned a network utility, which could indicate scanning, reconnaissance, or port forwarding.",
        parent_names=["bash", "sh", "dash", "zsh", "ash"],
        child_names=["nc", "netcat", "ncat", "nmap", "socat", "hydra"],
        mitre_attack=[
            MitreMapping("Discovery", "T1046", "Network Service Discovery"),
            MitreMapping("Lateral Movement", "T1570", "Lateral Tool Transfer"),
        ],
    ),
    BehavioralRule(
        id="shell_downloader",
        name="Shell Spawning Downloader",
        score=10,
        description="A shell process spawned a web transfer utility, potentially attempting to download a secondary payload.",
        parent_names=["bash", "sh", "dash", "zsh", "ash"],
        child_names=["curl", "wget", "tftp", "ftp"],
        mitre_attack=[
            MitreMapping("Command and Control", "T1105", "Ingress Tool Transfer"),
            MitreMapping("Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
        ],
    ),
    BehavioralRule(
        id="web_server_compiler",
        name="Web Server Spawning Compiler or Interpreter",
        score=18,
        description="A web server process spawned a compiler, build tool, or scripting interpreter. This is highly suspicious and common in exploit delivery.",
        parent_names=["nginx", "apache2", "httpd", "lighttpd", "node", "tomcat"],
        child_names=["gcc", "g++", "make", "python", "python3", "perl", "ruby", "php"],
        mitre_attack=[
            MitreMapping("Execution", "T1059", "Command and Scripting Interpreter"),
            MitreMapping(
                "Defense Evasion",
                "T1027.004",
                "Obfuscated Files or Information: Compile After Delivery",
            ),
        ],
    ),
]


def load_rules_from_file(filepath: str) -> list[BehavioralRule]:
    """
    Loads custom behavioral rules from a JSON file.
    Falls back to DEFAULT_RULES if file does not exist or fails to parse.
    """
    import json
    import os

    if not os.path.exists(filepath):
        print(f"[!] Rule file {filepath} not found. Using default preset rules.")
        return DEFAULT_RULES

    try:
        with open(filepath) as f:
            data = json.load(f)
            if not isinstance(data, list):
                print("[!] Invalid rule file format (must be a list). Using default rules.")
                return DEFAULT_RULES

            rules = []
            for item in data:
                try:
                    rules.append(BehavioralRule.from_dict(item))
                except KeyError as e:
                    print(
                        f"[!] Missing required key {e} in rule {item.get('id', 'unknown')}. Skipping rule.",
                    )
            return rules
    except Exception as e:
        print(f"[!] Failed to parse rule file {filepath}: {e}. Using default rules.")
        return DEFAULT_RULES
