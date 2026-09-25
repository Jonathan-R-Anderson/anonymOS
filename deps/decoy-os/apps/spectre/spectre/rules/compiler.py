"""
Rule Compiler - Compiles Sigma rules to Spectre BehavioralRule objects
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .core import BehavioralRule, MitreMapping
from .field_mapper import extract_mitre_from_tags, map_sigma_field
from .sigma_parser import SigmaParser, SigmaRule


@dataclass
class CompilationResult:
    """Result of Sigma to Spectre compilation"""

    rule: BehavioralRule | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class SigmaCompiler:
    """Compiles Sigma rules to Spectre BehavioralRule objects"""

    def __init__(self):
        self.parser = SigmaParser()

    def compile(self, sigma_rule: SigmaRule) -> CompilationResult:
        """Compile a Sigma rule to Spectre BehavioralRule"""
        result = CompilationResult()

        try:
            # Extract detection logic
            detection = sigma_rule.detection
            condition = detection.get("condition", "")

            if not condition:
                result.errors.append("No condition in detection section")
                return result

            # Parse selections
            selections = {k: v for k, v in detection.items() if k != "condition"}

            # Build rule fields from selections
            rule_fields = self._build_rule_fields(selections, condition, sigma_rule)

            if not rule_fields:
                result.warnings.append("No mappable fields found in rule")
                return result

            # Extract MITRE tags
            mitre_mappings = self._extract_mitre(sigma_rule)

            # Calculate score based on level
            score = self._level_to_score(sigma_rule.level)

            # Create BehavioralRule
            rule = BehavioralRule(
                id=sigma_rule.id.replace(":", "-").replace("/", "-"),
                name=sigma_rule.title,
                score=score,
                description=sigma_rule.description
                or f"Converted from Sigma rule: {sigma_rule.title}",
                parent_names=rule_fields.get("parent_names"),
                child_names=rule_fields.get("child_names"),
                ancestor_names=rule_fields.get("ancestor_names"),
                descendant_names=rule_fields.get("descendant_names"),
                process_names=rule_fields.get("process_names"),
                file_paths=rule_fields.get("file_paths"),
                file_events=rule_fields.get("file_events"),
                socket_events=rule_fields.get("socket_events"),
                mitre_attack=mitre_mappings if mitre_mappings else None,
            )

            result.rule = rule

        except Exception as e:
            result.errors.append(f"Compilation error: {e}")

        return result

    def _build_rule_fields(
        self,
        selections: dict[str, Any],
        condition: str,
        sigma_rule: SigmaRule,
    ) -> dict[str, list[str]]:
        """Build Spectre rule fields from Sigma selections"""
        fields: dict[str, set] = {
            "parent_names": set(),
            "child_names": set(),
            "ancestor_names": set(),
            "descendant_names": set(),
            "process_names": set(),
            "file_paths": set(),
            "file_events": set(),
            "socket_events": set(),
        }

        # Determine rule type from logsource
        logsource = sigma_rule.logsource
        category = logsource.get("category", "")
        logsource.get("product", "")
        logsource.get("service", "")

        is_process_creation = category in ["process_creation", "process_access"]
        is_file_event = category in [
            "file_event",
            "file_creation",
            "file_deletion",
            "file_modification",
        ]
        is_network = category in ["network_connection", "dns_query", "http"]

        # Process each selection
        for _sel_name, sel_data in selections.items():
            if not isinstance(sel_data, dict):
                continue

            for sigma_field, value in sel_data.items():
                mapping = map_sigma_field(sigma_field)
                if not mapping:
                    continue

                # Normalize value to list
                values = value if isinstance(value, list) else [value]

                # Map to appropriate Spectre field based on logsource category
                if is_process_creation:
                    if mapping.spectre_field in ["name", "cmdline"]:
                        fields["child_names"].update(values)
                    elif mapping.spectre_field in ["parent_name", "parent_cmdline"]:
                        fields["parent_names"].update(values)
                elif is_file_event:
                    if mapping.spectre_field == "file_path":
                        fields["file_paths"].update(values)
                        # Default to READ/WRITE for file events
                        fields["file_events"].update(["READ", "WRITE"])
                elif is_network:
                    # Network events map to socket events
                    fields["socket_events"].update(["CONNECT"])
                    # Could extract IPs/ports for more specific matching

        # Also check for process names in any selection
        for _sel_name, sel_data in selections.items():
            if not isinstance(sel_data, dict):
                continue
            for sigma_field, value in sel_data.items():
                mapping = map_sigma_field(sigma_field)
                if not mapping:
                    continue
                values = value if isinstance(value, list) else [value]
                if mapping.spectre_field in ["name", "cmdline"]:
                    fields["process_names"].update(values)

        # Convert sets to lists, remove empty
        return {k: list(v) for k, v in fields.items() if v}

    def _extract_mitre(self, sigma_rule: SigmaRule) -> list[MitreMapping] | None:
        """Extract MITRE ATT&CK mappings from Sigma rule"""
        mitre_data = extract_mitre_from_tags(sigma_rule.tags)

        if not mitre_data:
            return None

        mappings = []
        for m in mitre_data:
            mappings.append(
                MitreMapping(
                    tactic=m.get("tactic", "Unknown"),
                    technique_id=m["technique_id"],
                    technique_name=m.get("technique_name", "Unknown"),
                ),
            )

        return mappings if mappings else None

    def _level_to_score(self, level: str) -> int:
        """Convert Sigma level to Spectre score"""
        level_map = {
            "critical": 25,
            "high": 20,
            "medium": 15,
            "low": 10,
            "informational": 5,
        }
        return level_map.get(level.lower(), 15)


def compile_sigma_rule(sigma_rule: SigmaRule) -> CompilationResult:
    """Convenience function to compile a Sigma rule"""
    compiler = SigmaCompiler()
    return compiler.compile(sigma_rule)


def compile_sigma_file(path: str) -> CompilationResult:
    """Convenience function to compile a Sigma rule from file"""
    parser = SigmaParser()
    sigma_rule = parser.parse_file(path)
    return compile_sigma_rule(sigma_rule)


def compile_sigma_string(content: str) -> CompilationResult:
    """Convenience function to compile a Sigma rule from string"""
    parser = SigmaParser()
    sigma_rule = parser.parse_string(content)
    return compile_sigma_rule(sigma_rule)
