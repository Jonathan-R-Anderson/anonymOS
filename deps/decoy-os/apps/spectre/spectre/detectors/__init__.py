from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from spectre.rules import BehavioralRule


class DetectionEngine:
    """
    Evaluates process ancestry chains and resource actions (files/sockets)
    against behavioral rules to match threats.
    """

    def __init__(self, rules: list[BehavioralRule]):
        self.rules = rules

    def evaluate_chain(self, chain: list[dict]) -> list[tuple[BehavioralRule, dict, str]]:
        """
        Evaluates a process chain and its resources against rules.
        Returns a list of matches: (matched_rule, offending_process_dict, detail_str)
        """
        matches: list[tuple[BehavioralRule, dict, str]] = []
        if not chain:
            return matches

        for rule in self.rules:
            # 1. Process Resource Matching (File paths/events, Socket connections/listeners)
            if rule.process_names:
                for proc in chain:
                    if proc["name"] in rule.process_names:
                        # Match File Access
                        if rule.file_paths and proc.get("files"):
                            for f in proc["files"]:
                                if f["path"] in rule.file_paths:
                                    if not rule.file_events or f["event"] in rule.file_events:
                                        detail = f"read/write file: {f['path']} ({f['event']})"
                                        matches.append((rule, proc, detail))

                        # Match Socket/Network activity
                        if rule.socket_events and proc.get("connections"):
                            for conn in proc["connections"]:
                                if conn["event"] in rule.socket_events:
                                    detail = (
                                        f"network connection: {conn['raddr']} ({conn['event']})"
                                    )
                                    matches.append((rule, proc, detail))

            # 2. Process Ancestry Matching (Direct Parent-Child)
            if len(chain) >= 2:
                child = chain[-1]
                parent = chain[-2]

                parent_match = False
                child_match = False

                if rule.parent_names:
                    if parent["name"] in rule.parent_names:
                        parent_match = True
                else:
                    parent_match = True

                if rule.child_names:
                    if child["name"] in rule.child_names:
                        child_match = True
                else:
                    child_match = True

                if parent_match and child_match and (rule.parent_names or rule.child_names):
                    detail = f"spawned child process: {child['name']} (PID: {child['pid']})"
                    matches.append((rule, child, detail))
                    continue

                # 3. Ancestor-Descendant Matching
                ancestor_match = False
                descendant_match = False
                matched_ancestor = None

                if rule.ancestor_names:
                    for ancestor in chain[:-1]:
                        if ancestor["name"] in rule.ancestor_names:
                            ancestor_match = True
                            matched_ancestor = ancestor
                            break

                if rule.descendant_names and child["name"] in rule.descendant_names:
                    descendant_match = True

                if ancestor_match and descendant_match:
                    parent_ctx = matched_ancestor if matched_ancestor else parent
                    detail = f"descendant process: {child['name']} (PID: {child['pid']}) spawned from ancestor: {parent_ctx['name']}"
                    matches.append((rule, child, detail))

        return matches
