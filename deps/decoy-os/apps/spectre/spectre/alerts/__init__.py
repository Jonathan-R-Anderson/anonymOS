from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    score: int
    chain: list[dict]
    explanation: str
    timestamp: float = field(default_factory=time.time)


def format_process_resource_tree(chain: list[dict]) -> list[str]:
    """
    Formats a process chain and its resource events (Files, Sockets)
    as a clean, structured ASCII tree.
    """
    lines: list[str] = []
    if not chain:
        return lines

    def helper(idx: int, prefix: str) -> None:
        proc = chain[idx]
        cmd_str = " ".join(proc["cmdline"]) if proc["cmdline"] else proc["name"]
        if len(cmd_str) > 80:
            cmd_str = cmd_str[:77] + "..."

        proc_line = f"{proc['name']} (PID: {proc['pid']}) [Cmd: {cmd_str}]"
        lines.append(f"{prefix}{proc_line}")

        # Gather resource sub-items
        resources: list[str] = []
        for f in proc.get("files", []):
            resources.append(f"[{f['event']}] {f['path']}")
        for c in proc.get("connections", []):
            status_suffix = f" ({c['status']})" if c["status"] else ""
            resources.append(f"[{c['event']}] {c['raddr']}{status_suffix}")

        # Is there a next process in the chain?
        has_next_proc = idx < len(chain) - 1

        # All children of this process node
        children: list[tuple[str, str | int]] = []
        for res in resources:
            children.append(("resource", res))
        if has_next_proc:
            children.append(("process", idx + 1))

        # Render children
        for i, child in enumerate(children):
            is_last = i == len(children) - 1
            char_branch = "└── " if is_last else "├── "
            char_extension = "    " if is_last else "│   "

            child_type, child_val = child
            if child_type == "resource":
                lines.append(f"{prefix}{char_branch}{child_val}")
            elif child_type == "process":
                helper(int(child_val), prefix + char_extension)

    helper(0, "")
    return lines


class ExplanationEngine:
    """
    Generates human-readable, detailed explanations for security alerts
    describing what happened, why it is suspicious, and which processes were involved.
    """

    @staticmethod
    def generate(rule_id: str, parent: dict, child: dict) -> str:
        parent_cmd = " ".join(parent["cmdline"]) if parent["cmdline"] else parent["name"]
        child_cmd = " ".join(child["cmdline"]) if child["cmdline"] else child["name"]

        if len(parent_cmd) > 80:
            parent_cmd = parent_cmd[:77] + "..."
        if len(child_cmd) > 80:
            child_cmd = child_cmd[:77] + "..."

        if rule_id == "web_server_shell":
            return (
                f"Web server '{parent['name']}' (PID: {parent['pid']}) "
                f"spawned an interactive shell '{child['name']}' (PID: {child['pid']}) "
                f"[Cmd: {child_cmd}]. "
                f"This process pattern is highly suspicious and typical of web shell "
                f"access or remote code execution (RCE) attempts."
            )
        if rule_id == "shell_network_tool":
            return (
                f"Shell '{parent['name']}' (PID: {parent['pid']}) "
                f"spawned network tool '{child['name']}' (PID: {child['pid']}) "
                f"[Cmd: {child_cmd}]. "
                f"This may indicate active host reconnaissance, port scanning, or the "
                f"establishment of outbound traffic redirection."
            )
        if rule_id == "shell_downloader":
            return (
                f"Shell '{parent['name']}' (PID: {parent['pid']}) "
                f"spawned transfer utility '{child['name']}' (PID: {child['pid']}) "
                f"[Cmd: {child_cmd}]. "
                f"This is a common behavior when downloading secondary payloads, "
                f"scripts, or post-exploitation toolkits."
            )
        if rule_id == "web_server_compiler":
            return (
                f"Web server '{parent['name']}' (PID: {parent['pid']}) "
                f"spawned compiler/interpreter '{child['name']}' (PID: {child['pid']}) "
                f"[Cmd: {child_cmd}]. "
                f"This suggests compile-on-site exploits or the execution of "
                f"server-side automation scripts by an unauthorized user."
            )
        return (
            f"Process '{child['name']}' (PID: {child['pid']}) [Cmd: {child_cmd}] "
            f"was spawned by '{parent['name']}' (PID: {parent['pid']}) "
            f"[Cmd: {parent_cmd}], violating rule '{rule_id}'."
        )


class AlertLogger:
    """
    Handles logging of security alerts to console and to file, formatting
    each alert into a readable, detailed report with process-resource graph trees.
    """

    def __init__(self, log_file: str = "spectre_alerts.log"):
        self.logger = logging.getLogger("SpectreHIDS")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        # Create file handler to log security alerts
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

    def log_alert(self, alert: Alert):
        """
        Logs a security alert to the log file and prints a formatted
        warning block directly to console/stdout.
        """
        # Log to file
        log_msg = (
            f"[ALERT] {alert.rule_name} (Score: {alert.score}) - Explanation: {alert.explanation}"
        )
        self.logger.warning(log_msg)

        # Print detailed warning block to console
        print("\n" + "!" * 60)
        print(f"⚠️  SECURITY ALERT: {alert.rule_name.upper()}")
        print(f"Severity Score: {alert.score}/20")
        print(f"Explanation:    {alert.explanation}")
        print("\nExecution Chain & Resources:")

        # Print the process-resource tree
        tree_lines = format_process_resource_tree(alert.chain)
        for line in tree_lines:
            print(f"  {line}")

        print("!" * 60)
        sys.stdout.flush()
