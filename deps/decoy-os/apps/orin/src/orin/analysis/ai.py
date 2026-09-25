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
# src/orin/analysis/ai.py
"""
orin.analysis.ai – Local AI Forensic Triage & Multi-Host Correlation
===================================================================
Provides utilities to bundle unresolved security alerts across system hostnames
and request analytical summaries/remediation advice from a local Ollama model.
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any
from orin.core.database import OrinStorage

def _aggregate_events(events: list[dict[str, Any]]) -> list[str]:
    """Aggregate and summarize raw forensic security events to avoid LLM context bloat.

    Parameters
    ----------
    events : list[dict[str, Any]]
        List of raw forensic events queried from the database.

    Returns
    -------
    list[str]
        List of summarized, structured event string descriptions.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in events:
        key = (ev["event_type"], ev["severity"])
        if key not in grouped:
            grouped[key] = {
                "event_type": ev["event_type"],
                "severity": ev["severity"],
                "attck_technique": ev["attck_technique"],
                "attck_tactic": ev["attck_tactic"],
                "count": 0,
                "descriptions": set(),
                "ports": set(),
                "processes": set(),
                "files": set(),
                "pids": set(),
                "timestamps": []
            }

        g = grouped[key]
        g["count"] += 1
        g["descriptions"].add(ev["description"])
        g["timestamps"].append(ev["timestamp"])

        if ev.get("raw_details"):
            try:
                details = json.loads(ev["raw_details"])
                if isinstance(details, dict):
                    if "port" in details:
                        g["ports"].add(str(details["port"]))
                    if "process_name" in details:
                        g["processes"].add(details["process_name"])
                    if "name" in details:
                        g["processes"].add(details["name"])
                    if "pid" in details:
                        g["pids"].add(str(details["pid"]))
                    if "file_path" in details:
                        g["files"].add(details["file_path"])
                    if "resolved_path" in details:
                        g["files"].add(details["resolved_path"])
            except Exception:
                pass

    summary_list: list[str] = []
    for g in grouped.values():
        parts: list[str] = []
        if g["ports"]:
            parts.append(f"Ports: {sorted(list(g['ports']))}")
        if g["processes"]:
            parts.append(f"Processes: {sorted(list(g['processes']))}")
        if g["pids"]:
            parts.append(f"PIDs: {sorted(list(g['pids']))}")
        if g["files"]:
            parts.append(f"Paths: {sorted(list(g['files']))}")

        desc_summary: str = "; ".join(sorted(list(g["descriptions"])))
        if len(desc_summary) > 200:
            desc_summary = desc_summary[:197] + "..."

        details_part: str = f" | {', '.join(parts)}" if parts else ""
        g["timestamps"].sort()
        time_part: str = f"Time: {g['timestamps'][0]} to {g['timestamps'][-1]}" if len(g["timestamps"]) > 1 else f"Time: {g['timestamps'][0]}"

        attck: str = f" [MITRE: {g['attck_technique']} - {g['attck_tactic']}]" if g.get("attck_technique") else ""
        summary_list.append(
            f"- [{g['severity'].upper()}] {g['event_type']}{attck} (Count: {g['count']}) - {desc_summary}{details_part} ({time_part})"
        )
    return summary_list

def run_ai_correlation(db_path: Path, hostnames: list[str] = None, url: str = "http://127.0.0.1:11434", model: str = "gemma3:1b", timeout: int = 300) -> str:
    """Query unresolved security events across hostnames and generate correlation insights using local Ollama.

    Parameters
    ----------
    db_path : Path
        Filesystem path location to the SQLite forensic database.
    hostnames : list[str], optional
        Specific set of hostnames to evaluate. If omitted, all hostnames in database system snapshots are targeted.
    url : str, optional
        API URL endpoint to local Ollama. Defaults to 'http://127.0.0.1:11434'.
    model : str, optional
        Name identifier of the LLM model to query. Defaults to 'gemma3:1b'.
    timeout : int, optional
        Timeout limit in seconds for the Ollama generation request. Defaults to 300.

    Returns
    -------
    str
        Markdown formatted analysis brief.
    """
    storage = OrinStorage(db_path)

    with storage.get_connection() as conn:
        cursor = conn.cursor()

        # 1. Fetch hostnames if not specified
        if not hostnames:
            cursor.execute("SELECT DISTINCT hostname FROM system_snapshots;")
            hostnames = [row["hostname"] for row in cursor.fetchall() if row["hostname"]]

        if not hostnames:
            return "🟢 No host snapshots found in the database. Nothing to analyze."

        # 2. Query unresolved events for each host
        host_data = {}
        for host in hostnames:
            cursor.execute("""
                SELECT event_type, severity, description, attck_technique, attck_tactic, timestamp, raw_details
                FROM security_events
                WHERE resolved = 0 AND (hostname = ? OR (hostname IS NULL AND ? = 'local'))
                ORDER BY timestamp DESC;
            """, (host, host))
            events = cursor.fetchall()
            if events:
                host_data[host] = [dict(ev) for ev in events]

    if not host_data:
        return "🟢 No unresolved security events found across the selected hosts. Nothing to correlate."

    # 3. Build the prompt
    prompt = (
        "You are an expert cybersecurity incident responder and forensic analyst.\n"
        "You are analyzing security alerts collected by the Orin Forensic Engine across multiple Linux hosts.\n"
        "Analyze the following unresolved alerts for potential lateral movement, shared attack campaigns, "
        "privilege escalation paths, or coordinated actions across the network.\n\n"
        "Host Alert Summary:\n"
    )
    for host, events in host_data.items():
        prompt += f"\nHost: {host}\n"
        summarized_events = _aggregate_events(events)
        for ev_str in summarized_events:
            prompt += f"{ev_str}\n"

    prompt += (
        "\nProvide a unified multi-host incident brief. You MUST write a detailed, thorough, and highly specific report. "
        "Do NOT write high-level or generic descriptions. For each point, you must specify:\n"
        "1. **What was really done**: Describe the specific actions taken, including exact process names (with PIDs), listening ports, "
        "modified configuration files (like /etc/shadow or /etc/sudoers), and hashes.\n"
        "2. **By who and When**: Identify any user accounts involved and specify the exact timestamps of the events.\n"
        "3. **Analysis of Techniques & Lateral Movement**: Correlate events across hosts (e.g. comparing files, modules, ports) to explain the attack vector.\n"
        "4. **Containment & Remediation Actions**: Provide explicit, step-by-step recovery actions, including actual bash commands "
        "(e.g., to restore files, kill processes, unload kernel modules, or block ports) that the administrator should run.\n"
        "\nFormat the response in clean Markdown with proper headings."
    )

    # 4. Query Ollama HTTP API
    api_url = f"{url.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 8192,
            "num_predict": 2048,
            "temperature": 0.2
        }
    }

    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(api_url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("response", "Error: No response text returned from model.")
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError) or "timed out" in str(e):
            raise TimeoutError(
                f"Request to local Ollama instance at {url} timed out.\n"
                f"Generating correlation briefs on CPU can be slow. Consider running Ollama on GPU "
                f"or using a smaller model."
            ) from e
        raise ConnectionError(
            f"Failed to connect to local Ollama instance at {url}.\n"
            f"Please ensure Ollama is running and model '{model}' is downloaded (run `ollama run {model}`).\n"
            f"Error details: {e}"
        )