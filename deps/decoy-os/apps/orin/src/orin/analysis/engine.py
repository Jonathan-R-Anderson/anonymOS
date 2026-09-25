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
# src/orin/analysis/engine.py
"""
orin.analysis.engine – Threat Detection Rules Engine
=====================================================
Implements the core analysis cycle that evaluates the most recent system
snapshot stored in the Orin SQLite vault against a set of security rules.

Now includes YARA pattern matching integration for malware detection.
"""
import re
import json
import sqlite3
from pathlib import Path
from orin.core.database import OrinStorage
from orin.collectors.logs import parse_authentication_logs
from orin.core.config import load_config
from orin.analysis.unhide import detect_hidden_processes
from orin.analysis.attck import get_attck_enrichment
from orin.intel.ioc_importer import IOCImporter
from orin.analysis.yara_engine import YaraEngine, YARA_AVAILABLE
from orin.analysis.rootkit import run_rootkit_detection

#: Exact process names (lowercased) that are always considered suspicious
SUSPICIOUS_EXACT_NAMES = {"nc", "ncat", "netcat", "socat", "nmap", "miner", "xmrig"}

#: Compiled regex patterns applied against the full command-line string
SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r'\bpython\s+-c\b', re.IGNORECASE),
    re.compile(r'\bbash\s+-i\b', re.IGNORECASE),
    re.compile(r'\bsh\s+-i\b', re.IGNORECASE),
]

#: Filesystem prefixes considered "volatile".
VOLATILE_DIRS = {"/tmp", "/dev/shm", "/var/tmp"}
BLOCKLIST_FILE_PATH = Path("/var/lib/orin/intel_blocklist.txt")
INTEL_DIR_PATH = Path("/var/lib/orin/intel")

#: Kernel thread name prefixes that are *only* valid when their PPID is 0 or 2.
KERNEL_THREAD_PREFIXES = (
    "kworker", "kthreadd", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "watchdog", "kdevtmpfs",
)

def load_offline_intel_blocklist() -> tuple[set[str], IOCImporter]:
    """
    Load the offline threat-intelligence blocklist using the new IOC importer.

    Supports multiple formats:
    - Legacy TXT blocklist (backward compatible)
    - STIX 2.x JSON/XML
    - CSV threat feeds

    Returns:
        Tuple of (ip_blocklist_set, ioc_importer_instance)
    """
    # Try new multi-format importer first
    if INTEL_DIR_PATH.exists():
        try:
            importer = IOCImporter(intel_dir=INTEL_DIR_PATH)
            importer.load_all_intel()
            summary = importer.get_summary()
            if summary['total_indicators'] > 0:
                print(f"[+] Loaded {summary['total_indicators']} IOCs from {len(summary['sources'])} threat intel sources")
                print(f"    IPs: {summary['ip_count']}, Domains: {summary['domain_count']}, Hashes: {summary['hash_count']}")
                return importer.ip_blocklist, importer
        except Exception as e:
            print(f"[!] Error loading threat intel from {INTEL_DIR_PATH}: {e}")

    # Fallback to legacy blocklist file
    if not BLOCKLIST_FILE_PATH.exists():
        print("[!] Warning: No threat intelligence found (missing intel directory and blocklist file)")
        print("[!] Outbound C2 identification rules will be bypassed during this run.")
        return set(), None

    try:
        cleaned_ips = set()
        with open(BLOCKLIST_FILE_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                cleaned_ips.add(line.split()[0])
        if cleaned_ips:
            print(f"[+] Loaded {len(cleaned_ips)} IPs from legacy blocklist file")
        return cleaned_ips, None
    except Exception as e:
        print(f"[!] Error reading blocklist file definitions: {e}")
        return set(), None

def run_analysis_cycle(db_path: Path) -> dict:
    """Execute all security rules against the most recent snapshot in the vault."""
    config = load_config()
    expected_ports = set(config["expected_ports"])
    whitelisted_processes = set(config["whitelisted_processes"])
    storage = OrinStorage(db_path)
    events_found = []
    max_severity_weight = 0
    blacklisted_ips, ioc_importer = load_offline_intel_blocklist()

    # Load and group Sigma rules for generalized telemetry evaluation
    from orin.analysis.sigma import load_rules, evaluate_rule_against_event, evaluate_rule_against_log

    import sys
    raw_dirs = [
        Path("/etc/orin/rules"),
        Path("./rules"),
        Path(__file__).resolve().parents[3] / "rules",
        Path(__file__).resolve().parents[2] / "rules",
    ]
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        raw_dirs.append(Path(sys._MEIPASS) / "rules")

    rules_dirs = []
    seen_dirs = set()
    for r_dir in raw_dirs:
        if r_dir.exists() and r_dir.is_dir():
            try:
                resolved = r_dir.resolve()
                if resolved not in seen_dirs:
                    seen_dirs.add(resolved)
                    rules_dirs.append(resolved)
            except Exception:
                if r_dir not in seen_dirs:
                    seen_dirs.add(r_dir)
                    rules_dirs.append(r_dir)

    rules = []
    for r_dir in rules_dirs:
        rules.extend(load_rules(r_dir))

    seen_ids = set()
    deduped_rules = []
    for rule in rules:
        rule_id = rule.get("id")
        if rule_id not in seen_ids:
            seen_ids.add(rule_id)
            deduped_rules.append(rule)

    # Helper to trigger alerts for matched Sigma rules
    def trigger_sigma_alert(rule, matching_event):
        nonlocal max_severity_weight
        level = rule.get("level", "medium").lower()
        if level not in {"low", "medium", "high", "critical"}:
            level = "medium"

        tech_tag = ""
        for tag in rule.get("tags", []):
            if tag.lower().startswith("attack.t"):
                tech_tag = tag.lower().replace("attack.t", "T").upper()
                break

        desc_prefix = f"[{tech_tag}] " if tech_tag else ""
        description = f"{desc_prefix}{rule.get('title', 'Sigma Rule Match')}"

        weight_map = {"low": 10, "medium": 30, "high": 50, "critical": 80}
        max_severity_weight += weight_map.get(level, 30)
        events_found.append({
            "type": "sigma_rule_match",
            "severity": level,
            "description": description,
            "raw_details": json.dumps({
                "rule_id": rule.get("id"),
                "rule_title": rule.get("title"),
                "matching_event": matching_event,
                "tags": rule.get("tags", []),
                "level": rule.get("level")
            })
        })

    # Group rules by service type
    auth_rules = []
    ebpf_rules = []
    connections_rules = []
    fim_rules = []
    suid_rules = []

    for rule in deduped_rules:
        service = rule.get("logsource", {}).get("service", "auth").lower()
        if service == "ebpf":
            ebpf_rules.append(rule)
        elif service in ("connections", "connection"):
            connections_rules.append(rule)
        elif service in ("fim", "integrity"):
            fim_rules.append(rule)
        elif service == "suid":
            suid_rules.append(rule)
        else:
            auth_rules.append(rule)

    with storage.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, hostname FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snap_row = cursor.fetchone()
        snapshot_id = snap_row["id"]
        hostname = snap_row["hostname"]

        # 1. Network Listening Ports Rule
        cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snapshot_id,))
        active_unexpected_ports = set()
        for port_row in cursor.fetchall():
            port = port_row["port"]
            process_full = port_row["process_name"] or "unknown"
            process_base = process_full.split(" (PID:")[0].strip()
            if port in expected_ports or (port >= 32768 and process_base in whitelisted_processes):
                continue
            active_unexpected_ports.add(port)
            max_severity_weight += 20
            events_found.append({
                "type": "unexpected_port", "severity": "medium",
                # Real-world defense: description is static per port to block row duplication
                "description": f"Unexpected listening network port detected: {port}",
                "raw_details": json.dumps(dict(port_row))
            })

        # 2. Outbound Connection Blocklist Check (IP, Domain, and Hash matching)
        cursor.execute("SELECT local_ip, remote_ip, remote_port, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snapshot_id,))
        for conn_row in cursor.fetchall():
            current_remote_ip = conn_row["remote_ip"].strip()

            # Check IP against blocklist
            if current_remote_ip in blacklisted_ips:
                max_severity_weight += 60
                events_found.append({
                    "type": "outbound_c2_communication", "severity": "critical",
                    "description": f"Active network communication targeting blacklisted C2 IP: {current_remote_ip} on Port {conn_row['remote_port']}",
                    "raw_details": json.dumps(dict(conn_row))
                })
            # If using new IOC importer, also check for enriched threat intel
            elif ioc_importer:
                matched_indicator = ioc_importer.match_ip(current_remote_ip)
                if matched_indicator:
                    max_severity_weight += 60
                    events_found.append({
                        "type": "outbound_c2_communication", "severity": "critical",
                        "description": f"Threat intel match: {matched_indicator.description} (Confidence: {matched_indicator.confidence}, Source: {matched_indicator.source})",
                        "raw_details": json.dumps({**dict(conn_row), "indicator": matched_indicator.to_dict()})
                    })

        # 3. Process Execution Analysis Rules
        cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snapshot_id,))
        active_processes = set()
        for proc_row in cursor.fetchall():
            active_processes.add(proc_row["pid"])
            ppid = proc_row["ppid"]
            name = (proc_row["name"] or "").lower()
            exe = (proc_row["exe"] or "").lower()
            cmdline = (proc_row["cmdline"] or "").lower()
            flagged, reason = False, ""

            # Rule A: Kernel thread ancestry validation
            if any(name.startswith(p) for p in KERNEL_THREAD_PREFIXES):
                if ppid not in (0, 2):
                    flagged, reason = True, f"Masquerade Fraud: Non-system ancestry parent discovered for worker (PPID {ppid})"

            # Rule B: Exact signature validation matching
            if not flagged and name in SUSPICIOUS_EXACT_NAMES:
                flagged, reason = True, f"Suspicious binary signature running detected: {name}"

            # Rule C: Execution arguments validation matching
            if not flagged and any(p.search(cmdline) for p in SUSPICIOUS_CMD_PATTERNS):
                flagged, reason = True, "Suspicious interactive command parameter flags matched"

            # Rule D: Filesystem path validation matching
            if not flagged and any(exe.startswith(d) for d in VOLATILE_DIRS):
                flagged, reason = True, f"Process running from volatile system workspace directory: {exe}"

            if flagged:
                max_severity_weight += 45
                events_found.append({
                    "type": "suspicious_process_ancestry", "severity": "high",
                    # Transient PID is stripped from the description to stop ledger row explosion
                    "description": f"{reason} (Binary: {proc_row['name']})",
                    "raw_details": json.dumps(dict(proc_row))
                })

        # 4. Historical Delta Analysis (FIM & SSH Persistence checks)
        cursor.execute("SELECT id FROM system_snapshots WHERE id < ? ORDER BY id DESC LIMIT 1;", (snapshot_id,))
        prev_snapshot_row = cursor.fetchone()
        if prev_snapshot_row:
            prev_snapshot_id = prev_snapshot_row["id"]

            # File Integrity Monitoring Check
            cursor.execute("""
                SELECT cur.file_path, cur.sha256_hash as cur_hash, prev.sha256_hash as prev_hash
                FROM collected_file_hashes cur
                JOIN collected_file_hashes prev ON cur.file_path = prev.file_path
                WHERE cur.snapshot_id = ? AND prev.snapshot_id = ?;
            """, (snapshot_id, prev_snapshot_id))
            for f_row in cursor.fetchall():
                if f_row["cur_hash"] != f_row["prev_hash"]:
                    max_severity_weight += 50
                    events_found.append({
                        "type": "file_modification", "severity": "critical",
                        "description": f"Critical modification change verified on config: {f_row['file_path']}",
                        "raw_details": json.dumps(dict(f_row))
                    })
                    # Evaluate FIM Sigma rules
                    fim_event = {
                        "file_path": f_row["file_path"],
                        "cur_hash": f_row["cur_hash"],
                        "prev_hash": f_row["prev_hash"],
                        "status": "modified"
                    }
                    for rule in fim_rules:
                        if evaluate_rule_against_event(fim_event, rule):
                            trigger_sigma_alert(rule, fim_event)

            # New SSH Key Persistence Modification Checker
            cursor.execute("""
                SELECT cur.user_account, cur.fingerprint, cur.raw_key_comment
                FROM collected_ssh_keys cur
                WHERE cur.snapshot_id = ? AND cur.fingerprint NOT IN (
                    SELECT fingerprint FROM collected_ssh_keys WHERE snapshot_id = ?
                );
            """, (snapshot_id, prev_snapshot_id))
            for key_row in cursor.fetchall():
                max_severity_weight += 55
                events_found.append({
                    "type": "new_ssh_authorized_key", "severity": "critical",
                    "description": f"New unauthorized SSH signature deployed for account '{key_row['user_account']}': {key_row['raw_key_comment']}",
                    "raw_details": json.dumps(dict(key_row))
                })

            # New Cron Job Persistence Modification Checker
            cursor.execute("SELECT COUNT(*) as count FROM collected_crontabs WHERE snapshot_id = ?;", (prev_snapshot_id,))
            has_prev_crontabs = cursor.fetchone()["count"] > 0

            if has_prev_crontabs:
                cursor.execute("""
                    SELECT cur.source, cur.user, cur.schedule, cur.command
                    FROM collected_crontabs cur
                    WHERE cur.snapshot_id = ? AND NOT EXISTS (
                        SELECT 1 FROM collected_crontabs prev
                        WHERE prev.snapshot_id = ?
                          AND prev.source = cur.source
                          AND prev.user = cur.user
                          AND prev.schedule = cur.schedule
                          AND prev.command = cur.command
                    );
                """, (snapshot_id, prev_snapshot_id))
                for cron_row in cursor.fetchall():
                    max_severity_weight += 65
                    events_found.append({
                        "type": "new_cron_job", "severity": "high",
                        "description": f"New scheduled cron job registered for user '{cron_row['user']}' in '{cron_row['source']}': {cron_row['schedule']} - {cron_row['command']}",
                        "raw_details": json.dumps(dict(cron_row))
                    })

        # 5. Auth Log Parsing Indicators
        auth_data = parse_authentication_logs()
        for ip, count in auth_data["failed_ssh_counts"].items():
            if count >= 5:
                max_severity_weight += 40
                events_found.append({
                    "type": "ssh_bruteforce", "severity": "high",
                    # Count variable is decoupled from description text to prevent incremental key drift entries
                    "description": f"SSH brute-force pattern verified from source IP: {ip}",
                    "raw_details": json.dumps({"source_ip": ip, "failed_attempts_count": count})
                })
        for placement in auth_data["privileged_additions"]:
            max_severity_weight += 50
            events_found.append({
                "type": placement["type"], "severity": "critical",
                "description": placement["details"], "raw_details": None
            })

        # 5b. Sigma Rules Evaluation
        # 1. Evaluate auth rules
        cursor.execute("SELECT log_line FROM collected_auth_logs WHERE snapshot_id = ?;", (snapshot_id,))
        auth_log_lines = [row["log_line"] for row in cursor.fetchall()]

        for log_line in auth_log_lines:
            if not log_line or not log_line.strip():
                continue
            for rule in auth_rules:
                if evaluate_rule_against_log(log_line, rule):
                    trigger_sigma_alert(rule, log_line)

        # 2. Evaluate ebpf rules
        cursor.execute("SELECT bpf_id, name, type, tag, gpl_compatible FROM collected_ebpf_programs WHERE snapshot_id = ?;", (snapshot_id,))
        ebpf_progs = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT path, type FROM collected_ebpf_pinned WHERE snapshot_id = ?;", (snapshot_id,))
        ebpf_pinned = [dict(row) for row in cursor.fetchall()]

        for prog in ebpf_progs:
            for rule in ebpf_rules:
                if evaluate_rule_against_event(prog, rule):
                    trigger_sigma_alert(rule, prog)

        for pin in ebpf_pinned:
            for rule in ebpf_rules:
                if evaluate_rule_against_event(pin, rule):
                    trigger_sigma_alert(rule, pin)

        # 3. Evaluate connection rules
        cursor.execute("SELECT local_ip, remote_ip, remote_port, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snapshot_id,))
        outbound_conns = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snapshot_id,))
        listening_ports = [dict(row) for row in cursor.fetchall()]

        for conn_row in outbound_conns:
            for rule in connections_rules:
                if evaluate_rule_against_event(conn_row, rule):
                    trigger_sigma_alert(rule, conn_row)

        for port_row in listening_ports:
            for rule in connections_rules:
                if evaluate_rule_against_event(port_row, rule):
                    trigger_sigma_alert(rule, port_row)

        # 5c. YARA Pattern Matching Scan (Malware Detection)
        if YARA_AVAILABLE:
            try:
                yara_engine = YaraEngine()
                rules_loaded = yara_engine.load_rules()

                if rules_loaded > 0:
                    # Scan critical directories for malware signatures
                    scan_dirs = [Path("/tmp"), Path("/dev/shm"), Path("/var/tmp")]

                    for scan_dir in scan_dirs:
                        if not scan_dir.exists():
                            continue

                        result = yara_engine.scan_directory(
                            scan_dir,
                            recursive=True,
                            max_file_size=50 * 1024 * 1024,  # 50MB limit
                            timeout_per_file=30
                        )

                        if result.total_matches > 0:
                            for match in result.matches:
                                severity = yara_engine.get_severity_for_match(match)
                                techniques = yara_engine.get_attck_techniques(match)

                                max_severity_weight += 80 if severity == "critical" else 60 if severity == "high" else 40

                                tech_str = f" [{', '.join(techniques)}]" if techniques else ""
                                events_found.append({
                                    "type": "yara_malware_match",
                                    "severity": severity,
                                    "description": f"YARA malware signature detected{tech_str}: {match.rule_name} in {match.file_path}",
                                    "raw_details": json.dumps({
                                        "rule_name": match.rule_name,
                                        "namespace": match.namespace,
                                        "file_path": match.file_path,
                                        "severity": severity,
                                        "attck_techniques": techniques,
                                        "matched_strings": match.matched_strings[:5],  # First 5 strings
                                        "tags": match.tags
                                    })
                                })

                    # Scan active user-space processes' memory
                    cursor.execute("SELECT pid, name FROM collected_processes WHERE snapshot_id = ? AND pid > 2 AND ppid != 2 AND ppid != 0;", (snapshot_id,))
                    pids_to_scan = [row["pid"] for row in cursor.fetchall() if not any((row["name"] or "").lower().startswith(p) for p in KERNEL_THREAD_PREFIXES)]

                    for pid in pids_to_scan:
                        try:
                            proc_matches = yara_engine.scan_process(pid, timeout=10)
                            for match in proc_matches:
                                severity = yara_engine.get_severity_for_match(match)
                                techniques = yara_engine.get_attck_techniques(match)

                                max_severity_weight += 80 if severity == "critical" else 60 if severity == "high" else 40
                                tech_str = f" [{', '.join(techniques)}]" if techniques else ""
                                events_found.append({
                                    "type": "yara_malware_match",
                                    "severity": severity,
                                    "description": f"YARA malware signature detected{tech_str}: {match.rule_name} in memory of PID {pid}",
                                    "raw_details": json.dumps({
                                        "rule_name": match.rule_name,
                                        "namespace": match.namespace,
                                        "file_path": None,
                                        "process_pid": pid,
                                        "severity": severity,
                                        "attck_techniques": techniques,
                                        "matched_strings": match.matched_strings[:5],
                                        "tags": match.tags
                                    })
                                })
                        except Exception:
                            pass

                    # Store YARA scan results in database
                    from datetime import datetime, timezone
                    scan_summary = {
                        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                        "rules_loaded": rules_loaded,
                        "files_scanned": sum(1 for d in scan_dirs if d.exists()),
                        "total_matches": len([e for e in events_found if e["type"] == "yara_malware_match"]),
                        "scan_errors": [],
                        "matches": [
                            {
                                "rule_name": details["rule_name"],
                                "namespace": details["namespace"],
                                "file_path": details["file_path"],
                                "severity": e["severity"],
                                "attck_techniques": details["attck_techniques"],
                                "matched_strings": details["matched_strings"],
                                "meta_data": {},
                                "match_context": None
                            }
                            for e in events_found if e["type"] == "yara_malware_match"
                            for details in [json.loads(e["raw_details"])]
                        ]
                    }

                    storage.store_yara_scan_results(conn, snapshot_id, scan_summary)

            except Exception as e:
                print(f"[!] YARA scan error: {e}")
        else:
            print("[!] YARA library not available - skipping malware pattern matching")

        # 6. Kernel Module Integrity Verification Rule
        cursor.execute("SELECT module_name, memory_size FROM baseline_kernel_modules WHERE hostname = ?;", (hostname,))
        trusted_modules = {row["module_name"] for row in cursor.fetchall()}

        cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
        collected_mods = cursor.fetchall()

        active_untrusted_mods = set()
        if trusted_modules:
            for mod in collected_mods:
                name = mod["module_name"]
                if name not in trusted_modules:
                    active_untrusted_mods.add(name)
                    max_severity_weight += 80
                    events_found.append({
                        "type": "untrusted_kernel_module", "severity": "critical",
                        "description": f"CRITICAL: Untrusted or unsigned LKM kernel driver module detected: {name}",
                        "raw_details": json.dumps(dict(mod))
                    })

        # 7. User Privilege Escalation & Backdoor Audit Rule
        cursor.execute("SELECT username, uid, login_shell FROM baseline_users WHERE hostname = ?;", (hostname,))
        baseline_users_map = {row["username"]: row for row in cursor.fetchall()}
        cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
        active_users = set()
        active_user_uids = {}
        for user in cursor.fetchall():
            active_users.add(user["username"])
            active_user_uids[user["username"]] = user["uid"]
            if user["username"] not in baseline_users_map:
                is_root = (user["uid"] == 0)
                max_severity_weight += 90 if is_root else 50
                events_found.append({
                    "type": "unauthorized_user_created",
                    "severity": "critical" if is_root else "high",
                    "description": f"Unauthorized profile: {user['username']}",
                    "raw_details": json.dumps(dict(user))
                })
            elif user["uid"] == 0 and baseline_users_map[user["username"]]["uid"] != 0:
                max_severity_weight += 100
                events_found.append({
                    "type": "privilege_escalation_hijack",
                    "severity": "critical",
                    "description": f"Hijack: {user['username']} promoted to root",
                    "raw_details": json.dumps(dict(user))
                })

        # 8. Deleted Binaries Execution Check
        cursor.execute("SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;", (snapshot_id,))
        active_deleted_binaries = set()
        for row in cursor.fetchall():
            active_deleted_binaries.add((row["pid"], row["exe"]))
            max_severity_weight += 75
            events_found.append({
                "type": "deleted_binary_execution", "severity": "high",
                # The description field tracks the executable target safely without PID parameters
                "description": f"Running process points to a deleted binary executable: {row['exe']}",
                "raw_details": json.dumps(dict(row))
            })

        # 9. Promiscuous Mode Interface Check
        cursor.execute("SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;", (snapshot_id,))
        active_promisc_interfaces = set()
        for row in cursor.fetchall():
            if row["is_promiscuous"] == 1:
                active_promisc_interfaces.add(row["interface"])
                max_severity_weight += 70
                events_found.append({
                    "type": "promiscuous_interface", "severity": "high",
                    "description": f"Promiscuous mode active on interface: {row['interface']}. Host may be capturing raw promiscuous packets.",
                    "raw_details": json.dumps(dict(row))
                })

        # 10. WTMP / Lastlog Session Audit Tampering Check
        cursor.execute("SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;", (snapshot_id,))
        for row in cursor.fetchall():
            if row["anomaly_detected"] == 1:
                max_severity_weight += 95
                events_found.append({
                    "type": "log_tampering", "severity": "critical",
                    "description": f"WTMP session audit anomaly: {row['anomaly_reason']}",
                    "raw_details": json.dumps(dict(row))
                })

        cursor.execute("SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;", (snapshot_id,))
        for row in cursor.fetchall():
            if row["anomaly_detected"] == 1:
                max_severity_weight += 95
                events_found.append({
                    "type": "log_tampering", "severity": "critical",
                    "description": f"Lastlog session audit anomaly for user '{row['username']}': {row['anomaly_reason']}",
                    "raw_details": json.dumps(dict(row))
                })

        # 11. Hidden Process (Unhide) Check
        hidden_procs = detect_hidden_processes()
        active_hidden_pids = {hp["pid"] for hp in hidden_procs}
        for hp in hidden_procs:
            max_severity_weight += 95
            events_found.append({
                "type": "hidden_process", "severity": "critical",
                "description": "CRITICAL: Hidden process detected active in the system scheduler but missing from the /proc file system mapping architecture.",
                "raw_details": json.dumps(hp)
            })

        # 12. Package Integrity Violation Check
        cursor.execute("SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;", (snapshot_id,))
        active_pkg_violations = set()
        for row in cursor.fetchall():
            active_pkg_violations.add((row["package"], row["file_path"]))
            max_severity_weight += 85
            desc = f"CRITICAL: Package integrity violation in package '{row['package']}': binary '{row['file_path']}' "
            if row["status"] == "missing":
                desc += "is missing from disk structural trees."
            else:
                desc += "has been altered from upstream md5 signatures."
            events_found.append({
                "type": "pkg_integrity_violation", "severity": "critical",
                "description": desc,
                "raw_details": json.dumps(dict(row))
            })

        # 13. Cron Job Persistence Security Rules
        cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snapshot_id,))
        for cron_row in cursor.fetchall():
            command = cron_row["command"].lower()
            # Check for volatile directory execution
            if any(dir_path in command for dir_path in VOLATILE_DIRS):
                max_severity_weight += 70
                events_found.append({
                    "type": "cron_volatile_execution", "severity": "high",
                    "description": f"Cron job executes command from volatile system workspace: {cron_row['command']} ({cron_row['source']})",
                    "raw_details": json.dumps(dict(cron_row))
                })
            # Check for suspicious command components
            elif any(p.search(command) for p in SUSPICIOUS_CMD_PATTERNS) or any(re.search(rf"\b{name}\b", command) for name in SUSPICIOUS_EXACT_NAMES):
                max_severity_weight += 80
                events_found.append({
                    "type": "cron_suspicious_command", "severity": "critical",
                    "description": f"Suspicious interactive command or reverse shell signature in cron job: {cron_row['command']} ({cron_row['source']})",
                    "raw_details": json.dumps(dict(cron_row))
                })

        # 14. SUID/SGID Binary Auditor Rule
        cursor.execute("SELECT file_path, sha256 FROM baseline_suid_binaries WHERE hostname = ?;", (hostname,))
        baseline_suid = {row["file_path"]: row["sha256"] for row in cursor.fetchall()}

        cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ?;", (snapshot_id,))
        collected_suid = cursor.fetchall()

        active_suid_violations = set()
        for suid in collected_suid:
            fp = suid["file_path"]
            owner = suid["owner"]
            grp_name = suid["grp"]
            perms = suid["permissions"]
            sha = suid["sha256"]

            suid_event = dict(suid)
            is_violation = False

            if fp not in baseline_suid:
                active_suid_violations.add(fp)
                max_severity_weight += 85
                events_found.append({
                    "type": "new_suid_binary", "severity": "high",
                    "description": f"New untrusted SUID/SGID binary discovered: {fp} (Owner: {owner}, Group: {grp_name}, Perms: {perms})",
                    "raw_details": json.dumps(dict(suid))
                })
                suid_event["status"] = "new"
                is_violation = True
            elif baseline_suid[fp] != sha and sha != "unknown":
                active_suid_violations.add(fp)
                max_severity_weight += 95
                events_found.append({
                    "type": "modified_suid_binary", "severity": "critical",
                    "description": f"CRITICAL: Baseline SUID/SGID binary modified or replaced: {fp} (Hash mismatch)",
                    "raw_details": json.dumps(dict(suid))
                })
                suid_event["status"] = "modified"
                is_violation = True

            if is_violation:
                for rule in suid_rules:
                    if evaluate_rule_against_event(suid_event, rule):
                        trigger_sigma_alert(rule, suid_event)

        # 15. eBPF Subsystem Verification Rules
        cursor.execute("SELECT bpf_id, name, type, tag, gpl_compatible FROM collected_ebpf_programs WHERE snapshot_id = ?;", (snapshot_id,))
        ebpf_programs_list = [dict(row) for row in cursor.fetchall()]
        for prog_row in ebpf_programs_list:
            name = prog_row["name"].lower()
            gpl = prog_row["gpl_compatible"]
            is_suspicious = False
            reason = ""
            if gpl == 0:
                is_suspicious = True
                reason = "Non-GPL compatible eBPF program detected"
            elif any(pattern in name for pattern in ("hook", "rootkit", "hide", "sniff", "pamspy", "ebpfkit", "triplecross")):
                is_suspicious = True
                reason = f"Suspicious eBPF program name detected: {prog_row['name']}"

            if is_suspicious:
                max_severity_weight += 80
                events_found.append({
                    "type": "ebpf_rootkit", "severity": "critical",
                    # bpf_id is kernel-assigned and changes on every reload — stripped to keep dedup key stable
                    "description": f"{reason} (Type: {prog_row['type']})",
                    "raw_details": json.dumps(dict(prog_row))
                })

        cursor.execute("SELECT path, type FROM collected_ebpf_pinned WHERE snapshot_id = ?;", (snapshot_id,))
        ebpf_pinned_list = [dict(row) for row in cursor.fetchall()]
        for pin_row in ebpf_pinned_list:
            path_lower = pin_row["path"].lower()
            is_suspicious = False
            reason = ""
            if any(pattern in path_lower for pattern in ("hook", "rootkit", "hide", "sniff", "pamspy", "ebpfkit", "triplecross")):
                is_suspicious = True
                reason = f"Suspicious eBPF pinned object path detected: {pin_row['path']}"

            if is_suspicious:
                max_severity_weight += 80
                events_found.append({
                    "type": "ebpf_rootkit", "severity": "critical",
                    "description": f"{reason} (Type: {pin_row['type']})",
                    "raw_details": json.dumps(dict(pin_row))
                })

        # 15b. Advanced Rootkit Detection (Cross-View Differential Analysis)
        cursor.execute("SELECT address, symbol_type, symbol_name, module_name, is_critical, suspicious FROM collected_kernel_symbols WHERE snapshot_id = ?;", (snapshot_id,))
        kernel_symbols_list = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
        kernel_modules_list = [dict(row) for row in cursor.fetchall()]

        # Load baseline symbols if available for comparison
        baseline_symbols_dict = None
        try:
            cursor.execute("SELECT symbol_name, address FROM baseline_kernel_symbols WHERE hostname = ?;", (hostname,))
            baseline_rows = cursor.fetchall()
            if baseline_rows:
                baseline_symbols_dict = {row["symbol_name"]: {"address": row["address"]} for row in baseline_rows}
        except sqlite3.OperationalError:
            # Table doesn't exist yet - skip baseline comparison
            pass

        # Run comprehensive rootkit detection
        rootkit_results = run_rootkit_detection(
            ebpf_programs=ebpf_programs_list,
            ebpf_pinned=ebpf_pinned_list,
            kernel_symbols=kernel_symbols_list,
            kernel_modules=kernel_modules_list,
            baseline_symbols=baseline_symbols_dict
        )

        # Report detected rootkit indicators
        for indicator in rootkit_results.get("indicators", []):
            severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            severity = severity_map.get(indicator["severity"], "medium")
            weight_map = {"critical": 95, "high": 75, "medium": 50, "low": 30}
            max_severity_weight += weight_map.get(severity, 50)

            events_found.append({
                "type": indicator["indicator_type"],
                "severity": severity,
                "description": indicator["description"],
                "raw_details": json.dumps(indicator["evidence"])
            })

        # 16. Dynamic Linker Hijacking Preload Overrides
        cursor.execute("SELECT line FROM collected_ld_preload WHERE snapshot_id = ?;", (snapshot_id,))
        for preload_row in cursor.fetchall():
            line = preload_row["line"].strip()
            max_severity_weight += 90
            events_found.append({
                "type": "ld_preload_hijack", "severity": "critical",
                "description": f"Dynamic Linker Hijacking: library configured in /etc/ld.so.preload: {line}",
                "raw_details": json.dumps(dict(preload_row))
            })

        # 17. Special Process File Descriptors
        cursor.execute("SELECT pid, fd_num, fd_type, resolved_path FROM collected_special_fds WHERE snapshot_id = ?;", (snapshot_id,))
        for fd_row in cursor.fetchall():
            fd_type = fd_row["fd_type"]
            pid = fd_row["pid"]
            path = fd_row["resolved_path"]

            cursor.execute("SELECT name FROM collected_processes WHERE snapshot_id = ? AND pid = ? LIMIT 1;", (snapshot_id, pid))
            p_row = cursor.fetchone()
            proc_name = p_row["name"] if p_row else "unknown"

            if fd_type == "memfd":
                whitelisted_memfd = {"chrome", "firefox", "code", "pulseaudio", "systemd"}
                if proc_name.lower() not in whitelisted_memfd:
                    max_severity_weight += 75
                    events_found.append({
                        "type": "memfd_execution", "severity": "high",
                        # PID is transient and stripped from description to prevent dedup bypass on every new scan
                        "description": f"Memory-only execution: Process '{proc_name}' has open fd pointing to memfd anonymous segment: {path}",
                        "raw_details": json.dumps(dict(fd_row))
                    })
            elif fd_type == "deleted":
                is_suspicious = False
                if any(v_dir in path for v_dir in VOLATILE_DIRS):
                    is_suspicious = True
                elif "/bin/" in path or "/sbin/" in path or "/usr/" in path:
                    is_suspicious = True

                if is_suspicious:
                    max_severity_weight += 70
                    events_found.append({
                        "type": "deleted_binary_execution", "severity": "high",
                        # PID is transient and stripped from description to prevent dedup bypass on every new scan
                        "description": f"Suspicious deleted file descriptor: Process '{proc_name}' holds open fd to deleted file in volatile/system directory: {path}",
                        "raw_details": json.dumps(dict(fd_row))
                    })

        # Relational correlation evaluation
        if events_found:
            event_types = {e["type"] for e in events_found}

            # Rule 1: Execution & C2 Channel
            execution_anomalies = {"deleted_binary_execution", "memfd_execution", "hidden_process"}
            network_anomalies = {"unexpected_port", "outbound_c2_communication"}
            has_exec = any(t in event_types for t in execution_anomalies)
            has_net = any(t in event_types for t in network_anomalies)
            if has_exec and has_net:
                events_found.append({
                    "type": "relational_threat_chain",
                    "severity": "critical",
                    "description": "CRITICAL CORRELATION: Co-occurring execution anomaly and network C2 channel detected.",
                    "raw_details": json.dumps({"reason": "Co-occurring execution anomaly and network anomalies."})
                })
                for e in events_found:
                    if e["type"] in execution_anomalies or e["type"] in network_anomalies:
                        e["severity"] = "critical"

            # Rule 2: Privilege Escalation & Persistence
            privilege_anomalies = {"privilege_escalation_hijack", "new_suid_binary", "modified_suid_binary", "privileged_group_escalation"}
            persistence_anomalies = {"new_user", "unauthorized_user_created", "new_ssh_authorized_key", "new_cron_job", "cron_volatile_execution", "cron_suspicious_command"}
            has_priv = any(t in event_types for t in privilege_anomalies)
            has_pers = any(t in event_types for t in persistence_anomalies)
            if has_priv and has_pers:
                events_found.append({
                    "type": "relational_threat_chain",
                    "severity": "critical",
                    "description": "CRITICAL CORRELATION: Co-occurring privilege escalation anomaly and persistence changes detected.",
                    "raw_details": json.dumps({"reason": "Co-occurring privilege escalation and persistence changes."})
                })
                for e in events_found:
                    if e["type"] in privilege_anomalies or e["type"] in persistence_anomalies:
                        e["severity"] = "critical"

            # Rule 3: Rootkit/Preload & Defense Evasion
            rootkit_anomalies = {"ebpf_rootkit", "untrusted_kernel_module", "ld_preload_hijack"}
            evasion_anomalies = {"log_tampering", "hidden_process"}
            has_root = any(t in event_types for t in rootkit_anomalies)
            has_evas = any(t in event_types for t in evasion_anomalies)
            if has_root and has_evas:
                events_found.append({
                    "type": "relational_threat_chain",
                    "severity": "critical",
                    "description": "CRITICAL CORRELATION: Co-occurring kernel rootkit/preload persistence and defense evasion detected.",
                    "raw_details": json.dumps({"reason": "Co-occurring rootkit/preload and evasion anomalies."})
                })
                for e in events_found:
                    if e["type"] in rootkit_anomalies or e["type"] in evasion_anomalies:
                        e["severity"] = "critical"

        # Final DB Commit Sequence
        if events_found:
            cursor.execute("PRAGMA table_info(security_events);")
            columns = {row["name"] for row in cursor.fetchall()}
            has_suppressed = "suppressed" in columns
            for e in events_found:
                # 1. Skip if this event type/description is suppressed
                if has_suppressed:
                    cursor.execute(
                        "SELECT id FROM security_events WHERE event_type = ? AND description = ? AND suppressed = 1 AND (hostname = ? OR hostname IS NULL) LIMIT 1;",
                        (e["type"], e["description"], hostname)
                    )
                    if cursor.fetchone():
                        continue

                # 2. Check if a severity override exists for this event type/description
                cursor.execute(
                    "SELECT severity FROM security_events WHERE event_type = ? AND description = ? AND severity != ? AND (hostname = ? OR hostname IS NULL) LIMIT 1;",
                    (e["type"], e["description"], e["severity"], hostname)
                )
                override_row = cursor.fetchone()
                if override_row:
                    e["severity"] = override_row["severity"]

                # 3. Insert if it does not already exist (unresolved OR manually resolved).
                #    Checking only resolved=0 would re-insert events the analyst already
                #    dismissed, making them reappear on every subsequent scan.
                cursor.execute(
                    "SELECT id FROM security_events WHERE event_type = ? AND description = ? AND (hostname = ? OR hostname IS NULL) LIMIT 1;",
                    (e["type"], e["description"], hostname)
                )
                if not cursor.fetchone():
                    attck_tech, attck_tactic, attck_url = get_attck_enrichment(e["type"], e["description"])
                    cursor.execute(
                        "INSERT INTO security_events (event_type, severity, description, raw_details, attck_technique, attck_tactic, attck_url, hostname) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                        (e["type"], e["severity"], e["description"], e.get("raw_details"), attck_tech, attck_tactic, attck_url, hostname)
                    )

        # Production Tuning: Auto-resolution sweeps read directly from raw_details JSON arrays
        cursor.execute("SELECT id, raw_details FROM security_events WHERE event_type = 'unexpected_port' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    port_val = json.loads(row["raw_details"]).get("port")
                    if port_val not in active_unexpected_ports:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        # Auto-resolve unexpected kernel drivers
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'untrusted_kernel_module' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            match = re.search(r"CRITICAL: Untrusted or unsigned LKM kernel driver module detected: (\S+)", row["description"])
            if match:
                mod_name = match.group(1)
                if mod_name not in active_untrusted_mods:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve hidden processes via parsed JSON metrics
        cursor.execute("SELECT id, raw_details FROM security_events WHERE event_type = 'hidden_process' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    pid_val = json.loads(row["raw_details"]).get("pid")
                    if pid_val not in active_hidden_pids:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        # Auto-resolve deleted binary executions via parsed JSON metrics
        cursor.execute("SELECT id, raw_details FROM security_events WHERE event_type = 'deleted_binary_execution' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    details = json.loads(row["raw_details"])
                    if (details.get("pid"), details.get("exe")) not in active_deleted_binaries:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        # Auto-resolve promiscuous interfaces
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'promiscuous_interface' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            match = re.search(r"Promiscuous mode active on interface: (\S+)", row["description"])
            if match:
                iface_val = match.group(1).rstrip('.')
                if iface_val not in active_promisc_interfaces:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve package integrity violations via parsed JSON metrics
        cursor.execute("SELECT id, raw_details FROM security_events WHERE event_type = 'pkg_integrity_violation' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    details = json.loads(row["raw_details"])
                    if (details.get("package"), details.get("file_path")) not in active_pkg_violations:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        # Auto-resolve unauthorized user profiles
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'unauthorized_user_created' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            match = re.search(r"Unauthorized profile: (\S+)", row["description"])
            if match:
                user_val = match.group(1)
                if user_val not in active_users:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve privilege escalation hijacks
        cursor.execute("SELECT id, description FROM security_events WHERE event_type = 'privilege_escalation_hijack' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            match = re.search(r"Hijack: (\S+) promoted to root", row["description"])
            if match:
                user_val = match.group(1)
                if user_val not in active_user_uids or active_user_uids[user_val] != 0:
                    cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))

        # Auto-resolve suspicious process ancestry via parsed JSON metrics
        cursor.execute("SELECT id, raw_details FROM security_events WHERE event_type = 'suspicious_process_ancestry' AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    pid_val = json.loads(row["raw_details"]).get("pid")
                    if pid_val not in active_processes:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        # Auto-resolve cron alerts (volatile, suspicious, new)
        cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snapshot_id,))
        active_crontabs = {(c_row["source"], c_row["user"], c_row["schedule"], c_row["command"]) for c_row in cursor.fetchall()}

        cursor.execute("SELECT id, raw_details, event_type FROM security_events WHERE event_type IN ('cron_volatile_execution', 'cron_suspicious_command', 'new_cron_job') AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    details = json.loads(row["raw_details"])
                    cron_key = (details.get("source"), details.get("user"), details.get("schedule"), details.get("command"))
                    if cron_key not in active_crontabs:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        # Auto-resolve SUID/SGID alerts
        cursor.execute("SELECT id, raw_details FROM security_events WHERE event_type IN ('new_suid_binary', 'modified_suid_binary') AND resolved = 0 AND (hostname = ? OR hostname IS NULL);", (hostname,))
        for row in cursor.fetchall():
            if row["raw_details"]:
                try:
                    fp_val = json.loads(row["raw_details"]).get("file_path")
                    if fp_val not in active_suid_violations:
                        cursor.execute("UPDATE security_events SET resolved = 1 WHERE id = ?;", (row["id"],))
                except Exception:
                    pass

        conn.commit()

    # Severity-Tiered Risk Scoring Module
    if not events_found:
        risk_score = 0
    else:
        print("\nDEBUG: events_found =", [(e["type"], e["description"]) for e in events_found])
        severities = [e["severity"].lower() for e in events_found]
        crit_count = severities.count("critical")
        high_count = severities.count("high")
        med_count = severities.count("medium")
        low_count = len(severities) - crit_count - high_count - med_count

        if crit_count > 0:
            risk_score = min(90 + (crit_count - 1) * 5, 100)
        elif high_count > 0:
            risk_score = min(65 + (high_count - 1) * 3 + med_count * 1.5 + low_count * 0.5, 89)
        elif med_count > 0:
            risk_score = min(35 + (med_count - 1) * 1.5 + low_count * 0.5, 64)
        else:
            risk_score = min(15 + (low_count - 1) * 0.5, 34)

        risk_score = int(risk_score + 0.5)

    storage.close_pool()
    return {
        "status": "success",
        "snapshot_id": snapshot_id,
        "risk_score": risk_score,
        "events_count": len(events_found)
    }