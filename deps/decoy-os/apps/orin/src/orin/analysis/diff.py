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
# src/orin/analysis/diff.py
"""
orin.analysis.diff – Snapshot Comparator
=========================================
Provides tools to compare two point-in-time Orin forensic snapshots and
produce a structured drift report.

Supported input formats
-----------------------
* **SQLite database** – the live ``orin_vault.db`` (most recent snapshot is
  used automatically).
* **Signed JSON export** – a ``.json`` bundle produced by ``orin export``
  (requires the HMAC passphrase to verify integrity).
"""

import sqlite3
from pathlib import Path
from orin.core.crypto import verify_signed_export

def load_snapshot_data(file_path: Path, secret_key: str = None) -> dict:
    """Load a single snapshot from either a SQLite vault or a signed JSON export.

    Attempts to open ``file_path`` as a SQLite database first.  If that
    succeeds and the ``system_snapshots`` table exists, the most recent
    snapshot row is loaded.  Otherwise, the file is treated as a signed JSON
    export and verification handles authentication and decoding.

    Parameters
    ----------
    file_path : Path
        Path to either a SQLite ``.db`` file or a signed ``.json`` export.
    secret_key : str, optional
        HMAC passphrase required when ``file_path`` is a signed JSON export.

    Returns
    -------
    dict
        Normalised snapshot dictionary with standard forensic telemetry keys.

    Raises
    ------
    FileNotFoundError
        If ``file_path`` does not exist.
    ValueError
        If the file cannot be parsed as either format, or if a passphrase is
        required for a JSON export but was not provided.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # 1. Try to read as a SQLite database safely
    try:
        conn = sqlite3.connect(file_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Verify schema validity by checking for the primary system tracking table explicitly
        cursor.execute("SELECT id, hostname, os_platform, timestamp FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snap = cursor.fetchone()
        if snap:
            snapshot_id = snap['id']

            cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snapshot_id,))
            processes = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snapshot_id,))
            ports = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT local_ip, local_port, remote_ip, remote_port, state, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snapshot_id,))
            outbound = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
            kernel_modules = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT user_account, key_type, fingerprint, raw_key_comment FROM collected_ssh_keys WHERE snapshot_id = ?;", (snapshot_id,))
            ssh_keys = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
            users = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (snapshot_id,))
            file_hashes = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;", (snapshot_id,))
            deleted_binaries = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;", (snapshot_id,))
            promisc_interfaces = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;", (snapshot_id,))
            wtmp_sessions = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;", (snapshot_id,))
            lastlog_records = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;", (snapshot_id,))
            pkg_integrity = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snapshot_id,))
            crontabs = [dict(r) for r in cursor.fetchall()]

            conn.close()
            return {
                "source": "database",
                "metadata": dict(snap),
                "processes": processes,
                "ports": ports,
                "outbound": outbound,
                "kernel_modules": kernel_modules,
                "ssh_keys": ssh_keys,
                "users": users,
                "file_hashes": file_hashes,
                "deleted_binaries": deleted_binaries,
                "promisc_interfaces": promisc_interfaces,
                "wtmp_sessions": wtmp_sessions,
                "lastlog_records": lastlog_records,
                "pkg_integrity": pkg_integrity,
                "crontabs": crontabs
            }
    except sqlite3.Error:
        # File descriptor open or schema operation query validation failed, fallback to json check path
        pass
    finally:
        try:
            conn.close()
        except UnboundLocalError:
            pass
        except Exception:
            pass

    # 2. Try to read as a signed JSON export securely
    try:
        if not secret_key:
            raise ValueError("Passphrase (--secret) is required to verify/decrypt the export file.")

        verified_data = verify_signed_export(file_path, secret_key)
        return {
            "source": "export",
            "metadata": verified_data["metadata"],
            "processes": verified_data["processes"],
            "ports": verified_data["ports"],
            "outbound": verified_data["outbound"],
            "kernel_modules": verified_data.get("kernel_modules", []),
            "ssh_keys": verified_data.get("ssh_keys", []),
            "users": verified_data.get("users", []),
            "file_hashes": verified_data.get("file_hashes", []),
            "deleted_binaries": verified_data.get("deleted_binaries", []),
            "promisc_interfaces": verified_data.get("promisc_interfaces", []),
            "wtmp_sessions": verified_data.get("wtmp_sessions", []),
            "lastlog_records": verified_data.get("lastlog_records", []),
            "pkg_integrity": verified_data.get("pkg_integrity", []),
            "crontabs": verified_data.get("crontabs", [])
        }
    except Exception as e:
        raise ValueError(f"Failed to parse '{file_path}' as relational vault or authenticated signed export: {e}")


def compare_snapshots(base: dict, target: dict) -> dict:
    """Compute a structural identity diff between two normalised snapshot dictionaries.

    Compares each telemetry category using set-based identity keys appropriate
    to that specific category. Field changes are caught dynamically.
    """
    diff = {
        "metadata": {
            "base": base["metadata"],
            "target": target["metadata"]
        },
        "ports": {"added": [], "removed": []},
        "outbound": {"added": [], "removed": []},
        "processes": {"added": [], "removed": []},
        "kernel_modules": {"added": [], "removed": []},
        "users": {"added": [], "removed": [], "modified": []},
        "ssh_keys": {"added": [], "removed": []},
        "file_hashes": {"added": [], "removed": [], "modified": []},
        "deleted_binaries": {"added": [], "removed": []},
        "promisc_interfaces": {"added": [], "removed": [], "modified": []},
        "wtmp_sessions": {"added": [], "removed": []},
        "lastlog_records": {"added": [], "removed": []},
        "pkg_integrity": {"added": [], "removed": []},
        "crontabs": {"added": [], "removed": []}
    }

    # Helper function to normalize text strings to prevent false drift matching
    def clean_str(val):
        if val is None:
            return ""
        return str(val).strip()

    # 1. Ports Diff
    base_ports = {(p["port"], p["protocol"]) for p in base["ports"]}
    target_ports = {(p["port"], p["protocol"]): p for p in target["ports"]}
    for k in (target_ports.keys() - base_ports):
        diff["ports"]["added"].append(target_ports[k])

    base_ports_map = {(p["port"], p["protocol"]): p for p in base["ports"]}
    for k in (base_ports - target_ports.keys()):
        diff["ports"]["removed"].append(base_ports_map[k])

    # 2. Outbound Connections Diff
    base_outbound = {(o["remote_ip"], o["remote_port"]) for o in base["outbound"]}
    target_outbound = {(o["remote_ip"], o["remote_port"]): o for o in target["outbound"]}
    for k in (target_outbound.keys() - base_outbound):
        diff["outbound"]["added"].append(target_outbound[k])

    base_outbound_map = {(o["remote_ip"], o["remote_port"]): o for o in base["outbound"]}
    for k in (base_outbound - target_outbound.keys()):
        diff["outbound"]["removed"].append(base_outbound_map[k])

    # 3. Processes Diff (Using name, exe, cmdline as identity key — PID stripped)
    base_procs = {(clean_str(p["name"]), clean_str(p["exe"]), clean_str(p["cmdline"])) for p in base["processes"]}
    target_procs = {(clean_str(p["name"]), clean_str(p["exe"]), clean_str(p["cmdline"])): p for p in target["processes"]}
    for k in (target_procs.keys() - base_procs):
        diff["processes"]["added"].append(target_procs[k])

    base_procs_map = {(clean_str(p["name"]), clean_str(p["exe"]), clean_str(p["cmdline"])): p for p in base["processes"]}
    for k in (base_procs - target_procs.keys()):
        diff["processes"]["removed"].append(base_procs_map[k])

    # 4. Kernel Modules Diff
    base_mods = {m["module_name"] for m in base["kernel_modules"]}
    target_mods = {m["module_name"]: m for m in target["kernel_modules"]}
    for k in (target_mods.keys() - base_mods):
        diff["kernel_modules"]["added"].append(target_mods[k])

    base_mods_map = {m["module_name"]: m for m in base["kernel_modules"]}
    for k in (base_mods - target_mods.keys()):
        diff["kernel_modules"]["removed"].append(base_mods_map[k])

    # 5. Users Diff
    base_users = {u["username"] for u in base["users"]}
    target_users = {u["username"]: u for u in target["users"]}
    for k in (target_users.keys() - base_users):
        diff["users"]["added"].append(target_users[k])

    base_users_map = {u["username"]: u for u in base["users"]}
    for k in (base_users - target_users.keys()):
        diff["users"]["removed"].append(base_users_map[k])

    for k in (base_users & target_users.keys()):
        b_u = base_users_map[k]
        t_u = target_users[k]
        modifications = {}
        for field in ["uid", "gid", "home_dir", "login_shell"]:
            if clean_str(b_u.get(field)) != clean_str(t_u.get(field)):
                modifications[field] = {"old": b_u.get(field), "new": t_u.get(field)}
        if modifications:
            diff["users"]["modified"].append({"username": k, "changes": modifications})

    # 6. SSH Keys Diff
    base_ssh = {(s["user_account"], s["fingerprint"]) for s in base["ssh_keys"]}
    target_ssh = {(s["user_account"], s["fingerprint"]): s for s in target["ssh_keys"]}
    for k in (target_ssh.keys() - base_ssh):
        diff["ssh_keys"]["added"].append(target_ssh[k])

    base_ssh_map = {(s["user_account"], s["fingerprint"]): s for s in base["ssh_keys"]}
    for k in (base_ssh - target_ssh.keys()):
        diff["ssh_keys"]["removed"].append(base_ssh_map[k])

    # 7. File Integrity Monitor Diff
    base_files = {f["file_path"] for f in base["file_hashes"]}
    target_files = {f["file_path"]: f for f in target["file_hashes"]}
    for k in (target_files.keys() - base_files):
        diff["file_hashes"]["added"].append(target_files[k])

    base_files_map = {f["file_path"]: f for f in base["file_hashes"]}
    for k in (base_files - target_files.keys()):
        diff["file_hashes"]["removed"].append(base_files_map[k])

    for k in (base_files & target_files.keys()):
        b_f = base_files_map[k]
        t_f = target_files[k]
        if b_f["sha256_hash"] != t_f["sha256_hash"]:
            diff["file_hashes"]["modified"].append({
                "file_path": k,
                "old_hash": b_f["sha256_hash"],
                "new_hash": t_f["sha256_hash"]
            })

    # 8. Deleted Binaries Diff
    base_del = {(d["pid"], clean_str(d["exe"]), d["sha256"]) for d in base.get("deleted_binaries", [])}
    target_del = {(d["pid"], clean_str(d["exe"]), d["sha256"]): d for d in target.get("deleted_binaries", [])}
    for k in (target_del.keys() - base_del):
        diff["deleted_binaries"]["added"].append(target_del[k])
    base_del_map = {(d["pid"], clean_str(d["exe"]), d["sha256"]): d for d in base.get("deleted_binaries", [])}
    for k in (base_del - target_del.keys()):
        diff["deleted_binaries"]["removed"].append(base_del_map[k])

    # 9. Promisc Interfaces Diff
    base_prom = {p["interface"] for p in base.get("promisc_interfaces", [])}
    target_prom = {p["interface"]: p for p in target.get("promisc_interfaces", [])}
    for k in (target_prom.keys() - base_prom):
        diff["promisc_interfaces"]["added"].append(target_prom[k])
    base_prom_map = {p["interface"]: p for p in base.get("promisc_interfaces", [])}
    for k in (base_prom - target_prom.keys()):
        diff["promisc_interfaces"]["removed"].append(base_prom_map[k])
    for k in (base_prom & target_prom.keys()):
        bp = base_prom_map[k]
        tp = target_prom[k]
        modifications = {}
        for field in ["flags", "is_promiscuous"]:
            if clean_str(bp.get(field)) != clean_str(tp.get(field)):
                modifications[field] = {"old": bp.get(field), "new": tp.get(field)}
        if modifications:
            diff["promisc_interfaces"]["modified"].append({"interface": k, "changes": modifications})

    # 10. WTMP Sessions Diff
    base_wtmp = {(w["user"], w["line"], w["host"], w["pid"], w["login_time"]) for w in base.get("wtmp_sessions", [])}
    target_wtmp = {(w["user"], w["line"], w["host"], w["pid"], w["login_time"]): w for w in target.get("wtmp_sessions", [])}
    for k in (target_wtmp.keys() - base_wtmp):
        diff["wtmp_sessions"]["added"].append(target_wtmp[k])
    base_wtmp_map = {(w["user"], w["line"], w["host"], w["pid"], w["login_time"]): w for w in base.get("wtmp_sessions", [])}
    for k in (base_wtmp - target_wtmp.keys()):
        diff["wtmp_sessions"]["removed"].append(base_wtmp_map[k])

    # 11. Lastlog Records Diff
    base_lastlog = {(l["username"], l["login_time"]) for l in base.get("lastlog_records", [])}
    target_lastlog = {(l["username"], l["login_time"]): l for l in target.get("lastlog_records", [])}
    for k in (target_lastlog.keys() - base_lastlog):
        diff["lastlog_records"]["added"].append(target_lastlog[k])
    base_lastlog_map = {(l["username"], l["login_time"]): l for l in base.get("lastlog_records", [])}
    for k in (base_lastlog - target_lastlog.keys()):
        diff["lastlog_records"]["removed"].append(base_lastlog_map[k])

    # 12. Pkg Integrity Diff
    base_pkg = {(p["package"], p["file_path"]) for p in base.get("pkg_integrity", [])}
    target_pkg = {(p["package"], p["file_path"]): p for p in target.get("pkg_integrity", [])}
    for k in (target_pkg.keys() - base_pkg):
        diff["pkg_integrity"]["added"].append(target_pkg[k])
    base_pkg_map = {(p["package"], p["file_path"]): p for p in base.get("pkg_integrity", [])}
    for k in (base_pkg - target_pkg.keys()):
        diff["pkg_integrity"]["removed"].append(base_pkg_map[k])

    # 13. Crontabs Diff
    base_crontabs = {(c["source"], c["user"], c["schedule"], clean_str(c["command"])) for c in base.get("crontabs", [])}
    target_crontabs = {(c["source"], c["user"], c["schedule"], clean_str(c["command"])): c for c in target.get("crontabs", [])}
    for k in (target_crontabs.keys() - base_crontabs):
        diff["crontabs"]["added"].append(target_crontabs[k])
    base_crontabs_map = {(c["source"], c["user"], c["schedule"], clean_str(c["command"])): c for c in base.get("crontabs", [])}
    for k in (base_crontabs - target_crontabs.keys()):
        diff["crontabs"]["removed"].append(base_crontabs_map[k])

    return diff


def print_diff_report(diff: dict) -> None:
    """Render a snapshot diff report to stdout in a human-readable format."""
    base_meta = diff["metadata"]["base"]
    target_meta = diff["metadata"]["target"]

    print("\n" + "="*70)
    print("                 ORIN FORENSIC SNAPSHOT DIFF REPORT")
    print("="*70)
    print(f"Base   : Host: {base_meta.get('hostname')} | OS: {base_meta.get('os_platform')} | Captured: {base_meta.get('timestamp')}")
    print(f"Target : Host: {target_meta.get('hostname')} | OS: {target_meta.get('os_platform')} | Captured: {target_meta.get('timestamp')}")
    print("="*70)

    # 1. Ports
    added_ports = diff["ports"]["added"]
    removed_ports = diff["ports"]["removed"]
    if added_ports or removed_ports:
        print("\n[🌐] Network Sockets Drift:")
        for p in added_ports:
            print(f"    [+] ADDED Listening Port: {p['port']}/{p['protocol']} ({p['process_name'] or 'unknown'})")
        for p in removed_ports:
            print(f"    [-] REMOVED Listening Port: {p['port']}/{p['protocol']} ({p['process_name'] or 'unknown'})")

    # 2. Outbound Connections
    added_out = diff["outbound"]["added"]
    removed_out = diff["outbound"]["removed"]
    if added_out or removed_out:
        print("\n[📤] Outbound Connections Drift:")
        for o in added_out:
            print(f"    [+] ADDED Outbound Connection: -> {o['remote_ip']}:{o['remote_port']} ({o['process_name'] or 'unknown'})")
        for o in removed_out:
            print(f"    [-] REMOVED Outbound Connection: -> {o['remote_ip']}:{o['remote_port']} ({o['process_name'] or 'unknown'})")

    # 3. Processes
    added_procs = diff["processes"]["added"]
    removed_procs = diff["processes"]["removed"]
    if added_procs or removed_procs:
        print("\n[⚙️] Processes Drift:")
        for p in added_procs:
            print(f"    [+] NEW Process Running: {p['name']} (PID: {p['pid']}, PPID: {p['ppid']})")
            if p['cmdline']:
                print(f"        CMD: {p['cmdline']}")
        for p in removed_procs:
            print(f"    [-] TERMINATED Process: {p['name']} (PID: {p['pid']})")

    # 4. Kernel Modules
    added_mods = diff["kernel_modules"]["added"]
    removed_mods = diff["kernel_modules"]["removed"]
    if added_mods or removed_mods:
        print("\n[🛡️] Loaded Kernel Modules Drift:")
        for m in added_mods:
            print(f"    [+] ADDED Module: {m['module_name']} ({m['memory_size']} bytes)")
        for m in removed_mods:
            print(f"    [-] REMOVED Module: {m['module_name']}")

    # 5. User Accounts
    added_users = diff["users"]["added"]
    removed_users = diff["users"]["removed"]
    modified_users = diff["users"]["modified"]
    if added_users or removed_users or modified_users:
        print("\n[👤] User Accounts Drift:")
        for u in added_users:
            print(f"    [+] ADDED User: {u['username']} (UID: {u['uid']})")
        for u in removed_users:
            print(f"    [-] REMOVED User: {u['username']}")
        for u in modified_users:
            print(f"    [*] MODIFIED User: {u['username']}:")
            for field, change in u["changes"].items():
                print(f"        -> {field}: {change['old']} -> {change['new']}")

    # 6. SSH Keys
    added_ssh = diff["ssh_keys"]["added"]
    removed_ssh = diff["ssh_keys"]["removed"]
    if added_ssh or removed_ssh:
        print("\n[🔑] SSH Authorized Keys Drift:")
        for s in added_ssh:
            print(f"    [+] ADDED SSH Key for {s['user_account']}: comment '{s['raw_key_comment']}'")
        for s in removed_ssh:
            print(f"    [-] REMOVED SSH Key for {s['user_account']}: comment '{s['raw_key_comment']}'")

    # 7. File Integrity Monitor
    added_files = diff["file_hashes"]["added"]
    removed_files = diff["file_hashes"]["removed"]
    modified_files = diff["file_hashes"]["modified"]
    if added_files or removed_files or modified_files:
        print("\n[📂] File Integrity Monitor (FIM) Drift:")
        for f in added_files:
            print(f"    [+] ADDED Monitored File: {f['file_path']}")
        for f in removed_files:
            print(f"    [-] REMOVED Monitored File: {f['file_path']}")
        for f in modified_files:
            print(f"    [🛑] MODIFIED File: {f['file_path']}")
            print(f"        Old Hash: {f['old_hash']}")
            print(f"        New Hash: {f['new_hash']}")

    # 8. Deleted Binaries
    added_del = diff.get("deleted_binaries", {}).get("added", [])
    removed_del = diff.get("deleted_binaries", {}).get("removed", [])
    if added_del or removed_del:
        print("\n[🗑️] Deleted Binaries Execution Drift:")
        for d in added_del:
            print(f"    [+] ADDED Deleted Binary: PID {d['pid']} ({d['exe']}) -> Vault: {d['vault_path']}")
        for d in removed_del:
            print(f"    [-] REMOVED Deleted Binary: PID {d['pid']} ({d['exe']})")

    # 9. Promisc Interfaces
    added_prom = diff.get("promisc_interfaces", {}).get("added", [])
    removed_prom = diff.get("promisc_interfaces", {}).get("removed", [])
    modified_prom = diff.get("promisc_interfaces", {}).get("modified", [])
    if added_prom or removed_prom or modified_prom:
        print("\n[📡] Network Promiscuous State Drift:")
        for p in added_prom:
            print(f"    [+] ADDED Interface: {p['interface']} (Flags: {p['flags']}, Promiscuous: {p['is_promiscuous']})")
        for p in removed_prom:
            print(f"    [-] REMOVED Interface: {p['interface']}")
        for p in modified_prom:
            print(f"    [*] MODIFIED Interface: {p['interface']}:")
            for field, change in p["changes"].items():
                print(f"        -> {field}: {change['old']} -> {change['new']}")

    # 10. WTMP Sessions
    added_wtmp = diff.get("wtmp_sessions", {}).get("added", [])
    removed_wtmp = diff.get("wtmp_sessions", {}).get("removed", [])
    if added_wtmp or removed_wtmp:
        print("\n[🪵] WTMP Session Audit Log Drift:")
        for w in added_wtmp:
            print(f"    [+] ADDED Session: User: {w['user']} | Line: {w['line']} | Host: {w['host']} | Login: {w['login_time']} | Logout: {w['logout_time']}")
        for w in removed_wtmp:
            print(f"    [-] REMOVED Session: User: {w['user']} | Line: {w['line']} | Host: {w['host']} | Login: {w['login_time']}")

    # 11. Lastlog Records
    added_last = diff.get("lastlog_records", {}).get("added", [])
    removed_last = diff.get("lastlog_records", {}).get("removed", [])
    if added_last or removed_last:
        print("\n[🪵] Lastlog Record Audit Drift:")
        for l in added_last:
            print(f"    [+] ADDED Lastlogin: User: {l['username']} | Line: {l['line']} | Host: {l['host']} | Time: {l['login_time']}")
        for l in removed_last:
            print(f"    [-] REMOVED Lastlogin: User: {l['username']}")

    # 12. Package Integrity
    added_pkg = diff.get("pkg_integrity", {}).get("added", [])
    removed_pkg = diff.get("pkg_integrity", {}).get("removed", [])
    if added_pkg or removed_pkg:
        print("\n[📦] Package Integrity Mismatch Drift:")
        for p in added_pkg:
            print(f"    [+] ADDED Integrity Violation: Package: {p['package']} | File: {p['file_path']} | Status: {p['status']}")
        for p in removed_pkg:
            print(f"    [-] REMOVED Integrity Violation: Package: {p['package']} | File: {p['file_path']}")

    # 13. Crontabs
    added_cron = diff.get("crontabs", {}).get("added", [])
    removed_cron = diff.get("crontabs", {}).get("removed", [])
    if added_cron or removed_cron:
        print("\n[⏰] Crontab Schedules Drift:")
        for c in added_cron:
            print(f"    [+] ADDED Cron Job: User: {c['user']} | Source: {c['source']} | Schedule: {c['schedule']} | Command: {c['command']}")
        for c in removed_cron:
            print(f"    [-] REMOVED Cron Job: User: {c['user']} | Source: {c['source']} | Schedule: {c['schedule']}")

    # If no drift
    if not (added_ports or removed_ports or added_out or removed_out or added_procs or removed_procs or
            added_mods or removed_mods or added_users or removed_users or modified_users or
            added_ssh or removed_ssh or added_files or removed_files or modified_files or
            added_del or removed_del or added_prom or removed_prom or modified_prom or
            added_wtmp or removed_wtmp or added_last or removed_last or added_pkg or removed_pkg or
            added_cron or removed_cron):
        print("\n🟢 No configuration, network, process, or file integrity drift detected between snapshots.")

    print("="*70 + "\n")