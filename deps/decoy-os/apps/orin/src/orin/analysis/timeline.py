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
# orin/analysis/timeline.py
"""
orin.analysis.timeline – Snapshot Delta Calculator
==================================================
Provides :func:`calculate_snapshot_delta`, which computes the structural
differences between two named snapshot IDs stored in the Orin SQLite vault.

Unlike :mod:`orin.analysis.diff`, which compares arbitrary files, this module
operates exclusively within the live vault database and additionally surfaces
any ``security_events`` that were recorded *between* the timestamps of the
two chosen snapshots.
"""
from pathlib import Path
from orin.core.database import OrinStorage

def calculate_snapshot_delta(db_path: Path, base_id: int, target_id: int) -> dict:
    """Compute systemic differences between two snapshot IDs within the vault.

    Fetches the timestamps of both snapshots to identify the intermediate
    time window, then queries for security events that fired during that
    window.  Port, process, and outbound-connection deltas are computed by
    set difference between the two snapshot datasets.

    Parameters
    ----------
    db_path : Path
        Filesystem path to the Orin SQLite vault.
    base_id : int
        Primary-key ID of the earlier (base) snapshot.
    target_id : int
        Primary-key ID of the later (target) snapshot.

    Returns
    -------
    dict
        A summary dict with keys:
        - ``base_id``          (int)        – echoed back from the input.
        - ``target_id``        (int)        – echoed back from the input.
        - ``new_ports``        (list[dict]) – ports present in target but not base.
        - ``new_processes``    (list[dict]) – processes present in target but not base.
        - ``new_connections``  (list[dict]) – outbound connections in target but not base.
        - ``triggered_alerts`` (list[dict]) – security events between the two timestamps.
    """
    storage = OrinStorage(db_path)
    delta_report = {
        "base_id": base_id,
        "target_id": target_id,
        "new_ports": [],
        "new_processes": [],
        "new_connections": [],
        "triggered_alerts": []
    }

    with storage.get_connection() as conn:
        cursor = conn.cursor()

        # 0. Extract Snapshot timestamps to isolate intermediate events
        cursor.execute("SELECT timestamp FROM system_snapshots WHERE id = ?;", (base_id,))
        base_row = cursor.fetchone()
        cursor.execute("SELECT timestamp FROM system_snapshots WHERE id = ?;", (target_id,))
        target_row = cursor.fetchone()

        if base_row and target_row:
            cursor.execute(
                """
                SELECT timestamp, event_type, severity, description FROM security_events
                WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC;
                """,
                (base_row["timestamp"], target_row["timestamp"])
            )
            for r in cursor.fetchall():
                delta_report["triggered_alerts"].append({
                    "timestamp": r["timestamp"], "type": r["event_type"],
                    "severity": r["severity"], "description": r["description"]
                })

        # 1. Evaluate Port Deltas
        cursor.execute("SELECT port, protocol FROM collected_ports WHERE snapshot_id = ?;", (base_id,))
        base_ports = {(r["port"], r["protocol"]) for r in cursor.fetchall()}
        cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (target_id,))
        target_ports = {(r["port"], r["protocol"]): r for r in cursor.fetchall()}

        for port_key in (target_ports.keys() - base_ports):
            row = target_ports[port_key]
            delta_report["new_ports"].append({"port": row["port"], "protocol": row["protocol"], "process": row["process_name"]})

        # 2. Evaluate Process Deltas
        cursor.execute("SELECT name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (base_id,))
        base_procs = {(r["name"], r["exe"], r["cmdline"]) for r in cursor.fetchall()}
        cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (target_id,))
        for r in cursor.fetchall():
            if (r["name"], r["exe"], r["cmdline"]) not in base_procs:
                delta_report["new_processes"].append({
                    "pid": r["pid"], "ppid": r["ppid"], "name": r["name"], "exe": r["exe"], "cmdline": r["cmdline"]
                })

        # 3. Evaluate Outbound Connection Deltas
        cursor.execute("SELECT remote_ip, remote_port FROM collected_outbound_connections WHERE snapshot_id = ?;", (base_id,))
        base_conns = {(r["remote_ip"], r["remote_port"]) for r in cursor.fetchall()}
        cursor.execute("SELECT remote_ip, remote_port, local_port, state FROM collected_outbound_connections WHERE snapshot_id = ?;", (target_id,))
        for r in cursor.fetchall():
            if (r["remote_ip"], r["remote_port"]) not in base_conns:
                delta_report["new_connections"].append({
                    "remote_ip": r["remote_ip"], "remote_port": r["remote_port"], "local_port": r["local_port"], "state": r["state"]
                })

    return delta_report