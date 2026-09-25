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
# src/orin/analysis/reporter.py
"""
orin.analysis.reporter – Audit Report Compilers
================================================
Generates human-readable forensic briefing documents from the data stored
in the Orin SQLite vault.

Two output formats are supported:

* **Markdown** (:func:`compile_markdown_report`) – lightweight, portable, and
  suitable for version-controlled incident response playbooks.
* **HTML** (:func:`compile_html_report`) – a fully self-contained, responsive
  dark-mode dashboard with tabbed navigation and severity badges.  No external
  CSS or JavaScript CDN dependencies; everything is inlined.
"""
import html
from pathlib import Path
from datetime import datetime
from orin.core.database import OrinStorage

def _escape_markdown(text: str) -> str:
    """Sanitize raw data fields to protect Markdown table column structures."""
    if text is None:
        return "N/A"
    # Escapes the vertical pipe character to prevent row fracturing
    return str(text).replace("|", "\\|")


def compile_markdown_report(db_path: Path, output_path: Path) -> None:
    """Query the vault and write a Markdown security briefing to ``output_path``.

    Fetches the most recent snapshot metadata and all unresolved security
    events (ordered by severity), then formats them as a Markdown table and
    writes the result to a file.

    Parameters
    ----------
    db_path : Path
        Filesystem path to the Orin SQLite vault.
    output_path : Path
        Destination file for the Markdown report.  Parent directories must
        already exist.

    Raises
    ------
    ValueError
        If no snapshots exist in the vault (``orin collect`` has not been run).
    """
    storage = OrinStorage(db_path)

    with storage.get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snapshot = cursor.fetchone()
        if not snapshot:
            raise ValueError("No system data snapshots exist. Run 'orin collect' first.")

        cursor.execute("PRAGMA table_info(security_events);")
        columns = {row["name"] for row in cursor.fetchall()}
        has_attck = "attck_technique" in columns
        attck_select = ", attck_technique, attck_tactic, attck_url" if has_attck else ""

        cursor.execute(f"""
            SELECT id, timestamp, event_type, severity, description{attck_select}
            FROM security_events
            WHERE resolved = 0
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END, id DESC;
        """)
        events = cursor.fetchall()

        cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ? ORDER BY file_path ASC;", (snapshot['id'],))
        suid_binaries = cursor.fetchall()

    generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md_content = f"""# ORIN INVESTIGATION FORENSIC SUMMARY REPORT
Generated on: `{generation_time}` | Core Engine: Fully Offline MVP

## 🖥️ Target Machine Context
- **Analysis Snapshot ID:** {snapshot['id']}
- **Collection Timestamp:** {snapshot['timestamp']}
- **Target Hostname:** {_escape_markdown(snapshot['hostname'])}
- **OS Platform:** {_escape_markdown(snapshot['os_platform'])}

## 🚨 Security Anomaly Events Detected ({len(events)})
"""

    if not events:
        md_content += "\n🟢 **No anomalous security indicators or policy drift patterns identified on this host.**\n"
    else:
        md_content += "\n| ID | Timestamp | Severity | Event Type | MITRE ATT&CK | Incident Description |\n"
        md_content += "|---|---|---|---|---|---|\n"
        for ev in events:
            severity_icon = "🔴" if ev['severity'] in ('critical', 'high') else "🟡"
            attck_cell = "N/A"
            if has_attck and ev['attck_technique']:
                tech_id = ev['attck_technique']
                tactic = ev['attck_tactic'] or ""
                url = ev['attck_url'] or f"https://attack.mitre.org/techniques/{tech_id}/"
                attck_cell = f"[{tech_id}]({url}) ({tactic})"
            md_content += f"| {ev['id']} | {ev['timestamp']} | {severity_icon} {ev['severity'].upper()} | {_escape_markdown(ev['event_type'])} | {attck_cell} | {_escape_markdown(ev['description'])} |\n"

    md_content += "\n## 🔒 SUID/SGID Binaries Captured\n"
    if not suid_binaries:
        md_content += "\n🟢 No SUID/SGID binaries identified in this snapshot.\n"
    else:
        md_content += "\n| File Path | Owner | Group | Permissions | SHA-256 |\n"
        md_content += "|---|---|---|---|---|\n"
        for s in suid_binaries:
            md_content += f"| `{_escape_markdown(s['file_path'])}` | `{_escape_markdown(s['owner'])}` | `{_escape_markdown(s['grp'])}` | `{_escape_markdown(s['permissions'])}` | `{_escape_markdown(s['sha256'])}` |\n"

    md_content += """
---
*End of Verification Report — Secure Local Relational Vault File Ledger Integrity Intact.*
"""
    output_path.write_text(md_content.strip() + "\n", encoding="utf-8")


def compile_html_report(db_path: Path, output_path: Path) -> None:
    """Generate a responsive, self-contained HTML dashboard report.

    Queries the vault for the latest snapshot metadata, unresolved security
    events, listening ports, outbound connections, running processes, user
    accounts, and file integrity hashes.  All data is embedded directly into
    the HTML file; no network requests are made at display time.
    """
    storage = OrinStorage(db_path)

    with storage.get_connection() as conn:
        cursor = conn.cursor()

        # 1. Fetch latest snapshot
        cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snapshot = cursor.fetchone()
        if not snapshot:
            raise ValueError("No system data snapshots exist. Run 'orin collect' first.")

        snapshot_id = snapshot['id']

        cursor.execute("PRAGMA table_info(security_events);")
        columns = {row["name"] for row in cursor.fetchall()}
        has_attck = "attck_technique" in columns
        attck_select = ", attck_technique, attck_tactic, attck_url" if has_attck else ""

        # 2. Fetch security alerts
        cursor.execute(f"""
            SELECT id, timestamp, event_type, severity, description{attck_select}
            FROM security_events
            WHERE resolved = 0
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END, id DESC;
        """)
        events = cursor.fetchall()

        # 3. Fetch ports
        cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ? ORDER BY port ASC;", (snapshot_id,))
        ports = cursor.fetchall()

        # 4. Fetch processes
        cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ? ORDER BY pid ASC;", (snapshot_id,))
        processes = cursor.fetchall()

        # 5. Fetch users
        cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ? ORDER BY uid ASC;", (snapshot_id,))
        users = cursor.fetchall()

        # 6. Fetch file integrity hashes
        cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ? ORDER BY file_path ASC;", (snapshot_id,))
        file_hashes = cursor.fetchall()

        # 7. Fetch outbound connections
        cursor.execute("SELECT local_ip, local_port, remote_ip, remote_port, state, process_name FROM collected_outbound_connections WHERE snapshot_id = ? ORDER BY local_port ASC;", (snapshot_id,))
        outbound = cursor.fetchall()

        # 8. Fetch deleted binaries
        cursor.execute("SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ? ORDER BY pid ASC;", (snapshot_id,))
        deleted_binaries = cursor.fetchall()

        # 9. Fetch promiscuous interfaces
        cursor.execute("SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ? ORDER BY interface ASC;", (snapshot_id,))
        promisc_interfaces = cursor.fetchall()

        # 10. Fetch wtmp sessions
        cursor.execute("SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ? ORDER BY login_time DESC;", (snapshot_id,))
        wtmp_sessions = cursor.fetchall()

        # 11. Fetch lastlog records
        cursor.execute("SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ? ORDER BY uid ASC;", (snapshot_id,))
        lastlog_records = cursor.fetchall()

        # 12. Fetch package integrity mismatches
        cursor.execute("SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ? ORDER BY package ASC;", (snapshot_id,))
        pkg_integrity = cursor.fetchall()

        # 13. Fetch crontabs
        cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ? ORDER BY source ASC, user ASC;", (snapshot_id,))
        crontabs = cursor.fetchall()

        # 14. Fetch SUID/SGID binaries
        cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ? ORDER BY file_path ASC;", (snapshot_id,))
        suid_binaries = cursor.fetchall()

    generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = snapshot['hostname']
    os_platform = snapshot['os_platform']

    events_count = len(events)
    sockets_count = len(ports) + len(outbound)
    processes_count = len(processes)
    users_count = len(users)
    hashes_count = len(file_hashes)

    if events_count > 0:
        status_text = "ANOMALOUS"
        status_class = "status-anomalous"
    else:
        status_text = "CLEAN"
        status_class = "status-clean"

    # Events Content
    if not events:
        events_content = """
        <div class="empty-state">
            <div class="empty-icon">🟢</div>
            <h3>No anomalous security indicators identified</h3>
            <p>Your system configuration baseline integrity is intact.</p>
        </div>
        """
    else:
        events_content = """
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Event Type</th>
                        <th>MITRE ATT&CK</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
        """
        for ev in events:
            sev = ev['severity'].lower()
            badge_class = f"badge-{sev}"
            attck_html = '<span class="text-muted">N/A</span>'
            if has_attck and ev['attck_technique']:
                tech_id = html.escape(ev['attck_technique'])
                tactic = html.escape(ev['attck_tactic'] or '')
                url = html.escape(ev['attck_url'] or '')
                attck_html = f'<a href="{url}" target="_blank" class="badge badge-info" title="{tactic}" style="text-decoration:none;">{tech_id}</a>'

            events_content += f"""
                    <tr>
                        <td><code>{ev['id']}</code></td>
                        <td>{html.escape(ev['timestamp'])}</td>
                        <td><span class="badge {badge_class}">{html.escape(ev['severity'].upper())}</span></td>
                        <td><strong>{html.escape(ev['event_type'])}</strong></td>
                        <td>{attck_html}</td>
                        <td>{html.escape(ev['description'])}</td>
                    </tr>
            """
        events_content += """
                </tbody>
            </table>
        </div>
        """

    # Sockets Content
    sockets_content = f"""
    <div class="grid grid-2">
        <div class="card">
            <h3 class="section-title">📥 Listening Sockets ({len(ports)})</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Process</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    if not ports:
        sockets_content += """<tr><td colspan="3" class="text-muted text-center">No listening sockets recorded</td></tr>"""
    else:
        for p in ports:
            proto_badge = "badge-tcp" if p['protocol'].upper() == "TCP" else "badge-udp"
            sockets_content += f"""
                        <tr>
                            <td><code>{p['port']}</code></td>
                            <td><span class="badge {proto_badge}">{html.escape(p['protocol'].upper())}</span></td>
                            <td>{html.escape(p['process_name'] or 'Unknown')}</td>
                        </tr>
            """
    sockets_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h3 class="section-title">📤 Outbound Connections ({len(outbound)})</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Local Endpoint</th>
                            <th>Remote Endpoint</th>
                            <th>State</th>
                            <th>Process</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    if not outbound:
        sockets_content += """<tr><td colspan="4" class="text-muted text-center">No active outbound connections recorded</td></tr>"""
    else:
        for o in outbound:
            sockets_content += f"""
                        <tr>
                            <td><code>{html.escape(o['local_ip'])}:{o['local_port']}</code></td>
                            <td><code>{html.escape(o['remote_ip'])}:{o['remote_port']}</code></td>
                            <td><span class="badge badge-info">{html.escape(o['state'] or 'ESTABLISHED')}</span></td>
                            <td>{html.escape(o['process_name'] or 'Unknown')}</td>
                        </tr>
            """
    sockets_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """

    # Processes Content
    processes_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>PPID</th>
                    <th>Name</th>
                    <th>Executable Path</th>
                    <th>Command Line</th>
                </tr>
            </thead>
            <tbody>
    """
    for pr in processes:
        cmdline_esc = html.escape(pr['cmdline'] or '')
        processes_content += f"""
                <tr>
                    <td><code>{pr['pid']}</code></td>
                    <td><code>{pr['ppid']}</code></td>
                    <td><strong>{html.escape(pr['name'])}</strong></td>
                    <td class="text-truncate" title="{html.escape(pr['exe'] or '')}"><code>{html.escape(pr['exe'] or 'N/A')}</code></td>
                    <td class="text-wrap" title="{cmdline_esc}"><code>{cmdline_esc or 'N/A'}</code></td>
                </tr>
        """
    processes_content += """
            </tbody>
        </table>
    </div>
    """

    # Users Content
    users_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>UID</th>
                    <th>GID</th>
                    <th>Home Directory</th>
                    <th>Login Shell</th>
                </tr>
            </thead>
            <tbody>
    """
    for u in users:
        users_content += f"""
                <tr>
                    <td><strong>{html.escape(u['username'])}</strong></td>
                    <td><code>{u['uid']}</code></td>
                    <td><code>{u['gid']}</code></td>
                    <td><code>{html.escape(u['home_dir'] or 'N/A')}</code></td>
                    <td><code>{html.escape(u['login_shell'] or 'N/A')}</code></td>
                </tr>
        """
    users_content += """
            </tbody>
        </table>
    </div>
    """

    # FIM Content
    fim_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>File Path</th>
                    <th>SHA-256 Signature Hash</th>
                </tr>
            </thead>
            <tbody>
    """
    for f in file_hashes:
        fim_content += f"""
                <tr>
                    <td><strong class="text-break">{html.escape(f['file_path'])}</strong></td>
                    <td><code class="text-break hash-code">{html.escape(f['sha256_hash'])}</code></td>
                </tr>
        """
    fim_content += """
            </tbody>
        </table>
    </div>
    """

    # Deleted Binaries Content
    deleted_binaries_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Executable Link</th>
                    <th>SHA-256 Hash</th>
                    <th>MD5 Hash</th>
                    <th>Vault Path</th>
                </tr>
            </thead>
            <tbody>
    """
    if not deleted_binaries:
        deleted_binaries_content += """<tr><td colspan="5" class="text-muted text-center">No running deleted binaries detected</td></tr>"""
    else:
        for db in deleted_binaries:
            deleted_binaries_content += f"""
                <tr>
                    <td><code>{db['pid']}</code></td>
                    <td><strong>{html.escape(db['exe'])}</strong></td>
                    <td><code class="hash-code">{html.escape(db['sha256'])}</code></td>
                    <td><code class="hash-code">{html.escape(db['md5'])}</code></td>
                    <td><code class="text-break">{html.escape(db['vault_path'])}</code></td>
                </tr>
            """
    deleted_binaries_content += """
            </tbody>
        </table>
    </div>
    """

    # Promisc Content
    promisc_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Interface</th>
                    <th>Flags</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
    """
    if not promisc_interfaces:
        promisc_content += """<tr><td colspan="3" class="text-muted text-center">No network interfaces audited</td></tr>"""
    else:
        for pi in promisc_interfaces:
            status_badge = '<span class="badge badge-critical">PROMISCUOUS</span>' if pi['is_promiscuous'] == 1 else '<span class="badge badge-info">NORMAL</span>'
            promisc_content += f"""
                <tr>
                    <td><strong>{html.escape(pi['interface'])}</strong></td>
                    <td><code>{html.escape(pi['flags'])}</code></td>
                    <td>{status_badge}</td>
                </tr>
            """
    promisc_content += """
            </tbody>
        </table>
    </div>
    """

    # Session Audit Content
    session_audit_content = f"""
    <div class="grid grid-2">
        <div class="card">
            <h3 class="section-title">🪵 WTMP Session Lifecycles ({len(wtmp_sessions)})</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Line</th>
                            <th>Host</th>
                            <th>PID</th>
                            <th>Login</th>
                            <th>Logout</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    if not wtmp_sessions:
        session_audit_content += """<tr><td colspan="7" class="text-muted text-center">No WTMP sessions recorded</td></tr>"""
    else:
        for ws in wtmp_sessions:
            status = f'<span class="badge badge-critical" title="{html.escape(ws["anomaly_reason"] or "")}">TAMPERED</span>' if ws['anomaly_detected'] == 1 else '<span class="badge badge-info">OK</span>'
            session_audit_content += f"""
                        <tr>
                            <td><strong>{html.escape(ws['user'])}</strong></td>
                            <td><code>{html.escape(ws['line'])}</code></td>
                            <td><code>{html.escape(ws['host'])}</code></td>
                            <td><code>{ws['pid']}</code></td>
                            <td>{html.escape(ws['login_time'] or 'N/A')}</td>
                            <td>{html.escape(ws['logout_time'] or 'N/A')}</td>
                            <td>{status}</td>
                        </tr>
            """
    session_audit_content += f"""
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h3 class="section-title">👤 Lastlog User Audit ({len(lastlog_records)})</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>UID</th>
                            <th>Line</th>
                            <th>Host</th>
                            <th>Last Login</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    if not lastlog_records:
        session_audit_content += """<tr><td colspan="6" class="text-muted text-center">No lastlog records recorded</td></tr>"""
    else:
        for lr in lastlog_records:
            status = f'<span class="badge badge-critical" title="{html.escape(lr["anomaly_reason"] or "")}">TAMPERED</span>' if lr['anomaly_detected'] == 1 else '<span class="badge badge-info">OK</span>'
            session_audit_content += f"""
                        <tr>
                            <td><strong>{html.escape(lr['username'])}</strong></td>
                            <td><code>{lr['uid']}</code></td>
                            <td><code>{html.escape(lr['line'])}</code></td>
                            <td><code>{html.escape(lr['host'])}</code></td>
                            <td>{html.escape(lr['login_time'] or 'N/A')}</td>
                            <td>{status}</td>
                        </tr>
            """
    session_audit_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """

    # Package Integrity Content
    pkg_integrity_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Binary File Path</th>
                    <th>Expected MD5</th>
                    <th>Actual MD5</th>
                    <th>Actual SHA-256</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
    """
    if not pkg_integrity:
        pkg_integrity_content += """<tr><td colspan="6" class="text-muted text-center">🟢 No package integrity violations detected</td></tr>"""
    else:
        for pi in pkg_integrity:
            status_badge = f'<span class="badge badge-critical">{html.escape(pi["status"].upper())}</span>'
            pkg_integrity_content += f"""
                <tr>
                    <td><strong>{html.escape(pi['package'])}</strong></td>
                    <td><code>{html.escape(pi['file_path'])}</code></td>
                    <td><code class="hash-code">{html.escape(pi['expected_md5'])}</code></td>
                    <td><code class="hash-code">{html.escape(pi['actual_md5'] or 'N/A')}</code></td>
                    <td><code class="hash-code">{html.escape(pi['actual_sha256'] or 'N/A')}</code></td>
                    <td>{status_badge}</td>
                </tr>
            """
    pkg_integrity_content += """
            </tbody>
        </table>
    </div>
    """

    # Package Crontabs Content
    crontabs_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>User</th>
                    <th>Schedule</th>
                    <th>Command</th>
                </tr>
            </thead>
            <tbody>
    """
    if not crontabs:
        crontabs_content += """<tr><td colspan="4" class="text-muted text-center">🟢 No crontab entries detected</td></tr>"""
    else:
        for cron in crontabs:
            crontabs_content += f"""
                <tr>
                    <td><strong>{html.escape(cron['source'])}</strong></td>
                    <td><code>{html.escape(cron['user'])}</code></td>
                    <td><code>{html.escape(cron['schedule'])}</code></td>
                    <td><code class="text-break">{html.escape(cron['command'])}</code></td>
                </tr>
            """
    crontabs_content += """
            </tbody>
        </table>
    </div>
    """

    # Package SUID/SGID Binaries Content
    suid_content = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>File Path</th>
                    <th>Owner</th>
                    <th>Group</th>
                    <th>Permissions</th>
                    <th>SHA-256 Hash</th>
                </tr>
            </thead>
            <tbody>
    """
    if not suid_binaries:
        suid_content += """<tr><td colspan="5" class="text-muted text-center">🟢 No SUID/SGID binaries detected</td></tr>"""
    else:
        for s in suid_binaries:
            suid_content += f"""
                <tr>
                    <td><code>{html.escape(s['file_path'])}</code></td>
                    <td><code>{html.escape(s['owner'])}</code></td>
                    <td><code>{html.escape(s['grp'])}</code></td>
                    <td><code>{html.escape(s['permissions'])}</code></td>
                    <td><code class="hash-code">{html.escape(s['sha256'])}</code></td>
                </tr>
            """
    suid_content += """
            </tbody>
        </table>
    </div>
    """

    # Complete Self-Contained HTML Template Layout
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orin Forensic Investigation Report - {html.escape(hostname)}</title>
    <style>
        :root {{
            --bg-primary: #0F172A;
            --bg-secondary: #1E293B;
            --bg-card: #1E293B;
            --border-color: #334155;
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --primary: #6366F1;
            --primary-hover: #4F46E5;

            --critical: #EF4444;
            --high: #F97316;
            --medium: #F59E0B;
            --low: #3B82F6;
            --info: #10B981;

            --tcp: #8B5CF6;
            --udp: #EC4899;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 2rem;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }}

        .logo-title {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .logo {{
            font-size: 2.5rem;
        }}

        h1 {{
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.025em;
            background: linear-gradient(135deg, #A5B4FC, #6366F1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .meta-tag {{
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}

        .grid {{
            display: grid;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .grid-4 {{
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        }}

        .grid-2 {{
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
        }}

        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s, border-color 0.2s;
        }}

        .card:hover {{
            border-color: #475569;
        }}

        .metric-card {{
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            height: 100px;
        }}

        .metric-title {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }}

        .metric-value {{
            font-size: 1.75rem;
            font-weight: 700;
            margin-top: 0.5rem;
        }}

        .status-clean {{
            color: var(--info);
        }}

        .status-anomalous {{
            color: var(--critical);
        }}

        .tab-nav {{
            display: flex;
            gap: 0.5rem;
            background-color: var(--bg-secondary);
            padding: 0.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-color);
            overflow-x: auto;
        }}

        .tab-btn {{
            background: none;
            border: none;
            color: var(--text-secondary);
            padding: 0.75rem 1.25rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            font-size: 0.95rem;
            transition: background-color 0.2s, color 0.2s;
            white-space: nowrap;
        }}

        .tab-btn:hover {{
            color: var(--text-primary);
            background-color: rgba(255, 255, 255, 0.05);
        }}

        .tab-btn.active {{
            background-color: var(--primary);
            color: var(--text-primary);
        }}

        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
        }}

        .section-title {{
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .table-container {{
            width: 100%;
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background-color: rgba(30, 41, 59, 0.5);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}

        th, td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background-color: rgba(15, 23, 42, 0.6);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        tr:hover td {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background-color: rgba(0, 0, 0, 0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85em;
            color: #E2E8F0;
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-critical {{ background-color: rgba(239, 68, 68, 0.15); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-high {{ background-color: rgba(249, 115, 22, 0.15); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge-medium {{ background-color: rgba(245, 158, 11, 0.15); color: var(--medium); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-low {{ background-color: rgba(59, 130, 246, 0.15); color: var(--low); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-info {{ background-color: rgba(16, 185, 129, 0.15); color: var(--info); border: 1px solid rgba(16, 185, 129, 0.3); }}

        .badge-tcp {{ background-color: rgba(139, 92, 246, 0.15); color: var(--tcp); border: 1px solid rgba(139, 92, 246, 0.3); }}
        .badge-udp {{ background-color: rgba(236, 72, 153, 0.15); color: var(--udp); border: 1px solid rgba(236, 72, 153, 0.3); }}

        .empty-state {{
            text-align: center;
            padding: 3rem 2rem;
            border: 1px dashed var(--border-color);
            border-radius: 8px;
            color: var(--text-secondary);
        }}

        .empty-icon {{ font-size: 3rem; margin-bottom: 1rem; }}
        .empty-state h3 {{ color: var(--text-primary); margin-bottom: 0.5rem; }}

        .text-muted {{ color: var(--text-secondary); }}
        .text-center {{ text-align: center; }}
        .text-truncate {{ max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .text-wrap {{ max-width: 400px; white-space: normal; word-break: break-all; }}
        .text-break {{ word-break: break-all; }}
        .hash-code {{ font-size: 0.75rem; color: #94A3B8; }}

        footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }}

        @media (max-width: 768px) {{
            body {{ padding: 1rem; }}
            header {{ flex-direction: column; align-items: flex-start; gap: 1rem; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo-title">
            <span class="logo">🛡️</span>
            <div>
                <h1>Orin Forensic Investigation Report</h1>
                <div class="meta-tag">Generated: {generation_time} | Host: <code>{html.escape(hostname)}</code></div>
            </div>
        </div>
        <div class="meta-tag">
            OS Platform: <code>{html.escape(os_platform)}</code>
        </div>
    </header>

    <div class="grid grid-4">
        <div class="card metric-card">
            <span class="metric-title">Snapshot ID</span>
            <span class="metric-value">#{snapshot_id}</span>
        </div>
        <div class="card metric-card">
            <span class="metric-title">Risk Status</span>
            <span class="metric-value {status_class}">{status_text}</span>
        </div>
        <div class="card metric-card">
            <span class="metric-title">Anomalies Detected</span>
            <span class="metric-value">{events_count}</span>
        </div>
        <div class="card metric-card">
            <span class="metric-title">Monitored Hashes</span>
            <span class="metric-value">{hashes_count}</span>
        </div>
    </div>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="switchTab('alerts')">🚨 Security Alerts ({events_count})</button>
        <button class="tab-btn" onclick="switchTab('sockets')">🌐 Network Sockets ({sockets_count})</button>
        <button class="tab-btn" onclick="switchTab('processes')">⚙️ Processes ({processes_count})</button>
        <button class="tab-btn" onclick="switchTab('users')">👤 User Accounts ({users_count})</button>
        <button class="tab-btn" onclick="switchTab('fim')">📂 File Integrity ({hashes_count})</button>
        <button class="tab-btn" onclick="switchTab('deleted_binaries')">🗑️ Deleted Binaries ({len(deleted_binaries)})</button>
        <button class="tab-btn" onclick="switchTab('promisc')">📡 Promisc Interfaces ({len(promisc_interfaces)})</button>
        <button class="tab-btn" onclick="switchTab('session_audit')">🪵 Session Audit ({len(wtmp_sessions) + len(lastlog_records)})</button>
        <button class="tab-btn" onclick="switchTab('pkg_integrity')">📦 Pkg Integrity ({len(pkg_integrity)})</button>
        <button class="tab-btn" onclick="switchTab('crontabs')">⏰ Crontabs ({len(crontabs)})</button>
        <button class="tab-btn" onclick="switchTab('suid')">🔒 SUID/SGID ({len(suid_binaries)})</button>
    </div>

    <div id="alerts" class="tab-content active">
        {events_content}
    </div>

    <div id="sockets" class="tab-content">
        {sockets_content}
    </div>

    <div id="processes" class="tab-content">
        {processes_content}
    </div>

    <div id="users" class="tab-content">
        {users_content}
    </div>

    <div id="fim" class="tab-content">
        {fim_content}
    </div>

    <div id="deleted_binaries" class="tab-content">
        {deleted_binaries_content}
    </div>

    <div id="promisc" class="tab-content">
        {promisc_content}
    </div>

    <div id="session_audit" class="tab-content">
        {session_audit_content}
    </div>

    <div id="pkg_integrity" class="tab-content">
        {pkg_integrity_content}
    </div>

    <div id="crontabs" class="tab-content">
        {crontabs_content}
    </div>

    <div id="suid" class="tab-content">
        {suid_content}
    </div>

    <footer>
        Orin Offline Forensics & Integrity Engine | Secure Local Relational Vault Ledger Intact
    </footer>

    <script>
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
            if (btn) btn.classList.add('active');
        }}
    </script>
</body>
</html>
"""
    output_path.write_text(html_content.strip() + "\n", encoding="utf-8")