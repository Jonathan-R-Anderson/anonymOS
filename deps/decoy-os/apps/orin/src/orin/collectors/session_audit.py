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
# src/orin/collectors/session_audit.py
"""
orin.collectors.session_audit – Binary Login and Session Auditor
===============================================================
Extracts session details from binary structures like `/var/log/lastlog` and
`/var/log/wtmp` using Python-native struct parsing. Flags anti-forensics
anomalies (like completely zeroed-out records or epoch timestamp resets).
"""
import struct
from pathlib import Path
from datetime import datetime, timezone
from orin.collectors.users import gather_system_accounts

def gather_wtmp_sessions(wtmp_path: Path = Path("/var/log/wtmp")) -> list[dict]:
    """Parse `/var/log/wtmp` to extract precise session lifecycles.

    Parameters
    ----------
    wtmp_path : Path, optional
        Filesystem path to the WTMP binary log. Defaults to /var/log/wtmp.

    Returns
    -------
    list[dict]
        List of session dictionaries:
        - user (str): login name.
        - line (str): tty line.
        - host (str): remote hostname or source IP.
        - pid (int): PID of the login process.
        - login_time (str/None): ISO 8601 UTC timestamp of login.
        - logout_time (str/None): ISO 8601 UTC timestamp of logout, or "active" / "reboot (...)".
        - anomaly_detected (int): 1 if anomalies (e.g. tampering, epoch resets) are found, 0 otherwise.
        - anomaly_reason (str): details of any detected anomaly.
    """
    sessions = []
    if not wtmp_path.exists():
        return sessions

    # Format: h (type), x2 (pad), i (pid), 32s (line), 4s (id), 32s (user), 256s (host)
    # exit_status: h (term), h (exit)
    # session: i
    # tv: i (sec), i (usec)
    # addr_v6: 4i
    # unused: 20s
    utmp_format = "<h2xi32s4s32s256shhiii4I20s"
    record_size = struct.calcsize(utmp_format)

    active_sessions = {}  # (line, pid) -> session_dict

    try:
        with open(wtmp_path, "rb") as f:
            while True:
                chunk = f.read(record_size)
                if not chunk:
                    break
                if len(chunk) < record_size:
                    sessions.append({
                        "user": "unknown",
                        "line": "unknown",
                        "host": "unknown",
                        "pid": 0,
                        "login_time": None,
                        "logout_time": None,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Corrupted wtmp record of size {len(chunk)} (expected {record_size})"
                    })
                    break

                # 1. Anti-forensics: check if record is completely zeroed-out
                if chunk == b'\x00' * record_size:
                    sessions.append({
                        "user": "unknown",
                        "line": "unknown",
                        "host": "unknown",
                        "pid": 0,
                        "login_time": None,
                        "logout_time": None,
                        "anomaly_detected": 1,
                        "anomaly_reason": "Zeroed-out wtmp record detected (potential log tampering)"
                    })
                    continue

                # 2. Unpack wtmp record fields safely
                try:
                    (
                        ut_type, ut_pid, ut_line, ut_id, ut_user, ut_host,
                        ut_exit_term, ut_exit_code, ut_session, tv_sec, tv_usec,
                        ut_addr_v6_1, ut_addr_v6_2, ut_addr_v6_3, ut_addr_v6_4,
                        __unused
                    ) = struct.unpack(utmp_format, chunk)
                except struct.error as e:
                    sessions.append({
                        "user": "unknown",
                        "line": "unknown",
                        "host": "unknown",
                        "pid": 0,
                        "login_time": None,
                        "logout_time": None,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Binary struct unpacking failure: {e} (malformed layout)"
                    })
                    continue

                # Clean and decode strings safely
                user = ut_user.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                line = ut_line.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                host = ut_host.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()

                anomaly_detected = 0
                anomaly_reason = ""

                # 3. Anti-forensics: zeroed timestamp on user/dead process
                if tv_sec == 0 and ut_type in (7, 8):  # USER_PROCESS or DEAD_PROCESS
                    anomaly_detected = 1
                    anomaly_reason = "Zeroed-out or epoch timestamp in active/dead record (potential log tampering)"

                def format_timestamp(ts):
                    if ts == 0 or ts is None:
                        return None
                    try:
                        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    except Exception:
                        return None

                time_str = format_timestamp(tv_sec)

                # Match session lifecycles
                if ut_type == 7:  # USER_PROCESS (Login)
                    session_key = (line, ut_pid)
                    active_sessions[session_key] = {
                        "user": user,
                        "line": line,
                        "host": host,
                        "pid": ut_pid,
                        "login_time": time_str,
                        "logout_time": None,
                        "anomaly_detected": anomaly_detected,
                        "anomaly_reason": anomaly_reason
                    }
                elif ut_type == 8:  # DEAD_PROCESS (Logout)
                    session_key = (line, ut_pid)
                    if session_key in active_sessions:
                        session = active_sessions.pop(session_key)
                        session["logout_time"] = time_str
                        if anomaly_detected:
                            session["anomaly_detected"] = 1
                            session["anomaly_reason"] = (session["anomaly_reason"] + "; " + anomaly_reason).strip("; ")
                        sessions.append(session)
                    else:
                        sessions.append({
                            "user": user if user else "unknown",
                            "line": line,
                            "host": host,
                            "pid": ut_pid,
                            "login_time": None,
                            "logout_time": time_str,
                            "anomaly_detected": anomaly_detected,
                            "anomaly_reason": anomaly_reason or "Orphaned logout record (no matching login record)"
                        })
                elif ut_type == 2:  # BOOT_TIME (System Reboot)
                    boot_time_str = time_str
                    # System reboot terminates all active sessions
                    for session_key, session in list(active_sessions.items()):
                        session["logout_time"] = f"reboot ({boot_time_str})"
                        sessions.append(session)
                    active_sessions.clear()

        # Any remaining sessions at end of file are still active
        for session in active_sessions.values():
            session["logout_time"] = "active"
            sessions.append(session)

    except OSError as e:
        sessions.append({
            "user": "error",
            "line": "error",
            "host": "error",
            "pid": 0,
            "login_time": None,
            "logout_time": None,
            "anomaly_detected": 1,
            "anomaly_reason": f"File I/O failure accessing wtmp: {e}"
        })

    return sessions


def gather_lastlog_records(lastlog_path: Path = Path("/var/log/lastlog")) -> list[dict]:
    """Parse `/var/log/lastlog` to check the last login state for each system user.

    Parameters
    ----------
    lastlog_path : Path, optional
        Filesystem path to the lastlog binary. Defaults to /var/log/lastlog.

    Returns
    -------
    list[dict]
        Each dict contains:
        - username (str): account login name.
        - uid (int): numeric User ID.
        - line (str): tty line used.
        - host (str): remote host or source IP.
        - login_time (str/None): ISO 8601 UTC timestamp of last login.
        - anomaly_detected (int): 1 if suspicious discrepancies are found, 0 otherwise.
        - anomaly_reason (str): details of any detected anomaly.
    """
    records = []
    if not lastlog_path.exists():
        return records

    accounts = gather_system_accounts()

    # Format: I (time), 32s (line), 256s (host) -> size = 292 bytes
    lastlog_format = "<I32s256s"
    record_size = struct.calcsize(lastlog_format)

    try:
        file_size = lastlog_path.stat().st_size
        with open(lastlog_path, "rb") as f:
            for acc in accounts:
                uid = acc["uid"]
                
                # Defend against malicious or erratic high UID arithmetic calculations
                if uid < 0 or uid > 2147483647:
                    continue
                    
                offset = uid * record_size

                # Sparse file boundary handling: if past EOF, no record is written
                if offset + record_size > file_size:
                    continue

                f.seek(offset)
                chunk = f.read(record_size)
                if not chunk or len(chunk) < record_size:
                    continue

                try:
                    ll_time, ll_line, ll_host = struct.unpack(lastlog_format, chunk)
                except struct.error as e:
                    records.append({
                        "username": acc["username"],
                        "uid": uid,
                        "line": "error",
                        "host": "error",
                        "login_time": None,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Malformed structural chunk entry for UID {uid}: {e}"
                    })
                    continue

                # Clean and decode strings safely
                line = ll_line.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                host = ll_host.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()

                if ll_time == 0:
                    # 1. Anti-forensics: time is 0 (Epoch 1970) but line/host metadata is populated
                    if line or host:
                        records.append({
                            "username": acc["username"],
                            "uid": uid,
                            "line": line,
                            "host": host,
                            "login_time": None,
                            "anomaly_detected": 1,
                            "anomaly_reason": "Zeroed timestamp with non-empty metadata in lastlog (potential log tampering)"
                        })
                    continue

                # Normal log entry parsing
                login_time_str = None
                try:
                    login_time_str = datetime.fromtimestamp(ll_time, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                except Exception:
                    pass

                records.append({
                    "username": acc["username"],
                    "uid": uid,
                    "line": line,
                    "host": host,
                    "login_time": login_time_str,
                    "anomaly_detected": 0,
                    "anomaly_reason": ""
                })

    except OSError as e:
        # Prevent blind suppression; escalate access failures cleanly
        records.append({
            "username": "root",
            "uid": 0,
            "line": "error",
            "host": "error",
            "login_time": None,
            "anomaly_detected": 1,
            "anomaly_reason": f"File system descriptor fault during lastlog read pass: {e}"
        })

    return records
    