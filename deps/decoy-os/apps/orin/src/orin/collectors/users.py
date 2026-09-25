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
# orin/collectors/users.py
"""
orin.collectors.users – System Account Harvester
================================================
Parses ``/etc/passwd`` directly to enumerate all local user accounts without
relying on external utilities such as ``getent`` or ``id``.

The harvested data feeds both the ``baseline_users`` table (at ``orin init``)
and the ``collected_users`` table (at every ``orin collect`` run), enabling
the analysis engine to detect newly created or privilege-escalated accounts.
"""
from pathlib import Path

#: Filesystem path to the POSIX account database file.
PASSWD_PATH = Path("/etc/passwd")


def gather_system_accounts() -> list[dict]:
    """Parse ``/etc/passwd`` and return structured account records for each entry.

    Lines beginning with ``#`` and blank lines are ignored. Each colon-
    delimited record must have at least seven fields to be included.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``username``    (str) – login name (field 0).
        - ``uid``         (int) – numeric user ID (field 2).
        - ``gid``         (int) – numeric primary group ID (field 3).
        - ``home_dir``    (str) – home directory path (field 5).
        - ``login_shell`` (str) – login shell path (field 6).

    Notes
    -----
    The password field (field 1) is deliberately excluded; it is always ``"x"``
    on modern systems and the actual hash lives in ``/etc/shadow``.
    """
    accounts = []
    if not PASSWD_PATH.exists():
        return accounts

    try:
        # Real-world defense: Enforce explicit UTF-8 parsing with error replacements 
        # to ensure malicious non-ASCII username injections cannot cause decoder failures.
        with open(PASSWD_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split(":")
                if len(parts) < 7:
                    accounts.append({
                        "username": f"ERROR_MALFORMED_ROW_{line_num}",
                        "uid": -1,
                        "gid": -1,
                        "home_dir": "unknown",
                        "login_shell": "unknown",
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Malformed passwd entry layout (expected >= 7 fields, got {len(parts)})"
                    })
                    continue
                
                # Real-world defense: Isolate row parameter casting to prevent validation 
                # injection faults from completely breaking the systemic log collection loop.
                try:
                    accounts.append({
                        "username": parts[0],
                        "uid": int(parts[2]),
                        "gid": int(parts[3]),
                        "home_dir": parts[5],
                        "login_shell": parts[6]
                    })
                except ValueError as cast_error:
                    accounts.append({
                        "username": f"ERROR_INVALID_UID_{parts[0]}",
                        "uid": -1,
                        "gid": -1,
                        "home_dir": parts[5],
                        "login_shell": parts[6],
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Account field integer type validation fault on line {line_num}: {cast_error}"
                    })
                    continue
                    
    except (PermissionError, OSError) as io_error:
        # Surface access blocks and system visibility boundaries transparently
        accounts.append({
            "username": "ERROR_PASSWD_IO_FAULT",
            "uid": -1,
            "gid": -1,
            "home_dir": "unknown",
            "login_shell": "unknown",
            "anomaly_detected": 1,
            "anomaly_reason": f"Critical identity harvesting failure reading passwd node: {io_error.strerror}"
        })

    return accounts