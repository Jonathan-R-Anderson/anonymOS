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
# orin/collectors/logs.py
"""
orin.collectors.logs – Authentication Log Parser
================================================
Parses ``/var/log/auth.log`` to extract two categories of forensic indicators:

1. **SSH brute-force attempts** – consecutive failed password events from the
   same source IP, counted inline for memory safety.
2. **Privilege-escalation events** – new account creation (``useradd``) and
   additions to administrative groups (``usermod`` + ``sudo``/``root``).

The module operates entirely offline; no network calls are made.
"""
import re
import sys
from pathlib import Path

#: Absolute path to the system authentication log processed by this module.
AUTH_LOG_PATH = Path("/var/log/auth.log")

#: Compiled regex to extract the source IP from a failed SSH password line.
SSH_FAIL_RE = re.compile(r"Failed password for .* from (?P<ip>\S+) port")
#: Compiled regex to extract the new username from a ``useradd`` event.
USER_ADD_RE = re.compile(r"useradd.*new user: name=(?P<user>\S+)")

#: Compiled regex to detect privilege escalation via ``usermod`` adding
#: a user to the ``sudo`` or ``root`` group.  Single-quote characters are
#: matched literally (not escaped) to match real auth.log output such as::
#:
#:     usermod[1234]: add 'alice' to group 'sudo'
GROUP_ADD_RE = re.compile(
    r"usermod.*add '(?P<user>\S+)' to group '(?P<group>sudo|root)'"
)


def parse_authentication_logs() -> dict:
    """Parse ``/var/log/auth.log`` for brute-force indicators and privilege changes.

    Makes a single sequential read pass over :data:`AUTH_LOG_PATH`, applying
    three compiled regular expressions to each line:

    * :data:`SSH_FAIL_RE`   – counts failed SSH password attempts per source IP.
    * :data:`USER_ADD_RE`   – records new system account creation events.
    * :data:`GROUP_ADD_RE`  – records assignments to privileged groups.

    Returns
    -------
    dict
        A dictionary with two keys:

        ``"failed_ssh_counts"`` : dict[str, int]
            Maps source IP address strings to the number of failed password
            attempts observed in the log.

        ``"privileged_additions"`` : list[dict]
            Each entry contains:
            - ``type``    (str) – ``"new_user"``, ``"privileged_group_escalation"``,
              or ``"auth_log_access_failure"``.
            - ``details`` (str) – human-readable description of the event.
    """
    results: dict = {
        "failed_ssh_counts": {},
        "privileged_additions": [],
    }

    if not AUTH_LOG_PATH.exists():
        return results

    try:
        # Real-world defense: Use errors="replace" instead of "ignore" to ensure an attacker
        # cannot inject non-UTF8 byte garbage to disrupt the text parsing alignment.
        with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ssh_match = SSH_FAIL_RE.search(line)
                if ssh_match:
                    ip_addr = ssh_match.group("ip")
                    # Production tuning: Accumulate directly into a dictionary counter.
                    # Appending to an unbounded raw list causes massive memory allocations
                    # on production systems under prolonged high-intensity brute force attacks.
                    results["failed_ssh_counts"][ip_addr] = results["failed_ssh_counts"].get(ip_addr, 0) + 1
                    continue

                user_match = USER_ADD_RE.search(line)
                if user_match:
                    results["privileged_additions"].append({
                        "type": "new_user",
                        "details": (
                            f"New local system account created: user={user_match.group('user')}"
                        ),
                    })
                    continue

                group_match = GROUP_ADD_RE.search(line)
                if group_match:
                    results["privileged_additions"].append({
                        "type": "privileged_group_escalation",
                        "details": (
                            f"Account assigned to administrative group: "
                            f"user={group_match.group('user')} "
                            f"group={group_match.group('group')}"
                        ),
                    })
                    continue

    except (PermissionError, OSError) as access_fault:
        # Real-world defense: Do not allow permission denials to drop silently on stdout.
        # Bubble an active telemetry alert row so engine.py exposes the visibility blockage.
        print(
            f"[!] Access Failure: Cannot read system security logs: {access_fault}",
            file=sys.stderr,
        )
        results["privileged_additions"].append({
            "type": "auth_log_access_failure",
            "details": f"CRITICAL: Engine lacked sufficient security context to parse auth logs: {access_fault.strerror}"
        })

    return results


def gather_auth_logs() -> list[str]:
    """Collect the last 1000 lines of authentication logs locally."""
    log_lines = []
    
    # 1. Try /var/log/auth.log
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        try:
            with open(auth_log, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                return [line.rstrip("\n") for line in lines[-1000:]]
        except (PermissionError, OSError) as e:
            log_lines.append(f"ERROR: Permission denied or read error on /var/log/auth.log: {e}")

    # 2. Try /var/log/secure
    secure_log = Path("/var/log/secure")
    if secure_log.exists():
        try:
            with open(secure_log, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                return [line.rstrip("\n") for line in lines[-1000:]]
        except (PermissionError, OSError) as e:
            log_lines.append(f"ERROR: Permission denied or read error on /var/log/secure: {e}")

    # 3. Fallback to journalctl
    import subprocess
    try:
        result = subprocess.run(
            ["journalctl", "-n", "1000", "--no-pager"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            return lines
        else:
            log_lines.append(f"ERROR: journalctl returned non-zero code {result.returncode}: {result.stderr.strip()}")
    except Exception as e:
        log_lines.append(f"ERROR: Failed to run journalctl: {e}")

    return log_lines
    