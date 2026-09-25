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
# src/orin/collectors/crontabs.py
"""
orin.collectors.crontabs – System & User Crontab Persistence Harvester
=====================================================================
Audits and parses scheduled tasks from user crontabs, /etc/crontab,
/etc/cron.d/, and standard cron interval directories.
"""
import re
from pathlib import Path

def parse_cron_line(line: str, default_user: str = "root", has_user_field: bool = False) -> dict | None:
    """Parse a single crontab line securely.

    Parameters
    ----------
    line : str
        The raw line from the crontab file.
    default_user : str
        Default executing user if no user field exists.
    has_user_field : bool
        If True, expects the 6th field (or 2nd for @reboot) to be the username.

    Returns
    -------
    dict or None
        A dictionary with keys 'user', 'schedule', 'command', or None if invalid/comment.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Skip environment variables setting (e.g. SHELL=/bin/sh, PATH=...)
    if "=" in line and not line.startswith("@"):
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            return None

    try:
        if line.startswith("@"):
            # Special schedules: @reboot, @daily, @hourly, etc.
            parts = line.split(None, 2 if has_user_field else 1)
            schedule = parts[0]
            if has_user_field:
                if len(parts) < 2:
                    return None
                user = parts[1]
                command = parts[2] if len(parts) > 2 else ""
            else:
                user = default_user
                command = parts[1] if len(parts) > 1 else ""
        else:
            # Standard 5-field time expression (minute, hour, day, month, day-of-week)
            parts = line.split(None, 6 if has_user_field else 5)
            if len(parts) < (7 if has_user_field else 6):
                return None
            schedule = " ".join(parts[0:5])
            if has_user_field:
                user = parts[5]
                command = parts[6]
            else:
                user = default_user
                command = parts[5]

        return {
            "user": user,
            "schedule": schedule,
            "command": command.strip()
        }
    except (IndexError, ValueError):
        return None


def gather_crontabs() -> list[dict]:
    """Harvest all scheduled cron tasks on the host.

    Iterates through:
      - /var/spool/cron/crontabs/ (user crontabs)
      - /etc/crontab (system-wide)
      - /etc/cron.d/ (system configuration snippets)
      - /etc/cron.hourly/, .daily/, .weekly/, .monthly/ (system scripts)

    Returns
    -------
    list[dict]
        List of gathered cron task dicts.
    """
    crontabs = []

    # 1. Parse User Crontabs
    user_cron_dir = Path("/var/spool/cron/crontabs")
    if user_cron_dir.exists():
        try:
            for p in user_cron_dir.iterdir():
                if p.is_file():
                    username = p.name
                    try:
                        content = p.read_text(errors="replace")
                        for line in content.splitlines():
                            parsed = parse_cron_line(line, default_user=username, has_user_field=False)
                            if parsed:
                                parsed["source"] = str(p)
                                crontabs.append(parsed)
                    except (PermissionError, OSError) as e:
                        crontabs.append({
                            "source": str(p),
                            "user": "root",
                            "schedule": "ERROR",
                            "command": f"Access Failure: Failed to read user crontab file descriptor: {e}"
                        })
        except (PermissionError, OSError) as e:
            crontabs.append({
                "source": str(user_cron_dir),
                "user": "root",
                "schedule": "ERROR",
                "command": f"Directory Isolation: Permission denied traversing user crontab directory structure: {e}"
            })

    # 2. Parse /etc/crontab
    system_crontab = Path("/etc/crontab")
    if system_crontab.exists():
        try:
            content = system_crontab.read_text(errors="replace")
            for line in content.splitlines():
                parsed = parse_cron_line(line, default_user="root", has_user_field=True)
                if parsed:
                    parsed["source"] = str(system_crontab)
                    crontabs.append(parsed)
        except (PermissionError, OSError) as e:
            crontabs.append({
                "source": str(system_crontab),
                "user": "root",
                "schedule": "ERROR",
                "command": f"Access Failure: Failed to read system global crontab: {e}"
            })

    # 3. Parse /etc/cron.d/
    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        try:
            for p in cron_d.iterdir():
                # Skip hidden/backup configurations
                if p.is_file() and not p.name.startswith(".") and not p.name.endswith("~") and not p.name.endswith(".bak"):
                    try:
                        content = p.read_text(errors="replace")
                        for line in content.splitlines():
                            parsed = parse_cron_line(line, default_user="root", has_user_field=True)
                            if parsed:
                                parsed["source"] = str(p)
                                crontabs.append(parsed)
                    except (PermissionError, OSError) as e:
                        crontabs.append({
                            "source": str(p),
                            "user": "root",
                            "schedule": "ERROR",
                            "command": f"Access Failure: Failed to parse cron.d snippet file item: {e}"
                        })
        except (PermissionError, OSError) as e:
            crontabs.append({
                "source": str(cron_d),
                "user": "root",
                "schedule": "ERROR",
                "command": f"Directory Isolation: Failed to read system cron snippets directory: {e}"
            })

    # 4. Parse Timed Script Directories
    timed_dirs = {
        "/etc/cron.hourly": "@hourly",
        "/etc/cron.daily": "@daily",
        "/etc/cron.weekly": "@weekly",
        "/etc/cron.monthly": "@monthly",
    }
    for dir_str, schedule in timed_dirs.items():
        dir_path = Path(dir_str)
        if dir_path.exists():
            try:
                for p in dir_path.iterdir():
                    # Skip hidden/backup/package-manager items cleanly
                    if p.is_file() and not p.name.startswith(".") and not p.name.endswith("~") and not p.name.endswith(".bak") and ".dpkg-" not in p.name:
                        crontabs.append({
                            "source": str(p),
                            "user": "root",
                            "schedule": schedule,
                            "command": str(p)
                        })
            except (PermissionError, OSError) as e:
                crontabs.append({
                    "source": dir_str,
                    "user": "root",
                    "schedule": "ERROR",
                    "command": f"Directory Isolation: Failed to inventory timed cron execution target folder: {e}"
                })

    return crontabs