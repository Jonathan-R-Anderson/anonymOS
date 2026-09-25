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

# orin/collectors/services.py
"""
orin.collectors.services – System Service Harvester
===================================================
Queries systemd to extract details on all system services, including active state,
enablement, and running owner (via process UID correlation).
"""

import subprocess
import psutil
from typing import List, Dict


def gather_active_services() -> List[Dict]:
    """Enumerate systemd services on the host.

    Gathers the active runtime status and configuration of services using systemctl.
    Gracefully degrades if systemd is not present on the host or if permissions restrict access.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``name`` (str) – unit name (e.g. "sshd.service").
        - ``status`` (str) – active (sub-state) state (e.g. "active (running)").
        - ``enabled`` (str) – enablement state (e.g. "enabled", "disabled", "static").
        - ``user`` (str) – the username running the service (defaults to "root").
        - ``description`` (str) – human-readable description of the service.
    """
    services = {}

    # 1. Parse active state using systemctl list-units
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Neutralize leading symbol (e.g., bullet point) indicating warnings/failed states
                if line.startswith("●") or line.startswith("*"):
                    line = line.lstrip("●* ").strip()

                parts = line.split(None, 4)
                if len(parts) >= 4:
                    unit = parts[0]
                    active_state = parts[2]
                    sub_state = parts[3]
                    description = parts[4] if len(parts) > 4 else ""

                    services[unit] = {
                        "name": unit,
                        "status": f"{active_state} ({sub_state})",
                        "enabled": "N/A",
                        "user": "root",
                        "description": description
                    }
    except Exception:
        pass

    # 2. Cross-reference with systemctl list-unit-files for enabling state
    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    unit = parts[0]
                    state = parts[1]
                    if unit in services:
                        services[unit]["enabled"] = state
                    else:
                        services[unit] = {
                            "name": unit,
                            "status": "inactive (dead)",
                            "enabled": state,
                            "user": "root",
                            "description": ""
                        }
    except Exception:
        pass

    # 3. Retrieve systemctl properties (User, MainPID) to resolve user owners
    try:
        result = subprocess.run(
            ["systemctl", "show", "--type=service", "-p", "Id", "-p", "User", "-p", "MainPID", "--all", "--no-pager"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            current_unit = None
            current_user = None
            current_pid = 0

            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    # End of block: process unit user owner
                    if current_unit and current_unit in services:
                        resolved_user = "root"
                        if current_user:
                            resolved_user = current_user
                        elif current_pid > 0:
                            try:
                                resolved_user = psutil.Process(current_pid).username()
                            except Exception:
                                pass
                        services[current_unit]["user"] = resolved_user
                    current_unit = None
                    current_user = None
                    current_pid = 0
                    continue

                if "=" in line:
                    key, val = line.split("=", 1)
                    if key == "Id":
                        current_unit = val
                    elif key == "User":
                        current_user = val
                    elif key == "MainPID":
                        try:
                            current_pid = int(val)
                        except ValueError:
                            current_pid = 0

            # Handle final block
            if current_unit and current_unit in services:
                resolved_user = "root"
                if current_user:
                    resolved_user = current_user
                elif current_pid > 0:
                    try:
                        resolved_user = psutil.Process(current_pid).username()
                    except Exception:
                        pass
                services[current_unit]["user"] = resolved_user

    except Exception:
        pass

    return list(services.values())
