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
# src/orin/analysis/unhide.py
"""
orin.analysis.unhide – Out-of-Band Hidden Process Detector
==========================================================
Identifies processes hidden from /proc directory listings by comparing PIDs
returned by system scheduler signaling (os.kill) against visible /proc entries.
"""
import os
import errno
from pathlib import Path

def _get_system_pid_max() -> int:
    """Read the dynamic PID allocation limit from the Linux kernel parameters.

    Returns
    -------
    int
        The maximum allowable PID on the host system. Falls back to 32768
        if the proc filesystem parameter is inaccessible.
    """
    pid_max_path = Path("/proc/sys/kernel/pid_max")
    if pid_max_path.exists():
        try:
            return int(pid_max_path.read_text().strip())
        except (ValueError, OSError):
            pass
    return 32768  # Conservative standard POSIX fallback boundary


def detect_hidden_processes() -> list[dict]:
    """Scan the PID space to detect scheduler-active processes hidden from `/proc`.

    Returns
    -------
    list[dict]
        Each dict represents a discovered hidden process:
        - pid (int): PID of the hidden process.
        - status (str): "hidden".
        - reason (str): verification failure details.
    """
    hidden_processes = []
    proc_path = Path("/proc")
    if not proc_path.exists():
        return hidden_processes

    # 1. Gather all visible PIDs and TIDs from /proc listing
    visible_pids = set()
    visible_tids = set()
    for p in proc_path.iterdir():
        if p.is_dir() and p.name.isdigit():
            try:
                pid = int(p.name)
                visible_pids.add(pid)

                # Read all thread IDs (TIDs) under /proc/[pid]/task/
                task_dir = p / "task"
                if task_dir.exists():
                    for t in task_dir.iterdir():
                        if t.name.isdigit():
                            visible_tids.add(int(t.name))
            except (ValueError, OSError):
                pass

    if not visible_pids:
        return hidden_processes

    # 2. Determine bounds of the scanning loop securely
    max_visible_pid = max(visible_pids)
    pid_max = _get_system_pid_max()

    # Strategy: If pid_max is relatively small (e.g., <= 65536), scan the entire
    # keyspace exhaustively. If it's a massive 4-million allocation space, use an
    # expanded adaptive buffer to prevent extreme CPU cycles while retaining detection coverage.
    if pid_max <= 65536:
        scan_limit = pid_max
    else:
        scan_limit = min(max(32768, max_visible_pid + 5000), pid_max)

    # 3. Probe the calculated PID keyspace
    for pid in range(1, scan_limit + 1):
        if pid in visible_pids or pid in visible_tids:
            continue

        try:
            # Send null signal (0) to check process existence without altering state
            os.kill(pid, 0)

            # If no exception is raised, double check if /proc/{pid} is missing right now.
            if not Path(f"/proc/{pid}").exists():
                # Mitigation against fast transient processes: re-verify scheduler response
                try:
                    os.kill(pid, 0)
                    hidden_processes.append({
                        "pid": pid,
                        "status": "hidden",
                        "reason": "Process responds to signal 0 but is entirely absent from /proc directory structures"
                    })
                except OSError:
                    # Process died naturally between the first signal and directory verification check
                    pass

        except OSError as e:
            if e.errno == errno.EPERM:
                # PermissionError: Process exists but Orin engine execution scope lacks signal privileges.
                # Double check /proc/{pid} to handle fast-forking race conditions securely
                if not Path(f"/proc/{pid}").exists():
                    try:
                        os.kill(pid, 0)
                    except OSError as e2:
                        if e2.errno == errno.EPERM:
                            hidden_processes.append({
                                "pid": pid,
                                "status": "hidden",
                                "reason": "Process exists (EPERM verification) but is hidden from the /proc file mapping"
                            })
            elif e.errno == errno.ESRCH:
                # ProcessLookupError: process cleanly does not exist (standard state)
                pass

    return hidden_processes