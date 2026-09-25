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
# orin/collectors/ebpf.py
"""
orin.collectors.ebpf – eBPF Auditor & File Descriptor Harvester
===============================================================
Harvests eBPF programs, pinned objects under /sys/fs/bpf, ld.so.preload linker
overrides, and special (anomalous) open process file descriptors from procfs.
"""
import os
import subprocess
import json
from pathlib import Path

BPF_FS_PATH = Path("/sys/fs/bpf")
PRELOAD_PATH = Path("/etc/ld.so.preload")
PROC_PATH = Path("/proc")


def gather_ebpf_programs() -> list[dict]:
    """Enumerate loaded BPF programs using bpftool."""
    programs = []
    try:
        result = subprocess.run(
            ["bpftool", "prog", "show", "-j"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            raw_programs = json.loads(result.stdout)
            for prog in raw_programs:
                programs.append({
                    "bpf_id": prog.get("id"),
                    "name": prog.get("name", "unknown"),
                    "type": prog.get("type", "unknown"),
                    "tag": prog.get("tag", "unknown"),
                    "gpl_compatible": 1 if prog.get("gpl_compatible") else 0
                })
        else:
            # bpftool failed or not installed/authorized
            pass
    except Exception:
        pass
    return programs


def gather_ebpf_pinned() -> list[dict]:
    """Recursively walk /sys/fs/bpf and retrieve pinned objects."""
    pinned = []
    if not BPF_FS_PATH.exists() or not BPF_FS_PATH.is_dir():
        return pinned

    try:
        for path in BPF_FS_PATH.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink():
                    pinned.append({
                        "path": str(path.resolve()),
                        "type": "pinned_object"
                    })
            except (PermissionError, FileNotFoundError, OSError):
                continue
    except Exception:
        pass
    return pinned


def gather_ld_preload() -> list[str]:
    """Read dynamic linker preload overrides from /etc/ld.so.preload."""
    lines = []
    if not PRELOAD_PATH.exists():
        return lines

    try:
        with open(PRELOAD_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    except Exception:
        pass
    return lines


def gather_special_fds() -> list[dict]:
    """Walk procfs and identify anomalous or high-risk open file descriptors."""
    special_fds = []
    if not PROC_PATH.exists() or not PROC_PATH.is_dir():
        return special_fds

    try:
        for pid_dir in PROC_PATH.iterdir():
            if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                continue

            try:
                pid = int(pid_dir.name)
                fd_dir = pid_dir / "fd"
                if not fd_dir.exists() or not fd_dir.is_dir():
                    continue

                for fd_file in fd_dir.iterdir():
                    try:
                        fd_num = int(fd_file.name)
                        target = os.readlink(str(fd_file))

                        fd_type = None
                        if "memfd:" in target:
                            fd_type = "memfd"
                        elif target.startswith("socket:["):
                            fd_type = "socket"
                        elif target.endswith(" (deleted)") and "memfd:" not in target:
                            fd_type = "deleted"

                        if fd_type:
                            special_fds.append({
                                "pid": pid,
                                "fd_num": fd_num,
                                "fd_type": fd_type,
                                "resolved_path": target
                            })
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            except (ValueError, PermissionError, FileNotFoundError, OSError):
                continue
    except Exception:
        pass
    return special_fds