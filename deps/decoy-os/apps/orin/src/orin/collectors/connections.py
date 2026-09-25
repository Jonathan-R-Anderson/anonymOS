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
# orin/collectors/connections.py
"""
orin.collectors.connections – Network Socket Harvester
=====================================================
Reads the Linux kernel's virtual network files under ``/proc/net/`` and
maps each socket inode back to the owning process via ``/proc/[pid]/fd/``.

Public API
----------
gather_listening_ports()     – All bound TCP/UDP listening sockets.
gather_outbound_connections() – All established (non-loopback) TCP sessions.
"""
import os
import sys
import struct
import socket
from pathlib import Path

#: Root of the Linux process pseudo-filesystem used for all /proc lookups.
PROC_PATH = Path("/proc")


def _get_socket_inode_map() -> dict[str, str]:
    """Build a mapping of socket inodes to owning process descriptors.

    Walks every numeric directory under ``/proc`` (one per running process),
    reads ``/proc/[pid]/comm`` for the process name, then iterates over every
    file-descriptor symlink in ``/proc/[pid]/fd/``.  File descriptors whose
    symlink target starts with ``socket:[`` identify open sockets; their inode
    numbers are extracted and stored.

    Returns
    -------
    dict[str, str]
        Mapping of inode string  ->  ``"<process_name> (PID: <pid>)"``.
        Entries for which the process name could not be read are labelled
        ``"unknown"``.

    Notes
    ----
    Processes owned by other users may raise :exc:`PermissionError` when
    their ``fd/`` directories are accessed; such entries are silently skipped.
    """
    inode_to_process = {}
    if not PROC_PATH.exists():
        return inode_to_process

    for pid_dir in PROC_PATH.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        pid = pid_dir.name
        fd_dir = pid_dir / "fd"
        if not fd_dir.exists():
            continue

        # Extract friendly process string name from the command execution file
        comm_path = pid_dir / "comm"
        process_name = "unknown"
        if comm_path.exists():
            try:
                process_name = comm_path.read_text().strip()
            except (PermissionError, FileNotFoundError):
                pass

        try:
            for fd_link in fd_dir.iterdir():
                try:
                    target = os.readlink(str(fd_link))
                    # Sockets show up as text descriptors like 'socket:[123456]'
                    if target.startswith("socket:["):
                        inode = target.partition("[")[2].partition("]")[0]
                        if inode:
                            inode_to_process[inode] = f"{process_name} (PID: {pid})"
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        except (PermissionError, FileNotFoundError, OSError):
            continue

    return inode_to_process


def _parse_hex_endpoint(hex_str: str) -> tuple[str, int]:
    """Translate a raw ``/proc/net`` hex endpoint token to a human-readable form.

    Supports both IPv4 (8 hex digits for IP) and IPv6 (32 hex digits for IP).
    For IPv6, the address is represented as four 32-bit hex integers in host
    byte order (little-endian on x86, big-endian on big-endian arches).

    Parameters
    ----------
    hex_str : str
        Raw ``<ip_hex>:<port_hex>`` token exactly as it appears in the file.

    Returns
    -------
    tuple[str, int]
        ``(IP address as string, port number as int)``. On any parse
        error the fallback ``("0.0.0.0", 0)`` is returned.
    """
    try:
        if ":" not in hex_str:
            return "0.0.0.0", 0

        ip_hex, port_hex = hex_str.split(":", 1)
        port = int(port_hex, 16)

        if len(ip_hex) == 8:
            # IPv4 (32-bit little-endian hex)
            ip_bytes = struct.pack("<I", int(ip_hex, 16))
            ip = socket.inet_ntoa(ip_bytes)
        elif len(ip_hex) == 32:
            # IPv6 (four 32-bit hex integers in host byte order)
            chunks = [ip_hex[i:i+8] for i in range(0, 32, 8)]
            ip_bytes = b"".join(int(c, 16).to_bytes(4, byteorder=sys.byteorder) for c in chunks)
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return "0.0.0.0", 0

        return ip, port
    except (ValueError, struct.error, socket.error):
        return "0.0.0.0", 0


def _parse_proc_net_file(file_path: Path, target_state: str | None, protocol: str, inode_map: dict) -> list[dict]:
    """Parse a ``/proc/net/{tcp,udp,tcp6,udp6}`` file and return matching socket records.

    Parameters
    ----------
    file_path : Path
        Absolute path to the kernel network file.
    target_state : str | None
        Hex state string to filter on (e.g. ``"0A"`` for TCP_LISTEN). Pass
        ``None`` to return all rows regardless of state.
    protocol : str
        Human-readable label (``"TCP"`` or ``"UDP"``), stored as-is in the
        returned dicts.
    inode_map : dict
        Pre-built inode-to-process mapping from :func:`_get_socket_inode_map`.

    Returns
    -------
    list[dict]
        Each dict contains ``port`` (int), ``protocol`` (str), and
        ``process_name`` (str or ``"unknown"``).
    """
    ports = []
    if not file_path.exists():
        return ports
    try:
        with open(file_path, "r") as f:
            next(f, None)  # Memory safety: skip the header line safely via iterator
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                state = parts[3]
                if target_state is None or state == target_state:
                    _, local_port = _parse_hex_endpoint(parts[1])
                    inode = parts[9]
                    resolved_process = inode_map.get(inode, "unknown")
                    ports.append({
                        "port": local_port,
                        "protocol": protocol,
                        "process_name": resolved_process
                    })
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return ports


def gather_listening_ports() -> list[dict]:
    """Harvest all bound listening TCP and UDP ports (IPv4 and IPv6) on the system.

    Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`,
    then deduplicates by ``(port, protocol)`` before returning.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``port``         (int)   – local port number.
        - ``protocol``     (str)   – ``"TCP"`` or ``"UDP"``.
        - ``process_name`` (str)   – owning process and PID, or ``"unknown"``.
    """
    inode_map = _get_socket_inode_map()
    ports_list = []
    seen_ports = set()  # Production tuning: linear O(1) identity cache

    targets = [
        (Path("/proc/net/tcp"), "0A", "TCP"),
        (Path("/proc/net/tcp6"), "0A", "TCP"),
        (Path("/proc/net/udp"), "07", "UDP"),
        (Path("/proc/net/udp6"), "07", "UDP")
    ]

    for path, state, proto in targets:
        extracted = _parse_proc_net_file(path, state, proto, inode_map)
        for p in extracted:
            port_key = (p["port"], p["protocol"])
            if port_key not in seen_ports:
                seen_ports.add(port_key)
                ports_list.append(p)

    return ports_list


def gather_outbound_connections() -> list[dict]:
    """Harvest all established outbound TCP connections (IPv4 and IPv6).

    Reads `/proc/net/tcp` and `/proc/net/tcp6`, filtering for rows where
    the state field equals ``01`` (``TCP_ESTABLISHED``). Connections whose
    remote address is loopback (``127.0.0.1`` or ``::1``) are excluded.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``local_ip``    (str)  – local interface address.
        - ``local_port``  (int)  – local port number.
        - ``remote_ip``   (str)  – remote server IP address.
        - ``remote_port`` (int)  – remote server port.
        - ``state``       (str)  – always ``"ESTABLISHED"`` for rows returned.
        - ``process_name`` (str) – owning process and PID, or ``"unknown"``.
    """
    connections = []
    inode_map = _get_socket_inode_map()

    # Files to process for established TCP connections
    net_files = [
        (Path("/proc/net/tcp"), {"127.0.0.1"}),
        (Path("/proc/net/tcp6"), {"::1", "0000:0000:0000:0000:0000:0000:0000:0001", "::ffff:127.0.0.1"})
    ]

    for file_path, loopbacks in net_files:
        if not file_path.exists():
            continue
        try:
            with open(file_path, "r") as f:
                next(f, None)  # Memory safety: skip header row safely via iterator
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue

                    state = parts[3]
                    if state == "01":  # TCP_ESTABLISHED
                        local_ip, local_port = _parse_hex_endpoint(parts[1])
                        remote_ip, remote_port = _parse_hex_endpoint(parts[2])
                        inode = parts[9]
                        resolved_process = inode_map.get(inode, "unknown")

                        if remote_ip in loopbacks:
                            continue

                        connections.append({
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "state": "ESTABLISHED",
                            "process_name": resolved_process
                        })
        except (FileNotFoundError, PermissionError, OSError):
            pass

    return connections