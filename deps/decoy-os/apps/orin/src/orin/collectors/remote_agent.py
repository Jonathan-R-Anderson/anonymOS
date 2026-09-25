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
# src/orin/collectors/remote_agent.py
"""
Orin Remote Agent
=================
A self-contained, zero-dependency Python script designed to execute on remote Linux
hosts over SSH. It gathers raw system security telemetry using ONLY standard library
modules and outputs a single canonical JSON structure to stdout.
"""
import os
import sys
import json
import stat
import errno
import struct
import socket
import re
import hashlib
import pwd
import grp
import platform
from pathlib import Path
from datetime import datetime, timezone

def is_safe_path(path_str: str) -> bool:
    """Resolve a path and verify it does not contain sensitive or unsafe directory traversal.

    Parameters
    ----------
    path_str : str
        The path to validate.

    Returns
    -------
    bool
        True if the path is safe to access, False otherwise.
    """
    try:
        if not path_str:
            return False
        # Expand user and resolve the real path to prevent traversal (e.g. '../../')
        resolved = os.path.realpath(os.path.expanduser(path_str))

        # Verify that path parts do not contain sensitive folder names or files
        parts = resolved.split(os.sep)
        for part in parts:
            if part.startswith(".") and part in (".ssh", ".aws", ".env", ".git"):
                return False
            if part in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials"):
                return False
        return True
    except Exception:
        return False

# --- CONFIGURATION DEFAULTS ---
DEFAULT_SUID_PATHS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/lib", "/lib64", "/usr/lib", "/usr/lib64"
]

DEFAULT_BINARY_DIRS = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"
)

_CHUNK_SIZE = 65536

# --- PROCESS COLLECTOR ---
def gather_active_processes() -> list[dict]:
    process_list = []
    proc_path = Path("/proc")
    if not proc_path.exists():
        return process_list

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        pid = int(pid_dir.name)
        ppid = -1
        name = "unknown"
        exe = "unknown"
        cmdline = ""

        try:
            stat_path = pid_dir / "stat"
            try:
                with open(stat_path, "r", encoding="utf-8", errors="replace") as f:
                    stat_content = f.read().strip()

                r_paren_index = stat_content.rfind(")")
                if r_paren_index != -1:
                    after_name = stat_content[r_paren_index + 2:].split()
                    if len(after_name) >= 2:
                        ppid = int(after_name[1])
                else:
                    name = "ERROR: Malformed stat descriptor layout"
            except OSError as e:
                if e.errno == errno.ENOENT:
                    continue
                elif e.errno == errno.EACCES:
                    name = "Permission Denied"
                else:
                    name = f"ERROR: OS read fault: {e.strerror}"

            if name in ("unknown", "Permission Denied"):
                comm_path = pid_dir / "comm"
                try:
                    with open(comm_path, "r", encoding="utf-8", errors="replace") as f:
                        name = f.read().strip()
                except OSError as e:
                    if e.errno == errno.ENOENT:
                        continue
                    elif e.errno != errno.EACCES:
                        name = f"ERROR: Comm link block: {e.strerror}"

            exe_link = pid_dir / "exe"
            try:
                exe = os.readlink(str(exe_link))
            except OSError as e:
                if e.errno == errno.ENOENT:
                    exe = "unknown"
                elif e.errno == errno.EACCES:
                    exe = "Permission Denied"
                else:
                    exe = f"ERROR: Resolution fault: {e.strerror}"

            cmdline_path = pid_dir / "cmdline"
            try:
                with open(cmdline_path, "r", encoding="utf-8", errors="replace") as f:
                    cmdline_raw = f.read()

                if cmdline_raw:
                    cmdline = " ".join(cmdline_raw.split("\x00")).strip()
                else:
                    cmdline = name
            except OSError as e:
                if e.errno == errno.ENOENT:
                    continue
                elif e.errno == errno.EACCES:
                    cmdline = "Permission Denied"
                else:
                    cmdline = f"ERROR: Stream fault: {e.strerror}"

            process_list.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline if cmdline else name
            })

        except Exception:
            continue

    return process_list

# --- NETWORKS/CONNECTIONS COLLECTOR ---
def _get_socket_inode_map() -> dict[str, str]:
    inode_to_process = {}
    proc_path = Path("/proc")
    if not proc_path.exists():
        return inode_to_process

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        pid = pid_dir.name
        fd_dir = pid_dir / "fd"
        if not fd_dir.exists():
            continue

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
    try:
        if ":" not in hex_str:
            return "0.0.0.0", 0

        ip_hex, port_hex = hex_str.split(":", 1)
        port = int(port_hex, 16)

        if len(ip_hex) == 8:
            ip_bytes = struct.pack("<I", int(ip_hex, 16))
            ip = socket.inet_ntoa(ip_bytes)
        elif len(ip_hex) == 32:
            chunks = [ip_hex[i:i+8] for i in range(0, 32, 8)]
            ip_bytes = b"".join(int(c, 16).to_bytes(4, byteorder=sys.byteorder) for c in chunks)
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return "0.0.0.0", 0

        return ip, port
    except (ValueError, struct.error, socket.error):
        return "0.0.0.0", 0

def _parse_proc_net_file(file_path: Path, target_state: str | None, protocol: str, inode_map: dict) -> list[dict]:
    ports = []
    if not file_path.exists():
        return ports
    try:
        with open(file_path, "r") as f:
            next(f, None)
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
    inode_map = _get_socket_inode_map()
    ports_list = []
    seen_ports = set()

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
    connections = []
    inode_map = _get_socket_inode_map()

    net_files = [
        (Path("/proc/net/tcp"), {"127.0.0.1"}),
        (Path("/proc/net/tcp6"), {"::1", "0000:0000:0000:0000:0000:0000:0000:0001", "::ffff:127.0.0.1"})
    ]

    for file_path, loopbacks in net_files:
        if not file_path.exists():
            continue
        try:
            with open(file_path, "r") as f:
                next(f, None)
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue

                    state = parts[3]
                    if state == "01":
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

# --- PROMISCUOUS INTERFACE AUDITOR ---
def gather_promisc_interfaces() -> list[dict]:
    interfaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists() or not net_path.is_dir():
        return interfaces

    try:
        for iface_dir in net_path.iterdir():
            if not iface_dir.is_dir():
                continue

            interface_name = iface_dir.name
            flags_file = iface_dir / "flags"

            if not flags_file.exists():
                continue
            try:
                content = flags_file.read_text().strip()
                clean_content = content.lower()
                if clean_content.startswith("0x"):
                    clean_content = clean_content[2:]

                flags = int(clean_content, 16)
                is_promiscuous = 1 if (flags & 0x100) != 0 else 0

                interfaces.append({
                    "interface": interface_name,
                    "flags": content,
                    "is_promiscuous": is_promiscuous
                })
            except ValueError as parse_error:
                interfaces.append({
                    "interface": interface_name,
                    "flags": "ERROR_MALFORMED_HEX",
                    "is_promiscuous": 0,
                    "anomaly_detected": 1,
                    "anomaly_reason": f"Failed to parse kernel device flags token string '{content}': {parse_error}"
                })
            except (PermissionError, OSError) as io_error:
                if io_error.errno == errno.ENOENT:
                    continue
                interfaces.append({
                    "interface": interface_name,
                    "flags": "ERROR_ACCESS_DENIED",
                    "is_promiscuous": 0,
                    "anomaly_detected": 1,
                    "anomaly_reason": f"Kernel restricted descriptor read interface context: {io_error.strerror}"
                })
    except (PermissionError, OSError) as traversal_error:
        interfaces.append({
            "interface": "ERROR_SYS_CLASS_NET_ROOT",
            "flags": "ERROR_TRAVERSAL_FAULT",
            "is_promiscuous": 0,
            "anomaly_detected": 1,
            "anomaly_reason": f"Critical visibility gap traversing sysfs network interfaces space: {traversal_error.strerror}"
        })
    return interfaces

# --- KERNEL MODULE COLLECTOR ---
def gather_loaded_kernel_modules() -> list[dict]:
    modules_list = []
    modules_path = Path("/proc/modules")
    if not modules_path.exists():
        return modules_list

    try:
        with open(modules_path, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split()
                if not parts:
                    continue

                if len(parts) < 3:
                    modules_list.append({
                        "module_name": f"ERROR_LINE_{line_num}",
                        "memory_size": 0,
                        "instances_loaded": 0,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Malformed kernel module line layout (expected >= 3 fields, got {len(parts)})"
                    })
                    continue

                try:
                    modules_list.append({
                        "module_name": parts[0],
                        "memory_size": int(parts[1]),
                        "instances_loaded": int(parts[2])
                    })
                except ValueError as cast_error:
                    modules_list.append({
                        "module_name": f"ERROR_INVALID_CAST_{parts[0]}",
                        "memory_size": 0,
                        "instances_loaded": 0,
                        "anomaly_detected": 1,
                        "anomaly_reason": f"Type validation fault on row {line_num}: {cast_error}"
                    })
                    continue
    except (PermissionError, OSError) as io_error:
        modules_list.append({
            "module_name": "ERROR_PROC_MODULES_IO_FAULT",
            "memory_size": 0,
            "instances_loaded": 0,
            "anomaly_detected": 1,
            "anomaly_reason": f"Failed to access virtual filesystem descriptor node: {io_error}"
        })
    return modules_list


def gather_kernel_symbols() -> list[dict]:
    """Parse /proc/kallsyms and return all exported kernel symbols.

    Returns
    -------
    list[dict]
        Each dict contains address, symbol_type, symbol_name, module_name,
        is_critical, suspicious, anomaly_detected, anomaly_reason.
    """
    from orin.collectors.kernel import gather_kernel_symbols as _gather_symbols
    return _gather_symbols()


def analyze_kernel_integrity(modules: list[dict], symbols: list[dict]) -> dict:
    """Analyze kernel modules and symbols for rootkit indicators.

    Parameters
    ----------
    modules : list[dict]
        List of loaded modules from /proc/modules.
    symbols : list[dict]
        List of kernel symbols from /proc/kallsyms.

    Returns
    -------
    dict
        Analysis summary with risk level, suspicious symbols count,
        potential rootkit indicators, and hidden module detections.
    """
    from orin.collectors.kernel import (
        analyze_kernel_symbol_overrides,
        check_for_unlinked_modules
    )

    symbol_analysis = analyze_kernel_symbol_overrides(symbols)
    hidden_modules = check_for_unlinked_modules(modules, symbols)

    return {
        **symbol_analysis,
        "hidden_modules": hidden_modules,
        "hidden_module_count": len(hidden_modules)
    }

# --- SYSTEM USERS COLLECTOR ---
def gather_system_accounts() -> list[dict]:
    accounts = []
    passwd_path = Path("/etc/passwd")
    if not passwd_path.exists():
        return accounts

    try:
        with open(passwd_path, "r", encoding="utf-8", errors="replace") as f:
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

# --- SSH PERSISTENCE COLLECTOR ---
_KNOWN_KEY_TYPES = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com"
}

def gather_active_ssh_keys() -> list[dict]:
    ssh_records: list[dict] = []
    try:
        system_accounts = pwd.getpwall()
    except OSError as e:
        ssh_records.append({
            "user_account": "root",
            "key_type": "ERROR",
            "fingerprint": "SYSTEM_PASSWD_READ_FAULT",
            "raw_key_comment": f"Failed to interface with systemic passwd database pipeline: {e}"
        })
        return ssh_records

    for account in system_accounts:
        user = account.pw_name
        home_dir = account.pw_dir
        if not home_dir:
            continue

        auth_keys_path = Path(home_dir) / ".ssh" / "authorized_keys"
        try:
            if not auth_keys_path.exists():
                continue
        except (PermissionError, OSError) as access_fault:
            ssh_records.append({
                "user_account": user,
                "key_type": "ERROR",
                "fingerprint": "ACCESS_DENIED_INVENTORY_FAULT",
                "raw_key_comment": f"Failed to access secure profile target path: {access_fault.strerror if hasattr(access_fault, 'strerror') else str(access_fault)}"
            })
            continue

        try:
            with open(auth_keys_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    first_token = parts[0].lower()
                    if first_token in _KNOWN_KEY_TYPES or first_token.startswith("ssh-"):
                        key_type = parts[0]
                        key_body = parts[1]
                        comment = " ".join(parts[2:]) if len(parts) > 2 else "No Comment"
                    else:
                        if len(parts) >= 3:
                            key_type = parts[1]
                            key_body = parts[2]
                            comment = " ".join(parts[3:]) if len(parts) > 3 else "No Comment"
                        else:
                            continue

                    try:
                        fingerprint = hashlib.sha256(key_body.encode("utf-8")).hexdigest()
                        ssh_records.append({
                            "user_account": user,
                            "key_type": key_type,
                            "fingerprint": fingerprint,
                            "raw_key_comment": comment.strip(),
                        })
                    except Exception as crypt_error:
                        ssh_records.append({
                            "user_account": user,
                            "key_type": "ERROR",
                            "fingerprint": f"HASH_FAULT_LINE_{line_num}",
                            "raw_key_comment": f"Malformed base64 block serialization: {crypt_error}"
                        })
        except (PermissionError, OSError) as access_fault:
            ssh_records.append({
                "user_account": user,
                "key_type": "ERROR",
                "fingerprint": "ACCESS_DENIED_INVENTORY_FAULT",
                "raw_key_comment": f"Failed to open secure profile target path: {access_fault.strerror}"
            })
    return ssh_records

# --- CRONTAB COLLECTOR ---
def parse_cron_line(line: str, default_user: str = "root", has_user_field: bool = False) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "=" in line and not line.startswith("@"):
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            return None

    try:
        if line.startswith("@"):
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
    crontabs = []

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

    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        try:
            for p in cron_d.iterdir():
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

# --- LOGIN SESSION AUDIT ---
def gather_wtmp_sessions(wtmp_path: Path = Path("/var/log/wtmp")) -> list[dict]:
    sessions = []
    if not wtmp_path.exists():
        return sessions

    utmp_format = "<h2xi32s4s32s256shhiii4I20s"
    record_size = struct.calcsize(utmp_format)
    active_sessions = {}

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

                user = ut_user.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                line = ut_line.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                host = ut_host.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()

                anomaly_detected = 0
                anomaly_reason = ""

                if tv_sec == 0 and ut_type in (7, 8):
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

                if ut_type == 7:
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
                elif ut_type == 8:
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
                elif ut_type == 2:
                    boot_time_str = time_str
                    for session_key, session in list(active_sessions.items()):
                        session["logout_time"] = f"reboot ({boot_time_str})"
                        sessions.append(session)
                    active_sessions.clear()

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
    records = []
    if not lastlog_path.exists():
        return records

    accounts = gather_system_accounts()
    lastlog_format = "<I32s256s"
    record_size = struct.calcsize(lastlog_format)

    try:
        file_size = lastlog_path.stat().st_size
        with open(lastlog_path, "rb") as f:
            for acc in accounts:
                uid = acc["uid"]
                if uid < 0 or uid > 2147483647:
                    continue

                offset = uid * record_size
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

                line = ll_line.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                host = ll_host.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()

                if ll_time == 0:
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

# --- IN-MEMORY DELETED EXECUTABLE RECOVERY ---
def gather_deleted_binaries(vault_dir: Path = Path("/var/lib/orin/vault")) -> list[dict]:
    records = []
    vault_dir_str = str(vault_dir)
    if not is_safe_path(vault_dir_str):
        vault_dir = Path("/var/lib/orin/vault")
    proc_path = Path("/proc")
    if not proc_path.exists():
        return records

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        pid = int(pid_dir.name)
        exe_link = pid_dir / "exe"

        try:
            try:
                target_exe = os.readlink(str(exe_link))
            except (FileNotFoundError, PermissionError, OSError):
                continue

            if not target_exe.endswith(" (deleted)"):
                continue

            md5_alg = hashlib.md5(usedforsecurity=False)  # nosec
            sha256_alg = hashlib.sha256()
            vault_path_str = "failed_to_write_vault"

            try:
                vault_dir.mkdir(parents=True, exist_ok=True)
                temp_dest = vault_dir / f"recovery_{pid}.tmp"

                with exe_link.open("rb") as src_f, open(temp_dest, "wb") as dest_f:
                    while chunk := src_f.read(_CHUNK_SIZE):
                        md5_alg.update(chunk)
                        sha256_alg.update(chunk)
                        dest_f.write(chunk)

                md5_hash = md5_alg.hexdigest()
                sha256_hash = sha256_alg.hexdigest()

                dest_file = vault_dir / sha256_hash
                if dest_file.exists():
                    temp_dest.unlink(missing_ok=True)
                else:
                    temp_dest.rename(dest_file)

                vault_path_str = str(dest_file.resolve())

            except (PermissionError, OSError) as storage_error:
                try:
                    md5_alg = hashlib.md5(usedforsecurity=False)  # nosec
                    sha256_alg = hashlib.sha256()
                    with exe_link.open("rb") as src_f:
                        while chunk := src_f.read(_CHUNK_SIZE):
                            md5_alg.update(chunk)
                            sha256_alg.update(chunk)

                    md5_hash = md5_alg.hexdigest()
                    sha256_hash = sha256_alg.hexdigest()
                    vault_path_str = f"failed_to_write_vault: {storage_error}"
                except (FileNotFoundError, PermissionError, OSError):
                    continue

            records.append({
                "pid": pid,
                "exe": target_exe,
                "sha256": sha256_hash,
                "md5": md5_hash,
                "vault_path": vault_path_str
            })
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            continue

    return records

# --- FILE INTEGRITY MONITOR (FIM) ---
def _hash_file_opportunistically(target_path: Path, file_signatures: list) -> None:
    if not target_path.exists() or target_path.is_symlink():
        return

    resolved = str(target_path.resolve())
    if not is_safe_path(resolved):
        return
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        error_msg = "ERROR: "
        if e.errno == errno.ELOOP:
            error_msg += "Symlink exploit signature detected via O_NOFOLLOW"
        elif e.errno == errno.EACCES:
            error_msg += "Permission denied accessing target object"
        else:
            error_msg += f"OS file descriptor allocation fault: {e.strerror}"

        file_signatures.append({
            "file_path": resolved,
            "sha256_hash": error_msg,
            "mtime": 0.0,
            "ctime": 0.0,
            "size": 0,
        })
        return

    try:
        stat_info = os.fstat(fd)
        current_mtime = stat_info.st_mtime
        current_ctime = stat_info.st_ctime
        current_size  = stat_info.st_size

        hasher = hashlib.sha256()
        with open(fd, "rb", closefd=False) as fh:
            while chunk := fh.read(65536):
                hasher.update(chunk)

        file_signatures.append({
            "file_path":   resolved,
            "sha256_hash": hasher.hexdigest(),
            "mtime":       current_mtime,
            "ctime":       current_ctime,
            "size":        current_size,
        })

    except (PermissionError, OSError) as runtime_error:
        file_signatures.append({
            "file_path": resolved,
            "sha256_hash": f"ERROR: Content extraction failure: {runtime_error}",
            "mtime": 0.0,
            "ctime": 0.0,
            "size": 0,
        })
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

def gather_file_integrity_signatures(critical_paths: list[str], critical_dirs: list[str]) -> list[dict]:
    file_signatures: list[dict] = []

    for path_str in critical_paths:
        resolved_path = os.path.realpath(os.path.expanduser(path_str))
        if not is_safe_path(resolved_path):
            continue
        _hash_file_opportunistically(Path(resolved_path), file_signatures)

    for dir_str in critical_dirs:
        resolved_dir = os.path.realpath(os.path.expanduser(dir_str))
        if not is_safe_path(resolved_dir):
            continue
        target_dir = Path(resolved_dir)
        if target_dir.exists() and target_dir.is_dir():
            try:
                for filepath in target_dir.rglob("*"):
                    if filepath.is_file() and not filepath.is_symlink():
                        _hash_file_opportunistically(filepath, file_signatures)
            except (PermissionError, OSError) as e:
                file_signatures.append({
                    "file_path": str(target_dir),
                    "sha256_hash": f"ERROR: Directory traversal failure: {e}",
                    "mtime": 0.0,
                    "ctime": 0.0,
                    "size": 0,
                })

    return file_signatures

# --- SUID/SGID BINARY MONITOR ---
def gather_suid_binaries(paths: list[str] = None) -> list[dict]:
    if paths is None:
        paths = DEFAULT_SUID_PATHS

    records = []
    seen = set()

    for path_str in paths:
        resolved_path = os.path.realpath(os.path.expanduser(path_str))
        if not is_safe_path(resolved_path):
            continue
        path = Path(resolved_path)
        if not path.exists() or not path.is_dir():
            continue

        try:
            for entry in path.rglob("*"):
                try:
                    if entry.is_symlink() or not entry.is_file():
                        continue
                except OSError:
                    continue

                try:
                    abs_path = str(entry.resolve())
                except OSError:
                    abs_path = str(entry.absolute())

                if not is_safe_path(abs_path):
                    continue

                if abs_path in seen:
                    continue
                seen.add(abs_path)

                try:
                    st = entry.stat()
                    mode = st.st_mode
                    is_suid = bool(mode & stat.S_ISUID)
                    is_sgid = bool(mode & stat.S_ISGID)

                    if is_suid or is_sgid:
                        try:
                            owner = pwd.getpwuid(st.st_uid).pw_name
                        except KeyError:
                            owner = str(st.st_uid)
                        try:
                            group = grp.getgrgid(st.st_gid).gr_name
                        except KeyError:
                            group = str(st.st_gid)

                        permissions = oct(stat.S_IMODE(mode))

                        h = hashlib.sha256()
                        try:
                            with open(entry, "rb") as f:
                                for chunk in iter(lambda: f.read(65536), b""):
                                    h.update(chunk)
                            sha256 = h.hexdigest()
                        except (OSError, PermissionError):
                            sha256 = "unknown"

                        records.append({
                            "file_path": abs_path,
                            "owner": owner,
                            "grp": group,
                            "permissions": permissions,
                            "sha256": sha256
                        })
                except OSError:
                    continue
        except OSError:
            continue

    return records

# --- DPKG PACKAGE INTEGRITY ENGINE ---
def _md5_of_fd(fd: int) -> str:
    alg = hashlib.md5(usedforsecurity=False)  # nosec
    with open(fd, "rb", closefd=False) as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            alg.update(chunk)
    return alg.hexdigest()

def _sha256_of_fd(fd: int) -> str:
    alg = hashlib.sha256()
    with open(fd, "rb", closefd=False) as fh:
        while chunk := fh.read(_CHUNK_SIZE):
            alg.update(chunk)
    return alg.hexdigest()

def gather_pkg_integrity_drift(dpkg_info_dir: Path = Path("/var/lib/dpkg/info")) -> list[dict]:
    violations = []
    if not dpkg_info_dir.exists() or not dpkg_info_dir.is_dir():
        return violations

    try:
        for md5sums_file in dpkg_info_dir.glob("*.md5sums"):
            package = md5sums_file.stem

            try:
                with md5sums_file.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or len(line) < 34:
                            continue

                        expected_md5 = line[:32]
                        file_path_str = line[32:].strip()
                        file_path = Path("/") / file_path_str
                        path_str = str(file_path)

                        if not path_str.startswith(DEFAULT_BINARY_DIRS):
                            continue

                        fd = -1
                        try:
                            fd = os.open(path_str, os.O_RDONLY | os.O_NOFOLLOW)
                        except OSError as e:
                            if e.errno == errno.ENOENT:
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": None,
                                    "actual_sha256": None,
                                    "status": "missing",
                                })
                            elif e.errno == errno.ELOOP:
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": "ERROR: Symlink exploit detected via O_NOFOLLOW",
                                    "actual_sha256": "ERROR: Access Restricted",
                                    "status": "mismatch",
                                })
                            else:
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": f"ERROR: OS descriptor fault: {e.strerror}",
                                    "actual_sha256": None,
                                    "status": "mismatch",
                                })
                            continue

                        try:
                            stat_info = os.fstat(fd)
                            if not os.path.stat.S_ISREG(stat_info.st_mode):
                                continue

                            try:
                                os.lseek(fd, 0, os.SEEK_SET)
                                actual_md5 = _md5_of_fd(fd)
                            except (OSError, PermissionError) as hash_err:
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": f"ERROR: MD5 processing fault: {hash_err}",
                                    "actual_sha256": None,
                                    "status": "mismatch",
                                })
                                continue

                            if actual_md5 == expected_md5:
                                continue

                            try:
                                os.lseek(fd, 0, os.SEEK_SET)
                                actual_sha256 = _sha256_of_fd(fd)
                            except (OSError, PermissionError) as hash_err:
                                actual_sha256 = f"ERROR: SHA-256 processing fault: {hash_err}"

                            violations.append({
                                "package": package,
                                "file_path": path_str,
                                "expected_md5": expected_md5,
                                "actual_md5": actual_md5,
                                "actual_sha256": actual_sha256,
                                "status": "mismatch",
                            })
                        finally:
                            if fd != -1:
                                try:
                                    os.close(fd)
                                except OSError:
                                    pass
            except (PermissionError, OSError) as file_err:
                violations.append({
                    "package": package,
                    "file_path": "ERROR_METADATA_MANIFEST",
                    "expected_md5": "MANIFEST_READ_FAULT",
                    "actual_md5": f"Failed to interface with metadata manifest file: {file_err}",
                    "actual_sha256": None,
                    "status": "mismatch",
                })
                continue
    except (PermissionError, OSError) as dir_err:
        violations.append({
            "package": "ERROR_PKG_INTEGRITY_ROOT",
            "file_path": str(dpkg_info_dir),
            "expected_md5": "DIRECTORY_TRAVERSAL_FAULT",
            "actual_md5": f"Critical visibility gap traversing dpkg metadata space: {dir_err}",
            "actual_sha256": None,
            "status": "mismatch",
        })
    return violations


def gather_auth_logs() -> list[str]:
    """Collect the last 1000 lines of auth log."""
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


def gather_ebpf_programs() -> list[dict]:
    """Enumerate loaded BPF programs using bpftool."""
    programs = []
    try:
        import subprocess
        result = subprocess.run(
            ["bpftool", "prog", "show", "-j"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            import json
            raw_programs = json.loads(result.stdout)
            for prog in raw_programs:
                programs.append({
                    "bpf_id": prog.get("id"),
                    "name": prog.get("name", "unknown"),
                    "type": prog.get("type", "unknown"),
                    "tag": prog.get("tag", "unknown"),
                    "gpl_compatible": 1 if prog.get("gpl_compatible") else 0
                })
    except Exception:
        pass
    return programs


def gather_ebpf_pinned() -> list[dict]:
    """Recursively walk /sys/fs/bpf and retrieve pinned objects."""
    pinned = []
    bpf_fs = Path("/sys/fs/bpf")
    if not bpf_fs.exists() or not bpf_fs.is_dir():
        return pinned

    try:
        for path in bpf_fs.rglob("*"):
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
    preload_path = Path("/etc/ld.so.preload")
    if not preload_path.exists():
        return lines

    try:
        with open(preload_path, "r", encoding="utf-8", errors="replace") as f:
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
    proc_path = Path("/proc")
    if not proc_path.exists() or not proc_path.is_dir():
        return special_fds

    try:
        for pid_dir in proc_path.iterdir():
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


# --- MAIN EXECUTION PIPELINE ---
def main():
    # Read config from JSON string argument if passed, else fallback to empty config
    config = {}
    if len(sys.argv) > 1:
        try:
            config = json.loads(sys.argv[1])
        except Exception as e:
            sys.stderr.write(f"[-] Warning: Failed to parse configuration argument: {e}\n")

    critical_paths = config.get("critical_paths", [
        "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab"
    ])
    critical_dirs = config.get("critical_dirs", [
        "/etc/cron.d", "/etc/systemd/system"
    ])
    suid_paths = config.get("suid_paths", DEFAULT_SUID_PATHS)
    vault_path_str = config.get("vault_path", "/var/lib/orin/vault")
    vault_path_resolved = os.path.realpath(os.path.expanduser(vault_path_str))
    if not is_safe_path(vault_path_resolved):
        vault_path_resolved = "/var/lib/orin/vault"

    # Gather target identification
    hostname = platform.node() or "unknown_host"
    os_platform = platform.platform() or "Linux"

    # Sequential execution of collectors
    processes = gather_active_processes()
    ports = gather_listening_ports()
    outbound = gather_outbound_connections()
    promisc = gather_promisc_interfaces()
    modules = gather_loaded_kernel_modules()
    symbols = gather_kernel_symbols()
    kernel_analysis = analyze_kernel_integrity(modules, symbols)
    users = gather_system_accounts()
    ssh_keys = gather_active_ssh_keys()
    crontabs = gather_crontabs()

    # WTMP/Lastlog
    wtmp = gather_wtmp_sessions()
    lastlog = gather_lastlog_records()

    # Deleted binaries
    deleted = gather_deleted_binaries(vault_dir=Path(vault_path_resolved))

    # File hashes (FIM)
    fim = gather_file_integrity_signatures(critical_paths, critical_dirs)

    # SUID binaries
    suid = gather_suid_binaries(suid_paths)

    # DPKG Package Integrity
    pkg_integrity = gather_pkg_integrity_drift()

    # Auth logs collection
    auth_logs = gather_auth_logs()

    # eBPF and special file descriptors
    ebpf_programs = gather_ebpf_programs()
    ebpf_pinned = gather_ebpf_pinned()
    ld_preload = gather_ld_preload()
    special_fds = gather_special_fds()

    # Compile report structure
    telemetry = {
        "hostname": hostname,
        "os_platform": os_platform,
        "processes": processes,
        "ports": ports,
        "outbound": outbound,
        "promisc": promisc,
        "modules": modules,
        "kernel_symbols": symbols,
        "kernel_analysis": kernel_analysis,
        "users": users,
        "ssh_keys": ssh_keys,
        "crontabs": crontabs,
        "wtmp": wtmp,
        "lastlog": lastlog,
        "deleted": deleted,
        "fim": fim,
        "suid": suid,
        "pkg_integrity": pkg_integrity,
        "auth_logs": auth_logs,
        "ebpf_programs": ebpf_programs,
        "ebpf_pinned": ebpf_pinned,
        "ld_preload": ld_preload,
        "special_fds": special_fds
    }

    # Print to stdout in a single line or clean JSON representation
    print(json.dumps(telemetry))

if __name__ == "__main__":
    main()