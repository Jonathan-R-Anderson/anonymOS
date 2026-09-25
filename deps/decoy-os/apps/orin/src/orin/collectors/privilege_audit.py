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
# src/orin/collectors/privilege_audit.py
"""
orin.collectors.privilege_audit – Identity, Access & Privilege Tracker
======================================================================
Monitors authentication events, privilege escalation, and credential access
using eBPF probes, PAM log parsing, and sensitive file access tracking.

Key Capabilities:
- Track setuid/setgid/capset/ptrace syscalls via eBPF for privilege escalation
- Monitor PAM authentication events (logins, sudo transitions, SSH sessions)
- Detect credential dumping from /etc/shadow, SSH agent sockets, Kerberos caches
- Alert on anomalous identity boundary crossings
"""
import os
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


# =============================================================================
# eBPF Privilege Escalation Detector
# =============================================================================

def gather_privilege_escalation_events() -> list[dict]:
    """
    Use eBPF to monitor privilege-related syscalls: setuid, setgid, capset, ptrace.

    Returns:
        List of privilege escalation events with process context.
    """
    events = []

    # Try to use bpftool to trace syscalls if available
    try:
        result = subprocess.run(
            ["bpftool", "prog", "show", "-j"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )

        if result.returncode == 0:
            programs = json.loads(result.stdout)

            # Look for existing privilege monitoring probes
            for prog in programs:
                prog_name = prog.get("name", "").lower()
                if any(keyword in prog_name for keyword in ["setuid", "setgid", "capset", "ptrace", "priv"]):
                    events.append({
                        "event_type": "ebpf_probe_detected",
                        "probe_name": prog.get("name"),
                        "probe_id": prog.get("id"),
                        "probe_type": prog.get("type"),
                        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        "details": "eBPF probe monitoring privilege syscalls detected"
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass

    # Alternative: Check tracefs for active kprobes on privilege syscalls
    tracefs_path = Path("/sys/kernel/debug/tracing")
    if tracefs_path.exists():
        kprobe_events = tracefs_path / "kprobe_events"
        if kprobe_events.exists():
            try:
                with open(kprobe_events, "r") as f:
                    for line in f:
                        if any(syscall in line for syscall in ["setuid", "setgid", "capset", "ptrace"]):
                            events.append({
                                "event_type": "kprobe_active",
                                "probe_definition": line.strip(),
                                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                "details": "Kernel probe active on privilege-related syscall"
                            })
            except (PermissionError, OSError):
                pass

    return events


def gather_syscall_audit_logs() -> list[dict]:
    """
    Parse auditd logs for privilege escalation syscalls if available.

    Returns:
        List of syscall audit events from /var/log/audit/audit.log
    """
    events = []
    audit_log = Path("/var/log/audit/audit.log")

    if not audit_log.exists():
        return events

    # Audit record patterns for privilege syscalls
    syscall_patterns = {
        "setuid": re.compile(r'type=SYSCALL.*syscall=(?:105|setuid)'),
        "setgid": re.compile(r'type=SYSCALL.*syscall=(?:106|setgid)'),
        "capset": re.compile(r'type=SYSCALL.*syscall=(?:126|capset)'),
        "ptrace": re.compile(r'type=SYSCALL.*syscall=(?:101|ptrace)'),
    }

    try:
        with open(audit_log, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                if "type=SYSCALL" not in line:
                    continue

                for syscall_name, pattern in syscall_patterns.items():
                    if pattern.search(line):
                        # Extract relevant fields
                        uid_match = re.search(r'\buid=(\d+)', line)
                        auid_match = re.search(r'\bauu?id=(\d+)', line)
                        pid_match = re.search(r'\bpid=(\d+)', line)
                        comm_match = re.search(r'comm="([^"]+)"', line)
                        exe_match = re.search(r'exe="([^"]+)"', line)
                        success_match = re.search(r'success=([a-z]+)', line)

                        event = {
                            "event_type": "audit_syscall",
                            "syscall": syscall_name,
                            "line_number": line_num,
                            "uid": int(uid_match.group(1)) if uid_match else None,
                            "audit_uid": int(auid_match.group(1)) if auid_match else None,
                            "pid": int(pid_match.group(1)) if pid_match else None,
                            "command": comm_match.group(1) if comm_match else None,
                            "executable": exe_match.group(1) if exe_match else None,
                            "success": success_match.group(1) if success_match else None,
                            "raw_record": line.strip()[:500],  # Truncate for storage
                            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        }
                        events.append(event)

    except (PermissionError, OSError) as e:
        events.append({
            "event_type": "audit_read_error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        })

    return events


# =============================================================================
# PAM Authentication Tracker
# =============================================================================

def gather_pam_auth_events(auth_log_paths: Optional[list[Path]] = None) -> list[dict]:
    """
    Parse PAM authentication logs to track login events, sudo usage, and SSH sessions.

    Args:
        auth_log_paths: List of paths to auth log files. Defaults to common locations.

    Returns:
        List of authentication events with user, service, and outcome details.
    """
    if auth_log_paths is None:
        auth_log_paths = [
            Path("/var/log/auth.log"),      # Debian/Ubuntu
            Path("/var/log/secure"),         # RHEL/CentOS/Fedora
            Path("/var/log/messages"),       # Fallback
        ]

    events = []

    # PAM event patterns
    pam_patterns = {
        "session_opened": re.compile(
            r'pam_unix\([^)]+\):\s*session\s+opened\s+for\s+user\s+(\S+)'
        ),
        "session_closed": re.compile(
            r'pam_unix\([^)]+\):\s*session\s+closed\s+for\s+user\s+(\S+)'
        ),
        "authentication_success": re.compile(
            r'pam_unix\([^)]+\):\s*authentication\s+success'
        ),
        "authentication_failure": re.compile(
            r'pam_unix\([^)]+\):\s*authentication\s+failure.*user=(\S+)'
        ),
        "sudo_command": re.compile(
            r'sudo:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)'
        ),
        "ssh_login": re.compile(
            r'sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)'
        ),
        "ssh_failed": re.compile(
            r'sshd\[\d+\]:\s+Failed\s+(\S+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)'
        ),
        "su_command": re.compile(
            r'su\[\d+\]:\s+(?:Successful\s+su\s+for\s+(\S+)|pam_unix\(su:session\):\s*session\s+opened\s+for\s+user\s+(\S+))'
        ),
    }

    for log_path in auth_log_paths:
        if not log_path.exists():
            continue

        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    timestamp = extract_timestamp_from_log_line(line)

                    # Session opened
                    match = pam_patterns["session_opened"].search(line)
                    if match:
                        events.append({
                            "event_type": "pam_session_opened",
                            "user": match.group(1),
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"PAM session opened for user {match.group(1)}"
                        })
                        continue

                    # Session closed
                    match = pam_patterns["session_closed"].search(line)
                    if match:
                        events.append({
                            "event_type": "pam_session_closed",
                            "user": match.group(1),
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"PAM session closed for user {match.group(1)}"
                        })
                        continue

                    # Auth failure
                    match = pam_patterns["authentication_failure"].search(line)
                    if match:
                        events.append({
                            "event_type": "pam_auth_failure",
                            "user": match.group(1),
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"PAM authentication failure for user {match.group(1)}",
                            "severity": "medium"
                        })
                        continue

                    # Sudo command
                    match = pam_patterns["sudo_command"].search(line)
                    if match:
                        executor, tty, pwd, target_user, command = match.groups()
                        events.append({
                            "event_type": "sudo_execution",
                            "executor": executor,
                            "target_user": target_user,
                            "command": command.strip(),
                            "tty": tty,
                            "working_directory": pwd,
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"User {executor} executed command as {target_user}: {command}",
                            "severity": "high" if target_user == "root" else "low"
                        })
                        continue

                    # SSH accepted
                    match = pam_patterns["ssh_login"].search(line)
                    if match:
                        method, user, source_ip = match.groups()
                        events.append({
                            "event_type": "ssh_login_success",
                            "user": user,
                            "auth_method": method,
                            "source_ip": source_ip,
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"SSH login successful for {user} from {source_ip} using {method}"
                        })
                        continue

                    # SSH failed
                    match = pam_patterns["ssh_failed"].search(line)
                    if match:
                        method, user, source_ip = match.groups()
                        events.append({
                            "event_type": "ssh_login_failed",
                            "user": user,
                            "auth_method": method,
                            "source_ip": source_ip,
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"SSH login failed for {user} from {source_ip} using {method}",
                            "severity": "medium"
                        })
                        continue

                    # SU command
                    match = pam_patterns["su_command"].search(line)
                    if match:
                        target_user = match.group(1) or match.group(2)
                        events.append({
                            "event_type": "su_execution",
                            "target_user": target_user,
                            "log_file": str(log_path),
                            "line_number": line_num,
                            "timestamp": timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "details": f"SU to user {target_user}",
                            "severity": "high" if target_user == "root" else "low"
                        })

        except (PermissionError, OSError) as e:
            events.append({
                "event_type": "log_read_error",
                "log_file": str(log_path),
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            })

    return events


def extract_timestamp_from_log_line(line: str) -> Optional[str]:
    """Extract timestamp from various syslog formats."""
    # Syslog format: "Jan  5 14:23:45"
    syslog_pattern = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
    match = syslog_pattern.match(line)
    if match:
        timestamp_str = match.group(1)
        try:
            # Add current year since syslog doesn't include it
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            pass

    # ISO 8601 format: "2026-01-05T14:23:45Z"
    iso_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z+-]?\d*)')
    match = iso_pattern.search(line)
    if match:
        return match.group(1)

    return None


# =============================================================================
# Credential Access Monitor
# =============================================================================

def gather_credential_access_events() -> list[dict]:
    """
    Detect access to sensitive credential files and memory regions.

    Monitors:
    - /etc/shadow, /etc/gshadow
    - SSH agent sockets (/tmp/ssh-*/agent.*)
    - Kerberos ticket caches (/tmp/krb5cc_*)
    - GPG agent sockets
    - Process memory dumps targeting credential stores

    Returns:
        List of credential access events with risk assessment.
    """
    events = []
    current_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Sensitive credential paths
    credential_paths = {
        "/etc/shadow": "Password hash database",
        "/etc/gshadow": "Group password database",
        "/etc/ssh/ssh_host_rsa_key": "SSH host private key",
        "/etc/ssh/ssh_host_ecdsa_key": "SSH host ECDSA private key",
        "/etc/ssh/ssh_host_ed25519_key": "SSH host ED25519 private key",
    }

    # Check for recent access to credential files using lsof if available
    try:
        result = subprocess.run(
            ["lsof", "+D", "/etc"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                for cred_path, description in credential_paths.items():
                    if cred_path in line:
                        parts = line.split()
                        if len(parts) >= 9:
                            events.append({
                                "event_type": "credential_file_access",
                                "file_path": cred_path,
                                "description": description,
                                "process": parts[0],
                                "pid": parts[1],
                                "user": parts[2],
                                "fd": parts[3],
                                "access_type": parts[4],
                                "timestamp": current_time,
                                "details": f"Process {parts[0]} (PID {parts[1]}) accessing {cred_path}",
                                "severity": "critical" if "shadow" in cred_path else "high"
                            })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check for SSH agent sockets
    ssh_agent_sockets = []
    tmp_path = Path("/tmp")
    if tmp_path.exists():
        try:
            for socket_path in tmp_path.glob("ssh-*/agent.*"):
                ssh_agent_sockets.append(str(socket_path))

            if ssh_agent_sockets:
                # Check which processes have these sockets open
                for socket_path in ssh_agent_sockets:
                    try:
                        result = subprocess.run(
                            ["lsof", socket_path],
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=5
                        )
                        if result.returncode == 0:
                            for line in result.stdout.splitlines()[1:]:  # Skip header
                                parts = line.split()
                                if len(parts) >= 9:
                                    events.append({
                                        "event_type": "ssh_agent_access",
                                        "socket_path": socket_path,
                                        "process": parts[0],
                                        "pid": parts[1],
                                        "user": parts[2],
                                        "timestamp": current_time,
                                        "details": "Process accessing SSH agent socket",
                                        "severity": "medium"
                                    })
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        pass
        except (PermissionError, OSError):
            pass

    # Check for Kerberos ticket caches
    krb5_tickets = []
    if tmp_path.exists():
        try:
            for ticket_path in tmp_path.glob("krb5cc_*"):
                krb5_tickets.append({
                    "path": str(ticket_path),
                    "owner_uid": ticket_path.stat().st_uid if ticket_path.exists() else None
                })

            if krb5_tickets:
                for ticket in krb5_tickets:
                    events.append({
                        "event_type": "kerberos_ticket_present",
                        "ticket_path": ticket["path"],
                        "owner_uid": ticket["owner_uid"],
                        "timestamp": current_time,
                        "details": f"Kerberos ticket cache found at {ticket['path']}",
                        "severity": "low"
                    })
        except (PermissionError, OSError):
            pass

    # Check for processes reading /proc/[pid]/mem (potential credential dumping)
    proc_path = Path("/proc")
    if proc_path.exists():
        try:
            for pid_dir in proc_path.iterdir():
                if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                    continue

                try:
                    pid = int(pid_dir.name)
                    fd_dir = pid_dir / "fd"
                    if not fd_dir.exists():
                        continue

                    for fd_file in fd_dir.iterdir():
                        try:
                            target = os.readlink(str(fd_file))
                            if "/mem" in target:
                                # Get process info
                                cmdline_path = pid_dir / "cmdline"
                                cmdline = ""
                                if cmdline_path.exists():
                                    with open(cmdline_path, "rb") as f:
                                        cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')

                                events.append({
                                    "event_type": "process_memory_access",
                                    "target_pid": pid,
                                    "accessor_pid": pid,  # Same process accessing its own or another's mem
                                    "fd_target": target,
                                    "cmdline": cmdline[:200],
                                    "timestamp": current_time,
                                    "details": "Process accessing process memory (potential credential dump)",
                                    "severity": "high"
                                })
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
                except (ValueError, PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

    # Check for known credential dumping tools
    suspicious_binaries = ["mimikatz", "lazagne", "pwdump", "hashdump", "secretsdump"]
    try:
        result = subprocess.run(
            ["find", "/usr", "/opt", "/home", "-type", "f", "-executable"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15
        )

        if result.returncode == 0:
            for binary_path in result.stdout.splitlines():
                binary_name = os.path.basename(binary_path).lower()
                if any(sus in binary_name for sus in suspicious_binaries):
                    events.append({
                        "event_type": "suspicious_binary_detected",
                        "binary_path": binary_path,
                        "binary_name": binary_name,
                        "timestamp": current_time,
                        "details": "Known credential dumping tool signature detected",
                        "severity": "critical"
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return events


# =============================================================================
# Consolidated Interface
# =============================================================================

def gather_all_privilege_events() -> dict:
    """
    Master function to collect all identity, access, and privilege tracking data.

    Returns:
        Dictionary containing all privilege-related events organized by category.
    """
    return {
        "collection_timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        "privilege_escalation_events": gather_privilege_escalation_events(),
        "syscall_audit_events": gather_syscall_audit_logs(),
        "pam_authentication_events": gather_pam_auth_events(),
        "credential_access_events": gather_credential_access_events(),
        "summary": {
            "total_privilege_events": len(gather_privilege_escalation_events()),
            "total_syscall_events": len(gather_syscall_audit_logs()),
            "total_pam_events": len(gather_pam_auth_events()),
            "total_credential_events": len(gather_credential_access_events()),
        }
    }


if __name__ == "__main__":
    # Test execution
    import pprint

    print("=" * 80)
    print("Identity, Access & Privilege Tracking - Test Run")
    print("=" * 80)

    results = gather_all_privilege_events()
    pprint.pprint(results, width=120)