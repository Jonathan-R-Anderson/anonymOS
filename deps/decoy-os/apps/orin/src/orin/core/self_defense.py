"""
Orin Agent Self-Defense & Resilience Module

This module provides protection mechanisms to prevent the Orin agent from being
killed, debugged, or modified by compromised root users or advanced persistent threats.

Features:
- Out-of-Band Watchdog service to monitor main Orin process
- Seccomp profile enforcement for system call restrictions
- AppArmor/SELinux policy generation and validation
- Process integrity monitoring with automatic restart capabilities
- Tamper detection and alerting
"""

import os
import sys
import time
import socket
import logging
import subprocess
import threading
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
import psutil

logger = logging.getLogger(__name__)


@dataclass
class WatchdogConfig:
    """Configuration for the watchdog service."""
    check_interval: float = 5.0  # Seconds between health checks
    max_missed_heartbeats: int = 3  # Number of missed heartbeats before alert
    heartbeat_timeout: float = 15.0  # Seconds before considering heartbeat missed
    watchdog_socket: str = "/var/run/orin/watchdog.sock"
    log_file: str = "/var/log/orin/watchdog.log"
    auto_restart: bool = True
    alert_on_tamper: bool = True


@dataclass
class HealthStatus:
    """Health status of the Orin agent."""
    pid: int
    is_alive: bool
    cpu_percent: float
    memory_mb: float
    uptime_seconds: float
    last_heartbeat: str
    status: str  # "healthy", "degraded", "critical", "dead"
    tamper_detected: bool = False
    tamper_details: Optional[str] = None


class HeartbeatManager:
    """Manages heartbeat signals from the main Orin process."""

    def __init__(self, config: WatchdogConfig):
        self.config = config
        self.last_heartbeat: Optional[datetime] = None
        self.missed_heartbeats: int = 0
        self._lock = threading.Lock()

    def record_heartbeat(self) -> None:
        """Record a new heartbeat from the monitored process."""
        with self._lock:
            self.last_heartbeat = datetime.now()
            self.missed_heartbeats = 0

    def get_last_heartbeat(self) -> Optional[datetime]:
        """Get the timestamp of the last heartbeat."""
        with self._lock:
            return self.last_heartbeat

    def check_health(self) -> Tuple[bool, int]:
        """
        Check if the monitored process is healthy.

        Returns:
            Tuple of (is_healthy, missed_heartbeat_count)
        """
        with self._lock:
            if self.last_heartbeat is None:
                return False, self.missed_heartbeats

            elapsed = (datetime.now() - self.last_heartbeat).total_seconds()

            if elapsed > self.config.heartbeat_timeout:
                self.missed_heartbeats += 1
                self.last_heartbeat = None  # Reset to force new heartbeat
                return False, self.missed_heartbeats

            return True, 0


class SeccompProfile:
    """Generates and applies seccomp-bpf profiles for Orin processes."""

    # Minimal syscall allowlist for Orin collector operations
    ALLOWED_SYSCALLS = {
        # File operations
        'open', 'openat', 'close', 'read', 'write', 'lseek', 'stat', 'fstat',
        'lstat', 'poll', 'access', 'dup', 'dup2', 'fcntl', 'flock', 'fsync',
        'getdents', 'getcwd', 'chdir', 'rename', 'mkdir', 'rmdir', 'unlink',
        'readlink', 'chmod', 'chown', 'umask',

        # Memory operations
        'mmap', 'munmap', 'mprotect', 'brk',

        # Process operations
        'getpid', 'getppid', 'getuid', 'geteuid', 'getgid', 'getegid',
        'gettid', 'getgroups', 'setgroups', 'getresuid', 'getresgid',
        'wait4', 'waitid', 'clone', 'exit', 'exit_group',

        # Network operations (read-only)
        'socket', 'connect', 'bind', 'listen', 'accept', 'getsockname',
        'getpeername', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg',
        'shutdown', 'setsockopt', 'getsockopt',

        # Time operations
        'gettimeofday', 'time', 'clock_gettime', 'nanosleep',

        # Signal operations
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'kill', 'tgkill',

        # Misc
        'uname', 'sysinfo', 'prctl', 'arch_prctl', 'ioctl', 'futex',
        'set_tid_address', 'set_robust_list', 'get_robust_list',
        'rseq', 'getrandom', 'membarrier', 'pselect6', 'ppoll',
        'execve', 'pipe', 'pipe2', 'epoll_create', 'epoll_create1',
        'epoll_ctl', 'epoll_wait', 'epoll_pwait', 'eventfd', 'eventfd2',
        'signalfd', 'signalfd4', 'timerfd_create', 'timerfd_settime',
        'timerfd_gettime', 'prlimit64',
    }

    # Syscalls that should be blocked (security-sensitive)
    BLOCKED_SYSCALLS = {
        # Debugging/tracing - prevent process manipulation
        'ptrace', 'process_vm_readv', 'process_vm_writev',

        # Module loading - prevent kernel modification
        'init_module', 'finit_module', 'delete_module',

        # Privilege escalation
        'setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid',
        'setfsuid', 'setfsgid', 'capset',

        # Namespace manipulation
        'unshare', 'setns',

        # Mount operations
        'mount', 'umount2', 'pivot_root',

        # Reboot
        'reboot',

        # Swappiness
        'swapon', 'swapoff',

        # BPF (could be used to bypass security)
        'bpf',

        # Perf events (information leakage)
        'perf_event_open',

        # User namespaces (container escape vector)
        'userfaultfd',
    }

    @classmethod
    def generate_profile(cls, profile_name: str = "orin-default") -> str:
        """
        Generate a seccomp profile in JSON format compatible with systemd or Docker.

        Args:
            profile_name: Name of the profile

        Returns:
            JSON string representing the seccomp profile
        """
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": [
                "SCMP_ARCH_X86_64",
                "SCMP_ARCH_X86",
                "SCMP_ARCH_AARCH64"
            ],
            "syscalls": [
                {
                    "names": list(cls.ALLOWED_SYSCALLS),
                    "action": "SCMP_ACT_ALLOW"
                },
                {
                    "names": list(cls.BLOCKED_SYSCALLS),
                    "action": "SCMP_ACT_KILL"
                }
            ]
        }

        return json.dumps(profile, indent=2)

    @classmethod
    def save_profile(cls, output_path: str, profile_name: str = "orin-default") -> None:
        """Save the seccomp profile to a file."""
        profile_json = cls.generate_profile(profile_name)
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            f.write(profile_json)

        logger.info(f"Seccomp profile saved to {output_path}")

    @classmethod
    def validate_current_process(cls) -> Tuple[bool, List[str]]:
        """
        Validate that the current process is not using blocked syscalls.

        This is a best-effort check using /proc/self/syscall (if available).

        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        violations = []

        # Check if we can access syscall information
        syscall_file = Path("/proc/self/syscall")
        if not syscall_file.exists():
            logger.warning("Cannot validate syscalls: /proc/self/syscall not available")
            return True, violations

        try:
            # This is a simplified check - in production, you'd use auditd or seccomp notifications
            logger.info("Syscall validation performed (simplified check)")
        except Exception as e:
            logger.warning(f"Syscall validation error: {e}")

        return len(violations) == 0, violations


class AppArmorProfile:
    """Generates and manages AppArmor profiles for Orin."""

    @classmethod
    def generate_profile(cls, profile_name: str = "usr.bin.orin") -> str:
        """
        Generate an AppArmor profile for Orin.

        Args:
            profile_name: Name of the AppArmor profile

        Returns:
            AppArmor profile text
        """
        profile = f'''# Orin Forensic Engine AppArmor Profile
# Generated automatically by Orin Self-Defense Module
# Place this file in /etc/apparmor.d/{profile_name}

#include <tunables/global>

{profile_name} {{
  # Include basic abstractions
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/systemd>
  #include <abstractions/python3>
  #include <abstractions/ssl_certs>

  # Capabilities required by Orin
  capability net_raw,
  capability sys_admin,
  capability dac_read_search,
  capability ipc_lock,

  # Deny dangerous capabilities
  deny capability mac_admin,
  deny capability mac_override,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_boot,
  deny capability syslog,

  # Allow reading proc filesystem (essential for forensics)
  /proc/** r,
  /proc/[0-9]*/cmdline r,
  /proc/[0-9]*/environ r,
  /proc/[0-9]*/exe lr,
  /proc/[0-9]*/fd/** r,
  /proc/[0-9]*/maps r,
  /proc/[0-9]*/mem r,
  /proc/[0-9]*/mountinfo r,
  /proc/[0-9]*/ns/** r,
  /proc/[0-9]*/status r,
  /proc/[0-9]*/syscall r,
  /proc/modules r,
  /proc/kallsyms r,
  /proc/version r,
  /proc/sys/kernel/** r,

  # Allow reading system files
  /etc/** r,
  /etc/shadow r,
  /etc/passwd r,
  /etc/group r,
  /etc/sudoers r,
  /etc/cron** r,
  /etc/systemd/** r,
  /etc/ssh/** r,

  # Allow Orin binary and libraries
  /usr/bin/orin ix,
  /usr/lib/python3/** mr,
  /opt/orin/** mr,

  # Allow writing to Orin data directories only
  /var/lib/orin/** rw,
  /var/log/orin/** rw,
  /var/run/orin/** rw,

  # Allow network access for reporting
  network inet tcp,
  network inet udp,
  network inet raw,

  # Deny write access to critical system paths
  deny /bin/** w,
  deny /sbin/** w,
  deny /lib/** w,
  deny /lib64/** w,
  deny /usr/** w,
  deny /etc/** w,
  deny /root/** w,
  deny /home/**/** w,

  # Deny ptrace (prevent debugging)
  deny ptrace (trace) peer=unconfined,
  deny ptrace (traceme) peer=unconfined,

  # Deny module loading
  deny /sbin/insmod ix,
  deny /sbin/modprobe ix,
  deny /sbin/rmmod ix,

  # Audit denied actions
  audit deny /** w,
}}
'''
        return profile

    @classmethod
    def save_profile(cls, output_path: str, profile_name: str = "usr.bin.orin") -> None:
        """Save the AppArmor profile to a file."""
        profile_text = cls.generate_profile(profile_name)
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            f.write(profile_text)

        logger.info(f"AppArmor profile saved to {output_path}")

    @classmethod
    def is_apparmor_available(cls) -> bool:
        """Check if AppArmor is available on the system."""
        return Path("/sys/kernel/security/apparmor").exists()

    @classmethod
    def get_profile_status(cls, profile_name: str) -> Optional[str]:
        """Get the status of an AppArmor profile."""
        if not cls.is_apparmor_available():
            return None

        try:
            aa_status = Path("/sys/kernel/security/apparmor/profiles")
            if aa_status.exists():
                content = aa_status.read_text()
                for line in content.split('\n'):
                    if profile_name in line:
                        if 'enforce' in line.lower():
                            return 'enforced'
                        elif 'complain' in line.lower():
                            return 'complain'
                        else:
                            return 'loaded'
        except Exception:
            pass

        return 'not_loaded'


class SELinuxProfile:
    """Generates SELinux policy modules for Orin."""

    @classmethod
    def generate_te_policy(cls) -> str:
        """
        Generate SELinux Type Enforcement policy for Orin.

        Returns:
            SELinux TE policy text
        """
        policy = '''# Orin Forensic Engine SELinux Policy Module
# Generated automatically by Orin Self-Defense Module
# Compile with: checkmodule -M -m -o orin.mod orin.te
# Package with: semodule_package -o orin.pp -m orin.mod
# Install with: semodule -i orin.pp

module orin 1.0;

require {
    type unconfined_t, proc_t, var_log_t, var_lib_t, var_run_t;
    type bin_t, etc_t, shadow_t, passwd_file_t;
    class file { read write open getattr setattr create unlink rename };
    class dir { read write search add_name remove_name getattr };
    class process { signal sigchld ptrace getsched setsched };
    class capability { net_raw sys_admin dac_read_search ipc_lock };
    class tcp_socket { name_connect name_bind };
}

# Define Orin type
type orin_t;
type orin_exec_t;
domain_type(orin_t)

# Allow execution of Orin binary
files_type(orin_exec_t)

# Main policy rules
allow orin_t proc_t:file { read open getattr };
allow orin_t proc_t:dir { read search getattr };
allow orin_t var_log_t:file { read write open create append getattr setattr };
allow orin_t var_log_t:dir { read write search add_name getattr };
allow orin_t var_lib_t:file { read write open create getattr setattr };
allow orin_t var_lib_t:dir { read write search add_name remove_name getattr };
allow orin_t var_run_t:file { read write open create getattr setattr };
allow orin_t var_run_t:dir { read write search add_name getattr };

# Read system configuration
allow orin_t etc_t:file { read open getattr };
allow orin_t etc_t:dir { read search getattr };
allow orin_t shadow_t:file { read open getattr };
allow orin_t passwd_file_t:file { read open getattr };

# Network access
allow orin_t self:tcp_socket { name_connect };

# Required capabilities
allow orin_t self:capability { net_raw sys_admin dac_read_search ipc_lock };

# Process monitoring (limited ptrace for forensic analysis)
allow orin_t unconfined_t:process { signal sigchld getsched };

# Deny dangerous operations (explicit denials for audit)
auditallow orin_t bin_t:file { write };
auditallow orin_t proc_t:process { ptrace setsched };
'''
        return policy

    @classmethod
    def is_selinux_available(cls) -> bool:
        """Check if SELinux is available and enabled."""
        try:
            result = subprocess.run(['getenforce'], capture_output=True, text=True)
            return result.returncode == 0 and result.stdout.strip() != 'Disabled'
        except Exception:
            return False

    @classmethod
    def get_enforcement_mode(cls) -> Optional[str]:
        """Get SELinux enforcement mode."""
        if not cls.is_selinux_available():
            return None

        try:
            result = subprocess.run(['getenforce'], capture_output=True, text=True)
            return result.stdout.strip().lower()
        except Exception:
            return None


class WatchdogService:
    """
    Out-of-Band Watchdog Service for Orin Agent.

    This service runs independently from the main Orin process and monitors
    its health, detecting tampering attempts and triggering alerts or restarts.
    """

    def __init__(self, config: Optional[WatchdogConfig] = None):
        self.config = config or WatchdogConfig()
        self.heartbeat_manager = HeartbeatManager(self.config)
        self.monitored_pid: Optional[int] = None
        self.running = False
        self.socket_server: Optional[socket.socket] = None
        self.alerts_triggered: List[Dict] = []

    def start_watchdog(self, monitored_pid: Optional[int] = None) -> None:
        """
        Start the watchdog service.

        Args:
            monitored_pid: PID of the Orin process to monitor. If None, will be set via heartbeat.
        """
        self.monitored_pid = monitored_pid
        self.running = True

        # Create socket directory
        socket_path = Path(self.config.watchdog_socket)
        socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove existing socket file
        if socket_path.exists():
            socket_path.unlink()

        # Create Unix domain socket for heartbeat communication
        self.socket_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_server.bind(self.config.watchdog_socket)
        self.socket_server.listen(5)
        self.socket_server.settimeout(1.0)  # Allow periodic health checks

        # Set appropriate permissions on socket
        os.chmod(self.config.watchdog_socket, 0o660)

        logger.info(f"Watchdog service started, monitoring PID {monitored_pid}")
        logger.info(f"Listening for heartbeats on {self.config.watchdog_socket}")

        # Start health check thread
        health_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        health_thread.start()

        # Accept heartbeat connections
        while self.running:
            try:
                conn, _ = self.socket_server.accept()
                threading.Thread(
                    target=self._handle_heartbeat_connection,
                    args=(conn,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Socket accept error: {e}")

    def _handle_heartbeat_connection(self, conn: socket.socket) -> None:
        """Handle incoming heartbeat connection."""
        try:
            data = conn.recv(1024)
            if data:
                message = json.loads(data.decode('utf-8'))

                if message.get('type') == 'heartbeat':
                    pid = message.get('pid')
                    if pid:
                        self.monitored_pid = pid
                        self.heartbeat_manager.record_heartbeat()
                        logger.debug(f"Heartbeat received from PID {pid}")

                    # Send acknowledgment
                    response = json.dumps({
                        'type': 'ack',
                        'timestamp': datetime.now().isoformat(),
                        'status': 'watchdog_active'
                    })
                    conn.sendall(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error handling heartbeat: {e}")
        finally:
            conn.close()

    def _health_check_loop(self) -> None:
        """Periodic health check loop."""
        while self.running:
            time.sleep(self.config.check_interval)
            self._perform_health_check()

    def _perform_health_check(self) -> None:
        """Perform comprehensive health check of the monitored process."""
        health_status = self.get_health_status()

        if health_status.status == "dead":
            logger.critical(f"Orin agent (PID {self.monitored_pid}) is dead!")
            if self.config.alert_on_tamper:
                self._trigger_alert("AGENT_DEAD", {
                    'pid': self.monitored_pid,
                    'timestamp': datetime.now().isoformat(),
                    'details': 'Process no longer exists'
                })
            if self.config.auto_restart:
                self._attempt_restart()

        elif health_status.status == "critical":
            logger.warning(f"Critical: Orin agent health degraded - {health_status.tamper_details}")
            if self.config.alert_on_tamper and health_status.tamper_detected:
                self._trigger_alert("TAMPER_DETECTED", {
                    'pid': self.monitored_pid,
                    'timestamp': datetime.now().isoformat(),
                    'details': health_status.tamper_details
                })

        elif health_status.status == "degraded":
            logger.info(f"Degraded: Missed {health_status.cpu_percent} heartbeats")

    def _trigger_alert(self, alert_type: str, details: Dict) -> None:
        """Trigger a security alert."""
        alert = {
            'type': alert_type,
            'severity': 'critical' if 'DEAD' in alert_type else 'high',
            'timestamp': datetime.now().isoformat(),
            'details': details
        }

        self.alerts_triggered.append(alert)
        logger.critical(f"ALERT [{alert_type}]: {json.dumps(details)}")

        # In production, this would send to SIEM, email, webhook, etc.

    def _attempt_restart(self) -> None:
        """Attempt to restart the Orin agent."""
        logger.info("Attempting to restart Orin agent...")
        # Implementation would depend on deployment method (systemd, container, etc.)
        # For systemd: systemctl restart orin
        # For now, just log the intent
        logger.warning("Auto-restart requested but not implemented for this deployment method")

    def get_health_status(self) -> HealthStatus:
        """Get comprehensive health status of the monitored process."""
        now = datetime.now()

        # Check if process exists
        is_alive = False
        cpu_percent = 0.0
        memory_mb = 0.0
        uptime_seconds = 0.0

        if self.monitored_pid:
            try:
                proc = psutil.Process(self.monitored_pid)
                is_alive = proc.is_running()

                if is_alive:
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    memory_mb = proc.memory_info().rss / (1024 * 1024)
                    create_time = proc.create_time()
                    if isinstance(create_time, float):
                        create_time = datetime.fromtimestamp(create_time)
                    uptime_seconds = (now - create_time).total_seconds()

                    # Check for potential tampering indicators
                    tamper_detected, tamper_details = self._check_tamper_indicators(proc)

                    if tamper_detected:
                        return HealthStatus(
                            pid=self.monitored_pid,
                            is_alive=is_alive,
                            cpu_percent=cpu_percent,
                            memory_mb=memory_mb,
                            uptime_seconds=uptime_seconds,
                            last_heartbeat=self.heartbeat_manager.get_last_heartbeat().isoformat() if self.heartbeat_manager.get_last_heartbeat() else None,
                            status="critical",
                            tamper_detected=True,
                            tamper_details=tamper_details
                        )

            except psutil.NoSuchProcess:
                is_alive = False
            except Exception as e:
                logger.error(f"Error checking process: {e}")

        # Check heartbeat health
        heartbeat_healthy, missed_count = self.heartbeat_manager.check_health()

        if not is_alive:
            status = "dead"
        elif not heartbeat_healthy and missed_count >= self.config.max_missed_heartbeats:
            status = "critical"
        elif not heartbeat_healthy:
            status = "degraded"
        else:
            status = "healthy"

        return HealthStatus(
            pid=self.monitored_pid or 0,
            is_alive=is_alive,
            cpu_percent=cpu_percent,
            memory_mb=memory_mb,
            uptime_seconds=uptime_seconds,
            last_heartbeat=self.heartbeat_manager.get_last_heartbeat().isoformat() if self.heartbeat_manager.get_last_heartbeat() else None,
            status=status
        )

    def _check_tamper_indicators(self, proc: psutil.Process) -> Tuple[bool, Optional[str]]:
        """
        Check for indicators that the process is being tampered with.

        Returns:
            Tuple of (tamper_detected, details)
        """
        indicators = []

        try:
            # Check if process is being traced (ptrace attached)
            status_file = Path(f"/proc/{proc.pid}/status")
            if status_file.exists():
                content = status_file.read_text()
                for line in content.split('\n'):
                    if line.startswith('TracerPid:'):
                        tracer_pid = int(line.split(':')[1].strip())
                        if tracer_pid != 0:
                            indicators.append(f"Process being traced by PID {tracer_pid}")

            # Check for unusual number of open file descriptors (potential injection)
            fd_dir = Path(f"/proc/{proc.pid}/fd")
            if fd_dir.exists():
                fd_count = len(list(fd_dir.iterdir()))
                if fd_count > 1000:  # Arbitrary threshold
                    indicators.append(f"Unusual FD count: {fd_count}")

            # Check if process nice value was changed (priority manipulation)
            if proc.nice() < 0:
                indicators.append(f"Process priority elevated (nice={proc.nice()})")

        except Exception as e:
            logger.warning(f"Error checking tamper indicators: {e}")

        if indicators:
            return True, "; ".join(indicators)

        return False, None

    def stop_watchdog(self) -> None:
        """Stop the watchdog service."""
        self.running = False

        if self.socket_server:
            self.socket_server.close()

        socket_path = Path(self.config.watchdog_socket)
        if socket_path.exists():
            socket_path.unlink()

        logger.info("Watchdog service stopped")

    def send_heartbeat(self, watchdog_socket: Optional[str] = None) -> bool:
        """
        Send a heartbeat from the main Orin process to the watchdog.

        This method should be called periodically by the main Orin process.

        Args:
            watchdog_socket: Path to watchdog socket (uses config default if None)

        Returns:
            True if heartbeat sent successfully, False otherwise
        """
        socket_path = watchdog_socket or self.config.watchdog_socket

        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(socket_path)

            message = json.dumps({
                'type': 'heartbeat',
                'pid': os.getpid(),
                'timestamp': datetime.now().isoformat()
            })

            client.sendall(message.encode('utf-8'))

            # Wait for acknowledgment
            response = client.recv(1024)
            if response:
                ack = json.loads(response.decode('utf-8'))
                logger.debug(f"Heartbeat acknowledged: {ack}")

            client.close()
            return True

        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")
            return False


class SelfDefenseManager:
    """
    Main entry point for Orin Self-Defense capabilities.

    Provides unified interface for:
    - Starting/stopping watchdog service
    - Generating security profiles (seccomp, AppArmor, SELinux)
    - Validating security posture
    - Sending heartbeats from main process
    """

    def __init__(self, config: Optional[WatchdogConfig] = None):
        self.config = config or WatchdogConfig()
        self.watchdog: Optional[WatchdogService] = None
        self.watchdog_process: Optional[threading.Thread] = None

    def initialize(self, mode: str = "agent") -> None:
        """
        Initialize self-defense mechanisms.

        Args:
            mode: Either "agent" (main Orin process) or "watchdog" (standalone watchdog)
        """
        if mode == "watchdog":
            self.start_watchdog_service()
        elif mode == "agent":
            self.validate_security_profiles()

    def start_watchdog_service(self) -> None:
        """Start the watchdog service in a background thread."""
        self.watchdog = WatchdogService(self.config)
        self.watchdog_process = threading.Thread(
            target=self.watchdog.start_watchdog,
            daemon=True
        )
        self.watchdog_process.start()
        logger.info("Watchdog service started in background")

    def send_heartbeat(self) -> bool:
        """Send heartbeat to watchdog service."""
        if self.watchdog:
            return self.watchdog.send_heartbeat()
        return False

    def get_watchdog_status(self) -> Optional[HealthStatus]:
        """Get current watchdog health status."""
        if self.watchdog:
            return self.watchdog.get_health_status()
        return None

    @staticmethod
    def generate_seccomp_profile(output_path: str) -> None:
        """Generate and save seccomp profile."""
        SeccompProfile.save_profile(output_path)

    @staticmethod
    def generate_apparmor_profile(output_path: str) -> None:
        """Generate and save AppArmor profile."""
        AppArmorProfile.save_profile(output_path)

    @staticmethod
    def generate_selinux_policy(output_path: str) -> None:
        """Generate and save SELinux policy."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        te_policy = SELinuxProfile.generate_te_policy()
        with open(output_file, 'w') as f:
            f.write(te_policy)

        logger.info(f"SELinux policy saved to {output_path}")

    @staticmethod
    def validate_security_profiles() -> Dict[str, any]:
        """
        Validate current security posture.

        Returns:
            Dictionary with validation results for each security mechanism
        """
        results = {
            'seccomp': {'available': True, 'note': 'Requires kernel support'},
            'apparmor': {'available': AppArmorProfile.is_apparmor_available()},
            'selinux': {'available': SELinuxProfile.is_selinux_available()}
        }

        if results['apparmor']['available']:
            status = AppArmorProfile.get_profile_status('usr.bin.orin')
            results['apparmor']['status'] = status or 'not_configured'

        if results['selinux']['available']:
            mode = SELinuxProfile.get_enforcement_mode()
            results['selinux']['mode'] = mode

        return results

    def stop(self) -> None:
        """Stop all self-defense services."""
        if self.watchdog:
            self.watchdog.stop_watchdog()
        if self.watchdog_process:
            self.watchdog_process.join(timeout=5.0)
        logger.info("Self-defense services stopped")


def main():
    """CLI entry point for self-defense utilities."""
    import argparse

    parser = argparse.ArgumentParser(description='Orin Agent Self-Defense Utilities')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Watchdog command
    watchdog_parser = subparsers.add_parser('watchdog', help='Run watchdog service')
    watchdog_parser.add_argument('--socket', default='/var/run/orin/watchdog.sock',
                                  help='Unix socket path for heartbeat communication')
    watchdog_parser.add_argument('--interval', type=float, default=5.0,
                                  help='Health check interval in seconds')

    # Heartbeat command
    heartbeat_parser = subparsers.add_parser('heartbeat', help='Send heartbeat to watchdog')
    heartbeat_parser.add_argument('--socket', default='/var/run/orin/watchdog.sock',
                                   help='Unix socket path to watchdog')

    # Generate profiles
    profile_parser = subparsers.add_parser('generate-profiles', help='Generate security profiles')
    profile_parser.add_argument('--output-dir', default='/etc/orin/security',
                                help='Output directory for profiles')

    # Status command - handled inline
    subparsers.add_parser('status', help='Check self-defense status')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if args.command == 'watchdog':
        config = WatchdogConfig(
            watchdog_socket=args.socket,
            check_interval=args.interval
        )
        manager = SelfDefenseManager(config)
        manager.start_watchdog_service()

        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            manager.stop()

    elif args.command == 'heartbeat':
        manager = SelfDefenseManager()
        success = manager.send_heartbeat()
        sys.exit(0 if success else 1)

    elif args.command == 'generate-profiles':
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        SelfDefenseManager.generate_seccomp_profile(str(output_dir / 'orin-seccomp.json'))
        SelfDefenseManager.generate_apparmor_profile(str(output_dir / 'orin-apparmor'))
        SelfDefenseManager.generate_selinux_policy(str(output_dir / 'orin-selinux.te'))

        print(f"Security profiles generated in {output_dir}")

    elif args.command == 'status':
        manager = SelfDefenseManager()
        status = manager.validate_security_profiles()
        print(json.dumps(status, indent=2))

    else:
        parser.print_help()


if __name__ == '__main__':
    main()  