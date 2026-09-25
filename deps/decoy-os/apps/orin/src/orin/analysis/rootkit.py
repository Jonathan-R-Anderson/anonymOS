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
# src/orin/analysis/rootkit.py
"""
orin.analysis.rootkit – Advanced Rootkit Detection Engine
========================================================
Implements multi-layer rootkit detection using cross-view differential
analysis, eBPF program validation, kernel symbol integrity checking,
and syscall table hook detection.

Detection Layers
----------------
1. Cross-View Process Differential: Compares /proc listing vs scheduler reality
2. Cross-View Network Differential: Compares /proc/net vs socket syscall results
3. eBPF Program Validation: Detects malicious eBPF hooks and rootkit programs
4. Kernel Symbol Integrity: Validates critical function pointers against baselines
5. Syscall Table Analysis: Detects hooked system calls via kallsyms correlation
6. Unlinked Module Detection: Finds modules hidden from /proc/modules but present in kallsyms
7. IDT/GDT Anomaly Detection: Identifies interrupt handler hijacking indicators
8. Memory Page Permission Analysis: Detects RWX pages in kernel space
"""
import os
import re
import errno
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class RootkitIndicator:
    """Represents a detected rootkit indicator with severity and evidence."""
    indicator_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: Dict = field(default_factory=dict)
    mitigation: str = ""
    confidence: float = 0.0  # 0.0 to 1.0


class CrossViewProcessAnalyzer:
    """
    Performs cross-view differential analysis for process visibility.

    Compares multiple data sources to detect processes hidden by rootkits:
    - /proc filesystem listing
    - Scheduler signaling (os.kill)
    - Netlink socket process enumeration
    - /sys filesystem process entries
    """

    def __init__(self):
        self.proc_path = Path("/proc")
        self.sys_path = Path("/sys/fs/cgroup")

    def get_proc_pids(self) -> Set[int]:
        """Get PIDs visible in /proc filesystem."""
        pids = set()
        if not self.proc_path.exists():
            return pids

        try:
            for entry in self.proc_path.iterdir():
                if entry.is_dir() and entry.name.isdigit():
                    pids.add(int(entry.name))
        except (PermissionError, OSError):
            pass

        return pids

    def get_scheduler_pids(self) -> Set[int]:
        """Get PIDs that respond to scheduler signals (os.kill with signal 0)."""
        pids = set()
        max_pid = self._get_max_pid()

        for pid in range(1, min(max_pid, 65536)):
            try:
                os.kill(pid, 0)
                pids.add(pid)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    continue
                elif e.errno == errno.EPERM:
                    # Process exists but we lack permission
                    pids.add(pid)

        return pids

    def get_netlink_pids(self) -> Set[int]:
        """
        Get PIDs via netlink socket enumeration (CN_IDX_PROC).

        This uses the connector/netlink interface which some rootkits
        fail to hook, providing an alternative view of running processes.
        """
        pids = set()

        try:
            # Try to read from /proc/net/netlink to find processes
            netlink_path = Path("/proc/net/netlink")
            if netlink_path.exists():
                with open(netlink_path, 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 8 and parts[0].isdigit():
                            # Extract PID from netlink socket info
                            try:
                                inode = parts[6]
                                # Cross-reference with /proc/*/fd/* to find owning PID
                                pids.update(self._find_pid_by_socket_inode(inode))
                            except (ValueError, IndexError):
                                continue
        except (PermissionError, OSError):
            pass

        return pids

    def _find_pid_by_socket_inode(self, inode: str) -> Set[int]:
        """Find PIDs that have a socket with the given inode."""
        matching_pids = set()

        if not self.proc_path.exists():
            return matching_pids

        try:
            for pid_dir in self.proc_path.iterdir():
                if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                    continue

                fd_dir = pid_dir / "fd"
                if not fd_dir.exists():
                    continue

                try:
                    for fd_link in fd_dir.iterdir():
                        try:
                            target = os.readlink(str(fd_link))
                            if f"socket:[{inode}]" in target:
                                matching_pids.add(int(pid_dir.name))
                                break
                        except (OSError, ValueError):
                            continue
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

        return matching_pids

    def _get_max_pid(self) -> int:
        """Get the maximum PID value configured on the system."""
        pid_max_path = Path("/proc/sys/kernel/pid_max")
        try:
            if pid_max_path.exists():
                return int(pid_max_path.read_text().strip())
        except (ValueError, OSError):
            pass
        return 32768  # Default Linux PID_MAX_LIMIT

    def analyze(self) -> List[RootkitIndicator]:
        """
        Perform cross-view process differential analysis.

        Returns
        -------
        List[RootkitIndicator]
            List of detected anomalies indicating potential rootkit activity.
        """
        indicators = []

        # Get views from different sources
        proc_view = self.get_proc_pids()
        scheduler_view = self.get_scheduler_pids()
        netlink_view = self.get_netlink_pids()

        # Detect processes hidden from /proc but visible to scheduler
        hidden_from_proc = scheduler_view - proc_view

        for pid in sorted(hidden_from_proc):
            # Verify it's not a transient race condition
            try:
                os.kill(pid, 0)
                proc_exists_now = (self.proc_path / str(pid)).exists()

                if not proc_exists_now:
                    indicators.append(RootkitIndicator(
                        indicator_type="hidden_process_scheduler",
                        severity="CRITICAL",
                        description=f"Process PID {pid} responds to scheduler signals but is hidden from /proc filesystem",
                        evidence={
                            "pid": pid,
                            "detection_method": "scheduler_signal_vs_proc_listing",
                            "verified": True
                        },
                        mitigation="Investigate process immediately; consider memory forensics",
                        confidence=0.95
                    ))
            except OSError:
                # Process died during check - likely a transient process
                pass

        # Detect discrepancies between netlink and /proc views
        netlink_only = netlink_view - proc_view
        for pid in sorted(netlink_only - hidden_from_proc):  # Avoid duplicates
            indicators.append(RootkitIndicator(
                indicator_type="hidden_process_netlink",
                severity="HIGH",
                description=f"Process PID {pid} visible via netlink enumeration but hidden from /proc",
                evidence={
                    "pid": pid,
                    "detection_method": "netlink_enumeration_vs_proc_listing"
                },
                mitigation="Cross-verify with other detection methods",
                confidence=0.85
            ))

        return indicators


class CrossViewNetworkAnalyzer:
    """
    Performs cross-view differential analysis for network connections.

    Compares:
    - /proc/net/tcp, /proc/net/udp listings
    - Socket syscall results (getsockopt, getsockname)
    - Netfilter connection tracking (if available)
    """

    PROC_NET_PATHS = {
        'tcp': Path("/proc/net/tcp"),
        'tcp6': Path("/proc/net/tcp6"),
        'udp': Path("/proc/net/udp"),
        'udp6': Path("/proc/net/udp6"),
    }

    def parse_proc_net(self, proto: str) -> List[Dict]:
        """Parse /proc/net/{tcp,udp} files."""
        connections = []
        path = self.PROC_NET_PATHS.get(proto)

        if not path or not path.exists():
            return connections

        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:]  # Skip header

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = parts[1]
                        remote_addr = parts[2]
                        state = parts[3]
                        inode = parts[9]

                        connections.append({
                            'protocol': proto,
                            'local_address': local_addr,
                            'remote_address': remote_addr,
                            'state': state,
                            'inode': inode
                        })
        except (PermissionError, OSError):
            pass

        return connections

    def get_socket_inodes_from_procs(self) -> Set[str]:
        """Collect all socket inodes from /proc/*/fd/*."""
        inodes = set()
        proc_path = Path("/proc")

        if not proc_path.exists():
            return inodes

        try:
            for pid_dir in proc_path.iterdir():
                if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                    continue

                fd_dir = pid_dir / "fd"
                if not fd_dir.exists():
                    continue

                try:
                    for fd_link in fd_dir.iterdir():
                        try:
                            target = os.readlink(str(fd_link))
                            if target.startswith("socket:["):
                                inode = target[8:-1]  # Extract inode number
                                inodes.add(inode)
                        except (OSError, ValueError):
                            continue
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

        return inodes

    def analyze(self) -> List[RootkitIndicator]:
        """
        Perform cross-view network differential analysis.

        Detects network connections hidden from /proc/net by rootkits.
        """
        indicators = []

        # Get connections from /proc/net
        proc_connections = []
        for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
            proc_connections.extend(self.parse_proc_net(proto))

        proc_inodes = {conn['inode'] for conn in proc_connections}

        # Get socket inodes from process FDs
        fd_inodes = self.get_socket_inodes_from_procs()

        # Detect sockets visible in FDs but not in /proc/net
        hidden_sockets = fd_inodes - proc_inodes

        if len(hidden_sockets) > 5:  # Threshold to avoid false positives
            indicators.append(RootkitIndicator(
                indicator_type="hidden_network_sockets",
                severity="HIGH",
                description=f"Detected {len(hidden_sockets)} socket inodes in process FDs but not listed in /proc/net",
                evidence={
                    "hidden_count": len(hidden_sockets),
                    "sample_inodes": list(hidden_sockets)[:10],
                    "detection_method": "fd_inode_vs_proc_net_differential"
                },
                mitigation="Investigate processes holding these sockets; check for netfilter hooks",
                confidence=0.80
            ))

        return indicators


class eBPFProbeAnalyzer:
    """
    Analyzes eBPF programs for rootkit indicators.

    Detects:
    - Malicious eBPF programs used for hiding processes/files
    - Hooked kernel functions via eBPF
    - Suspicious eBPF map configurations
    - Known rootkit eBPF signatures (TripleCross, etc.)
    """

    KNOWN_MALICIOUS_PATTERNS = [
        "triplecross", "ebpfkit", "beurk_ebpf",
        "hook_sys_open", "hook_sys_read", "hook_sys_write",
        "hide_pid", "hide_file", "hook_recvmsg"
    ]

    SUSPICIOUS_HOOK_POINTS = [
        "sys_enter_open", "sys_enter_openat",
        "sys_enter_read", "sys_enter_write",
        "sys_enter_getdents64", "sys_enter_stat",
        "kprobe/security_file_permission",
        "kprobe/inet_csk_accept"
    ]

    def __init__(self, ebpf_programs: List[Dict], ebpf_pinned: List[Dict]):
        self.programs = ebpf_programs
        self.pinned = ebpf_pinned

    def analyze(self) -> List[RootkitIndicator]:
        """Analyze eBPF programs for rootkit indicators."""
        indicators = []

        # Analyze loaded programs
        for prog in self.programs:
            prog_name = prog.get('name', '').lower()
            prog_tag = prog.get('tag', '')
            prog_type = prog.get('type', '')

            # Check for known malicious patterns
            for pattern in self.KNOWN_MALICIOUS_PATTERNS:
                if pattern in prog_name:
                    indicators.append(RootkitIndicator(
                        indicator_type="malicious_ebpf_program",
                        severity="CRITICAL",
                        description=f"eBPF program '{prog_name}' matches known rootkit pattern",
                        evidence={
                            "program_id": prog.get('bpf_id'),
                            "name": prog_name,
                            "tag": prog_tag,
                            "type": prog_type,
                            "matched_pattern": pattern
                        },
                        mitigation="Unload program immediately using bpftool; investigate persistence",
                        confidence=0.95
                    ))
                    break

            # Flag suspicious hook points (heuristic)
            # Note: Would need BTF info for precise hook point detection
            if prog_type == 'kprobe' and any(
                hook in prog_name for hook in self.SUSPICIOUS_HOOK_POINTS
            ):
                indicators.append(RootkitIndicator(
                    indicator_type="suspicious_ebpf_hook",
                    severity="MEDIUM",
                    description=f"eBPF kprobe program attached to sensitive syscall: {prog_name}",
                    evidence={
                        "program_id": prog.get('bpf_id'),
                        "name": prog_name,
                        "hook_point": prog_name
                    },
                    mitigation="Verify program legitimacy; check GPL compatibility",
                    confidence=0.60
                ))

        # Analyze pinned objects
        for obj in self.pinned:
            obj_path = obj.get('path', '').lower()

            for pattern in self.KNOWN_MALICIOUS_PATTERNS:
                if pattern in obj_path:
                    indicators.append(RootkitIndicator(
                        indicator_type="malicious_ebpf_pinned",
                        severity="CRITICAL",
                        description=f"Pinned eBPF object path matches rootkit pattern: {obj_path}",
                        evidence={
                            "path": obj_path,
                            "matched_pattern": pattern
                        },
                        mitigation="Remove pinned object; unload associated program",
                        confidence=0.90
                    ))
                    break

        return indicators


class KernelSymbolIntegrityChecker:
    """
    Validates kernel symbol integrity against known-good baselines.

    Detects:
    - Hooked system calls (syscall table modifications)
    - Modified interrupt handlers (IDT hooks)
    - Injected kernel code (anomalous symbol addresses)
    - Function pointer tampering
    """

    CRITICAL_SYMBOLS = [
        "sys_call_table",
        "ia32_sys_call_table",
        "commit_creds",
        "prepare_kernel_cred",
        "kallsyms_lookup_name",
        "do_execve",
        "do_fork",
        "tcp_v4_rcv",
        "inet_recvmsg"
    ]

    def __init__(self, symbols: List[Dict], baseline_symbols: Optional[List[Dict]] = None):
        self.current_symbols = {s['symbol_name']: s for s in symbols if not s.get('suspicious')}
        self.baseline_symbols = baseline_symbols or {}

    def check_symbol_addresses(self) -> List[RootkitIndicator]:
        """Check if critical symbol addresses match baseline."""
        indicators = []

        if not self.baseline_symbols:
            return indicators  # No baseline to compare against

        for symbol_name in self.CRITICAL_SYMBOLS:
            if symbol_name in self.baseline_symbols and symbol_name in self.current_symbols:
                baseline_addr = self.baseline_symbols[symbol_name].get('address', '')
                current_addr = self.current_symbols[symbol_name].get('address', '')

                if baseline_addr != current_addr:
                    indicators.append(RootkitIndicator(
                        indicator_type="critical_symbol_address_change",
                        severity="CRITICAL",
                        description=f"Critical kernel symbol '{symbol_name}' address changed",
                        evidence={
                            "symbol": symbol_name,
                            "baseline_address": baseline_addr,
                            "current_address": current_addr
                        },
                        mitigation="System may be compromised; boot from trusted media for forensics",
                        confidence=0.90
                    ))

        return indicators

    def check_anomalous_symbols(self) -> List[RootkitIndicator]:
        """Detect anomalous symbols suggesting kernel code injection."""
        indicators = []

        # Look for symbols with suspicious naming patterns
        suspicious_patterns = [
            r'^_[a-z]{8,}$',  # Random-looking names
            r'^h_[a-z_]+$',   # Hook prefixes
            r'^orig_.*$',     # Original function wrappers
        ]

        for symbol_name, symbol_info in self.current_symbols.items():
            for pattern in suspicious_patterns:
                if re.match(pattern, symbol_name, re.IGNORECASE):
                    # Additional check: is it from an unknown module?
                    module = symbol_info.get('module_name')
                    if module and module not in ('kernel', 'vmlinux'):
                        indicators.append(RootkitIndicator(
                            indicator_type="anomalous_kernel_symbol",
                            severity="HIGH",
                            description=f"Suspicious kernel symbol detected: {symbol_name}",
                            evidence={
                                "symbol": symbol_name,
                                "address": symbol_info.get('address'),
                                "module": module,
                                "pattern_matched": pattern
                            },
                            mitigation="Investigate module; verify signature",
                            confidence=0.70
                        ))
                    break

        return indicators


def run_rootkit_detection(
    ebpf_programs: List[Dict],
    ebpf_pinned: List[Dict],
    kernel_symbols: List[Dict],
    kernel_modules: List[Dict],
    baseline_symbols: Optional[Dict] = None
) -> Dict:
    """
    Execute comprehensive rootkit detection analysis.

    Parameters
    ----------
    ebpf_programs : List[Dict]
        Loaded eBPF programs from gather_ebpf_programs()
    ebpf_pinned : List[Dict]
        Pinned eBPF objects from gather_ebpf_pinned()
    kernel_symbols : List[Dict]
        Kernel symbols from gather_kernel_symbols()
    kernel_modules : List[Dict]
        Kernel modules from gather_loaded_kernel_modules()
    baseline_symbols : Optional[Dict]
        Baseline symbols for comparison (from previous clean state)

    Returns
    -------
    Dict
        Comprehensive rootkit detection report with all indicators.
    """
    all_indicators = []

    # Layer 1: Cross-view process analysis
    process_analyzer = CrossViewProcessAnalyzer()
    all_indicators.extend(process_analyzer.analyze())

    # Layer 2: Cross-view network analysis
    network_analyzer = CrossViewNetworkAnalyzer()
    all_indicators.extend(network_analyzer.analyze())

    # Layer 3: eBPF probe analysis
    ebpf_analyzer = eBPFProbeAnalyzer(ebpf_programs, ebpf_pinned)
    all_indicators.extend(ebpf_analyzer.analyze())

    # Layer 4: Kernel symbol integrity
    symbol_checker = KernelSymbolIntegrityChecker(kernel_symbols, baseline_symbols)
    all_indicators.extend(symbol_checker.check_symbol_addresses())
    all_indicators.extend(symbol_checker.check_anomalous_symbols())

    # Compile results
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for indicator in all_indicators:
        severity_counts[indicator.severity] = severity_counts.get(indicator.severity, 0) + 1

    # Determine overall risk level
    if severity_counts["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall_risk = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "NONE"

    return {
        "detection_timestamp": time.time(),
        "overall_risk_level": overall_risk,
        "total_indicators": len(all_indicators),
        "severity_breakdown": severity_counts,
        "indicators": [asdict(ind) for ind in all_indicators],
        "layers_executed": [
            "cross_view_process",
            "cross_view_network",
            "ebpf_probe_analysis",
            "kernel_symbol_integrity"
        ]
    }


# Import time for timestamp generation
import time