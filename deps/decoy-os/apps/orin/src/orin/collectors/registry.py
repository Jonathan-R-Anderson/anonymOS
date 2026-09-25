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

"""
orin.collectors.registry – Central Capability Registry for Forensic Collectors
==============================================================================
"""

import os
import inspect
from dataclasses import dataclass
from typing import Callable, List, Dict, Any, Optional

from orin.collectors.processes import gather_active_processes
from orin.collectors.connections import gather_listening_ports, gather_outbound_connections
from orin.collectors.promisc import gather_promisc_interfaces
from orin.collectors.kernel import gather_loaded_kernel_modules, gather_kernel_symbols
from orin.collectors.users import gather_system_accounts
from orin.collectors.persistence import gather_active_ssh_keys
from orin.collectors.crontabs import gather_crontabs
from orin.collectors.session_audit import gather_wtmp_sessions, gather_lastlog_records
from orin.collectors.deleted_binaries import gather_deleted_binaries
from orin.collectors.suid import gather_suid_binaries
from orin.collectors.logs import gather_auth_logs
from orin.collectors.privilege_audit import gather_all_privilege_events
from orin.collectors.ebpf import gather_ebpf_programs, gather_ebpf_pinned, gather_ld_preload, gather_special_fds
from orin.collectors.persistence import gather_system_persistence
from orin.collectors.dns_forensics import gather_dns_queries
from orin.collectors.integrity import gather_file_integrity_signatures
from orin.collectors.pkg_integrity import gather_pkg_integrity_drift
from orin.collectors.services import gather_active_services


@dataclass
class CollectorMetadata:
    """Metadata representing a single forensic collector."""
    name: str
    func: Callable
    description: str
    privilege_requirements: str  # "root" or "user"
    required_capabilities: List[str]
    runtime_impact: str  # "low", "medium", "high"
    impact_reason: str


COLLECTOR_REGISTRY: Dict[str, CollectorMetadata] = {
    "processes": CollectorMetadata(
        name="processes",
        func=gather_active_processes,
        description="Harvests running process tree metadata from /proc",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Fast process traversal via /proc filesystem parsing."
    ),
    "listening_ports": CollectorMetadata(
        name="listening_ports",
        func=gather_listening_ports,
        description="Enumerates open listening TCP/UDP ports from /proc/net",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Direct parsing of net descriptor tables in /proc."
    ),
    "outbound_connections": CollectorMetadata(
        name="outbound_connections",
        func=gather_outbound_connections,
        description="Enumerates active outbound TCP connections from /proc/net",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Direct parsing of net descriptor tables in /proc."
    ),
    "promisc_interfaces": CollectorMetadata(
        name="promisc_interfaces",
        func=gather_promisc_interfaces,
        description="Checks network interfaces for promiscuous mode flags in /sys/class/net",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Reads short flag files under sysfs directory tree."
    ),
    "kernel_modules": CollectorMetadata(
        name="kernel_modules",
        func=gather_loaded_kernel_modules,
        description="Parses loadable kernel modules from /proc/modules",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Reads and parses /proc/modules."
    ),
    "kernel_symbols": CollectorMetadata(
        name="kernel_symbols",
        func=gather_kernel_symbols,
        description="Harvests kernel symbols from /proc/kallsyms",
        privilege_requirements="root",
        required_capabilities=["CAP_SYSLOG"],
        runtime_impact="medium",
        impact_reason="Parses large kernel symbol map file (~100k+ entries)."
    ),
    "system_users": CollectorMetadata(
        name="system_users",
        func=gather_system_accounts,
        description="Harvests system account profiles from /etc/passwd",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Parses system-wide password profile records."
    ),
    "ssh_keys": CollectorMetadata(
        name="ssh_keys",
        func=gather_active_ssh_keys,
        description="Gathers SSH authorized_keys for all system accounts",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="low",
        impact_reason="Traverses user home directory configurations."
    ),
    "crontabs": CollectorMetadata(
        name="crontabs",
        func=gather_crontabs,
        description="Parses crontabs from system and user directories",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="low",
        impact_reason="Scans standard system cron scheduling directories."
    ),
    "wtmp_sessions": CollectorMetadata(
        name="wtmp_sessions",
        func=gather_wtmp_sessions,
        description="Parses login/session history from wtmp binary logs",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Performs sequential binary parsing of wtmp descriptor entries."
    ),
    "lastlog_records": CollectorMetadata(
        name="lastlog_records",
        func=gather_lastlog_records,
        description="Parses last login history from lastlog binary logs",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Performs sequential binary parsing of lastlog records."
    ),
    "deleted_binaries": CollectorMetadata(
        name="deleted_binaries",
        func=gather_deleted_binaries,
        description="Identifies running processes with deleted binaries from /proc/[pid]/exe",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Reads process symlinks in /proc."
    ),
    "suid_binaries": CollectorMetadata(
        name="suid_binaries",
        func=gather_suid_binaries,
        description="Discovers on-disk binaries with SUID/SGID bits set",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="medium",
        impact_reason="Traverses standard execution paths on the filesystem."
    ),
    "auth_logs": CollectorMetadata(
        name="auth_logs",
        func=gather_auth_logs,
        description="Parses authentication log records (e.g. /var/log/auth.log or journald)",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="medium",
        impact_reason="Performs text pattern matching across system security logs."
    ),
    "privilege_events": CollectorMetadata(
        name="privilege_events",
        func=gather_all_privilege_events,
        description="Tracks PAM logs and audits privilege escalation syscalls via tracefs",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="medium",
        impact_reason="Queries active authentication log streams and trace parameters."
    ),
    "ebpf_programs": CollectorMetadata(
        name="ebpf_programs",
        func=gather_ebpf_programs,
        description="Audits loaded eBPF programs on the system",
        privilege_requirements="root",
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        runtime_impact="low",
        impact_reason="Queries active kernel eBPF descriptors."
    ),
    "ebpf_pinned": CollectorMetadata(
        name="ebpf_pinned",
        func=gather_ebpf_pinned,
        description="Audits pinned eBPF maps and programs under /sys/fs/bpf",
        privilege_requirements="root",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Reads BPF virtual filesystem parameters."
    ),
    "ld_preload": CollectorMetadata(
        name="ld_preload",
        func=gather_ld_preload,
        description="Audits dynamic linker preloads in /etc/ld.so.preload",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Parses dynamic preloader config files."
    ),
    "special_fds": CollectorMetadata(
        name="special_fds",
        func=gather_special_fds,
        description="Audits special process file descriptors (deleted, anonymous, memfd)",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="medium",
        impact_reason="Scans process fd lists under /proc tree."
    ),
    "persistence_configs": CollectorMetadata(
        name="persistence_configs",
        func=gather_system_persistence,
        description="Harvests persistence configuration artifacts (systemd, shell profiles)",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="medium",
        impact_reason="Performs multi-directory file parsing for persistence markers."
    ),
    "dns_queries": CollectorMetadata(
        name="dns_queries",
        func=gather_dns_queries,
        description="Collects active network DNS query indicators",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Direct parsing of socket telemetry details."
    ),
    "file_integrity": CollectorMetadata(
        name="file_integrity",
        func=gather_file_integrity_signatures,
        description="Calculates file integrity signatures (FIM) for configured paths",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="high",
        impact_reason="Hashes monitored files (optimized with file metadata caching)."
    ),
    "package_drift": CollectorMetadata(
        name="package_drift",
        func=gather_pkg_integrity_drift,
        description="Verifies package integrity against dpkg database MD5 checksums",
        privilege_requirements="root",
        required_capabilities=["CAP_DAC_READ_SEARCH"],
        runtime_impact="high",
        impact_reason="Verifies MD5 hashes for all package files on disk."
    ),
    "services": CollectorMetadata(
        name="services",
        func=gather_active_services,
        description="Enumerates systemd services status and unit file state",
        privilege_requirements="user",
        required_capabilities=[],
        runtime_impact="low",
        impact_reason="Direct invocation of systemctl tool query status."
    )
}


def get_registered_collectors(
    privilege_level: Optional[str] = None,
    max_impact: Optional[str] = None
) -> List[CollectorMetadata]:
    """Retrieve and filter registered collectors based on requirements.

    Parameters
    ----------
    privilege_level : str, optional
        If specified, filters collectors. "user" only returns user-level,
        "root" returns all.
    max_impact : str, optional
        Filter collectors by maximum runtime impact level ("low", "medium", "high").

    Returns
    -------
    list of CollectorMetadata
        Filtered list of collector metadata.
    """
    impact_levels = {"low": 1, "medium": 2, "high": 3}
    filtered = list(COLLECTOR_REGISTRY.values())

    if privilege_level == "user":
        filtered = [c for c in filtered if c.privilege_requirements == "user"]

    if max_impact and max_impact in impact_levels:
        allowed_score = impact_levels[max_impact]
        filtered = [c for c in filtered if impact_levels[c.runtime_impact] <= allowed_score]

    return filtered


def check_privilege_satisfaction(metadata: CollectorMetadata) -> bool:
    """Check if the current session has privileges to execute the collector.

    Parameters
    ----------
    metadata : CollectorMetadata
        The metadata of the collector to check.

    Returns
    -------
    bool
        True if privilege is satisfied, False otherwise.
    """
    if metadata.privilege_requirements == "root":
        return os.geteuid() == 0
    return True


def execute_collector_with_context(metadata: CollectorMetadata, **ctx) -> Any:
    """Execute a collector dynamically, injecting required context parameters.

    Parameters
    ----------
    metadata : CollectorMetadata
        The collector metadata containing the function.
    **ctx
        Context dictionary containing parameters like db_conn.

    Returns
    -------
    Any
        The result of the collector function execution.
    """
    sig = inspect.signature(metadata.func)
    kwargs = {}
    if "db_conn" in sig.parameters and "db_conn" in ctx:
        kwargs["db_conn"] = ctx["db_conn"]
    return metadata.func(**kwargs)
