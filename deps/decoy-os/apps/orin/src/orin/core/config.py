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
# src/orin/core/config.py
"""
orin.core.config – Configuration Loader
=======================================
Provides a single public entry-point, :func:`load_config`, that reads the
Orin JSON configuration file and merges it with safe built-in defaults.

Search order
------------
1. ``ORIN_CONFIG_PATH`` environment variable path (if set)
2. ``./orin_config.json``  (working-directory local override)
3. ``/etc/orin/orin_config.json``  (system-wide deployment path)

If neither file is found, or if parsing fails, the built-in
``DEFAULT_CONFIG`` dictionary is returned unchanged.
"""
import json
import os
from pathlib import Path

#: Ordered list of filesystem paths that are checked for a user-supplied
#: configuration file.  The first readable file wins.
DEFAULT_CONFIG_LOCATIONS = [
    Path("orin_config.json"),
    Path("/etc/orin/orin_config.json")
]

#: Built-in fallback configuration values used when no config file is found.
#:
#: Keys
#: ----
#: expected_ports       – Port numbers that the analysis engine will *not* flag
#:                        as unexpected listening sockets.
#: whitelisted_processes – Process base-names whose high ephemeral ports are
#:                        excluded from "unexpected port" alerts.
#: critical_paths       – Absolute paths to individual files monitored by the
#:                        File Integrity Monitor (FIM).
#: critical_dirs        – Directories recursively scanned by the FIM.
DEFAULT_CONFIG = {
    "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
    "whitelisted_processes": ["code", "antigravity-ide", "language_server"],
    "critical_paths": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/crontab"
    ],
    "critical_dirs": [
        "/etc/cron.d",
        "/etc/systemd/system"
    ],
    # Encryption settings for evidence vault
    "vault_encryption": {
        "enabled": False,
        "passphrase_env": "ORIN_VAULT_PASSPHRASE",
        "min_passphrase_length": 12
    },
    # Structured logging configuration for SIEM integration
    "logging": {
        "enabled": True,
        "level": "INFO",
        "format": "json",
        "output_stderr": True,
        "output_file": None,
        "max_bytes": 10485760,
        "backup_count": 5
    },
    # Collector timeout and parallel execution settings
    "collectors": {
        "parallel_enabled": True,
        "default_timeout": 300.0,
        "max_workers": None,  # Auto-detect (CPU count + 4, max 32)
        "per_collector_timeouts": {
            "processes": 60.0,
            "listening_ports": 30.0,
            "outbound_connections": 30.0,
            "kernel_modules": 30.0,
            "system_users": 30.0,
            "crontabs": 30.0,
            "wtmp_sessions": 30.0,
            "lastlog_records": 30.0,
            "deleted_binaries": 60.0,
            "suid_binaries": 60.0,
            "auth_logs": 120.0,
            "ebpf_programs": 30.0,
            "ebpf_pinned": 30.0,
            "ld_preload": 30.0,
            "special_fds": 30.0,
            "persistence_configs": 60.0,
            "dns_queries": 120.0,
            "promisc_interfaces": 30.0
        }
    },
    # SSH security configuration for remote operations
    "ssh": {
        "strict_host_key_checking": "ask",  # Options: "yes", "no", "ask", "accept-new"
        "known_hosts_file": None,  # None uses default ~/.ssh/known_hosts
        "connection_timeout": 30,
        "max_retries": 3,
        # Rate limiting configuration to prevent overwhelming target systems
        "rate_limit": {
            "enabled": True,
            "max_concurrent_connections": 5,  # Maximum simultaneous SSH connections
            "delay_between_scans": 1.0,  # Seconds to wait between starting new scans
            "max_scans_per_minute": 10,  # Maximum scan initiations per minute per target
            "backoff_factor": 2.0,  # Exponential backoff multiplier on connection failures
            "max_backoff_delay": 60.0  # Maximum delay after repeated failures (seconds)
        }
    },
    # Alert forwarding — push notifications to webhooks and/or local syslog.
    # Zero external dependencies required; all transports use Python stdlib only.
    "notifications": {
        "enabled": False,
        # Minimum alert severity to forward: "low" | "medium" | "high" | "critical"
        "min_severity": "high",
        # Syslog channel — writes to local syslog via stdlib syslog module.
        "syslog": {
            "enabled": False,
            "facility": "LOG_LOCAL0",
            "tag": "orin-alert"
        },
        # Webhook channel list — POST to any HTTP endpoint (Slack, Teams, generic REST).
        # Each entry schema:
        #   { "name": "my-hook", "url": "http://...", "format": "slack"|"teams"|"generic",
        #     "min_severity": "critical",  // optional per-hook override
        #     "headers": {},               // optional extra HTTP headers (e.g. auth tokens)
        #     "timeout_seconds": 10, "enabled": true }
        "webhooks": [],
        # Retry settings applied to every webhook delivery attempt.
        "retry": {
            "max_attempts": 3,
            "backoff_seconds": 5
        },
        # Append-only JSONL audit log of every notification attempt (success or failure).
        "audit_log": "/var/log/orin/notification_audit.log"
    }
}


def load_config_with_source() -> tuple[dict, Path]:
    """Load and return the active configuration dictionary alongside its source path.

    Searches the path defined in the ``ORIN_CONFIG_PATH`` environment variable
    first if set, then falls back to :data:`DEFAULT_CONFIG_LOCATIONS` in order.
    The first successfully parsed JSON file is merged on top of :data:`DEFAULT_CONFIG`.

    Returns
    -------
    tuple[dict, Path]
        A tuple containing:
        - dict: The merged configuration mapping dictionary layout.
        - Path: The actual, validated file path location that was opened.
                Defaults to Path("orin_config.json") (or the environment variable path) if no file exists yet.
    """
    search_locations = []
    env_path = os.environ.get("ORIN_CONFIG_PATH")
    if env_path:
        search_locations.append(Path(env_path))
    search_locations.extend(DEFAULT_CONFIG_LOCATIONS)

    for loc in search_locations:
        if loc.exists() and loc.is_file():
            try:
                with open(loc, "r") as f:
                    data = json.load(f)
                    # Merge to ensure missing keys fallback to defaults
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(data)
                    return merged, loc
            except Exception:
                pass

    # Default fallback destination if no active configuration layout exists on disk
    fallback_path = Path(env_path) if env_path else Path("orin_config.json")
    return DEFAULT_CONFIG.copy(), fallback_path


def load_config() -> dict:
    """Load and return the active Orin configuration dictionary.

    Searches :data:`DEFAULT_CONFIG_LOCATIONS` in order.  The first successfully
    parsed JSON file is merged *on top of* :data:`DEFAULT_CONFIG`, so any keys
    absent from the user file still receive their default values.

    Returns
    -------
    dict
        Merged configuration mapping.  Always contains at minimum all keys
        present in :data:`DEFAULT_CONFIG`.
    """
    config_dict, _ = load_config_with_source()
    return config_dict