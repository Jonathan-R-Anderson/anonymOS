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
# src/orin/core/doctor.py
"""
orin.core.doctor – Platform Diagnostics CLI Command
===================================================
Performs comprehensive diagnostic checks on the system environment,
dependencies, permissions, vault database, and configuration files
without changing any system state or database contents.
"""
from __future__ import annotations

import os
import sys
import platform
import shutil
import sqlite3
import ctypes
import json
from pathlib import Path
from typing import Any

from orin.core.config import DEFAULT_CONFIG_LOCATIONS, DEFAULT_CONFIG

class CheckResult:
    """Represents the outcome of a single diagnostic check."""
    __slots__ = ("name", "status", "detail", "recommendation")

    def __init__(self, name: str, status: str, detail: str, recommendation: str = ""):
        self.name = name
        self.status = status  # "PASS", "WARNING", "FAIL"
        self.detail = detail
        self.recommendation = recommendation

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "recommendation": self.recommendation
        }


def _validate_config_schema(config_data: dict[str, Any]) -> list[str]:
    """Validate a loaded configuration dict against the expected schema types."""
    warnings = []

    # Helper for simple key/type check
    def check_type(key: str, expected_type: Any, parent_name: str = ""):
        prefix = f"{parent_name}." if parent_name else ""
        if key in config_data:
            val = config_data[key]
            if not isinstance(val, expected_type):
                warnings.append(
                    f"Config key '{prefix}{key}' should be type {expected_type.__name__ if hasattr(expected_type, '__name__') else expected_type}, got {type(val).__name__}"
                )

    # Validate top level array/list keys
    for list_key in ("expected_ports", "whitelisted_processes", "critical_paths", "critical_dirs"):
        if list_key in config_data:
            val = config_data[list_key]
            if not isinstance(val, list):
                warnings.append(f"Config key '{list_key}' should be a list, got {type(val).__name__}")
            else:
                # Check inner types
                if list_key == "expected_ports":
                    for idx, item in enumerate(val):
                        if not isinstance(item, int):
                            warnings.append(f"Config key 'expected_ports[{idx}]' should be an integer, got {type(item).__name__}")
                else:
                    for idx, item in enumerate(val):
                        if not isinstance(item, str):
                            warnings.append(f"Config key '{list_key}[{idx}]' should be a string, got {type(item).__name__}")

    # Validate vault_encryption block
    if "vault_encryption" in config_data:
        ve = config_data["vault_encryption"]
        if not isinstance(ve, dict):
            warnings.append(f"Config key 'vault_encryption' should be a dict, got {type(ve).__name__}")
        else:
            if "enabled" in ve and not isinstance(ve["enabled"], bool):
                warnings.append(f"Config key 'vault_encryption.enabled' should be boolean, got {type(ve['enabled']).__name__}")
            if "passphrase_env" in ve and not isinstance(ve["passphrase_env"], str):
                warnings.append(f"Config key 'vault_encryption.passphrase_env' should be string, got {type(ve['passphrase_env']).__name__}")
            if "min_passphrase_length" in ve and not isinstance(ve["min_passphrase_length"], int):
                warnings.append(f"Config key 'vault_encryption.min_passphrase_length' should be integer, got {type(ve['min_passphrase_length']).__name__}")

    # Validate logging block
    if "logging" in config_data:
        log = config_data["logging"]
        if not isinstance(log, dict):
            warnings.append(f"Config key 'logging' should be a dict, got {type(log).__name__}")
        else:
            if "enabled" in log and not isinstance(log["enabled"], bool):
                warnings.append(f"Config key 'logging.enabled' should be boolean, got {type(log['enabled']).__name__}")
            if "level" in log:
                if not isinstance(log["level"], str):
                    warnings.append(f"Config key 'logging.level' should be string, got {type(log['level']).__name__}")
                elif log["level"] not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                    warnings.append(f"Config key 'logging.level' has invalid value '{log['level']}'")
            if "format" in log and not isinstance(log["format"], str):
                warnings.append(f"Config key 'logging.format' should be string, got {type(log['format']).__name__}")
            if "output_stderr" in log and not isinstance(log["output_stderr"], bool):
                warnings.append(f"Config key 'logging.output_stderr' should be boolean, got {type(log['output_stderr']).__name__}")
            if "max_bytes" in log and not isinstance(log["max_bytes"], int):
                warnings.append(f"Config key 'logging.max_bytes' should be integer, got {type(log['max_bytes']).__name__}")
            if "backup_count" in log and not isinstance(log["backup_count"], int):
                warnings.append(f"Config key 'logging.backup_count' should be integer, got {type(log['backup_count']).__name__}")

    # Validate collectors block
    if "collectors" in config_data:
        coll = config_data["collectors"]
        if not isinstance(coll, dict):
            warnings.append(f"Config key 'collectors' should be a dict, got {type(coll).__name__}")
        else:
            if "parallel_enabled" in coll and not isinstance(coll["parallel_enabled"], bool):
                warnings.append(f"Config key 'collectors.parallel_enabled' should be boolean, got {type(coll['parallel_enabled']).__name__}")
            if "default_timeout" in coll and not isinstance(coll["default_timeout"], (int, float)):
                warnings.append(f"Config key 'collectors.default_timeout' should be numeric, got {type(coll['default_timeout']).__name__}")
            if "max_workers" in coll and coll["max_workers"] is not None and not isinstance(coll["max_workers"], int):
                warnings.append(f"Config key 'collectors.max_workers' should be integer or null, got {type(coll['max_workers']).__name__}")
            if "per_collector_timeouts" in coll:
                pct = coll["per_collector_timeouts"]
                if not isinstance(pct, dict):
                    warnings.append(f"Config key 'collectors.per_collector_timeouts' should be a dict, got {type(pct).__name__}")
                else:
                    for k, v in pct.items():
                        if not isinstance(v, (int, float)):
                            warnings.append(f"Config key 'collectors.per_collector_timeouts.{k}' should be numeric, got {type(v).__name__}")

    # Check for unrecognized top-level keys
    for k in config_data:
        if k not in DEFAULT_CONFIG:
            warnings.append(f"Unrecognized top-level configuration key: '{k}'")

    return warnings


def run_diagnostics(db_path_override: Path | None = None) -> list[CheckResult]:
    """Execute all system, permission, dependency, database and config health checks.

    Parameters
    ----------
    db_path_override:
        Optional file path to override the default SQLite vault.

    Returns
    -------
    list[CheckResult]
        A list containing the result of each diagnostic check.
    """
    results: list[CheckResult] = []

    # 1. Privilege check
    euid = os.geteuid()
    if euid == 0:
        results.append(CheckResult("Privileges", "PASS", "Running with administrative privileges (root)"))
    else:
        results.append(
            CheckResult(
                "Privileges",
                "WARNING",
                f"Running as non-root user (EUID: {euid}).",
                "Restricted system logs, raw outbound connections, and administrative kernel queries will be limited. Run with 'sudo'."
            )
        )

    # 2. Operating System / Kernel Check
    sys_name = platform.system()
    if sys_name != "Linux":
        results.append(
            CheckResult(
                "Operating System",
                "FAIL",
                f"Unsupported operating system: {sys_name}.",
                "Orin is designed exclusively for Linux-based operating systems. Execution on other platforms is unsupported."
            )
        )
    else:
        release = platform.release()
        try:
            # Parse major.minor version numbers
            parts = release.split("-")[0].split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            version_float = major + (minor / 100.0)
            
            if version_float >= 5.04:
                results.append(CheckResult("Kernel Version", "PASS", f"Linux kernel version {release} (meets recommended >= 5.4)"))
            elif version_float >= 4.04:
                results.append(
                    CheckResult(
                        "Kernel Version",
                        "WARNING",
                        f"Linux kernel version {release}.",
                        "Kernel >= 5.4 is recommended to support all eBPF streaming ring-buffer features."
                    )
                )
            else:
                results.append(
                    CheckResult(
                        "Kernel Version",
                        "FAIL",
                        f"Linux kernel version {release} is below minimal required version 4.4.",
                        "Upgrade host kernel to 4.4 or higher (5.4+ recommended)."
                    )
                )
        except Exception:
            results.append(CheckResult("Kernel Version", "PASS", f"Linux kernel version {release} (could not verify recommended version threshold)"))

    # 3. eBPF & BTF Kernel Prerequisites
    btf_path = Path("/sys/kernel/btf/vmlinux")
    if btf_path.exists():
        results.append(CheckResult("BTF Support", "PASS", "BTF Type Format support found at /sys/kernel/btf/vmlinux"))
    else:
        results.append(
            CheckResult(
                "BTF Support",
                "WARNING",
                "BTF Type Format support not found at /sys/kernel/btf/vmlinux.",
                "eBPF real-time event streaming ('orin stream') requires BTF. Periodic collection ('orin collect') is unaffected."
            )
        )

    jit_path = Path("/proc/sys/net/core/bpf_jit_enable")
    if jit_path.exists():
        try:
            val = jit_path.read_text().strip()
            if val in ("1", "2"):
                results.append(CheckResult("BPF JIT Compiler", "PASS", f"BPF JIT compiler is enabled ({val})"))
            else:
                results.append(
                    CheckResult(
                        "BPF JIT Compiler",
                        "WARNING",
                        f"BPF JIT compiler is disabled (value: {val}).",
                        "Enable JIT compiling for optimal BPF program execution speed: 'echo 1 > /proc/sys/net/core/bpf_jit_enable'."
                    )
                )
        except Exception as exc:
            results.append(
                CheckResult(
                    "BPF JIT Compiler",
                    "WARNING",
                    f"BPF JIT status exists but could not be read: {exc}",
                    "Check /proc access permissions."
                )
            )
    else:
        results.append(
            CheckResult(
                "BPF JIT Compiler",
                "WARNING",
                "BPF JIT configuration path not found in /proc.",
                "Kernel may not support standard BPF JIT compilation features."
            )
        )

    # 4. Dependency Checks: psutil & cryptography (Required)
    psutil_ok = False
    try:
        import psutil
        psutil_ok = True
        results.append(CheckResult("Dependency: psutil", "PASS", f"psutil is installed (v{psutil.__version__})"))
    except ImportError:
        results.append(
            CheckResult(
                "Dependency: psutil",
                "FAIL",
                "Required python dependency 'psutil' is missing.",
                "Install via 'pip install psutil' or install package dependencies."
            )
        )

    try:
        import cryptography
        results.append(CheckResult("Dependency: cryptography", "PASS", f"cryptography is installed (v{cryptography.__version__})"))
    except ImportError:
        results.append(
            CheckResult(
                "Dependency: cryptography",
                "FAIL",
                "Required python dependency 'cryptography' is missing.",
                "Install via 'pip install cryptography' or install package dependencies."
            )
        )

    # 5. Dependency Checks: Optional (yara, scapy, libbpf)
    try:
        import yara
        results.append(CheckResult("Dependency: yara (Optional)", "PASS", f"yara is installed (v{getattr(yara, '__version__', 'unknown')})"))
    except ImportError:
        results.append(
            CheckResult(
                "Dependency: yara (Optional)",
                "WARNING",
                "Optional dependency 'yara' is missing.",
                "YARA rule scanning capabilities will be disabled. Install via 'pip install yara-python'."
            )
        )

    try:
        import scapy
        results.append(CheckResult("Dependency: scapy (Optional)", "PASS", f"scapy is installed (v{getattr(scapy, '__version__', 'unknown')})"))
    except ImportError:
        results.append(
            CheckResult(
                "Dependency: scapy (Optional)",
                "WARNING",
                "Optional dependency 'scapy' is missing.",
                "Triggered packet captures will write raw binary sockets without packet reconstruction. Install via 'pip install scapy'."
            )
        )

    # libbpf loading check via ctypes
    libbpf_loaded = False
    loaded_lib_name = ""
    for lib_name in ("libbpf.so.1", "libbpf.so.0", "libbpf.so"):
        try:
            ctypes.CDLL(lib_name)
            libbpf_loaded = True
            loaded_lib_name = lib_name
            break
        except OSError:
            pass

    if libbpf_loaded:
        results.append(CheckResult("Dependency: libbpf", "PASS", f"libbpf shared library loaded successfully ({loaded_lib_name})"))
    else:
        results.append(
            CheckResult(
                "Dependency: libbpf",
                "WARNING",
                "libbpf shared library was not found in library paths.",
                "Real-time BPF event streaming will fail. Install system package 'libbpf1' (Debian/Ubuntu) or 'libbpf' (RHEL/CentOS)."
            )
        )

    # 6. System Resource Limits (RAM & Disk space)
    if psutil_ok:
        try:
            mem = psutil.virtual_memory()
            total_ram_mb = mem.total / (1024 * 1024)
            if total_ram_mb >= 256.0:
                results.append(CheckResult("System RAM", "PASS", f"Total RAM capacity: {total_ram_mb:.1f} MB (meets recommended >= 256MB)"))
            else:
                results.append(
                    CheckResult(
                        "System RAM",
                        "WARNING",
                        f"System has low RAM capacity: {total_ram_mb:.1f} MB.",
                        "Execution may trigger out-of-memory errors during concurrent collections or large YARA scans. Allocate more memory."
                    )
                )
        except Exception as exc:
            results.append(CheckResult("System RAM", "WARNING", f"Failed to retrieve RAM capacity details: {exc}"))

    # Determine vault path
    vault_file = db_path_override if db_path_override else Path("orin_vault.db")
    vault_dir = vault_file.parent.absolute()
    try:
        usage = shutil.disk_usage(str(vault_dir))
        free_space_mb = usage.free / (1024 * 1024)
        if free_space_mb >= 100.0:
            results.append(CheckResult("System Disk Space", "PASS", f"Free space at vault directory: {free_space_mb:.1f} MB (meets recommended >= 100MB)"))
        else:
            results.append(
                CheckResult(
                    "System Disk Space",
                    "WARNING",
                    f"Free space at vault directory is low: {free_space_mb:.1f} MB.",
                    "Ensure partition has free space to handle SQLite database transactions and log writes."
                )
            )
    except Exception as exc:
        results.append(CheckResult("System Disk Space", "WARNING", f"Failed to calculate disk capacity: {exc}"))

    # 7. Vault Database Access & Integrity Checks
    if not vault_file.exists():
        # Check if parent directory is writable
        try:
            if os.access(str(vault_dir), os.W_OK):
                results.append(CheckResult("Vault Database", "PASS", f"Database file does not exist yet; target directory '{vault_dir}' is writable"))
            else:
                results.append(
                    CheckResult(
                        "Vault Database",
                        "FAIL",
                        f"Database file does not exist and target directory '{vault_dir}' is not writable.",
                        "Verify directory permissions or configure a writable database vault using '-d /path/to/vault.db'."
                    )
                )
        except Exception as exc:
            results.append(CheckResult("Vault Database", "FAIL", f"Failed to check target vault directory write access: {exc}"))
    else:
        # File exists
        readable = os.access(str(vault_file), os.R_OK)
        writable = os.access(str(vault_file), os.W_OK)
        if readable and writable:
            results.append(CheckResult("Vault Database Permissions", "PASS", f"Database file '{vault_file}' is readable and writable"))
            
            # Run SQLite Integrity check
            try:
                conn = sqlite3.connect(str(vault_file), timeout=30.0)
                conn.execute("PRAGMA busy_timeout=30000;")
                try:
                    cur = conn.execute("PRAGMA integrity_check(1);")
                    res = cur.fetchone()[0]
                    if res == "ok":
                        results.append(CheckResult("Vault Database Integrity", "PASS", "SQLite integrity verification passed ('ok')"))
                    else:
                        results.append(
                            CheckResult(
                                "Vault Database Integrity",
                                "FAIL",
                                f"SQLite integrity check failed: {res}.",
                                "Repair or recreate the database vault to prevent forensic evidence loss."
                            )
                        )
                finally:
                    conn.close()
            except Exception as exc:
                results.append(
                    CheckResult(
                        "Vault Database Integrity",
                        "FAIL",
                        f"Failed to execute database integrity queries: {exc}.",
                        "Verify database file locking status or file corruption."
                    )
                )
        else:
            detail = "File exists but permissions are insufficient: "
            details_list = []
            if not readable:
                details_list.append("not readable")
            if not writable:
                details_list.append("not writable")
            detail += ", ".join(details_list)
            
            results.append(
                CheckResult(
                    "Vault Database Permissions",
                    "FAIL",
                    detail,
                    "Ensure Orin process has sufficient permissions to access the SQLite vault."
                )
            )

    # 8. Cron Directory Access Checks
    cron_dir = Path("/etc/cron.d")
    if cron_dir.exists():
        try:
            if os.access(str(cron_dir), os.W_OK):
                results.append(CheckResult("Cron Schedule Permissions", "PASS", "Cron directory /etc/cron.d is writable"))
            else:
                results.append(
                    CheckResult(
                        "Cron Schedule Permissions",
                        "WARNING",
                        "Cron directory /etc/cron.d is not writable by current user.",
                        "Cron jobs cannot be scheduled via 'orin schedule'. Run command as root to schedule tasks."
                    )
                )
        except Exception as exc:
            results.append(CheckResult("Cron Schedule Permissions", "WARNING", f"Failed to check cron directory access: {exc}"))
    else:
        results.append(
            CheckResult(
                "Cron Schedule Permissions",
                "WARNING",
                "Directory /etc/cron.d does not exist on this host.",
                "Automated recurring collections via local system cron will be unavailable."
            )
        )

    # 9. Configuration File Validation
    # Search locations manually to parse actual file contents and handle errors properly
    config_file_found = None
    search_locations = []
    env_path = os.environ.get("ORIN_CONFIG_PATH")
    if env_path:
        search_locations.append(Path(env_path))
    search_locations.extend(DEFAULT_CONFIG_LOCATIONS)

    for loc in search_locations:
        if loc.exists() and loc.is_file():
            config_file_found = loc
            break

    if not config_file_found:
        results.append(
            CheckResult(
                "Configuration File",
                "PASS",
                "No custom configuration file found on standard paths. Using built-in defaults."
            )
        )
    else:
        # Config file found, inspect it
        readable = os.access(str(config_file_found), os.R_OK)
        if not readable:
            results.append(
                CheckResult(
                    "Configuration File Permissions",
                    "FAIL",
                    f"Configuration file found at '{config_file_found}' but is not readable.",
                    "Ensure reading permissions are granted to the executing process."
                )
            )
        else:
            try:
                with open(config_file_found, "r") as f:
                    config_data = json.load(f)
                
                results.append(CheckResult("Configuration Syntax", "PASS", f"Parsed configuration file '{config_file_found}' successfully as JSON"))
                
                # Check config schema warnings
                schema_warnings = _validate_config_schema(config_data)
                if not schema_warnings:
                    results.append(CheckResult("Configuration Schema", "PASS", "Configuration schema parameters match expected types"))
                else:
                    warnings_str = " | ".join(schema_warnings)
                    results.append(
                        CheckResult(
                            "Configuration Schema",
                            "WARNING",
                            f"Schema verification found issues: {warnings_str}.",
                            "Check parameter types and configuration names in orin_config.json."
                        )
                    )
            except json.JSONDecodeError as exc:
                results.append(
                    CheckResult(
                        "Configuration Syntax",
                        "FAIL",
                        f"Failed to parse configuration file '{config_file_found}': {exc}.",
                        "Verify config file JSON formatting (missing commas, quotes, brackets)."
                    )
                )
            except Exception as exc:
                results.append(
                    CheckResult(
                        "Configuration Syntax",
                        "FAIL",
                        f"Unexpected error loading configuration file: {exc}.",
                        "Verify configuration file access."
                    )
                )

    return results


def cmd_doctor(args) -> None:
    """CLI subcommand entrypoint to execute doctor health check verification diagnostics."""
    print("=" * 80)
    print("                       ORIN SYSTEM DIAGNOSTIC REPORT")
    print("=" * 80)
    print(f"Platform: {platform.system()} {platform.release()} {platform.machine()}")
    print(f"Python:   {platform.python_version()} ({sys.executable})")
    print("-" * 80)

    db_path = Path(args.database) if hasattr(args, 'database') and args.database else None
    results = run_diagnostics(db_path_override=db_path)

    passes = 0
    warnings = 0
    failures = 0

    for r in results:
        if r.status == "PASS":
            status_indicator = "[\033[92m✓\033[0m]"  # Green tick
            passes += 1
        elif r.status == "WARNING":
            status_indicator = "[\033[93m!\033[0m]"  # Yellow exclamation
            warnings += 1
        else:
            status_indicator = "[\033[91m✗\033[0m]"  # Red cross
            failures += 1
            
        print(f"{status_indicator} {r.name}:")
        print(f"    Detail: {r.detail}")
        if r.recommendation:
            print(f"    Recommendation: {r.recommendation}")
        print()

    print("-" * 80)
    total = len(results)
    print(f"Summary: {passes}/{total} passed, {warnings} warning(s), {failures} failure(s)")
    print("=" * 80)

    # Strict mode handling or general failure
    strict = getattr(args, "strict", False)
    if failures > 0:
        print("\033[91mResult: Host verification failed. Correct critical failures before launching collection.\033[0m")
        sys.exit(1)
    elif strict and warnings > 0:
        print("\033[91mResult: Host verification failed due to strict mode warnings.\033[0m")
        sys.exit(1)
    else:
        print("\033[92mResult: Host is ready for production forensic collection.\033[0m")
        sys.exit(0)
