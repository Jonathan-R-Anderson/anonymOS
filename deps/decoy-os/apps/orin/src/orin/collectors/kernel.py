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
# orin/collectors/kernel.py
"""
orin.collectors.kernel – Linux Kernel Module Harvester
======================================================
Reads ``/proc/modules`` to enumerate every Loadable Kernel Module (LKM)
currently active in the kernel address space.

The analysis engine uses this data in two ways:

1. At ``orin init`` time, the snapshot is stored as an approved baseline in
   ``baseline_kernel_modules``.
2. At subsequent ``orin analyze`` runs, newly appearing modules that are
   absent from the baseline are flagged as untrusted LKMs.

Additionally, this module provides kernel symbol analysis capabilities by
parsing ``/proc/kallsyms`` to detect potential kernel rootkits that override
kernel function pointers or inject malicious code into kernel space.
"""
from pathlib import Path

#: Path to the Linux kernel module status file.
MODULES_PATH = Path("/proc/modules")

#: Path to the kernel symbols export file.
KALLSYMS_PATH = Path("/proc/kallsyms")

#: Common kernel function prefixes that should not be modified by third-party modules.
CRITICAL_KERNEL_SYMBOLS = {
    "sys_",           # System call handlers
    "do_syscall",     # System call entry points
    "native_write_msr",  # MSR write operations
    "write_cr0",      # Control register modifications
    "write_cr4",      # Control register modifications
    "kallsyms_lookup_name",  # Symbol lookup (often hooked by rootkits)
    "commit_creds",   # Credential manipulation
    "prepare_kernel_cred",  # Credential preparation
    "ptrace_attach",  # Process debugging/injection
    "security_file_permission",  # LSM hooks
    "apparmor_file_perm",  # AppArmor hooks
    "selinux_file_permission",  # SELinux hooks
}

#: Known rootkit module name patterns.
ROOTKIT_MODULE_PATTERNS = {
    "diamorphine",
    "reptile",
    "beurk",
    "vlany",
    "mbroot",
    "adore",
    "knark",
    "t0rnkit",
    "rkit",
    "darkroot",
}


def gather_loaded_kernel_modules() -> list[dict]:
    """Parse ``/proc/modules`` and return all currently loaded kernel modules.

    Each line in ``/proc/modules`` follows the format::

        <name> <memory_size> <instances_loaded> <dependencies> <state> <offset>

    Only the first three whitespace-delimited fields are captured.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``module_name``       (str) – kernel module identifier.
        - ``memory_size``       (int) – memory footprint of the module in bytes.
        - ``instances_loaded``  (int) – number of loaded instances / use-count.

    Notes
    -----
    Returns an empty list when ``/proc/modules`` is absent (e.g. non-Linux
    environments or containers that hide the pseudo-filesystem).
    """
    modules_list = []
    if not MODULES_PATH.exists():
        return modules_list

    try:
        with open(MODULES_PATH, "r", errors="replace") as f:
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

                # Real-world defense: Isolate row casting to prevent an anti-forensic string insertion
                # from crashing the remaining data-gathering iterator loop.
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
    """Parse ``/proc/kallsyms`` and return all exported kernel symbols.

    Each line in ``/proc/kallsyms`` follows the format::

        <address> <type> <symbol_name> [module_name]

    Where:
    - address: Hexadecimal memory address of the symbol
    - type: Symbol type (T=text/code, D=data, B=bss, etc.)
    - symbol_name: Name of the kernel symbol
    - module_name: Optional module name in brackets (e.g., [ext4])

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``address``         (str) – hexadecimal memory address.
        - ``symbol_type``     (str) – single character type code.
        - ``symbol_name``     (str) – kernel symbol identifier.
        - ``module_name``     (str|None) – owning module if applicable.
        - ``is_critical``     (bool) – whether symbol matches critical patterns.
        - ``suspicious``      (bool) – whether symbol appears suspicious.

    Notes
    -----
    Returns an empty list when ``/proc/kallsyms`` is absent or inaccessible.
    On most systems, reading kallsyms requires root privileges or
    ``kernel.kptr_restrict=0``.
    """
    symbols_list = []
    if not KALLSYMS_PATH.exists():
        return symbols_list

    try:
        with open(KALLSYMS_PATH, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split()
                if len(parts) < 3:
                    continue

                address = parts[0]
                symbol_type = parts[1]
                symbol_name = parts[2]

                # Check if symbol belongs to a module (format: symbol_name [module])
                module_name = None
                if len(parts) >= 4 and parts[3].startswith("[") and parts[3].endswith("]"):
                    module_name = parts[3][1:-1]

                # Detect suspicious symbols
                is_critical = any(
                    symbol_name.startswith(prefix) or symbol_name == prefix
                    for prefix in CRITICAL_KERNEL_SYMBOLS
                )

                # Flag potentially malicious symbols
                suspicious = False
                anomaly_reason = None

                # Check for known rootkit patterns
                if any(pattern in symbol_name.lower() for pattern in ROOTKIT_MODULE_PATTERNS):
                    suspicious = True
                    anomaly_reason = "Symbol name matches known rootkit pattern"

                # Check for hidden/replaced system calls (sys_* from non-kernel modules)
                elif symbol_name.startswith("sys_") and module_name and module_name not in ("kernel", "vmlinux"):
                    suspicious = True
                    anomaly_reason = f"System call handler '{symbol_name}' exported by third-party module '{module_name}'"

                # Check for credential manipulation symbols in unexpected modules
                elif symbol_name in ("commit_creds", "prepare_kernel_cred") and module_name:
                    suspicious = True
                    anomaly_reason = f"Credential manipulation symbol '{symbol_name}' found in module '{module_name}'"

                symbols_list.append({
                    "address": address,
                    "symbol_type": symbol_type,
                    "symbol_name": symbol_name,
                    "module_name": module_name,
                    "is_critical": is_critical,
                    "suspicious": suspicious,
                    "anomaly_detected": 1 if suspicious else 0,
                    "anomaly_reason": anomaly_reason
                })

    except (PermissionError, OSError) as io_error:
        symbols_list.append({
            "address": "0x0",
            "symbol_type": "E",
            "symbol_name": "ERROR_KALLSYMS_ACCESS_FAULT",
            "module_name": None,
            "is_critical": False,
            "suspicious": True,
            "anomaly_detected": 1,
            "anomaly_reason": f"Failed to access kernel symbols: {io_error}. Ensure running as root or set kernel.kptr_restrict=0"
        })

    return symbols_list


def analyze_kernel_symbol_overrides(symbols: list[dict]) -> dict:
    """Analyze kernel symbols for potential rootkit activity.

    This function performs heuristic analysis on collected kernel symbols to
    identify indicators of compromise related to kernel-level rootkits.

    Parameters
    ----------
    symbols : list[dict]
        List of symbol dictionaries from ``gather_kernel_symbols()``.

    Returns
    -------
    dict
        Analysis summary containing:
        - ``total_symbols`` (int) – total number of symbols analyzed.
        - ``critical_symbols`` (int) – count of critical kernel symbols.
        - ``suspicious_symbols`` (int) – count of flagged suspicious symbols.
        - ``potential_rootkit_indicators`` (list[dict]) – detailed findings.
        - ``risk_level`` (str) – "LOW", "MEDIUM", "HIGH", or "CRITICAL".
    """
    critical_count = sum(1 for s in symbols if s.get("is_critical", False))
    suspicious_count = sum(1 for s in symbols if s.get("suspicious", False))

    rootkit_indicators = []

    # Collect all suspicious symbols as indicators
    for symbol in symbols:
        if symbol.get("suspicious", False):
            rootkit_indicators.append({
                "symbol_name": symbol["symbol_name"],
                "address": symbol["address"],
                "module_name": symbol.get("module_name"),
                "reason": symbol.get("anomaly_reason", "Unknown"),
                "severity": "HIGH" if symbol["symbol_name"].startswith("sys_") else "MEDIUM"
            })

    # Determine overall risk level
    if suspicious_count == 0:
        risk_level = "LOW"
    elif suspicious_count <= 2:
        risk_level = "MEDIUM"
    elif suspicious_count <= 5:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # Upgrade risk if credential manipulation detected
    cred_manipulation = any(
        "credential" in ind.get("reason", "").lower()
        for ind in rootkit_indicators
    )
    if cred_manipulation and risk_level != "CRITICAL":
        risk_level = "HIGH"

    return {
        "total_symbols": len(symbols),
        "critical_symbols": critical_count,
        "suspicious_symbols": suspicious_count,
        "potential_rootkit_indicators": rootkit_indicators,
        "risk_level": risk_level
    }


def check_for_unlinked_modules(modules: list[dict], symbols: list[dict]) -> list[dict]:
    """Detect potential unlinked kernel modules hiding from /proc/modules.

    Advanced rootkits may unlink themselves from the kernel module list to
    evade detection, but their symbols may still appear in /proc/kallsyms.

    Parameters
    ----------
    modules : list[dict]
        List of modules from ``gather_loaded_kernel_modules()``.
    symbols : list[dict]
        List of symbols from ``gather_kernel_symbols()``.

    Returns
    -------
    list[dict]
        List of suspected unlinked modules with details.
    """
    # Extract module names from /proc/modules
    visible_modules = {m["module_name"] for m in modules if not m.get("module_name", "").startswith("ERROR")}

    # Extract unique module names from kallsyms
    modules_from_symbols = set()
    for sym in symbols:
        mod_name = sym.get("module_name")
        if mod_name and not sym.get("suspicious", False):
            modules_from_symbols.add(mod_name)

    # Find modules referenced in symbols but not in /proc/modules
    hidden_candidates = []
    for mod_name in modules_from_symbols:
        if mod_name not in visible_modules and mod_name not in ("kernel", "vmlinux"):
            # Count symbols belonging to this module
            mod_symbols = [s for s in symbols if s.get("module_name") == mod_name]

            # Only flag if module has significant presence (more than 2 symbols)
            if len(mod_symbols) > 2:
                hidden_candidates.append({
                    "module_name": mod_name,
                    "symbol_count": len(mod_symbols),
                    "sample_symbols": [s["symbol_name"] for s in mod_symbols[:5]],
                    "detection_method": "Present in /proc/kallsyms but absent from /proc/modules",
                    "severity": "HIGH"
                })

    return hidden_candidates