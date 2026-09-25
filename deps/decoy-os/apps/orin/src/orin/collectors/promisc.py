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
# src/orin/collectors/promisc.py
"""
orin.collectors.promisc – Promiscuous Mode Interface Flag Monitor
================================================================
Monitors network interfaces to verify if any are operating in promiscuous mode
by checking kernel device flags from the virtual /sys filesystem.
"""
import errno
from pathlib import Path

#: Standard IFF_PROMISC kernel flag bitmask value (defined in <net/if.h>)
_IFF_PROMISC_MASK = 0x100

def gather_promisc_interfaces() -> list[dict]:
    """Inspect network interfaces and check if promiscuous mode is enabled.

    Traverses the `/sys/class/net` pseudo-filesystem to extract raw hexadecimal
    interface flags. If an interface is operating in promiscuous mode, it can
    sniff and capture passing raw network packets off the shared local wire.

    Returns
    -------
    list[dict]
        Each dict contains:
        - interface (str): network interface name (e.g. eth0).
        - flags (str): hexadecimal representation of active interface flags.
        - is_promiscuous (int): 1 if IFF_PROMISC is active, 0 otherwise.
    """
    interfaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists() or not net_path.is_dir():
        return interfaces

    try:
        for iface_dir in net_path.iterdir():
            # Filter for valid interface directory boundaries cleanly
            if not iface_dir.is_dir():
                continue

            interface_name = iface_dir.name
            flags_file = iface_dir / "flags"

            if not flags_file.exists():
                continue
            try:
                content = flags_file.read_text().strip()
                
                # Strip potential common hex padding structures natively
                clean_content = content.lower()
                if clean_content.startswith("0x"):
                    clean_content = clean_content[2:]
                    
                flags = int(clean_content, 16)
                is_promiscuous = 1 if (flags & _IFF_PROMISC_MASK) != 0 else 0
                
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
                    # Device was dynamically detached or torn down mid-iteration pass
                    continue
                    
                interfaces.append({
                    "interface": interface_name,
                    "flags": "ERROR_ACCESS_DENIED",
                    "is_promiscuous": 0,
                    "anomaly_detected": 1,
                    "anomaly_reason": f"Kernel restricted descriptor read interface context: {io_error.strerror}"
                })

    except (PermissionError, OSError) as traversal_error:
        # Real-world defense: Propagate whole directory lockouts to the analysis engine ledger
        interfaces.append({
            "interface": "ERROR_SYS_CLASS_NET_ROOT",
            "flags": "ERROR_TRAVERSAL_FAULT",
            "is_promiscuous": 0,
            "anomaly_detected": 1,
            "anomaly_reason": f"Critical visibility gap traversing sysfs network interfaces space: {traversal_error.strerror}"
        })

    return interfaces