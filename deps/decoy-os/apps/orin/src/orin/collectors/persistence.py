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
# orin/collectors/persistence.py
"""
orin.collectors.persistence – SSH Authorized-Keys Inventory & System Persistence Harvester
==========================================================================================
Scans every user's ``~/.ssh/authorized_keys`` file to enumerate all public
keys that are trusted for SSH login. This data is used by the analysis
engine to detect newly injected SSH persistence keys between snapshots.

Additionally monitors system persistence vectors including:
  - systemd service units (/etc/systemd/system/)
  - udev rules (/etc/udev/rules.d/)
  - shell initialization files (~/.bashrc, ~/.profile, /etc/bash.bashrc)
  - sysctl configuration (/etc/sysctl.conf, /etc/sysctl.d/)

SHA-256 fingerprints are computed over the raw base64 key body, matching
the output format of ``ssh-keygen -lf`` with the SHA256 algorithm.
"""
import hashlib
import pwd
from pathlib import Path

#: Set of standard recognized SSH public key prefix tags to isolate options options
_KNOWN_KEY_TYPES = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com"
}

#: System persistence paths to monitor for unauthorized modifications
_SYSTEM_PERSISTENCE_PATHS = [
    # systemd service units
    ("/etc/systemd/system", "systemd_service"),
    # udev rules
    ("/etc/udev/rules.d", "udev_rule"),
    # sysctl configuration
    ("/etc/sysctl.conf", "sysctl_config"),
    ("/etc/sysctl.d", "sysctl_config"),
    # shell initialization files (system-wide)
    ("/etc/bash.bashrc", "shell_init"),
    ("/etc/profile", "shell_init"),
    ("/etc/profile.d", "shell_init"),
]

def _hash_file_content(file_path: Path) -> str:
    """Compute SHA-256 hash of a file's content.

    Parameters
    ----------
    file_path : Path
        Path to the file to hash.

    Returns
    -------
    str
        Hex-encoded SHA-256 digest, or error indicator on failure.
    """
    try:
        content = file_path.read_bytes()
        return hashlib.sha256(content).hexdigest()
    except (PermissionError, OSError) as e:
        return f"ACCESS_ERROR:{e.strerror if hasattr(e, 'strerror') else str(e)}"
    except Exception as e:
        return f"HASH_ERROR:{str(e)}"


def gather_active_ssh_keys() -> list[dict]:
    """Inventory all SSH public keys across every registered account profile.

    Queries the local system passwd database dynamically, tracks down mapped
    home directory locations, and securely serializes every active public key
    while isolating environment configuration option prefixes safely.

    Returns
    -------
    list[dict]
        Each dict contains:
        - ``user_account``    (str) – system username owning the key file.
        - ``key_type``        (str) – algorithm label, e.g. ``"ssh-rsa"``.
        - ``fingerprint``     (str) – SHA-256 hex digest of the base64 key body.
        - ``raw_key_comment`` (str) – optional comment field, or explicit error tag.
    """
    ssh_records: list[dict] = []

    try:
        # Real-world defense: Query the dynamic OS account database instead of
        # guessing home layout paths by recursively walking the /home workspace block.
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

                    # Real-world defense: Handle real SSH authorized_keys formatting criteria.
                    # If a line starts with environmental restrictions (e.g., choices, ports),
                    # the algorithm descriptor shifts to index position 1.
                    first_token = parts[0].lower()

                    if first_token in _KNOWN_KEY_TYPES or first_token.startswith("ssh-"):
                        key_type = parts[0]
                        key_body = parts[1]
                        comment = " ".join(parts[2:]) if len(parts) > 2 else "No Comment"
                    else:
                        # Index 0 contains an option configuration context (e.g. command="...",from="...")
                        if len(parts) >= 3:
                            key_type = parts[1]
                            key_body = parts[2]
                            comment = " ".join(parts[3:]) if len(parts) > 3 else "No Comment"
                        else:
                            # Structural tracking failure on malformed configuration payload line
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
            # Propagate and surface path manipulation obstacles to the analytical engine
            ssh_records.append({
                "user_account": user,
                "key_type": "ERROR",
                "fingerprint": "ACCESS_DENIED_INVENTORY_FAULT",
                "raw_key_comment": f"Failed to open secure profile target path: {access_fault.strerror}"
            })

    return ssh_records


def gather_system_persistence() -> list[dict]:
    """Harvest system-level persistence configuration artifacts.

    Scans critical system configuration locations where attackers commonly
    establish persistence mechanisms:
      - systemd service units in /etc/systemd/system/
      - udev hardware rules in /etc/udev/rules.d/
      - shell initialization files (~/.bashrc, /etc/profile, etc.)
      - sysctl kernel parameter configurations

    Returns
    -------
    list[dict]
        List of persistence artifact records with keys:
        - ``source_path``   (str) – Full path to the file/directory entry.
        - ``persistence_type`` (str) – Category label (systemd_service, udev_rule, sysctl_config, shell_init).
        - ``content_hash``  (str) – SHA-256 hex digest of file contents.
        - ``user_owner``    (str) – Username owning the file, or "N/A" for directories.
    """
    persistence_records: list[dict] = []

    for path_str, ptype in _SYSTEM_PERSISTENCE_PATHS:
        target_path = Path(path_str)

        try:
            if not target_path.exists():
                continue

            if target_path.is_file():
                # Single file: hash it directly
                content_hash = _hash_file_content(target_path)
                try:
                    file_stat = target_path.stat()
                    try:
                        owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
                    except KeyError:
                        owner_name = str(file_stat.st_uid)
                except (OSError, PermissionError):
                    owner_name = "UNKNOWN"

                persistence_records.append({
                    "source_path": str(target_path),
                    "persistence_type": ptype,
                    "content_hash": content_hash,
                    "user_owner": owner_name
                })

            elif target_path.is_dir():
                # Directory: iterate through files (non-recursive for security)
                try:
                    for item in target_path.iterdir():
                        if item.is_file() and not item.name.startswith("."):
                            content_hash = _hash_file_content(item)
                            try:
                                file_stat = item.stat()
                                try:
                                    owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
                                except KeyError:
                                    owner_name = str(file_stat.st_uid)
                            except (OSError, PermissionError):
                                owner_name = "UNKNOWN"

                            persistence_records.append({
                                "source_path": str(item),
                                "persistence_type": ptype,
                                "content_hash": content_hash,
                                "user_owner": owner_name
                            })
                except (PermissionError, OSError) as dir_error:
                    persistence_records.append({
                        "source_path": str(target_path),
                        "persistence_type": ptype,
                        "content_hash": f"DIR_READ_ERROR:{dir_error.strerror if hasattr(dir_error, 'strerror') else str(dir_error)}",
                        "user_owner": "N/A"
                    })

        except (PermissionError, OSError) as access_error:
            persistence_records.append({
                "source_path": str(target_path),
                "persistence_type": ptype,
                "content_hash": f"ACCESS_ERROR:{access_error.strerror if hasattr(access_error, 'strerror') else str(access_error)}",
                "user_owner": "N/A"
            })

    # Also scan user-specific shell init files
    try:
        system_accounts = pwd.getpwall()
        for account in system_accounts:
            home_dir = account.pw_dir

            if not home_dir:
                continue

            user_shell_files = [
                Path(home_dir) / ".bashrc",
                Path(home_dir) / ".profile",
                Path(home_dir) / ".bash_profile",
            ]

            for shell_file in user_shell_files:
                try:
                    if shell_file.exists() and shell_file.is_file():
                        content_hash = _hash_file_content(shell_file)
                        try:
                            file_stat = shell_file.stat()
                            try:
                                owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
                            except KeyError:
                                owner_name = str(file_stat.st_uid)
                        except (OSError, PermissionError):
                            owner_name = "UNKNOWN"

                        persistence_records.append({
                            "source_path": str(shell_file),
                            "persistence_type": "shell_init",
                            "content_hash": content_hash,
                            "user_owner": owner_name
                        })
                except (PermissionError, OSError):
                    continue

    except OSError:
        pass

    return persistence_records