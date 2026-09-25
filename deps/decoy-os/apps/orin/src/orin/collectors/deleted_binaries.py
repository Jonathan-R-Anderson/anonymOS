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
# src/orin/collectors/deleted_binaries.py
"""
orin.collectors.deleted_binaries – In-Memory Executable Recovery
==============================================================
Monitors processes for running deleted binaries by inspecting the virtual
symlinks in /proc/[pid]/exe. If a deleted binary is detected, its active
payload is recovered from the virtual symlink, hashed, and archived.
"""
import hashlib
import os
from pathlib import Path
from orin.core.config import load_config

#: Buffer chunk layout (64 KB) designed to keep memory allocations fixed
_CHUNK_SIZE = 65536

def gather_deleted_binaries(vault_dir: str = None) -> list[dict]:
    """Crawl `/proc` to find running processes referencing deleted binaries.

    Parameters
    ----------
    vault_dir : str, optional
        Target directory to archive recovered payloads. If None, it is resolved
        from the configuration (key "vault_path") or falls back to
        "/var/lib/orin/vault".

    Returns
    -------
    list[dict]
        Each dict contains details of a recovered deleted binary:
        - pid (int)
        - exe (str)
        - sha256 (str)
        - md5 (str)
        - vault_path (str)
    """
    records = []

    if vault_dir is None:
        config = load_config()
        vault_dir = Path(config.get("vault_path", "/var/lib/orin/vault"))
    else:
        vault_dir = Path(vault_dir)

    proc_path = Path("/proc")
    if not proc_path.exists():
        return records

    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        pid = int(pid_dir.name)
        exe_link = pid_dir / "exe"

        try:
            # 1. Resolve executable path link securely
            try:
                target_exe = os.readlink(str(exe_link))
            except (FileNotFoundError, PermissionError, OSError):
                continue

            if not target_exe.endswith(" (deleted)"):
                continue

            # 2. Extract active in-memory payload via streaming chunk blocks
            md5_alg = hashlib.md5(usedforsecurity=False)
            sha256_alg = hashlib.sha256()
            vault_path_str = "failed_to_write_vault"

            try:
                # Ensure storage tree is active
                vault_dir.mkdir(parents=True, exist_ok=True)
                temp_dest = vault_dir / f"recovery_{pid}.tmp"

                # Double streaming: hash calculation and disk write happen simultaneously
                with exe_link.open("rb") as src_f, open(temp_dest, "wb") as dest_f:
                    while chunk := src_f.read(_CHUNK_SIZE):
                        md5_alg.update(chunk)
                        sha256_alg.update(chunk)
                        dest_f.write(chunk)

                md5_hash = md5_alg.hexdigest()
                sha256_hash = sha256_alg.hexdigest()

                dest_file = vault_dir / sha256_hash
                if dest_file.exists():
                    # Binary payload already exists in the local vault; drop the temporary clone
                    temp_dest.unlink(missing_ok=True)
                else:
                    # Commit file swap atomically
                    temp_dest.rename(dest_file)

                vault_path_str = str(dest_file.resolve())

            except (PermissionError, OSError) as storage_error:
                # Storage fallback: if the disk partition is full or read-only,
                # run an isolated computational-only loop to guarantee signature collection
                try:
                    md5_alg = hashlib.md5(usedforsecurity=False)
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