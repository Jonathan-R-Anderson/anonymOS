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
# src/orin/collectors/suid.py
"""
orin.collectors.suid – SUID/SGID Binary Monitor
===============================================
Discovers binaries on the filesystem with SetUID (chmod +s) or SetGID bits active,
recording file ownership, permissions, and SHA-256 signatures.
"""
import stat
import hashlib
import pwd
import grp
from pathlib import Path

DEFAULT_SUID_PATHS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", 
    "/usr/local/bin", "/usr/local/sbin", 
    "/lib", "/lib64", "/usr/lib", "/usr/lib64"
]

def gather_suid_binaries(paths: list[str] = None) -> list[dict]:
    """Scan key executable directories and list all SUID/SGID binaries.

    Parameters
    ----------
    paths : list[str], optional
        Directories to walk recursively. Defaults to common bin/sbin/lib paths.

    Returns
    -------
    list[dict]
        List of dictionaries detailing each SUID/SGID binary found.
    """
    if paths is None:
        paths = DEFAULT_SUID_PATHS
        
    records = []
    seen = set()
    
    for path_str in paths:
        path = Path(path_str)
        if not path.exists() or not path.is_dir():
            continue
            
        try:
            # Recursively walk directories
            for entry in path.rglob("*"):
                try:
                    # Resolve links and only check regular files
                    if entry.is_symlink() or not entry.is_file():
                        continue
                except OSError:
                    continue
                    
                try:
                    abs_path = str(entry.resolve())
                except OSError:
                    abs_path = str(entry.absolute())
                    
                if abs_path in seen:
                    continue
                seen.add(abs_path)
                
                try:
                    st = entry.stat()
                    mode = st.st_mode
                    is_suid = bool(mode & stat.S_ISUID)
                    is_sgid = bool(mode & stat.S_ISGID)
                    
                    if is_suid or is_sgid:
                        try:
                            owner = pwd.getpwuid(st.st_uid).pw_name
                        except KeyError:
                            owner = str(st.st_uid)
                        try:
                            group = grp.getgrgid(st.st_gid).gr_name
                        except KeyError:
                            group = str(st.st_gid)
                            
                        # Format permissions mode as octal string
                        permissions = oct(stat.S_IMODE(mode))
                        
                        # SHA-256 hash calculation
                        h = hashlib.sha256()
                        try:
                            with open(entry, "rb") as f:
                                for chunk in iter(lambda: f.read(65536), b""):
                                    h.update(chunk)
                            sha256 = h.hexdigest()
                        except (OSError, PermissionError):
                            sha256 = "unknown"
                            
                        records.append({
                            "file_path": abs_path,
                            "owner": owner,
                            "grp": group,
                            "permissions": permissions,
                            "sha256": sha256
                        })
                except OSError:
                    continue
        except OSError:
            continue
            
    return records
