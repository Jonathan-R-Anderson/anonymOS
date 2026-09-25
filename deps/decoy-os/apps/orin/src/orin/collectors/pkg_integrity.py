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
# src/orin/collectors/pkg_integrity.py
"""
orin.collectors.pkg_integrity – Offline Package Integrity Engine
===============================================================
Parses `/var/lib/dpkg/info/*.md5sums` files on Debian/Ubuntu systems to detect
unauthorized modification or deletion of core system binaries.

Optimised Hashing Strategy
---------------------------
Debian's ``*.md5sums`` files only carry MD5 signatures.  During the primary
verification pass only an MD5 digest is computed using a 64 KB streaming
buffer.  A SHA-256 digest is computed *only* when the MD5 check fails — i.e.
when we have a confirmed tampered or corrupted file that needs to be logged
as a forensic artefact in the database.  This eliminates unnecessary double-
hashing on the large majority of unmodified system binaries.
"""
import hashlib
import os
import errno
from pathlib import Path

# Common binary directories to check (excludes doc, share, etc.)
DEFAULT_BINARY_DIRS = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"
)

_CHUNK = 65536  # 64 KB — aligns well with Linux page/block caches


def _md5_of_fd(fd: int) -> str:
    """Return the MD5 hex digest of an active file descriptor using a streaming buffer."""
    alg = hashlib.md5(usedforsecurity=False)  # nosec
    # closefd=False delegates file descriptor cleanup strictly to our underlying finally block
    with open(fd, "rb", closefd=False) as fh:
        while chunk := fh.read(_CHUNK):
            alg.update(chunk)
    return alg.hexdigest()


def _sha256_of_fd(fd: int) -> str:
    """Return the SHA-256 hex digest of an active file descriptor using a streaming buffer.

    Called only after a confirmed MD5 mismatch to capture a forensic hash of
    the tampered binary without paying the extra I/O cost on clean files.
    """
    alg = hashlib.sha256()
    with open(fd, "rb", closefd=False) as fh:
        while chunk := fh.read(_CHUNK):
            alg.update(chunk)
    return alg.hexdigest()


def gather_pkg_integrity_drift(dpkg_info_dir: Path = Path("/var/lib/dpkg/info")) -> list[dict]:
    """Recalculate hashes of system package binaries and report mismatches or deletions.

    Parameters
    ----------
    dpkg_info_dir : Path, optional
        Filesystem directory where dpkg info is located.
        Defaults to /var/lib/dpkg/info.

    Returns
    -------
    list[dict]
        Each dict represents a package integrity violation:
        - ``package``       (str)       – name of the Debian package.
        - ``file_path``     (str)       – absolute path to the binary.
        - ``expected_md5``  (str)       – expected MD5 hash from dpkg.
        - ``actual_md5``    (str/None)  – computed MD5, or error string.
        - ``actual_sha256`` (str/None)  – SHA-256 of tampered file, or error string.
        - ``status``        (str)       – ``"mismatch"`` or ``"missing"``.
    """
    violations = []
    if not dpkg_info_dir.exists() or not dpkg_info_dir.is_dir():
        return violations

    try:
        for md5sums_file in dpkg_info_dir.glob("*.md5sums"):
            package = md5sums_file.stem

            try:
                # Real-world defense: Stream rows sequentially line-by-line via iterator.
                # read_text().splitlines() forces heavy nested string array copies into VRAM/RAM.
                with md5sums_file.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or len(line) < 34:
                            continue

                        # First 32 chars are the MD5 hash; remainder is the file path
                        expected_md5 = line[:32]
                        file_path_str = line[32:].strip()

                        # Convert to absolute path
                        file_path = Path("/") / file_path_str
                        path_str = str(file_path)

                        # Restrict monitoring scope to system binary/library directories exclusively
                        if not path_str.startswith(DEFAULT_BINARY_DIRS):
                            continue

                        # Real-world defense: Open file descriptor with O_NOFOLLOW to completely 
                        # neutralize Time-of-Check to Time-of-Use (TOCTOU) symlink swap exploits.
                        fd = -1
                        try:
                            fd = os.open(path_str, os.O_RDONLY | os.O_NOFOLLOW)
                        except OSError as e:
                            if e.errno == errno.ENOENT:
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": None,
                                    "actual_sha256": None,
                                    "status": "missing",
                                })
                            elif e.errno == errno.ELOOP:
                                # Caught an explicit symlink redirect loop maneuver
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": "ERROR: Symlink exploit detected via O_NOFOLLOW",
                                    "actual_sha256": "ERROR: Access Restricted",
                                    "status": "mismatch",
                                })
                            else:
                                # Permission denials or systemic device blocks
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": f"ERROR: OS descriptor fault: {e.strerror}",
                                    "actual_sha256": None,
                                    "status": "mismatch",
                                })
                            continue

                        try:
                            # Verify descriptor references a regular file before processing data
                            stat_info = os.fstat(fd)
                            if not os.path.stat.S_ISREG(stat_info.st_mode):
                                continue

                            # ── Primary MD5 check ──────────────────────────────────────
                            try:
                                # Reset read pointer context to base position
                                os.lseek(fd, 0, os.SEEK_SET)
                                actual_md5 = _md5_of_fd(fd)
                            except (OSError, PermissionError) as hash_err:
                                violations.append({
                                    "package": package,
                                    "file_path": path_str,
                                    "expected_md5": expected_md5,
                                    "actual_md5": f"ERROR: MD5 processing fault: {hash_err}",
                                    "actual_sha256": None,
                                    "status": "mismatch",
                                })
                                continue

                            if actual_md5 == expected_md5:
                                # Clean — skip; no secondary SHA-256 needed
                                continue

                            # ── Mismatch confirmed: compute forensic SHA-256 ───────────
                            try:
                                os.lseek(fd, 0, os.SEEK_SET)
                                actual_sha256 = _sha256_of_fd(fd)
                            except (OSError, PermissionError) as hash_err:
                                actual_sha256 = f"ERROR: SHA-256 processing fault: {hash_err}"

                            violations.append({
                                "package": package,
                                "file_path": path_str,
                                "expected_md5": expected_md5,
                                "actual_md5": actual_md5,
                                "actual_sha256": actual_sha256,
                                "status": "mismatch",
                                })
                        finally:
                            if fd != -1:
                                try:
                                    os.close(fd)
                                except OSError:
                                    pass

            except (PermissionError, OSError) as file_err:
                violations.append({
                    "package": package,
                    "file_path": "ERROR_METADATA_MANIFEST",
                    "expected_md5": "MANIFEST_READ_FAULT",
                    "actual_md5": f"Failed to interface with metadata manifest file: {file_err}",
                    "actual_sha256": None,
                    "status": "mismatch",
                })
                continue

    except (PermissionError, OSError) as dir_err:
        # Real-world defense: Surface systemic directory access barriers loudly to the engine ledger
        violations.append({
            "package": "ERROR_PKG_INTEGRITY_ROOT",
            "file_path": str(dpkg_info_dir),
            "expected_md5": "DIRECTORY_TRAVERSAL_FAULT",
            "actual_md5": f"Critical visibility gap traversing dpkg metadata space: {dir_err}",
            "actual_sha256": None,
            "status": "mismatch",
        })

    return violations
    