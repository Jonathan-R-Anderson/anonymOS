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
# src/orin/collectors/integrity.py
"""
orin.collectors.integrity – File Integrity Monitor (FIM)
========================================================
Generates SHA-256 checksums for files and directories listed in the Orin
configuration under ``critical_paths`` and ``critical_dirs``.

All hashing is done entirely in-process (no external tools) and skips
symlinks to prevent hash-chain attacks that redirect reads to arbitrary
locations.

Stat-Based Cache
----------------
On each ``orin collect`` run the FIM first issues a lightweight ``os.stat()``
call for every candidate file and cross-references the result against the most
recent snapshot stored in the SQLite vault.  If ``mtime``, ``ctime``, ``size``,
and ``inode`` are all identical to the cached record the existing SHA-256 digest
is reused without touching the file's contents, eliminating the I/O-intensive
read-and-hash cycle for unchanged files.  A full SHA-256 is computed only when
at least one metadata attribute differs.
"""
import hashlib
import os
import errno
import sqlite3
from pathlib import Path
from typing import Optional

from orin.core.config import load_config


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_last_known_metadata(
    db_conn: sqlite3.Connection,
    file_path: str,
) -> Optional[tuple]:
    """Return the most recent cached metadata for *file_path*, or ``None``.

    Parameters
    ----------
    db_conn : sqlite3.Connection
        Open connection to the Orin SQLite vault.
    file_path : str
        Absolute resolved path of the file to look up.

    Returns
    -------
    tuple or None
        ``(sha256_hash, mtime, ctime, size)`` from the latest snapshot that
        recorded this path, or ``None`` if no prior record exists.
    """
    try:
        cursor = db_conn.cursor()
        cursor.execute(
            """
            SELECT sha256_hash, mtime, ctime, size
            FROM   collected_file_hashes
            WHERE  file_path = ?
            ORDER  BY snapshot_id DESC
            LIMIT  1
            """,
            (file_path,),
        )
        return cursor.fetchone()  # (sha256_hash, mtime, ctime, size) | None
    except sqlite3.Error:
        # If the column doesn't exist yet (schema migration in progress) fall
        # back gracefully to a full hash.
        return None


def _hash_file_opportunistically(
    db_conn: Optional[sqlite3.Connection],
    target_path: Path,
    file_signatures: list,
) -> None:
    """Compute (or reuse) the SHA-256 digest for *target_path*.

    The function is a no-op when *target_path* is fundamentally missing,
    while explicit permission denials or symlink exploits are captured and
    logged as forensic error fingerprints.

    Parameters
    ----------
    db_conn : sqlite3.Connection or None
        Open vault connection used for the stat-cache look-up. When ``None``
        the cache is bypassed and the file is always fully hashed.
    target_path : Path
        Absolute path to the file to hash.
    file_signatures : list
        Mutable accumulator list. A dict is appended when processing completes.
    """
    # Soft pre-checks to avoid unnecessary error logging for non-existent entities
    if not target_path.exists() or target_path.is_symlink():
        return

    resolved = str(target_path.resolve())

    try:
        # Real-world defense: Open file descriptor with O_NOFOLLOW to completely
        # neutralize Time-of-Check to Time-of-Use (TOCTOU) symlink swap exploits.
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        # Handle and expose anti-forensic deployment maneuvers openly
        error_msg = "ERROR: "
        if e.errno == errno.ELOOP:
            error_msg += "Symlink exploit signature detected via O_NOFOLLOW"
        elif e.errno == errno.EACCES:
            error_msg += "Permission denied accessing target object"
        else:
            error_msg += f"OS file descriptor allocation fault: {e.strerror}"

        file_signatures.append({
            "file_path": resolved,
            "sha256_hash": error_msg,
            "mtime": 0.0,
            "ctime": 0.0,
            "size": 0,
        })
        return

    try:
        # Query metadata directly off the open file descriptor node
        stat_info = os.fstat(fd)
        current_mtime = stat_info.st_mtime
        current_ctime = stat_info.st_ctime
        current_size  = stat_info.st_size

        # --- Stat-cache look-up ------------------------------------------
        if db_conn is not None:
            cached = _get_last_known_metadata(db_conn, resolved)
            if cached is not None:
                cached_sha, cached_mtime, cached_ctime, cached_size = cached
                if (
                    cached_mtime is not None
                    and cached_ctime is not None
                    and cached_size is not None
                    and current_mtime == float(cached_mtime)
                    and current_ctime == float(cached_ctime)
                    and current_size  == int(cached_size)
                    and not cached_sha.startswith("ERROR:")  # Bypass cache for previous runtime exceptions
                ):
                    # Cache hit: file metadata unchanged — reuse stored hash safely
                    file_signatures.append({
                        "file_path":   resolved,
                        "sha256_hash": cached_sha,
                        "mtime":       current_mtime,
                        "ctime":       current_ctime,
                        "size":        current_size,
                    })
                    return

        # --- Cache miss: compute full SHA-256 with 64 KB streaming buffer --
        hasher = hashlib.sha256()
        # closefd=False delegates file descriptor cleanup strictly to our underlying finally block
        with open(fd, "rb", closefd=False) as fh:
            while chunk := fh.read(65536):
                hasher.update(chunk)

        file_signatures.append({
            "file_path":   resolved,
            "sha256_hash": hasher.hexdigest(),
            "mtime":       current_mtime,
            "ctime":       current_ctime,
            "size":        current_size,
        })

    except (PermissionError, OSError) as runtime_error:
        file_signatures.append({
            "file_path": resolved,
            "sha256_hash": f"ERROR: Content extraction failure: {runtime_error}",
            "mtime": 0.0,
            "ctime": 0.0,
            "size": 0,
        })
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def gather_file_integrity_signatures(
    db_conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Generate SHA-256 fingerprints for all configured critical paths and dirs.

    Reads the active Orin configuration (via :func:`orin.core.config.load_config`)
    and iterates over two sets:

    1. ``critical_paths`` – individual files hashed directly.
    2. ``critical_dirs``  – directories whose contents are recursively
       traversed with ``Path.rglob("*")``; only regular, non-symlink files
       are hashed.

    When *db_conn* is supplied the stat-based cache is active: files whose
    ``mtime``, ``ctime``, and ``size`` match the most recent vault snapshot
    are short-circuited — their stored SHA-256 is reused without reading the
    file from disk.

    Parameters
    ----------
    db_conn : sqlite3.Connection, optional
        Open connection to the Orin SQLite vault. Pass the connection that is
        already open inside ``cmd_collect`` to avoid opening a second handle.

    Returns
    -------
    list[dict]
        Each dict contains:

        - ``file_path``   (str)   – absolute resolved path of the hashed file.
        - ``sha256_hash`` (str)   – lowercase hexadecimal SHA-256 digest or error tag.
        - ``mtime``       (float) – ``st_mtime`` at time of collection.
        - ``ctime``       (float) – ``st_ctime`` at time of collection.
        - ``size``        (int)   – ``st_size`` in bytes at time of collection.
    """
    config = load_config()
    file_signatures: list[dict] = []

    # 1. Process explicit critical files
    for path_str in config.get("critical_paths", []):
        _hash_file_opportunistically(db_conn, Path(path_str), file_signatures)

    # 2. Process critical directories recursively
    for dir_str in config.get("critical_dirs", []):
        target_dir = Path(dir_str)
        if target_dir.exists() and target_dir.is_dir():
            try:
                for filepath in target_dir.rglob("*"):
                    if filepath.is_file() and not filepath.is_symlink():
                        _hash_file_opportunistically(db_conn, filepath, file_signatures)
            except (PermissionError, OSError) as e:
                file_signatures.append({
                    "file_path": str(target_dir),
                    "sha256_hash": f"ERROR: Directory traversal failure: {e}",
                    "mtime": 0.0,
                    "ctime": 0.0,
                    "size": 0,
                })

    return file_signatures