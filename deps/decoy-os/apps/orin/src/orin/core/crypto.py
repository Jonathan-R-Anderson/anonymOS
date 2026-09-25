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
# orin/core/crypto.py
"""
orin.core.crypto – HMAC-SHA256 Export Signing & Verification
=============================================================
Provides tamper-evident serialisation of Orin forensic snapshots.

Workflow
--------
1. :func:`generate_signed_export`  – reads a snapshot from the SQLite vault,
   serialises it to canonical JSON (keys sorted for determinism), computes an
   HMAC-SHA256 signature, and writes a ``{signature, data}`` bundle to a file.
2. :func:`verify_signed_export`    – reads a bundle file, recomputes the HMAC,
   and raises :exc:`PermissionError` if the signature does not match.
3. :func:`generate_coc_manifest`   – creates a Chain-of-Custody manifest with
   SHA256 hashes, timestamps, and system info for legal defensibility.

Security notes
--------------
* A minimum passphrase length of 12 characters is enforced by
  :func:`_validate_secret` before any cryptographic operation.
* :func:`hmac.compare_digest` is used for the comparison to prevent
  timing-side-channel leaks.
"""
import hmac
import hashlib
import json
import sqlite3
import hashlib as hashlib_module
from pathlib import Path
from datetime import datetime, timezone

#: Minimum acceptable length (in characters) for the HMAC passphrase.
#: Enforced by :func:`_validate_secret` before any cryptographic call.
_MIN_SECRET_LENGTH = 12


def zero_memory(obj) -> None:
    """Zero out the memory buffer of a bytearray, bytes, or string object safely."""
    if not obj:
        return

    # 1. Handle mutable bytearray
    if isinstance(obj, bytearray):
        for i in range(len(obj)):
            obj[i] = 0
        return

    # 2. Handle immutable bytes or str (best-effort under CPython)
    if isinstance(obj, (bytes, str)):
        import ctypes
        import sys

        length = len(obj)
        if length == 0:
            return

        # Avoid zeroing if the object has high reference count (interned or shared)
        try:
            if sys.getrefcount(obj) > 4:
                return
        except Exception:
            pass

        try:
            if isinstance(obj, bytes):
                # Data buffer offset for bytes is empty size minus 1
                header_size = sys.getsizeof(bytes()) - 1
                address = id(obj) + header_size
                ctypes.memset(address, 0, length)
            elif isinstance(obj, str):
                # ASCII strings are PyASCIIObject with 1 byte per character.
                try:
                    obj.encode('ascii')
                    header_size = sys.getsizeof("") - 1
                    address = id(obj) + header_size
                    ctypes.memset(address, 0, length)
                except (UnicodeEncodeError, AttributeError):
                    pass
        except Exception:
            pass


def _validate_secret(secret_key: str) -> None:
    """Enforce a minimum passphrase strength before any cryptographic operation.

    Parameters
    ----------
    secret_key : str
        The passphrase to validate.

    Raises
    ------
    ValueError
        If ``secret_key`` is shorter than :data:`_MIN_SECRET_LENGTH` characters.
    """
    if len(secret_key) < _MIN_SECRET_LENGTH:
        raise ValueError(
            f"Passphrase is too short ({len(secret_key)} chars). "
            f"Minimum required: {_MIN_SECRET_LENGTH} characters."
        )


def generate_signed_export(db_path: Path, snapshot_id: int, secret_key: str) -> str:
    """Serialise a snapshot payload and bind it with an HMAC-SHA256 signature.

    All sub-tables belonging to ``snapshot_id`` are fetched from the Orin
    SQLite vault, assembled into a single Python dictionary, serialised with
    sorted keys (for byte-for-byte determinism), and then signed.

    Parameters
    ----------
    db_path : Path
        Filesystem path to the Orin SQLite vault.
    snapshot_id : int
        Primary-key ID of the ``system_snapshots`` row to export.
    secret_key : str
        HMAC passphrase.  Must be at least :data:`_MIN_SECRET_LENGTH` chars.

    Returns
    -------
    str
        Pretty-printed JSON string with two top-level keys:
        ``"signature"`` (hex HMAC-SHA256 digest) and ``"data"`` (the
        canonical serialised snapshot payload).

    Raises
    ------
    ValueError
        If ``secret_key`` is too short or if ``snapshot_id`` does not exist.
    sqlite3.Error
        On any unexpected database error.
    """
    _validate_secret(secret_key)

    payload = {
        "snapshot_id": snapshot_id,
        "metadata": {},
        "processes": [],
        "ports": [],
        "outbound": [],
        "kernel_modules": [],
        "ssh_keys": [],
        "users": [],
        "file_hashes": [],
        "deleted_binaries": [],
        "promisc_interfaces": [],
        "wtmp_sessions": [],
        "lastlog_records": [],
        "pkg_integrity": []
    }

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Fetch Snapshot Metadata
    cursor.execute(
        "SELECT hostname, os_platform, timestamp FROM system_snapshots WHERE id = ?;",
        (snapshot_id,)
    )
    snap = cursor.fetchone()
    if not snap:
        conn.close()
        raise ValueError(f"Snapshot ID {snapshot_id} does not exist.")
    payload["metadata"] = dict(snap)

    # 2. Extract Sub-tables
    cursor.execute(
        "SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["processes"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["ports"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT local_ip, local_port, remote_ip, remote_port, state, process_name "
        "FROM collected_outbound_connections WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["outbound"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["kernel_modules"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT user_account, key_type, fingerprint, raw_key_comment FROM collected_ssh_keys WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["ssh_keys"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["users"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["file_hashes"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["deleted_binaries"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["promisc_interfaces"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["wtmp_sessions"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["lastlog_records"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["pkg_integrity"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    payload["crontabs"] = [dict(r) for r in cursor.fetchall()]

    conn.close()

    # Canonical string sorting to preserve exact byte arrays
    serialized_data = json.dumps(payload, sort_keys=True)

    # Compute signature
    secret_bytes = bytearray(secret_key.encode("utf-8"))
    serialized_bytes = bytearray(serialized_data.encode("utf-8"))

    signature = hmac.new(
        bytes(secret_bytes),
        bytes(serialized_bytes),
        hashlib.sha256
    ).hexdigest()

    zero_memory(secret_bytes)
    zero_memory(serialized_bytes)
    zero_memory(secret_key)

    # Wrap together into the bundle export format
    return json.dumps({"signature": signature, "data": serialized_data}, indent=2)


def verify_signed_export(export_file_path: Path, secret_key: str) -> dict:
    """Verify a signed export bundle and return the decoded payload.

    Reads the ``{signature, data}`` JSON bundle at ``export_file_path``,
    recomputes the HMAC-SHA256 over the raw ``data`` string, and compares it
    against the stored signature using a constant-time digest comparison.

    Parameters
    ----------
    export_file_path : Path
        Path to the signed ``.json`` export file produced by
        :func:`generate_signed_export`.
    secret_key : str
        HMAC passphrase used at export time.

    Returns
    -------
    dict
        The decoded snapshot payload (the parsed value of the ``"data"`` key).

    Raises
    ------
    ValueError
        If ``secret_key`` fails the minimum-length check.
    PermissionError
        If the computed signature does not match the stored signature,
        indicating that the export file has been tampered with.
    FileNotFoundError
        If ``export_file_path`` does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    """
    _validate_secret(secret_key)

    with open(export_file_path, "r") as f:
        bundle = json.load(f)

    expected_signature = bundle["signature"]
    raw_data = bundle["data"]

    secret_bytes = bytearray(secret_key.encode("utf-8"))
    raw_bytes = bytearray(raw_data.encode("utf-8"))

    computed_signature = hmac.new(
        bytes(secret_bytes),
        bytes(raw_bytes),
        hashlib.sha256
    ).hexdigest()

    zero_memory(secret_bytes)
    zero_memory(raw_bytes)
    zero_memory(secret_key)

    if not hmac.compare_digest(expected_signature, computed_signature):
        raise PermissionError(
            "CRITICAL EXPORT INTEGRITY COLD-FAILURE: Payload signature has been modified!"
        )

    return json.loads(raw_data)


def generate_coc_manifest(db_path: Path, snapshot_id: int, output_dir: Path = None) -> dict:
    """Generate a Chain-of-Custody (CoC) manifest for legal defensibility.

    Creates a comprehensive manifest containing SHA256 hashes of all collected
    evidence files, timestamps, system information, and collector metadata.
    This manifest serves as proof of evidence integrity for forensic investigations.

    Parameters
    ----------
    db_path : Path
        Filesystem path to the Orin SQLite vault.
    snapshot_id : int
        Primary-key ID of the ``system_snapshots`` row to include in manifest.
    output_dir : Path, optional
        Directory to save the manifest file. If None, returns dict without saving.

    Returns
    -------
    dict
        Chain-of-Custody manifest with the following structure:
        - manifest_id: Unique identifier (timestamp-based)
        - generated_at: ISO 8601 timestamp
        - snapshot_id: Reference to the snapshot
        - system_info: Hostname, OS platform, collection timestamp
        - evidence_hashes: List of file paths with their SHA256 hashes
        - collector_info: Tool version and collection metadata
        - manifest_hash: SHA256 of the entire manifest (self-referential)

    Raises
    ------
    ValueError
        If ``snapshot_id`` does not exist in the database.
    sqlite3.Error
        On any unexpected database error.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch Snapshot Metadata
    cursor.execute(
        "SELECT hostname, os_platform, timestamp FROM system_snapshots WHERE id = ?;",
        (snapshot_id,)
    )
    snap = cursor.fetchone()
    if not snap:
        conn.close()
        raise ValueError(f"Snapshot ID {snapshot_id} does not exist.")

    # Build evidence list with hashes
    evidence_hashes = []

    # Get file hashes collected from the system
    cursor.execute(
        "SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    for row in cursor.fetchall():
        evidence_hashes.append({
            "type": "collected_file",
            "path": row["file_path"],
            "sha256": row["sha256_hash"]
        })

    # Get deleted binary hashes
    cursor.execute(
        "SELECT exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    for row in cursor.fetchall():
        evidence_hashes.append({
            "type": "deleted_binary",
            "executable": row["exe"],
            "sha256": row["sha256"],
            "md5": row["md5"],
            "vault_path": row["vault_path"]
        })

    # Get package integrity data
    cursor.execute(
        "SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;",
        (snapshot_id,)
    )
    for row in cursor.fetchall():
        evidence_hashes.append({
            "type": "package_integrity",
            "package": row["package"],
            "file_path": row["file_path"],
            "expected_md5": row["expected_md5"],
            "actual_md5": row["actual_md5"],
            "actual_sha256": row["actual_sha256"],
            "status": row["status"]
        })

    conn.close()

    # Build manifest
    manifest_timestamp = datetime.now(timezone.utc).isoformat()
    manifest_id = f"COC-{snapshot_id}-{manifest_timestamp.replace(':', '-').replace('+', 'Z')}"

    manifest = {
        "manifest_id": manifest_id,
        "generated_at": manifest_timestamp,
        "snapshot_id": snapshot_id,
        "system_info": {
            "hostname": snap["hostname"],
            "os_platform": snap["os_platform"],
            "collection_timestamp": snap["timestamp"]
        },
        "evidence_count": len(evidence_hashes),
        "evidence_hashes": evidence_hashes,
        "collector_info": {
            "tool_name": "orin-dfir",
            "version": "1.2.0",
            "collection_type": "agentless_forensic"
        }
    }

    # Compute self-hash of manifest (excluding the hash field itself)
    manifest_for_hashing = json.dumps(manifest, sort_keys=True)
    manifest_hash = hashlib_module.sha256(manifest_for_hashing.encode("utf-8")).hexdigest()
    manifest["manifest_hash"] = manifest_hash

    # Save to file if output directory specified
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = output_dir / f"coc_manifest_{snapshot_id}.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)

    return manifest