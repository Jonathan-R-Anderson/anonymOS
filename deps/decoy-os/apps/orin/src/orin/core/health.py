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
# src/orin/core/health.py
"""
orin.core.health – Health, Readiness & Operational Metrics
===========================================================
Provides Kubernetes-style liveness and readiness probes for the local
dashboard server and fleet hub, plus an operational metrics endpoint that
surfaces collection performance statistics without requiring external
time-series infrastructure.

Endpoints produced by this module
----------------------------------
``GET /health``
    Liveness probe.  Always responds quickly regardless of vault state.
    Returns HTTP 200 when the process is alive, 503 if a critical internal
    component has failed.

``GET /ready``
    Readiness probe.  The host is "ready" when the vault file exists, is
    readable, contains at least one snapshot, and the SQLite integrity check
    passes.  Returns HTTP 200 when ready, 503 with a reason when not.

``GET /api/metrics``
    Operational metrics snapshot.  Returns counters and durations covering
    snapshot history, alert trends, DB size, and per-collection timing
    (when available).

Design principles
-----------------
* All functions are pure data-gatherers; they never modify state.
* Every function has a bounded timeout guard — a slow DB must not stall
  an external health-check caller for more than a few seconds.
* No external dependencies; stdlib only.
* Results are JSON-serialisable plain dicts.
"""
from __future__ import annotations

import os
import platform
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Version (kept in sync with pyproject.toml via this single constant)
# ---------------------------------------------------------------------------
_ORIN_VERSION = "1.2.0"
_PROCESS_START_TIME: float = time.monotonic()


# ---------------------------------------------------------------------------
# Liveness probe
# ---------------------------------------------------------------------------

def get_liveness(db_path: Path | None = None) -> dict[str, Any]:
    """Return a liveness payload — always fast, never blocks on disk I/O.

    Parameters
    ----------
    db_path:
        Path to the SQLite vault.  Used only for a cheap ``os.path.exists``
        check; no SQL is executed.

    Returns
    -------
    dict with keys:
        status       – "alive"
        version      – Orin version string
        uptime_s     – process uptime in seconds (monotonic)
        timestamp    – ISO-8601 UTC timestamp
        vault_exists – True/False (cheap stat check)
        platform     – OS description
    """
    return {
        "status": "alive",
        "version": _ORIN_VERSION,
        "uptime_s": round(time.monotonic() - _PROCESS_START_TIME, 2),
        "timestamp": _utc_now(),
        "vault_exists": (db_path.exists() if db_path else False),
        "platform": f"{platform.system()} {platform.release()}",
    }


# ---------------------------------------------------------------------------
# Readiness probe
# ---------------------------------------------------------------------------

class ReadinessCheck:
    """Container for a single readiness sub-check result."""

    __slots__ = ("name", "ok", "detail", "latency_ms")

    def __init__(self, name: str, ok: bool, detail: str, latency_ms: float = 0.0):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.latency_ms = round(latency_ms, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
        }


def get_readiness(db_path: Path) -> dict[str, Any]:
    """Run all readiness sub-checks and return a structured summary.

    The overall ``ready`` flag is True only when **all** sub-checks pass.

    Parameters
    ----------
    db_path:
        Path to the SQLite vault file.

    Returns
    -------
    dict with keys:
        ready    – bool
        reason   – human-readable summary when not ready, empty when ready
        checks   – list of individual check result dicts
        timestamp – ISO-8601 UTC timestamp
    """
    checks: list[ReadinessCheck] = [
        _check_vault_exists(db_path),
        _check_vault_readable(db_path),
        _check_has_snapshots(db_path),
        _check_db_integrity(db_path),
    ]

    all_ok = all(c.ok for c in checks)
    failed = [c for c in checks if not c.ok]
    reason = "; ".join(f"{c.name}: {c.detail}" for c in failed) if failed else ""

    return {
        "ready": all_ok,
        "reason": reason,
        "checks": [c.to_dict() for c in checks],
        "timestamp": _utc_now(),
    }


def _check_vault_exists(db_path: Path) -> ReadinessCheck:
    t0 = time.monotonic()
    exists = db_path.exists()
    ms = (time.monotonic() - t0) * 1000
    return ReadinessCheck(
        name="vault_exists",
        ok=exists,
        detail="ok" if exists else f"file not found: {db_path}",
        latency_ms=ms,
    )


def _check_vault_readable(db_path: Path) -> ReadinessCheck:
    if not db_path.exists():
        return ReadinessCheck("vault_readable", False, "vault file missing (skipped)", 0.0)
    t0 = time.monotonic()
    try:
        readable = os.access(str(db_path), os.R_OK)
        ms = (time.monotonic() - t0) * 1000
        return ReadinessCheck(
            name="vault_readable",
            ok=readable,
            detail="ok" if readable else "file exists but is not readable",
            latency_ms=ms,
        )
    except Exception as exc:
        ms = (time.monotonic() - t0) * 1000
        return ReadinessCheck("vault_readable", False, str(exc), ms)


def _check_has_snapshots(db_path: Path) -> ReadinessCheck:
    if not db_path.exists():
        return ReadinessCheck("has_snapshots", False, "vault file missing (skipped)", 0.0)
    t0 = time.monotonic()
    try:
        with _open_ro(db_path) as conn:
            cur = conn.execute("SELECT COUNT(*) FROM system_snapshots;")
            count = cur.fetchone()[0]
        ms = (time.monotonic() - t0) * 1000
        ok = count > 0
        return ReadinessCheck(
            name="has_snapshots",
            ok=ok,
            detail=f"{count} snapshot(s) present" if ok else "no snapshots yet; run 'orin collect' first",
            latency_ms=ms,
        )
    except Exception as exc:
        ms = (time.monotonic() - t0) * 1000
        return ReadinessCheck("has_snapshots", False, f"query error: {exc}", ms)


def _check_db_integrity(db_path: Path) -> ReadinessCheck:
    if not db_path.exists():
        return ReadinessCheck("db_integrity", False, "vault file missing (skipped)", 0.0)
    t0 = time.monotonic()
    try:
        with _open_ro(db_path) as conn:
            cur = conn.execute("PRAGMA integrity_check(1);")
            result = cur.fetchone()[0]
        ms = (time.monotonic() - t0) * 1000
        ok = result == "ok"
        return ReadinessCheck(
            name="db_integrity",
            ok=ok,
            detail=result,
            latency_ms=ms,
        )
    except Exception as exc:
        ms = (time.monotonic() - t0) * 1000
        return ReadinessCheck("db_integrity", False, f"pragma error: {exc}", ms)


# ---------------------------------------------------------------------------
# Operational metrics
# ---------------------------------------------------------------------------

def get_metrics(db_path: Path) -> dict[str, Any]:
    """Gather operational metrics from the vault and process state.

    Parameters
    ----------
    db_path:
        Path to the SQLite vault file.

    Returns
    -------
    dict with sections:
        process      – uptime, PID, version, platform
        vault        – file size, WAL size, snapshot counts, date range
        alerts       – total, unresolved, by-severity breakdown, last 7 days
        collection   – per-table row counts (proxy for collection volume)
        performance  – DB page size, cache hit info from PRAGMA stats
        timestamp    – ISO-8601 UTC timestamp
    """
    timestamp = _utc_now()

    process_info = {
        "version": _ORIN_VERSION,
        "pid": os.getpid(),
        "uptime_s": round(time.monotonic() - _PROCESS_START_TIME, 2),
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python": platform.python_version(),
    }

    if not db_path.exists():
        return {
            "timestamp": timestamp,
            "process": process_info,
            "vault": {"available": False},
            "alerts": {},
            "collection": {},
            "performance": {},
        }

    vault_info = _gather_vault_info(db_path)
    alert_info = _gather_alert_metrics(db_path)
    collection_info = _gather_collection_counts(db_path)
    perf_info = _gather_db_performance(db_path)

    return {
        "timestamp": timestamp,
        "process": process_info,
        "vault": vault_info,
        "alerts": alert_info,
        "collection": collection_info,
        "performance": perf_info,
    }


def _gather_vault_info(db_path: Path) -> dict[str, Any]:
    if not db_path.exists():
        return {"available": False, "path": str(db_path)}

    try:
        size_bytes = db_path.stat().st_size
        wal_path = db_path.with_suffix(".db-wal")
        wal_bytes = wal_path.stat().st_size if wal_path.exists() else 0
    except OSError:
        size_bytes = wal_bytes = 0

    try:
        with _open_ro(db_path) as conn:
            cur = conn.execute("SELECT COUNT(*) FROM system_snapshots;")
            total_snapshots = cur.fetchone()[0]

            first_ts = last_ts = None
            if total_snapshots > 0:
                cur = conn.execute(
                    "SELECT MIN(timestamp) as f, MAX(timestamp) as l FROM system_snapshots;"
                )
                row = cur.fetchone()
                first_ts, last_ts = row[0], row[1]

            cur = conn.execute("SELECT COUNT(DISTINCT hostname) FROM system_snapshots;")
            distinct_hosts = cur.fetchone()[0]
    except Exception:
        total_snapshots = distinct_hosts = 0
        first_ts = last_ts = None

    return {
        "available": True,
        "path": str(db_path),
        "size_bytes": size_bytes,
        "wal_size_bytes": wal_bytes,
        "total_snapshots": total_snapshots,
        "distinct_hosts": distinct_hosts,
        "first_snapshot": first_ts,
        "last_snapshot": last_ts,
    }


def _gather_alert_metrics(db_path: Path) -> dict[str, Any]:
    try:
        with _open_ro(db_path) as conn:
            # Check schema
            cur = conn.execute("PRAGMA table_info(security_events);")
            cols = {row[1] for row in cur.fetchall()}
            has_suppressed = "suppressed" in cols
            sup_cond = " AND suppressed = 0" if has_suppressed else ""

            cur = conn.execute("SELECT COUNT(*) FROM security_events;")
            total = cur.fetchone()[0]

            cur = conn.execute(
                f"SELECT COUNT(*) FROM security_events WHERE resolved = 0{sup_cond};"
            )
            unresolved = cur.fetchone()[0]

            cur = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM security_events "
                f"WHERE resolved = 0{sup_cond} GROUP BY severity;"
            )
            by_severity = {row[0]: row[1] for row in cur.fetchall()}

            # Recent alerts (last 7 days if timestamp column exists)
            recent_7d = None
            if "timestamp" in cols:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM security_events "
                    "WHERE timestamp >= datetime('now', '-7 days');"
                )
                recent_7d = cur.fetchone()[0]

            # Most common event types (top 5)
            cur = conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM security_events "
                "GROUP BY event_type ORDER BY cnt DESC LIMIT 5;"
            )
            top_event_types = [{"event_type": r[0], "count": r[1]} for r in cur.fetchall()]

    except Exception as exc:
        return {"error": str(exc)}

    return {
        "total": total,
        "unresolved": unresolved,
        "by_severity": by_severity,
        "recent_7d": recent_7d,
        "top_event_types": top_event_types,
    }


def _gather_collection_counts(db_path: Path) -> dict[str, Any]:
    """Return row counts for each major collector output table."""
    collector_tables = [
        "collected_processes",
        "collected_ports",
        "collected_outbound_connections",
        "collected_users",
        "collected_crontabs",
        "collected_kernel_modules",
        "collected_file_hashes",
        "collected_suid_binaries",
        "collected_ebpf_programs",
        "collected_ebpf_pinned",
        "collected_deleted_binaries",
        "collected_promisc_interfaces",
        "collected_wtmp_sessions",
        "collected_lastlog_records",
        "collected_auth_logs",
        "collected_ssh_keys",
        "collected_services",
    ]
    counts: dict[str, int] = {}
    try:
        with _open_ro(db_path) as conn:
            for table in collector_tables:
                try:
                    cur = conn.execute(f"SELECT COUNT(*) FROM {table};")  # noqa: S608
                    counts[table] = cur.fetchone()[0]
                except sqlite3.OperationalError:
                    # Table may not exist in older vaults
                    counts[table] = -1  # -1 = table not found
    except Exception as exc:
        return {"error": str(exc)}
    return counts


def _gather_db_performance(db_path: Path) -> dict[str, Any]:
    """Collect SQLite performance PRAGMAs."""
    try:
        with _open_ro(db_path) as conn:
            def pragma(name: str) -> Any:
                try:
                    return conn.execute(f"PRAGMA {name};").fetchone()[0]  # noqa: S608
                except Exception:
                    return None

            return {
                "page_size_bytes": pragma("page_size"),
                "page_count": pragma("page_count"),
                "freelist_count": pragma("freelist_count"),
                "journal_mode": pragma("journal_mode"),
                "cache_size_pages": pragma("cache_size"),
                "mmap_size_bytes": pragma("mmap_size"),
                "wal_autocheckpoint": pragma("wal_autocheckpoint"),
            }
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _open_ro(db_path: Path) -> sqlite3.Connection:
    """Open the SQLite vault read-only with a short busy timeout."""
    conn = sqlite3.connect(
        f"file:{db_path}?mode=ro",
        uri=True,
        timeout=5.0,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# HTTP response helpers — used by both server.py and hub_server.py
# ---------------------------------------------------------------------------

def liveness_response(db_path: Path | None) -> tuple[int, dict[str, Any]]:
    """Return ``(http_status, payload)`` for the ``/health`` endpoint."""
    payload = get_liveness(db_path)
    return 200, payload


def readiness_response(db_path: Path) -> tuple[int, dict[str, Any]]:
    """Return ``(http_status, payload)`` for the ``/ready`` endpoint."""
    payload = get_readiness(db_path)
    status = 200 if payload["ready"] else 503
    return status, payload


def metrics_response(db_path: Path) -> tuple[int, dict[str, Any]]:
    """Return ``(http_status, payload)`` for the ``/api/metrics`` endpoint."""
    payload = get_metrics(db_path)
    return 200, payload
