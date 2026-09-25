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
"""
tests/test_health.py
====================
Unit tests for orin.core.health — liveness probe, readiness probe,
and operational metrics endpoint.

Coverage targets
----------------
* get_liveness: all fields present, vault_exists True/False, uptime
* Readiness sub-checks: vault_exists, vault_readable, has_snapshots, db_integrity
* get_readiness: all pass → ready=True; any fail → ready=False + reason
* ReadinessCheck.to_dict structure
* get_metrics: with vault, without vault, all sections present
* _gather_vault_info, _gather_alert_metrics, _gather_collection_counts, _gather_db_performance
* liveness_response / readiness_response / metrics_response HTTP tuple returns
* Error paths: unreadable DB, corrupt DB, missing tables
"""
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from orin.core.health import (
    ReadinessCheck,
    _check_db_integrity,
    _check_has_snapshots,
    _check_vault_exists,
    _check_vault_readable,
    _gather_alert_metrics,
    _gather_collection_counts,
    _gather_db_performance,
    _gather_vault_info,
    get_liveness,
    get_metrics,
    get_readiness,
    liveness_response,
    metrics_response,
    readiness_response,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_empty_vault(path: Path) -> None:
    """Create a minimal SQLite vault with the core tables but no data."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS system_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            timestamp TEXT,
            os_platform TEXT
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            severity TEXT,
            description TEXT,
            resolved INTEGER DEFAULT 0,
            suppressed INTEGER DEFAULT 0,
            timestamp TEXT,
            attck_technique TEXT,
            attck_tactic TEXT,
            hostname TEXT
        );
        CREATE TABLE IF NOT EXISTS collected_processes (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_ports (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_outbound_connections (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_users (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_crontabs (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_kernel_modules (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_file_hashes (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_suid_binaries (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_ebpf_programs (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_ebpf_pinned (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_deleted_binaries (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_promisc_interfaces (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_wtmp_sessions (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_lastlog_records (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_auth_logs (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS collected_ssh_keys (
            id INTEGER PRIMARY KEY, snapshot_id INTEGER
        );
    """)
    conn.commit()
    conn.close()


def _add_snapshot(path: Path, hostname: str = "host1") -> int:
    conn = sqlite3.connect(str(path))
    cur = conn.execute(
        "INSERT INTO system_snapshots (hostname, timestamp, os_platform) VALUES (?, datetime('now'), 'Linux');",
        (hostname,)
    )
    snap_id = cur.lastrowid
    conn.commit()
    conn.close()
    return snap_id


def _add_event(path: Path, severity: str = "critical", event_type: str = "test_event") -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(
        "INSERT INTO security_events (event_type, severity, description, resolved, suppressed, "
        "timestamp, hostname) VALUES (?, ?, 'test', 0, 0, datetime('now'), 'host1');",
        (event_type, severity)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# ReadinessCheck tests
# ---------------------------------------------------------------------------

class TestReadinessCheck(unittest.TestCase):

    def test_to_dict_keys(self):
        rc = ReadinessCheck("vault_exists", True, "ok", 1.5)
        d = rc.to_dict()
        self.assertIn("name", d)
        self.assertIn("ok", d)
        self.assertIn("detail", d)
        self.assertIn("latency_ms", d)

    def test_to_dict_values(self):
        rc = ReadinessCheck("test_check", False, "something failed", 12.345)
        d = rc.to_dict()
        self.assertEqual(d["name"], "test_check")
        self.assertFalse(d["ok"])
        self.assertEqual(d["detail"], "something failed")
        self.assertAlmostEqual(d["latency_ms"], 12.35, places=0)

    def test_latency_rounded(self):
        rc = ReadinessCheck("x", True, "ok", 1.23456789)
        self.assertEqual(rc.latency_ms, 1.23)


# ---------------------------------------------------------------------------
# Liveness tests
# ---------------------------------------------------------------------------

class TestGetLiveness(unittest.TestCase):

    def test_required_fields_present(self):
        result = get_liveness(None)
        for key in ("status", "version", "uptime_s", "timestamp", "vault_exists", "platform"):
            self.assertIn(key, result)

    def test_status_is_alive(self):
        self.assertEqual(get_liveness(None)["status"], "alive")

    def test_vault_exists_false_when_none(self):
        self.assertFalse(get_liveness(None)["vault_exists"])

    def test_vault_exists_false_when_missing(self):
        result = get_liveness(Path("/nonexistent/path/orin.db"))
        self.assertFalse(result["vault_exists"])

    def test_vault_exists_true_when_present(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            result = get_liveness(Path(tf.name))
            self.assertTrue(result["vault_exists"])

    def test_uptime_is_positive(self):
        result = get_liveness(None)
        self.assertGreater(result["uptime_s"], 0)

    def test_timestamp_is_string(self):
        result = get_liveness(None)
        self.assertIsInstance(result["timestamp"], str)
        self.assertIn("T", result["timestamp"])

    def test_platform_is_string(self):
        result = get_liveness(None)
        self.assertIsInstance(result["platform"], str)
        self.assertGreater(len(result["platform"]), 0)

    def test_version_is_string(self):
        result = get_liveness(None)
        self.assertIsInstance(result["version"], str)
        self.assertGreater(len(result["version"]), 0)


# ---------------------------------------------------------------------------
# Readiness sub-check tests
# ---------------------------------------------------------------------------

class TestCheckVaultExists(unittest.TestCase):

    def test_ok_when_file_exists(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            rc = _check_vault_exists(Path(tf.name))
            self.assertTrue(rc.ok)
            self.assertEqual(rc.name, "vault_exists")

    def test_fail_when_file_missing(self):
        rc = _check_vault_exists(Path("/tmp/__orin_nonexistent_test.db"))
        self.assertFalse(rc.ok)

    def test_latency_recorded(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            rc = _check_vault_exists(Path(tf.name))
            self.assertGreaterEqual(rc.latency_ms, 0.0)


class TestCheckVaultReadable(unittest.TestCase):

    def test_ok_when_readable(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            rc = _check_vault_readable(Path(tf.name))
            self.assertTrue(rc.ok)

    def test_skipped_when_missing(self):
        rc = _check_vault_readable(Path("/tmp/__orin_nonexistent_test.db"))
        self.assertFalse(rc.ok)
        self.assertIn("missing", rc.detail)


class TestCheckHasSnapshots(unittest.TestCase):

    def test_ok_when_snapshot_present(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path)
            rc = _check_has_snapshots(path)
            self.assertTrue(rc.ok)
            self.assertIn("1", rc.detail)

    def test_fail_when_no_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            rc = _check_has_snapshots(path)
            self.assertFalse(rc.ok)
            self.assertIn("no snapshots", rc.detail)

    def test_skipped_when_missing(self):
        rc = _check_has_snapshots(Path("/tmp/__orin_missing.db"))
        self.assertFalse(rc.ok)

    def test_error_on_corrupt_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            tf.write(b"not a valid sqlite database!!!!")
            tf.flush()
            rc = _check_has_snapshots(Path(tf.name))
        os.unlink(tf.name)
        self.assertFalse(rc.ok)
        self.assertIn("query error", rc.detail)


class TestCheckDbIntegrity(unittest.TestCase):

    def test_ok_on_valid_db(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            rc = _check_db_integrity(path)
            self.assertTrue(rc.ok)
            self.assertEqual(rc.detail, "ok")

    def test_skipped_when_missing(self):
        rc = _check_db_integrity(Path("/tmp/__orin_missing.db"))
        self.assertFalse(rc.ok)

    def test_error_on_corrupt_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            tf.write(b"CORRUPTED DATA NOT SQLITE FORMAT !!!!")
            tf.flush()
            rc = _check_db_integrity(Path(tf.name))
        os.unlink(tf.name)
        self.assertFalse(rc.ok)


# ---------------------------------------------------------------------------
# get_readiness integration tests
# ---------------------------------------------------------------------------

class TestGetReadiness(unittest.TestCase):

    def test_all_pass_returns_ready(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path)
            result = get_readiness(path)
            self.assertTrue(result["ready"])
            self.assertEqual(result["reason"], "")

    def test_no_snapshots_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_readiness(path)
            self.assertFalse(result["ready"])
            self.assertIn("has_snapshots", result["reason"])

    def test_missing_vault_not_ready(self):
        result = get_readiness(Path("/tmp/__orin_nonexistent.db"))
        self.assertFalse(result["ready"])

    def test_checks_list_has_four_items(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_readiness(path)
            self.assertEqual(len(result["checks"]), 4)

    def test_each_check_has_required_keys(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_readiness(path)
            for chk in result["checks"]:
                self.assertIn("name", chk)
                self.assertIn("ok", chk)
                self.assertIn("detail", chk)
                self.assertIn("latency_ms", chk)

    def test_timestamp_present(self):
        result = get_readiness(Path("/tmp/__nonexistent.db"))
        self.assertIn("timestamp", result)


# ---------------------------------------------------------------------------
# get_metrics tests
# ---------------------------------------------------------------------------

class TestGetMetrics(unittest.TestCase):

    def test_returns_all_sections_with_vault(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path)
            result = get_metrics(path)
            for key in ("timestamp", "process", "vault", "alerts", "collection", "performance"):
                self.assertIn(key, result)

    def test_vault_unavailable_without_file(self):
        result = get_metrics(Path("/tmp/__orin_missing.db"))
        self.assertFalse(result["vault"]["available"])

    def test_process_section_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_metrics(path)
            proc = result["process"]
            self.assertIn("version", proc)
            self.assertIn("pid", proc)
            self.assertIn("uptime_s", proc)
            self.assertIn("platform", proc)

    def test_process_pid_is_current(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_metrics(path)
            self.assertEqual(result["process"]["pid"], os.getpid())

    def test_vault_section_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path)
            result = get_metrics(path)
            vault = result["vault"]
            self.assertTrue(vault["available"])
            self.assertEqual(vault["total_snapshots"], 1)
            self.assertEqual(vault["distinct_hosts"], 1)
            self.assertGreater(vault["size_bytes"], 0)

    def test_alert_section_with_events(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_event(path, "critical", "untrusted_kernel_module")
            _add_event(path, "high", "file_modification")
            _add_event(path, "critical", "hidden_process")
            result = get_metrics(path)
            alerts = result["alerts"]
            self.assertEqual(alerts["total"], 3)
            self.assertEqual(alerts["unresolved"], 3)
            self.assertEqual(alerts["by_severity"].get("critical", 0), 2)
            self.assertEqual(alerts["by_severity"].get("high", 0), 1)

    def test_collection_section_has_table_counts(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_metrics(path)
            coll = result["collection"]
            self.assertIn("collected_processes", coll)
            self.assertIn("collected_ports", coll)
            # Empty vault → all counts are 0
            self.assertEqual(coll["collected_processes"], 0)

    def test_performance_section_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            result = get_metrics(path)
            perf = result["performance"]
            self.assertIn("page_size_bytes", perf)
            self.assertIn("journal_mode", perf)
            self.assertIn("page_count", perf)

    def test_multiple_snapshots_counted(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path, "host1")
            _add_snapshot(path, "host1")
            _add_snapshot(path, "host2")
            result = get_metrics(path)
            self.assertEqual(result["vault"]["total_snapshots"], 3)
            self.assertEqual(result["vault"]["distinct_hosts"], 2)

    def test_top_event_types_in_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            for _ in range(3):
                _add_event(path, "high", "file_modification")
            _add_event(path, "critical", "hidden_process")
            result = get_metrics(path)
            top = result["alerts"]["top_event_types"]
            self.assertIsInstance(top, list)
            self.assertGreater(len(top), 0)
            # Most common should be file_modification (3 occurrences)
            self.assertEqual(top[0]["event_type"], "file_modification")
            self.assertEqual(top[0]["count"], 3)

    def test_missing_collector_table_returns_minus_one(self):
        """When a collector table is absent (older vault), count = -1."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            # Create minimal vault WITHOUT all collector tables
            conn = sqlite3.connect(str(path))
            conn.executescript("""
                CREATE TABLE system_snapshots (id INTEGER PRIMARY KEY, hostname TEXT, timestamp TEXT, os_platform TEXT);
                CREATE TABLE security_events (id INTEGER PRIMARY KEY, event_type TEXT, severity TEXT,
                    description TEXT, resolved INTEGER DEFAULT 0, suppressed INTEGER DEFAULT 0,
                    timestamp TEXT, hostname TEXT);
            """)
            conn.commit()
            conn.close()
            result = get_metrics(path)
            coll = result["collection"]
            # Tables not present return -1
            self.assertEqual(coll.get("collected_processes"), -1)


# ---------------------------------------------------------------------------
# _gather_* unit tests
# ---------------------------------------------------------------------------

class TestGatherVaultInfo(unittest.TestCase):

    def test_available_false_when_missing(self):
        info = _gather_vault_info(Path("/tmp/__missing.db"))
        self.assertFalse(info["available"])

    def test_snapshot_counts_correct(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path, "alpha")
            _add_snapshot(path, "beta")
            info = _gather_vault_info(path)
            self.assertTrue(info["available"])
            self.assertEqual(info["total_snapshots"], 2)
            self.assertEqual(info["distinct_hosts"], 2)

    def test_size_bytes_positive(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            info = _gather_vault_info(path)
            self.assertGreater(info["size_bytes"], 0)


class TestGatherAlertMetrics(unittest.TestCase):

    def test_empty_db_all_zeros(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            metrics = _gather_alert_metrics(path)
            self.assertEqual(metrics["total"], 0)
            self.assertEqual(metrics["unresolved"], 0)

    def test_counts_by_severity(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_event(path, "critical")
            _add_event(path, "critical")
            _add_event(path, "high")
            metrics = _gather_alert_metrics(path)
            self.assertEqual(metrics["by_severity"]["critical"], 2)
            self.assertEqual(metrics["by_severity"]["high"], 1)

    def test_recent_7d_present(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_event(path, "high")
            metrics = _gather_alert_metrics(path)
            self.assertIsNotNone(metrics["recent_7d"])
            self.assertEqual(metrics["recent_7d"], 1)


class TestGatherDbPerformance(unittest.TestCase):

    def test_page_size_present_and_positive(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            perf = _gather_db_performance(path)
            self.assertIn("page_size_bytes", perf)
            self.assertGreater(perf["page_size_bytes"], 0)

    def test_journal_mode_present(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            perf = _gather_db_performance(path)
            self.assertIn("journal_mode", perf)

    def test_error_on_missing_db(self):
        perf = _gather_db_performance(Path("/tmp/__missing.db"))
        self.assertIn("error", perf)


# ---------------------------------------------------------------------------
# HTTP helper functions
# ---------------------------------------------------------------------------

class TestHttpHelpers(unittest.TestCase):

    def test_liveness_response_returns_200(self):
        status, payload = liveness_response(None)
        self.assertEqual(status, 200)
        self.assertIn("status", payload)

    def test_readiness_response_503_when_not_ready(self):
        status, payload = readiness_response(Path("/tmp/__orin_nonexistent_test.db"))
        self.assertEqual(status, 503)
        self.assertFalse(payload["ready"])

    def test_readiness_response_200_when_ready(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            _add_snapshot(path)
            status, payload = readiness_response(path)
            self.assertEqual(status, 200)
            self.assertTrue(payload["ready"])

    def test_metrics_response_returns_200(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.db"
            _make_empty_vault(path)
            status, payload = metrics_response(path)
            self.assertEqual(status, 200)
            self.assertIn("timestamp", payload)

    def test_metrics_response_missing_vault_still_200(self):
        status, payload = metrics_response(Path("/tmp/__orin_missing.db"))
        self.assertEqual(status, 200)
        self.assertFalse(payload["vault"]["available"])


if __name__ == "__main__":
    unittest.main()
