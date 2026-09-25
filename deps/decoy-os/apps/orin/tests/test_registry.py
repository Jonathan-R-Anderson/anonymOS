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
tests/test_registry.py – Unit and Integration Tests for Collector Framework
===========================================================================
"""

import unittest
import json
import sqlite3
import io
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from orin.collectors.registry import (
    COLLECTOR_REGISTRY,
    CollectorMetadata,
    get_registered_collectors,
    check_privilege_satisfaction,
    execute_collector_with_context
)
from orin.core.database import OrinStorage
from orin.orchestrator import cmd_collectors, cmd_collect


class TestRegistryUnit(unittest.TestCase):
    """Unit tests for registry data structures and filters."""

    def test_get_registered_collectors_no_filter(self):
        """Verify that all collectors are returned when no filters are set."""
        all_collectors = get_registered_collectors()
        self.assertEqual(len(all_collectors), len(COLLECTOR_REGISTRY))

    def test_get_registered_collectors_user_filter(self):
        """Verify that user filter only returns user-level privilege collectors."""
        user_collectors = get_registered_collectors(privilege_level="user")
        for c in user_collectors:
            self.assertEqual(c.privilege_requirements, "user")
        self.assertLess(len(user_collectors), len(COLLECTOR_REGISTRY))

    def test_get_registered_collectors_impact_filter(self):
        """Verify that max_impact filters work as expected."""
        low_impact = get_registered_collectors(max_impact="low")
        for c in low_impact:
            self.assertEqual(c.runtime_impact, "low")

        med_impact = get_registered_collectors(max_impact="medium")
        for c in med_impact:
            self.assertIn(c.runtime_impact, ["low", "medium"])
        self.assertGreater(len(med_impact), len(low_impact))

    @patch("orin.collectors.registry.os.geteuid")
    def test_check_privilege_satisfaction(self, mock_geteuid):
        """Verify check_privilege_satisfaction returns correctly for root vs user."""
        root_collector = CollectorMetadata(
            name="test_root",
            func=lambda: [],
            description="test",
            privilege_requirements="root",
            required_capabilities=[],
            runtime_impact="low",
            impact_reason="test"
        )
        user_collector = CollectorMetadata(
            name="test_user",
            func=lambda: [],
            description="test",
            privilege_requirements="user",
            required_capabilities=[],
            runtime_impact="low",
            impact_reason="test"
        )

        # Non-root session
        mock_geteuid.return_value = 1000
        self.assertFalse(check_privilege_satisfaction(root_collector))
        self.assertTrue(check_privilege_satisfaction(user_collector))

        # Root session
        mock_geteuid.return_value = 0
        self.assertTrue(check_privilege_satisfaction(root_collector))
        self.assertTrue(check_privilege_satisfaction(user_collector))

    def test_execute_collector_with_context(self):
        """Verify execute_collector_with_context injects ctx arguments correctly."""
        dummy_db_conn = MagicMock()
        
        def mock_func(db_conn=None):
            return db_conn

        meta = CollectorMetadata(
            name="test",
            func=mock_func,
            description="test",
            privilege_requirements="user",
            required_capabilities=[],
            runtime_impact="low",
            impact_reason="test"
        )

        res = execute_collector_with_context(meta, db_conn=dummy_db_conn)
        self.assertEqual(res, dummy_db_conn)


class TestCollectorsCLI(unittest.TestCase):
    """Integration/System level checks for the `collectors` CLI commands."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_collectors_list_table(self, mock_stdout):
        """Verify list command in default table format."""
        args = MagicMock(subcommand="list", format="table")
        cmd_collectors(args)
        output = mock_stdout.getvalue()
        self.assertIn("Collector Name", output)
        self.assertIn("processes", output)
        self.assertIn("listening_ports", output)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_collectors_list_json(self, mock_stdout):
        """Verify list command in JSON format."""
        args = MagicMock(subcommand="list", format="json")
        cmd_collectors(args)
        output = mock_stdout.getvalue()
        parsed = json.loads(output)
        self.assertIsInstance(parsed, list)
        self.assertGreater(len(parsed), 0)
        
        # Verify schema elements in JSON
        processes_entry = next(item for item in parsed if item["name"] == "processes")
        self.assertEqual(processes_entry["privilege_requirements"], "user")
        self.assertEqual(processes_entry["runtime_impact"], "low")

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_collectors_list_csv(self, mock_stdout):
        """Verify list command in CSV format."""
        args = MagicMock(subcommand="list", format="csv")
        cmd_collectors(args)
        output = mock_stdout.getvalue()
        self.assertIn("Name,Description,Privilege Requirements,Runtime Impact,Privilege Satisfied", output)
        self.assertIn('"processes"', output)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_collectors_show_valid(self, mock_stdout):
        """Verify show command works for a valid collector name."""
        args = MagicMock(subcommand="show", collector_name="processes")
        cmd_collectors(args)
        output = mock_stdout.getvalue()
        self.assertIn("Collector Details: processes", output)
        self.assertIn("Description:            Harvests running process tree metadata from /proc", output)

    @patch("sys.exit")
    def test_collectors_show_invalid(self, mock_exit):
        """Verify show command exits with error for invalid collector name."""
        args = MagicMock(subcommand="show", collector_name="non_existent")
        cmd_collectors(args)
        mock_exit.assert_called_once_with(1)


class TestCollectFilteringAndPersistence(unittest.TestCase):
    """Verifies that collect command respects filters and persists metadata."""

    def setUp(self):
        # Create a temporary database in memory for isolated check runs
        self.db_file = Path("test_collect_registry.db")
        if self.db_file.exists():
            self.db_file.unlink()
            
        self.storage = OrinStorage(self.db_file)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_file.exists():
            self.storage.cleanup_db()

    @patch("orin.orchestrator.gather_active_processes", return_value=[{"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "cmdline": "/sbin/init"}])
    @patch("orin.orchestrator.gather_listening_ports", return_value=[])
    @patch("orin.orchestrator.gather_outbound_connections", return_value=[])
    @patch("orin.orchestrator.gather_promisc_interfaces", return_value=[])
    @patch("orin.orchestrator.gather_loaded_kernel_modules", return_value=[])
    @patch("orin.orchestrator.gather_system_accounts", return_value=[])
    @patch("orin.orchestrator.gather_active_ssh_keys", return_value=[])
    @patch("orin.orchestrator.gather_crontabs", return_value=[])
    @patch("orin.orchestrator.gather_wtmp_sessions", return_value=[])
    @patch("orin.orchestrator.gather_lastlog_records", return_value=[])
    @patch("orin.orchestrator.gather_deleted_binaries", return_value=[])
    @patch("orin.orchestrator.gather_file_integrity_signatures", return_value=[])
    @patch("orin.orchestrator.gather_suid_binaries", return_value=[])
    @patch("orin.orchestrator.gather_auth_logs", return_value=[])
    @patch("orin.orchestrator.gather_all_privilege_events", return_value={})
    @patch("orin.orchestrator.gather_ebpf_programs", return_value=[])
    @patch("orin.orchestrator.gather_ebpf_pinned", return_value=[])
    @patch("orin.orchestrator.gather_ld_preload", return_value=[])
    @patch("orin.orchestrator.gather_special_fds", return_value=[])
    @patch("orin.orchestrator.gather_system_persistence", return_value=[])
    @patch("orin.orchestrator.gather_dns_queries", return_value=[])
    @patch("orin.orchestrator.gather_pkg_integrity_drift", return_value=[])
    def test_collect_filtering_and_saving(
        self, mock_pkg, mock_dns, mock_persistence, mock_fds, mock_preload, mock_pinned,
        mock_ebpf, mock_priv, mock_auth, mock_suid, mock_fim, mock_del, mock_ll,
        mock_wtmp, mock_cron, mock_keys, mock_users, mock_mod, mock_prom, mock_out,
        mock_ports, mock_proc
    ):
        """Verify collect runs successfully with filters and persists run history in DB."""
        # Setup command arguments for sequential collect with filters
        args = MagicMock(
            database=str(self.db_file),
            vault_path=None,
            read_only=False,
            parallel=False,
            privilege="user",
            max_impact="low"
        )

        cmd_collect(args)

        # Verify that only collectors matching 'user' privilege & 'low' impact were run.
        # E.g. processes, listening_ports, outbound_connections, promisc_interfaces, wtmp_sessions, etc.
        # file_integrity (root/high), auth_logs (root/med), ebpf_programs (root/low) should not execute.
        self.assertTrue(mock_proc.called)
        self.assertFalse(mock_fim.called)
        self.assertFalse(mock_ebpf.called)

        # Inspect database execution records
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM collector_runs;")
            runs = cursor.fetchall()

            # Ensure runs were stored in DB
            self.assertGreater(len(runs), 0)
            
            # Verify fields schema
            for row in runs:
                self.assertIsNotNone(row["id"])
                self.assertIsNotNone(row["snapshot_id"])
                self.assertIsNotNone(row["collector_name"])
                self.assertIn(row["success"], [0, 1])
                self.assertIsInstance(row["duration"], float)
                self.assertEqual(row["privilege_level"], "user")
                self.assertEqual(row["runtime_impact"], "low")


if __name__ == "__main__":
    unittest.main()
