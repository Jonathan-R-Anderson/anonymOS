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

import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sqlite3

from orin.collectors.services import gather_active_services
from orin.core.database import OrinStorage


class TestServicesCollector(unittest.TestCase):

    @patch("subprocess.run")
    @patch("psutil.Process")
    def test_gather_active_services_success(self, mock_process, mock_run):
        # 1. Mock list-units output
        list_units_stdout = (
            "  dbus.service             loaded active running D-Bus System Message Bus\n"
            "● sshd.service             loaded failed failed  OpenBSD Secure Shell server\n"
        )
        mock_units_res = MagicMock()
        mock_units_res.returncode = 0
        mock_units_res.stdout = list_units_stdout

        # 2. Mock list-unit-files output
        list_unit_files_stdout = (
            "dbus.service                                 static          -\n"
            "sshd.service                                 enabled         enabled\n"
            "unrelated.service                            disabled        enabled\n"
        )
        mock_files_res = MagicMock()
        mock_files_res.returncode = 0
        mock_files_res.stdout = list_unit_files_stdout

        # 3. Mock show output
        show_stdout = (
            "MainPID=1010\n"
            "User=messagebus\n"
            "Id=dbus.service\n"
            "\n"
            "MainPID=2020\n"
            "User=\n"
            "Id=sshd.service\n"
            "\n"
            "MainPID=0\n"
            "User=\n"
            "Id=unrelated.service\n"
        )
        mock_show_res = MagicMock()
        mock_show_res.returncode = 0
        mock_show_res.stdout = show_stdout

        # Set up side effects for subprocess runs
        mock_run.side_effect = [mock_units_res, mock_files_res, mock_show_res]

        # Mock psutil Process username resolution for sshd
        mock_proc_instance = MagicMock()
        mock_proc_instance.username.return_value = "sshd-user"
        mock_process.return_value = mock_proc_instance

        services = gather_active_services()

        # We should have 3 services (dbus, sshd, and unrelated)
        self.assertEqual(len(services), 3)

        dbus = next(s for s in services if s["name"] == "dbus.service")
        self.assertEqual(dbus["status"], "active (running)")
        self.assertEqual(dbus["enabled"], "static")
        self.assertEqual(dbus["user"], "messagebus")
        self.assertEqual(dbus["description"], "D-Bus System Message Bus")

        sshd = next(s for s in services if s["name"] == "sshd.service")
        self.assertEqual(sshd["status"], "failed (failed)")
        self.assertEqual(sshd["enabled"], "enabled")
        # should resolve to "sshd-user" via PID process lookup
        self.assertEqual(sshd["user"], "sshd-user")
        self.assertEqual(sshd["description"], "OpenBSD Secure Shell server")

        unrelated = next(s for s in services if s["name"] == "unrelated.service")
        self.assertEqual(unrelated["status"], "inactive (dead)")
        self.assertEqual(unrelated["enabled"], "disabled")
        # should resolve to fallback "root"
        self.assertEqual(unrelated["user"], "root")
        self.assertEqual(unrelated["description"], "")

    @patch("subprocess.run")
    def test_gather_active_services_no_systemd(self, mock_run):
        # systemctl not found or fails
        mock_run.side_effect = FileNotFoundError()
        services = gather_active_services()
        self.assertEqual(services, [])


class TestDatabaseServices(unittest.TestCase):

    def setUp(self):
        self.db_path = Path("test_db_services.db")
        if self.db_path.exists():
            self.db_path.unlink()
        self.storage = OrinStorage(self.db_path)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_initialize_and_store_services(self):
        self.storage.initialize_db()

        records = [
            {"name": "test1.service", "status": "active (running)", "enabled": "enabled", "user": "root", "description": "Test 1"},
            {"name": "test2.service", "status": "inactive (dead)", "enabled": "disabled", "user": "daemon", "description": "Test 2"},
        ]

        with self.storage.get_connection() as conn:
            # Create snapshot
            snap_id = self.storage.create_snapshot(conn)
            self.storage.store_services(conn, snap_id, records)
            conn.commit()

        # Query back to verify insertion
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, status, enabled, user, description FROM collected_services WHERE snapshot_id = ? ORDER BY name ASC;", (snap_id,))
            rows = [dict(r) for r in cursor.fetchall()]

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["name"], "test1.service")
            self.assertEqual(rows[0]["status"], "active (running)")
            self.assertEqual(rows[0]["enabled"], "enabled")
            self.assertEqual(rows[0]["user"], "root")
            self.assertEqual(rows[0]["description"], "Test 1")

            self.assertEqual(rows[1]["name"], "test2.service")
            self.assertEqual(rows[1]["status"], "inactive (dead)")
            self.assertEqual(rows[1]["enabled"], "disabled")
            self.assertEqual(rows[1]["user"], "daemon")
            self.assertEqual(rows[1]["description"], "Test 2")


if __name__ == "__main__":
    unittest.main()
