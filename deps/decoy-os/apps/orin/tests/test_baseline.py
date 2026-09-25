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
import json
import sqlite3

from orin.core.database import OrinStorage
from orin.analysis.engine import run_analysis_cycle
from orin.main import cmd_baseline

class TestBaselineManagerAndScoring(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_baseline_unit.db")
        for suffix in ["", "-wal", "-shm"]:
            p = self.db_path.with_name(self.db_path.name + suffix)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if hasattr(self, 'storage'):
            self.storage.cleanup_db()

    @patch("orin.analysis.engine.load_config")
    @patch("orin.analysis.engine.detect_hidden_processes")
    def test_relational_correlation_execution_and_c2(self, mock_detect_hidden, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }
        mock_detect_hidden.return_value = [{"pid": 666, "name": "backdoor"}]
        
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="debian", os_platform="Linux")
            # Execution anomaly: hidden process (will trigger hidden_process event)
            conn.execute(
                "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe) VALUES (?, ?, ?, ?, ?);",
                (snap_id, 666, 1, "backdoor", "/tmp/backdoor")
            )
            # Network anomaly: unexpected port listening (will trigger unexpected_port event)
            conn.execute(
                "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);",
                (snap_id, 4444, "TCP", "backdoor (PID: 666)")
            )
            conn.commit()
            
        run_analysis_cycle(self.db_path)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, severity, description FROM security_events ORDER BY id;")
            events = cursor.fetchall()
            
        event_types = [e["event_type"] for e in events]
        # Should contain Rule 1 correlation
        self.assertIn("relational_threat_chain", event_types)
        
        # Verify participants got upgraded to critical severity
        for e in events:
            if e["event_type"] in ("hidden_process", "unexpected_port", "relational_threat_chain"):
                self.assertEqual(e["severity"], "critical")

    @patch("orin.analysis.engine.load_config")
    @patch("orin.analysis.engine.detect_hidden_processes", return_value=[])
    def test_relational_correlation_privilege_and_persistence(self, mock_detect_hidden, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }
        
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="debian", os_platform="Linux")
            
            # Privilege escalation anomaly: modified SUID binary
            conn.execute("INSERT INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256) VALUES ('debian', '/usr/bin/sudo', 'root', 'root', '-rwsr-xr-x', 'old_hash');")
            conn.execute(
                "INSERT INTO collected_suid_binaries (snapshot_id, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                (snap_id, "/usr/bin/sudo", "root", "root", "-rwsr-xr-x", "new_hash")
            )
            # Persistence anomaly: new user created
            conn.execute(
                "INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (?, ?, ?, ?);",
                (snap_id, "evil_hacker", 1337, 1337)
            )
            conn.commit()
            
        run_analysis_cycle(self.db_path)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, severity FROM security_events ORDER BY id;")
            events = cursor.fetchall()
            
        event_types = [e["event_type"] for e in events]
        self.assertIn("relational_threat_chain", event_types)
        
        events_by_type = {e["event_type"]: e for e in events}
        self.assertEqual(events_by_type["modified_suid_binary"]["severity"], "critical")
        self.assertEqual(events_by_type["unauthorized_user_created"]["severity"], "critical")

    @patch("orin.analysis.engine.load_config")
    @patch("orin.analysis.engine.detect_hidden_processes", return_value=[])
    def test_relational_correlation_rootkit_and_evasion(self, mock_detect_hidden, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }
        
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="debian", os_platform="Linux")
            
            # Rootkit anomaly: non-GPL eBPF program
            conn.execute(
                "INSERT INTO collected_ebpf_programs (snapshot_id, bpf_id, name, type, tag, gpl_compatible) VALUES (?, ?, ?, ?, ?, ?);",
                (snap_id, 9, "pamspy", "kprobe", "tag", 0)
            )
            # Evasion anomaly: log tampering (zeroed out lastlog)
            conn.execute(
                "INSERT INTO collected_lastlog_records (snapshot_id, username, uid, line, host, login_time, anomaly_detected, anomaly_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (snap_id, "root", 0, "pts/0", "1.2.3.4", "1970-01-01 00:00:00", 1, "Epoch reset detected")
            )
            conn.commit()
            
        run_analysis_cycle(self.db_path)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, severity FROM security_events ORDER BY id;")
            events = cursor.fetchall()
            
        event_types = [e["event_type"] for e in events]
        self.assertIn("relational_threat_chain", event_types)
        
        events_by_type = {e["event_type"]: e for e in events}
        self.assertEqual(events_by_type["ebpf_rootkit"]["severity"], "critical")
        self.assertEqual(events_by_type["log_tampering"]["severity"], "critical")

    def test_cmd_baseline_add_user(self):
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="target_host", os_platform="Linux")
            conn.execute(
                "INSERT INTO collected_users (snapshot_id, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
                (snap_id, "trusted_user", 1001, 1001, "/home/trusted_user", "/bin/zsh")
            )
            conn.commit()
            
        args = MagicMock()
        args.database = str(self.db_path)
        args.host = "target_host"
        args.baseline_command = "add"
        args.user = "trusted_user"
        args.module = None
        args.suid = None
        
        cmd_baseline(args)
        
        # Verify it was added to baseline
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM baseline_users WHERE hostname = ?;", ("target_host",))
            row = cursor.fetchone()
            
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "trusted_user")
        self.assertEqual(row["uid"], 1001)

    def test_cmd_baseline_add_module(self):
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="target_host", os_platform="Linux")
            conn.execute(
                "INSERT INTO collected_kernel_modules (snapshot_id, module_name, memory_size, instances_loaded) VALUES (?, ?, ?, ?);",
                (snap_id, "wireguard", 50000, 1)
            )
            conn.commit()
            
        args = MagicMock()
        args.database = str(self.db_path)
        args.host = "target_host"
        args.baseline_command = "add"
        args.user = None
        args.module = "wireguard"
        args.suid = None
        
        cmd_baseline(args)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT module_name, memory_size FROM baseline_kernel_modules WHERE hostname = ?;", ("target_host",))
            row = cursor.fetchone()
            
        self.assertIsNotNone(row)
        self.assertEqual(row["module_name"], "wireguard")
        self.assertEqual(row["memory_size"], 50000)

    def test_cmd_baseline_add_suid(self):
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="target_host", os_platform="Linux")
            conn.execute(
                "INSERT INTO collected_suid_binaries (snapshot_id, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                (snap_id, "/usr/bin/new_suid", "root", "root", "-rwsr-xr-x", "suid_sha")
            )
            conn.commit()
            
        args = MagicMock()
        args.database = str(self.db_path)
        args.host = "target_host"
        args.baseline_command = "add"
        args.user = None
        args.module = None
        args.suid = "/usr/bin/new_suid"
        
        cmd_baseline(args)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM baseline_suid_binaries WHERE hostname = ?;", ("target_host",))
            row = cursor.fetchone()
            
        self.assertIsNotNone(row)
        self.assertEqual(row["file_path"], "/usr/bin/new_suid")
        self.assertEqual(row["sha256"], "suid_sha")

    def test_cmd_baseline_refresh(self):
        with self.storage.get_connection() as conn:
            # Setup pre-existing baseline records
            conn.execute("INSERT INTO baseline_users (hostname, username, uid, gid) VALUES ('target_host', 'old_user', 999, 999);")
            
            snap_id = self.storage.create_snapshot(conn, hostname="target_host", os_platform="Linux")
            conn.execute(
                "INSERT INTO collected_users (snapshot_id, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
                (snap_id, "new_user", 1000, 1000, "/home/new_user", "/bin/bash")
            )
            conn.execute(
                "INSERT INTO collected_kernel_modules (snapshot_id, module_name, memory_size, instances_loaded) VALUES (?, ?, ?, ?);",
                (snap_id, "ext4", 4000, 1)
            )
            conn.execute(
                "INSERT INTO collected_suid_binaries (snapshot_id, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                (snap_id, "/usr/bin/sudo", "root", "root", "-rwsr-xr-x", "sudo_sha")
            )
            conn.commit()
            
        # 1. Test Refresh Incremental (Append Mode)
        args = MagicMock()
        args.database = str(self.db_path)
        args.host = "target_host"
        args.baseline_command = "refresh"
        args.force_overwrite = False
        
        cmd_baseline(args)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM baseline_users WHERE hostname = ? ORDER BY username;", ("target_host",))
            users = [r["username"] for r in cursor.fetchall()]
            
        self.assertIn("old_user", users)
        self.assertIn("new_user", users)
        
        # 2. Test Refresh Force Overwrite Mode
        args.force_overwrite = True
        cmd_baseline(args)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM baseline_users WHERE hostname = ? ORDER BY username;", ("target_host",))
            users = [r["username"] for r in cursor.fetchall()]
            
        self.assertNotIn("old_user", users)
        self.assertIn("new_user", users)

if __name__ == "__main__":
    unittest.main()
