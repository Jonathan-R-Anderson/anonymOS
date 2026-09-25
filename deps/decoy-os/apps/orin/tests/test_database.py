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
from pathlib import Path
from orin.core.database import OrinStorage

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_db_unit.db")
        self.storage = OrinStorage(self.db_path)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_initialize_db(self):
        self.storage.initialize_db()
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row["name"] for row in cursor.fetchall()}
            
            expected_tables = {
                "system_snapshots",
                "baseline_kernel_modules",
                "collected_processes",
                "collected_ports",
                "collected_outbound_connections",
                "collected_kernel_modules",
                "collected_ssh_keys",
                "collected_file_hashes",
                "security_events",
                "baseline_users",
                "collected_users"
            }
            
            for table in expected_tables:
                self.assertIn(table, tables, f"Table {table} missing from DB schema.")

    def test_store_telemetry_apis(self):
        self.storage.initialize_db()
        with self.storage.get_connection() as conn:
            # Test create_snapshot
            snap_id = self.storage.create_snapshot(conn)
            self.assertGreater(snap_id, 0)
            
            # Test store_processes
            self.storage.store_processes(conn, snap_id, [{"pid": 100, "ppid": 1, "name": "systemd", "exe": "/sbin/init", "cmdline": "/sbin/init"}])
            
            # Test store_ports
            self.storage.store_ports(conn, snap_id, [{"port": 80, "protocol": "tcp", "process_name": "nginx"}])
            
            # Test store_outbound_connections
            self.storage.store_outbound_connections(conn, snap_id, [{"local_ip": "10.0.0.1", "local_port": 1234, "remote_ip": "8.8.8.8", "remote_port": 53, "state": "ESTABLISHED", "process_name": "dns"}])
            
            # Test store_kernel_modules
            self.storage.store_kernel_modules(conn, snap_id, [{"module_name": "ext4", "memory_size": 4000, "instances_loaded": 1}])
            
            # Test store_users
            self.storage.store_users(conn, snap_id, [{"username": "alice", "uid": 1000, "gid": 1000, "home_dir": "/home/alice", "login_shell": "/bin/bash"}])
            
            # Test store_ssh_keys
            self.storage.store_ssh_keys(conn, snap_id, [{"user_account": "alice", "key_type": "ssh-rsa", "fingerprint": "fp1", "raw_key_comment": "key1"}])
            
            # Test store_file_hashes
            self.storage.store_file_hashes(conn, snap_id, [{"file_path": "/etc/passwd", "sha256_hash": "sha1", "mtime": 0.0, "ctime": 0.0, "size": 100}])
            
            # Test store_deleted_binaries
            self.storage.store_deleted_binaries(conn, snap_id, [{"pid": 123, "exe": "/bin/evil", "sha256": "sha2", "md5": "md52", "vault_path": "/vault"}])
            
            # Test store_promisc_interfaces
            self.storage.store_promisc_interfaces(conn, snap_id, [{"interface": "eth0", "flags": "0x1103", "is_promiscuous": 1}])
            
            # Test store_wtmp_sessions
            self.storage.store_wtmp_sessions(conn, snap_id, [{"user": "root", "line": "pts/0", "host": "1.2.3.4", "pid": 12, "login_time": "2026-06-04", "logout_time": "", "anomaly_detected": 0, "anomaly_reason": ""}])
            
            # Test store_lastlog_records
            self.storage.store_lastlog_records(conn, snap_id, [{"username": "root", "uid": 0, "line": "pts/0", "host": "1.2.3.4", "login_time": "2026-06-04", "anomaly_detected": 0, "anomaly_reason": ""}])
            
            # Test store_pkg_integrity
            self.storage.store_pkg_integrity(conn, snap_id, [{"package": "sudo", "file_path": "/usr/bin/sudo", "expected_md5": "abc", "actual_md5": "def", "actual_sha256": "xyz", "status": "modified"}])
            
            # Test store_crontabs
            self.storage.store_crontabs(conn, snap_id, [{"source": "/etc/crontab", "user": "root", "schedule": "* * * * *", "command": "reboot"}])
            
            conn.commit()

    def test_database_migration_and_backfill(self):
        db_path_migration = Path("test_db_migration.db")
        if db_path_migration.exists():
            db_path_migration.unlink()
            
        storage_mig = OrinStorage(db_path_migration)
        try:
            with storage_mig.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        description TEXT NOT NULL,
                        raw_details TEXT,
                        notes TEXT DEFAULT '',
                        suppressed INTEGER DEFAULT 0,
                        reviewed_at TEXT,
                        resolved INTEGER DEFAULT 0
                    );
                """)
                cursor.execute(
                    "INSERT INTO security_events (event_type, severity, description) VALUES (?, ?, ?);",
                    ("unexpected_port", "medium", "Unexpected listening network port detected: 80")
                )
                conn.commit()
                
            storage_mig.initialize_db()
            
            with storage_mig.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(security_events);")
                columns = {row["name"] for row in cursor.fetchall()}
                self.assertIn("attck_technique", columns)
                self.assertIn("attck_tactic", columns)
                self.assertIn("attck_url", columns)
                
                cursor.execute("SELECT attck_technique, attck_tactic, attck_url FROM security_events WHERE id = 1;")
                row = cursor.fetchone()
                self.assertEqual(row["attck_technique"], "T1571")
                self.assertEqual(row["attck_tactic"], "Command and Control")
                self.assertEqual(row["attck_url"], "https://attack.mitre.org/techniques/T1571/")
        finally:
            if db_path_migration.exists():
                db_path_migration.unlink()

if __name__ == "__main__":
    unittest.main()
