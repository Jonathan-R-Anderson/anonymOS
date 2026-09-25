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
import json
from pathlib import Path
from orin.core.database import OrinStorage
from orin.core.scanner import run_remote_scan

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_db_scanner.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    @patch("subprocess.Popen")
    def test_run_remote_scan_success(self, mock_popen):
        # Mock successful subprocess response
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        
        telemetry_payload = {
            "hostname": "remote-test-host",
            "os_platform": "Linux-test-os",
            "processes": [{"pid": 100, "ppid": 1, "name": "systemd", "exe": "/sbin/init", "cmdline": "/sbin/init"}],
            "ports": [{"port": 80, "protocol": "tcp", "process_name": "nginx"}],
            "outbound": [{"local_ip": "10.0.0.1", "local_port": 1234, "remote_ip": "8.8.8.8", "remote_port": 53, "state": "ESTABLISHED", "process_name": "dns"}],
            "promisc": [{"interface": "eth0", "flags": "0x1103", "is_promiscuous": 1}],
            "modules": [{"module_name": "ext4", "memory_size": 4000, "instances_loaded": 1}],
            "users": [{"username": "alice", "uid": 1000, "gid": 1000, "home_dir": "/home/alice", "login_shell": "/bin/bash"}],
            "ssh_keys": [{"user_account": "alice", "key_type": "ssh-rsa", "fingerprint": "fp1", "raw_key_comment": "key1"}],
            "crontabs": [{"source": "/etc/crontab", "user": "root", "schedule": "* * * * *", "command": "reboot"}],
            "wtmp": [{"user": "root", "line": "pts/0", "host": "1.2.3.4", "pid": 12, "login_time": "2026-06-04", "logout_time": "", "anomaly_detected": 0, "anomaly_reason": ""}],
            "lastlog": [{"username": "root", "uid": 0, "line": "pts/0", "host": "1.2.3.4", "login_time": "2026-06-04", "anomaly_detected": 0, "anomaly_reason": ""}],
            "deleted": [{"pid": 123, "exe": "/bin/evil", "sha256": "sha2", "md5": "md52", "vault_path": "/vault"}],
            "fim": [{"file_path": "/etc/passwd", "sha256_hash": "sha1", "mtime": 0.0, "ctime": 0.0, "size": 100}],
            "suid": [{"file_path": "/bin/su", "owner": "root", "grp": "root", "permissions": "0o4755", "sha256": "sha3"}],
            "pkg_integrity": [{"package": "sudo", "file_path": "/usr/bin/sudo", "expected_md5": "abc", "actual_md5": "def", "actual_sha256": "xyz", "status": "modified"}]
        }
        
        mock_proc.communicate.return_value = (json.dumps(telemetry_payload), "")
        mock_popen.return_value = mock_proc
        
        # We also need to seed baselines so that analysis cycle doesn't crash or trigger alerts
        with self.storage.get_connection() as conn:
            # Add user/module/suid to baseline for "remote-test-host"
            conn.execute("INSERT INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell) VALUES ('remote-test-host', 'alice', 1000, 1000, '/home/alice', '/bin/bash');")
            conn.execute("INSERT INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES ('remote-test-host', 'ext4', 4000);")
            conn.execute("INSERT INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256) VALUES ('remote-test-host', '/bin/su', 'root', 'root', '0o4755', 'sha3');")
            conn.commit()

        metrics = run_remote_scan(
            host="192.168.1.10",
            user="root",
            port=2222,
            db_path=self.db_path
        )
        
        # Verify metrics returned
        self.assertEqual(metrics["status"], "success")
        self.assertIn("risk_score", metrics)
        self.assertIn("snapshot_id", metrics)
        self.assertIn("events_count", metrics)
        
        # Verify snapshot was written to DB
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT hostname, os_platform FROM system_snapshots ORDER BY id DESC LIMIT 1;")
            snap = cursor.fetchone()
            self.assertEqual(snap["hostname"], "remote-test-host")
            self.assertEqual(snap["os_platform"], "Linux-test-os")
            
            # Check SUID saved
            cursor.execute("SELECT file_path, owner, sha256 FROM collected_suid_binaries WHERE snapshot_id = 1;")
            suid_record = cursor.fetchone()
            self.assertEqual(suid_record["file_path"], "/bin/su")
            self.assertEqual(suid_record["owner"], "root")
            self.assertEqual(suid_record["sha256"], "sha3")

    @patch("subprocess.Popen")
    def test_run_remote_scan_ssh_failure(self, mock_popen):
        # Mock failed SSH connection/execution
        mock_proc = MagicMock()
        mock_proc.returncode = 255
        mock_proc.communicate.return_value = ("", "Permission denied (publickey).")
        mock_popen.return_value = mock_proc
        
        with self.assertRaises(RuntimeError) as context:
            run_remote_scan(
                host="192.168.1.10",
                user="root",
                db_path=self.db_path
            )
        self.assertIn("Permission denied", str(context.exception))

    @patch("subprocess.Popen")
    def test_run_remote_scan_malformed_json(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("this is not JSON", "")
        mock_popen.return_value = mock_proc
        
        with self.assertRaises(RuntimeError) as context:
            run_remote_scan(
                host="192.168.1.10",
                user="root",
                db_path=self.db_path
            )
        self.assertIn("Failed to parse remote telemetry JSON", str(context.exception))

if __name__ == "__main__":
    unittest.main()
