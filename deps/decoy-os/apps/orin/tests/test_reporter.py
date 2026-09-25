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
from orin.analysis.reporter import compile_markdown_report, compile_html_report

class TestReporter(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_reporter_unit.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()
        
        self.md_report_path = Path("test_report.md")
        self.html_report_path = Path("test_report.html")

    def tearDown(self):
        for path in [self.db_path, self.md_report_path, self.html_report_path]:
            if path.exists():
                path.unlink()

    def test_reporting_raises_on_empty_db(self):
        # Reporting should fail if no snapshots are present
        with self.assertRaises(ValueError):
            compile_markdown_report(self.db_path, self.md_report_path)
        with self.assertRaises(ValueError):
            compile_html_report(self.db_path, self.html_report_path)

    def test_compile_reports_success(self):
        # Create a mock snapshot and some related records
        with self.storage.get_connection() as conn:
            conn.execute(
                "INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'test-host', 'Linux');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, attck_technique, attck_tactic, attck_url) "
                "VALUES ('unexpected_port', 'high', 'Port 9999 is open', 0, 'T1571', 'Command and Control', 'https://attack.mitre.org/techniques/T1571/');"
            )
            conn.execute(
                "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) "
                "VALUES (1, 22, 'TCP', 'sshd');"
            )
            conn.execute(
                "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) "
                "VALUES (1, 100, 1, 'sshd', '/usr/sbin/sshd', '/usr/sbin/sshd -D');"
            )
            conn.execute(
                "INSERT INTO collected_users (snapshot_id, username, uid, gid, home_dir, login_shell) "
                "VALUES (1, 'musa', 1000, 1000, '/home/musa', '/bin/bash');"
            )
            conn.execute(
                "INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash) "
                "VALUES (1, '/etc/passwd', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');"
            )
            conn.execute(
                "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) "
                "VALUES (1, '/var/spool/cron/crontabs/alice', 'alice', '*/5 * * * *', '/tmp/payload.sh');"
            )
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, resolved, attck_technique, attck_tactic, attck_url) "
                "VALUES ('cron_volatile_execution', 'high', 'Cron job executes from volatile: /tmp/payload.sh', 0, 'T1053.003', 'Persistence', 'https://attack.mitre.org/techniques/T1053/003/');"
            )
            conn.commit()

        # Compile Markdown Report
        compile_markdown_report(self.db_path, self.md_report_path)
        self.assertTrue(self.md_report_path.exists())
        md_content = self.md_report_path.read_text()
        self.assertIn("test-host", md_content)
        self.assertIn("Port 9999 is open", md_content)
        self.assertIn("cron_volatile_execution", md_content)
        self.assertIn("Cron job executes from volatile: /tmp/payload.sh", md_content)
        self.assertIn("T1571", md_content)
        self.assertIn("Command and Control", md_content)
        self.assertIn("https://attack.mitre.org/techniques/T1571/", md_content)

        # Compile HTML Report
        compile_html_report(self.db_path, self.html_report_path)
        self.assertTrue(self.html_report_path.exists())
        html_content = self.html_report_path.read_text()
        self.assertIn("test-host", html_content)
        self.assertIn("Port 9999 is open", html_content)
        self.assertIn("sshd", html_content)
        self.assertIn("/home/musa", html_content)
        self.assertIn("/etc/passwd", html_content)
        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("cron_volatile_execution", html_content)
        self.assertIn("Cron job executes from volatile: /tmp/payload.sh", html_content)
        self.assertIn("Crontabs (1)", html_content)
        self.assertIn("/tmp/payload.sh", html_content)
        self.assertIn("alice", html_content)
        self.assertIn("*/5 * * * *", html_content)
        self.assertIn("T1571", html_content)
        self.assertIn("Command and Control", html_content)
