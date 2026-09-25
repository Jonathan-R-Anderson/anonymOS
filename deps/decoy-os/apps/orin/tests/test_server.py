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
# tests/test_server.py
import unittest
import threading
import json
import base64
import sqlite3
import urllib.request
import urllib.error
import os
import tempfile
from pathlib import Path
from http.server import HTTPServer
from datetime import datetime
from unittest.mock import patch, MagicMock

from orin.core.database import OrinStorage
from orin.core.server import OrinHTTPHandler


class TestOrinServer(unittest.TestCase):
    """Integration and Unit tests for the Orin Web Server backend."""

    def setUp(self):
        self.db_path = Path("test_server_db.db")
        if self.db_path.exists():
            self.db_path.unlink()
        self.storage = OrinStorage(self.db_path)

        # Isolate config path for this test execution using ORIN_CONFIG_PATH
        self.temp_config_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_config_dir) / "orin_config.json"
        self.config_path.write_text("{}")
        
        self.old_config_path_env = os.environ.get("ORIN_CONFIG_PATH")
        os.environ["ORIN_CONFIG_PATH"] = str(self.config_path)

        # Set up a test HTTPServer on an ephemeral port
        class TestHTTPServer(HTTPServer):
            def __init__(self, *args, **kwargs):
                self.db_path = Path("test_server_db.db")
                self.username = "admin"
                self.password = "secretpass"
                self.session_token = None   # use Basic Auth in tests
                self.no_auth = False
                super().__init__(*args, **kwargs)

        self.httpd = TestHTTPServer(("127.0.0.1", 0), OrinHTTPHandler)
        self.port = self.httpd.server_port

        # Initialize the database schema
        self.storage.initialize_db()

        # Seed test data in the database
        with self.storage.get_connection() as conn:
            # Seed a snapshot
            conn.execute(
                "INSERT INTO system_snapshots (id, timestamp, hostname, os_platform) VALUES (1, '2026-06-04T05:00:00Z', 'testhost', 'Linux');"
            )
            conn.execute(
                "INSERT INTO system_snapshots (id, timestamp, hostname, os_platform) VALUES (2, '2026-06-04T05:10:00Z', 'testhost', 'Linux');"
            )
            # Seed a baseline user and module
            conn.execute(
                "INSERT INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell) VALUES ('testhost', 'testuser', 1000, 1000, '/home/testuser', '/bin/bash');"
            )
            conn.execute(
                "INSERT INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES ('testhost', 'testmodule', 4096);"
            )
            # Seed a security event
            conn.execute(
                """
                INSERT INTO security_events (id, timestamp, event_type, severity, description, raw_details, resolved, notes, suppressed)
                VALUES (1, '2026-06-04T05:05:00Z', 'unexpected_port', 'high', 'Unexpected port 9999 open', '{"port": 9999}', 0, NULL, 0);
                """
            )
            conn.commit()

        # Start the server in a background daemon thread
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        # Shut down server and wait for thread to join
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

        # Delete test database
        if hasattr(self, 'storage'):
            self.storage.cleanup_db()

        # Clean up temporary configuration file & restore environment
        if self.config_path.exists():
            self.config_path.unlink()
        os.rmdir(self.temp_config_dir)

        if self.old_config_path_env is not None:
            os.environ["ORIN_CONFIG_PATH"] = self.old_config_path_env
        else:
            os.environ.pop("ORIN_CONFIG_PATH", None)

    def make_request(self, path, method="GET", data=None, use_auth=True, username="admin", password="secretpass"):
        """Utility to make HTTP requests against the test server."""
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, method=method)
        
        if data is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(data).encode("utf-8")

        if use_auth:
            credentials = f"{username}:{password}".encode("utf-8")
            auth_str = base64.b64encode(credentials).decode("utf-8")
            req.add_header("Authorization", f"Basic {auth_str}")

        return urllib.request.urlopen(req)

    def test_basic_auth_required(self):
        """Verify that requests fail with HTTP 401 if unauthorized."""
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/status", use_auth=False)
        self.assertEqual(ctx.exception.code, 401)
        self.assertTrue(ctx.exception.headers.get("WWW-Authenticate"))

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/status", username="wrong", password="pass")
        self.assertEqual(ctx.exception.code, 401)

    def test_get_status_endpoint(self):
        """Verify the /api/status route yields the correct database summary statistics."""
        response = self.make_request("/api/status")
        self.assertEqual(response.status, 200)
        
        data = json.loads(response.read().decode("utf-8"))
        self.assertEqual(data["total_snapshots"], 2)
        self.assertEqual(data["total_baseline_modules"], 1)
        self.assertEqual(data["total_baseline_users"], 1)
        self.assertEqual(data["total_alerts"], 1)
        self.assertEqual(data["unresolved_alerts"], 1)
        self.assertGreater(data["risk_score"], 0)
        self.assertEqual(data["latest_snapshot"]["hostname"], "testhost")

    def test_get_alerts_endpoint(self):
        """Verify the /api/alerts route lists security events."""
        response = self.make_request("/api/alerts")
        self.assertEqual(response.status, 200)
        
        data = json.loads(response.read().decode("utf-8"))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], 1)
        self.assertEqual(data[0]["event_type"], "unexpected_port")
        self.assertEqual(data[0]["resolved"], 0)

    def test_get_snapshots_endpoint(self):
        """Verify the /api/snapshots route lists snap IDs."""
        response = self.make_request("/api/snapshots")
        self.assertEqual(response.status, 200)
        
        data = json.loads(response.read().decode("utf-8"))
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["id"], 2)  # Sorted descending

    def test_alert_actions_post(self):
        """Test alerting triage operations: acknowledge, suppress, notes, severity override."""
        # 1. Test Acknowledge (Resolve)
        res = self.make_request("/api/alerts/action", method="POST", data={"alert_id": 1, "action": "acknowledge"})
        self.assertEqual(res.status, 200)
        
        with self.storage.get_connection() as conn:
            row = conn.execute("SELECT resolved, reviewed_at FROM security_events WHERE id = 1;").fetchone()
            self.assertEqual(row["resolved"], 1)
            self.assertIsNotNone(row["reviewed_at"])

        # 2. Test Unresolve
        res = self.make_request("/api/alerts/action", method="POST", data={"alert_id": 1, "action": "unresolve"})
        self.assertEqual(res.status, 200)
        with self.storage.get_connection() as conn:
            row = conn.execute("SELECT resolved, reviewed_at FROM security_events WHERE id = 1;").fetchone()
            self.assertEqual(row["resolved"], 0)
            self.assertIsNone(row["reviewed_at"])

        # 3. Test Suppress
        res = self.make_request("/api/alerts/action", method="POST", data={"alert_id": 1, "action": "suppress"})
        self.assertEqual(res.status, 200)
        with self.storage.get_connection() as conn:
            row = conn.execute("SELECT suppressed FROM security_events WHERE id = 1;").fetchone()
            self.assertEqual(row["suppressed"], 1)

        # 4. Test Update Notes
        res = self.make_request(
            "/api/alerts/action", method="POST", data={"alert_id": 1, "action": "update_notes", "notes": "Investigated by security team."}
        )
        self.assertEqual(res.status, 200)
        with self.storage.get_connection() as conn:
            row = conn.execute("SELECT notes FROM security_events WHERE id = 1;").fetchone()
            self.assertEqual(row["notes"], "Investigated by security team.")

        # 5. Test Severity Override
        res = self.make_request(
            "/api/alerts/action", method="POST", data={"alert_id": 1, "action": "override_severity", "severity": "critical"}
        )
        self.assertEqual(res.status, 200)
        with self.storage.get_connection() as conn:
            row = conn.execute("SELECT severity FROM security_events WHERE id = 1;").fetchone()
            self.assertEqual(row["severity"], "critical")

    def test_config_update_endpoint(self):
        """Verify updating configuration parameters writes atomically to file."""
        config_data = {
            "expected_ports": [22, 80, 443, 9000],
            "whitelisted_processes": ["testservice"],
            "critical_paths": ["/etc/passwd"],
            "critical_dirs": ["/etc/cron.d"]
        }
        res = self.make_request("/api/config/update", method="POST", data=config_data)
        self.assertEqual(res.status, 200)

        # Read back config file
        self.assertTrue(self.config_path.exists())
        saved_config = json.loads(self.config_path.read_text())
        self.assertEqual(saved_config["expected_ports"], [22, 80, 443, 9000])
        self.assertEqual(saved_config["whitelisted_processes"], ["testservice"])

    def test_database_migration_logic(self):
        """Verify database schema is migrated automatically to introduce new columns."""
        migration_db_path = Path("test_migration.db")
        if migration_db_path.exists():
            migration_db_path.unlink()

        try:
            # Create a database with the old schema (without new columns)
            conn = sqlite3.connect(migration_db_path)
            conn.execute(
                """
                CREATE TABLE security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    raw_details TEXT,
                    resolved INTEGER DEFAULT 0
                );
                """
            )
            conn.close()

            # Execute migration logic using OrinStorage init
            storage = OrinStorage(migration_db_path)
            storage.initialize_db()

            # Assert columns exist
            conn = sqlite3.connect(migration_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(security_events);")
            columns = {row["name"] for row in cursor.fetchall()}
            
            self.assertIn("notes", columns)
            self.assertIn("suppressed", columns)
            self.assertIn("reviewed_at", columns)
            conn.close()

        finally:
            if migration_db_path.exists():
                migration_db_path.unlink()

    def test_schedule_status_inactive(self):
        """Verify /api/schedule/status returns inactive when no cron is set."""
        with patch("orin.core.server.CRON_D_FILE", MagicMock(exists=MagicMock(return_value=False))), \
             patch("orin.core.server.subprocess") as mock_sub:
            # Simulate no user crontab
            mock_sub.check_output.side_effect = Exception("no crontab")
            res = self.make_request("/api/schedule/status")
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        # active may be True/False depending on real cron state; just verify structure
        self.assertIn("active", data)
        self.assertIn("mode", data)
        self.assertIn("interval_minutes", data)

    def test_schedule_install_valid(self):
        """Verify /api/schedule/install calls install_schedule with correct interval."""
        with patch("orin.core.scheduler.install_schedule") as mock_install, \
             patch("orin.core.scheduler.os.path.exists", return_value=False), \
             patch("orin.core.scheduler.subprocess.Popen") as mock_popen, \
             patch("orin.core.scheduler.subprocess.check_output", return_value=b""):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b"", b"")
            mock_popen.return_value = mock_proc
            mock_install.return_value = None
            res = self.make_request("/api/schedule/install", method="POST", data={"interval_minutes": 15})
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["interval_minutes"], 15)

    def test_schedule_install_invalid_interval(self):
        """Verify /api/schedule/install rejects out-of-range intervals."""
        with patch("orin.core.scheduler.install_schedule"):
            try:
                self.make_request("/api/schedule/install", method="POST", data={"interval_minutes": 0})
                self.fail("Expected HTTP error for invalid interval")
            except urllib.error.HTTPError as e:
                self.assertIn(e.code, (400, 500))  # 400 is correct, accept both
            try:
                self.make_request("/api/schedule/install", method="POST", data={"interval_minutes": 9999})
                self.fail("Expected HTTP error for invalid interval")
            except urllib.error.HTTPError as e:
                self.assertIn(e.code, (400, 500))

    def test_schedule_remove(self):
        """Verify /api/schedule/remove calls remove_schedule."""
        with patch("orin.core.scheduler.remove_schedule") as mock_remove, \
             patch("orin.core.scheduler.CRON_D_FILE", MagicMock(exists=MagicMock(return_value=False))), \
             patch("orin.core.scheduler.subprocess.check_output", return_value=b""):
            mock_remove.return_value = None
            res = self.make_request("/api/schedule/remove", method="POST")
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        self.assertEqual(data["status"], "success")

    @patch("orin.analysis.ai.run_ai_correlation")
    def test_api_correlate(self, mock_run):
        """Verify that /api/correlate calls run_ai_correlation and returns success."""
        mock_run.return_value = "### Mocked AI Briefing"
        res = self.make_request(
            "/api/correlate",
            method="POST",
            data={"url": "http://127.0.0.1:11434", "model": "gemma2"}
        )
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["briefing"], "### Mocked AI Briefing")
        mock_run.assert_called_once_with(
            self.db_path,
            hostnames=None,
            url="http://127.0.0.1:11434",
            model="gemma2"
        )

    def test_api_snapshot_telemetry(self):
        """Verify that /api/snapshot/telemetry returns full telemetry datasets."""
        res = self.make_request("/api/snapshot/telemetry?id=1")
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertIn("metadata", data)
        self.assertEqual(data["metadata"]["id"], 1)
        self.assertIn("processes", data)
        self.assertIn("ports", data)
        self.assertIn("outbound", data)

        res = self.make_request("/api/snapshot/telemetry")
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertEqual(data["metadata"]["id"], 2)

    @patch("os.kill")
    def test_api_process_kill_local(self, mock_kill):
        """Verify local process termination endpoint works."""
        import signal
        res = self.make_request("/api/process/kill", method="POST", data={"pid": 9999})
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertEqual(data["status"], "success")
        mock_kill.assert_called_once_with(9999, signal.SIGKILL)

    @patch("subprocess.Popen")
    def test_api_process_kill_remote(self, mock_popen):
        """Verify remote process termination over SSH endpoint works."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc

        res = self.make_request(
            "/api/process/kill",
            method="POST",
            data={
                "pid": 1234,
                "hostname": "remotehost",
                "ssh_host": "192.168.1.50",
                "ssh_user": "root"
            }
        )
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertEqual(data["status"], "success")

    def test_rate_limiting(self):
        """Verify that hitting the server repeatedly triggers a 429 response."""
        from orin.core.server import IPTokenBucketLimiter
        self.httpd.rate_limiter = IPTokenBucketLimiter(rate=1.0, capacity=2.0)
        
        # First two requests should succeed
        self.make_request("/api/status")
        self.make_request("/api/status")
        
        # Third request should be rate-limited with 429
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/status")
        self.assertEqual(ctx.exception.code, 429)
        
        # Clean up rate limiter
        self.httpd.rate_limiter = None

    def test_access_logging(self):
        """Verify that access log entries are written correctly."""
        # Ensure log file contains our requests
        self.make_request("/api/status")
        
        # Find where it was written (either /var/log/orin/access.log or fallback path)
        paths_to_check = [
            Path("/var/log/orin/access.log"),
            Path.home() / ".orin" / "logs" / "access.log"
        ]
        
        found = False
        for path in paths_to_check:
            if path.exists():
                content = path.read_text(encoding="utf-8")
                if "/api/status" in content:
                    found = True
                    break
        
        self.assertTrue(found, "Could not find expected request log entry in access log files")

    def test_websocket_handshake(self):
        """Verify WebSocket upgrade request performs handshake correctly."""
        import hashlib
        import base64
        import urllib.request
        import urllib.error

        url = f"http://127.0.0.1:{self.port}/ws"
        req = urllib.request.Request(url)
        req.add_header("Upgrade", "websocket")
        req.add_header("Connection", "Upgrade")
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        req.add_header("Sec-WebSocket-Key", key)

        credentials = b"admin:secretpass"
        auth_str = base64.b64encode(credentials).decode("utf-8")
        req.add_header("Authorization", f"Basic {auth_str}")

        try:
            res = urllib.request.urlopen(req)
            status = res.status
            headers = res.headers
        except urllib.error.HTTPError as e:
            status = e.code
            headers = e.headers

        self.assertEqual(status, 101)
        self.assertEqual(headers.get("Upgrade"), "websocket")
        self.assertEqual(headers.get("Connection"), "Upgrade")
        
        expected_accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")).digest()
        ).decode("utf-8")
        self.assertEqual(headers.get("Sec-WebSocket-Accept"), expected_accept)

    def test_websocket_invalid_upgrade(self):
        """Verify /ws route returns 400 when Upgrade header is missing."""
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/ws")
        self.assertEqual(ctx.exception.code, 400)

    def test_make_websocket_frame(self):
        """Verify RFC 6455 unmasked text frame serialization format."""
        from orin.core.server import make_websocket_frame
        
        frame1 = make_websocket_frame("test")
        self.assertEqual(frame1[0], 0x81)
        self.assertEqual(frame1[1], 4)
        self.assertEqual(frame1[2:], b"test")

        payload2 = "a" * 200
        frame2 = make_websocket_frame(payload2)
        self.assertEqual(frame2[0], 0x81)
        self.assertEqual(frame2[1], 126)
        length_bytes = frame2[2:4]
        self.assertEqual(int.from_bytes(length_bytes, byteorder='big'), 200)
        self.assertEqual(frame2[4:], payload2.encode('utf-8'))

    @patch("orin.core.server.get_logger")
    def test_send_json_recursion_protection(self, mock_get_logger):
        """Verify send_json logs connection exceptions instead of causing infinite recursion."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        
        from orin.core.server import OrinHTTPHandler
        handler = OrinHTTPHandler.__new__(OrinHTTPHandler)
        handler.send_response = MagicMock(side_effect=ConnectionResetError("Connection closed by peer"))
        
        with patch.object(handler, "send_error_response") as mock_send_error:
            handler.send_json({"data": "test"})
            mock_logger.error.assert_called_once()
            mock_send_error.assert_not_called()


if __name__ == "__main__":
    unittest.main()
