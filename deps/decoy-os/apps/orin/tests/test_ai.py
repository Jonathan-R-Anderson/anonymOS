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
import urllib.error

from orin.core.database import OrinStorage
from orin.analysis.ai import run_ai_correlation
from orin.main import cmd_correlate

class TestAICorrelation(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_ai_unit.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    @patch("orin.analysis.ai.urllib.request.urlopen")
    def test_run_ai_correlation_success(self, mock_urlopen):
        # 1. Setup mock database records across multiple hostnames
        with self.storage.get_connection() as conn:
            # Host 1 snapshot and unresolved alert
            snap1 = self.storage.create_snapshot(conn, hostname="host-a", os_platform="Linux")
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, attck_technique, attck_tactic, hostname, resolved) VALUES (?, ?, ?, ?, ?, ?, ?);",
                ("unexpected_port", "high", "Port 4444 open", "T1571", "C2", "host-a", 0)
            )
            
            # Host 2 snapshot and unresolved alert
            snap2 = self.storage.create_snapshot(conn, hostname="host-b", os_platform="Linux")
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, attck_technique, attck_tactic, hostname, resolved) VALUES (?, ?, ?, ?, ?, ?, ?);",
                ("new_user", "medium", "User evil added", "T1136.001", "Persistence", "host-b", 0)
            )
            conn.commit()

        # 2. Mock successful response from local Ollama instance
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": "### AI Analysis Report\nDetected potential lateral threat..."
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # 3. Execute correlation
        analysis_report = run_ai_correlation(self.db_path, model="gemma2")
        
        self.assertIn("### AI Analysis Report", analysis_report)
        self.assertIn("Detected potential lateral threat", analysis_report)
        
        # Verify call parameters (Ollama prompt contains hosts and alerts)
        called_args, called_kwargs = mock_urlopen.call_args
        called_request = called_args[0]
        
        # Verify headers and payload
        self.assertEqual(called_request.full_url, "http://127.0.0.1:11434/api/generate")
        payload = json.loads(called_request.data.decode("utf-8"))
        self.assertEqual(payload["model"], "gemma2")
        self.assertIn("host-a", payload["prompt"])
        self.assertIn("Port 4444 open", payload["prompt"])
        self.assertIn("host-b", payload["prompt"])
        self.assertIn("User evil added", payload["prompt"])

    @patch("orin.analysis.ai.urllib.request.urlopen")
    def test_run_ai_correlation_connection_failure(self, mock_urlopen):
        # Setup mock db record
        with self.storage.get_connection() as conn:
            self.storage.create_snapshot(conn, hostname="host-a", os_platform="Linux")
            conn.execute(
                "INSERT INTO security_events (event_type, severity, description, hostname, resolved) VALUES (?, ?, ?, ?, ?);",
                ("unexpected_port", "high", "Port 4444 open", "host-a", 0)
            )
            conn.commit()

        # Mock URLError to simulate Ollama not running
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        
        with self.assertRaises(ConnectionError) as ctx:
            run_ai_correlation(self.db_path)
            
        self.assertIn("Failed to connect to local Ollama instance", str(ctx.exception))

    @patch("orin.analysis.ai.urllib.request.urlopen")
    def test_run_ai_correlation_empty_database(self, mock_urlopen):
        # Empty database test
        analysis = run_ai_correlation(self.db_path)
        self.assertIn("No host snapshots found in the database", analysis)

    @patch("orin.analysis.ai.run_ai_correlation")
    def test_cmd_correlate_cli_handler(self, mock_run_correlation):
        mock_run_correlation.return_value = "### Fake Correlation Report"
        
        args = MagicMock()
        args.database = str(self.db_path)
        args.host = ["host-a", "host-b"]
        args.url = "http://127.0.0.1:11434"
        args.model = "gemma2"
        
        # Test direct print
        args.output = None
        with patch("builtins.print") as mock_print:
            cmd_correlate(args)
            mock_print.assert_any_call("### Fake Correlation Report")
            
        # Test writing to file
        output_file = Path("test_ai_output.md")
        if output_file.exists():
            output_file.unlink()
            
        try:
            args.output = str(output_file)
            cmd_correlate(args)
            self.assertTrue(output_file.exists())
            self.assertEqual(output_file.read_text(encoding="utf-8"), "### Fake Correlation Report")
        finally:
            if output_file.exists():
                output_file.unlink()

if __name__ == "__main__":
    unittest.main()
