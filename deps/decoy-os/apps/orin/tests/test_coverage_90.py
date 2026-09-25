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
Additional unit tests to improve code coverage to 90%
"""
import pytest
import tempfile
import os
import sys
import json
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

# 1. AI Correlation Coverage
class TestAICorrelationCoverage:
    """Test AI correlation edge cases."""
    
    def test_aggregate_events_edge_cases(self):
        """Test _aggregate_events function under various event payloads."""
        from orin.analysis.ai import _aggregate_events
        
        # Long description to check truncation
        long_desc = "A" * 300
        events = [
            {
                "event_type": "unexpected_port",
                "severity": "critical",
                "attck_technique": "T1571",
                "attck_tactic": "Command and Control",
                "description": long_desc,
                "timestamp": "2026-06-12T12:00:00Z",
                "raw_details": json.dumps({"port": 4444, "process_name": "malicious", "pid": 1234, "file_path": "/tmp/evil"})
            },
            {
                "event_type": "unexpected_port",
                "severity": "critical",
                "attck_technique": "T1571",
                "attck_tactic": "Command and Control",
                "description": "Short desc",
                "timestamp": "2026-06-12T12:05:00Z",
                "raw_details": "{invalid_json_to_trigger_exception}"
            }
        ]
        
        results = _aggregate_events(events)
        assert len(results) == 1
        assert "T1571" in results[0]
        assert "Count: 2" in results[0]
        assert "Ports: ['4444']" in results[0]
        assert "Processes: ['malicious']" in results[0]
        assert "PIDs: ['1234']" in results[0]
        assert "Paths: ['/tmp/evil']" in results[0]
        assert "..." in results[0]  # Truncation check

    @patch("orin.analysis.ai.urllib.request.urlopen")
    def test_run_ai_correlation_timeout_error(self, mock_urlopen):
        """Test run_ai_correlation handling TimeoutError."""
        from orin.analysis.ai import run_ai_correlation
        from orin.core.database import OrinStorage
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            db_path = Path(tmp_db.name)
            
        try:
            storage = OrinStorage(db_path)
            storage.initialize_db()
            with storage.get_connection() as conn:
                storage.create_snapshot(conn, hostname="host-a", os_platform="Linux")
                conn.execute(
                    "INSERT INTO security_events (event_type, severity, description, hostname, resolved) VALUES (?, ?, ?, ?, ?);",
                    ("unexpected_port", "high", "Port 4444 open", "host-a", 0)
                )
                conn.commit()

            # Mock urlopen to raise TimeoutError wrapped inside URLError or directly
            mock_urlopen.side_effect = urllib.error.URLError(TimeoutError("Request timed out"))
            
            with pytest.raises(TimeoutError) as ctx:
                run_ai_correlation(db_path, timeout=5)
            assert "Request to local Ollama instance" in str(ctx.value)
        finally:
            if db_path.exists():
                db_path.unlink()


# 2. MITRE ATT&CK Mapping Coverage
class TestATTCKCoverage:
    """Test ATT&CK mapping edge cases."""
    
    def test_get_attck_enrichment_edge_cases(self):
        """Test get_attck_enrichment with various inputs and overrides."""
        from orin.analysis.attck import get_attck_enrichment
        
        # Test case: technique ID in description
        tech, tactic, url = get_attck_enrichment("unknown_event", "Refers to technique T1059.001")
        assert tech == "T1059.001"
        assert tactic == "Execution"
        
        # Test case: process ancestry masquerade
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Process masquerade detected")
        assert tech == "T1036.004"
        assert tactic == "Defense Evasion"
        
        # Test case: process ancestry volatile
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "volatile execution")
        assert tech == "T1036"
        assert tactic == "Defense Evasion"
        
        # Test case: process ancestry other
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "some normal execution")
        assert tech == "T1059.004"
        assert tactic == "Execution"

        # Test case: prefix mapping (e.g. T1548)
        tech, tactic, url = get_attck_enrichment("unknown", "T1548.002")
        assert tech == "T1548.002"
        assert tactic == "Privilege Escalation"


# 3. Persistence Collector Coverage
class TestPersistenceCoverage:
    """Test persistence collector edge cases."""
    
    def test_gather_active_ssh_keys_faults(self):
        """Test gather_active_ssh_keys handles exceptions and formatting options."""
        from orin.collectors.persistence import gather_active_ssh_keys
        
        # Mock pwd.getpwall to return custom users
        mock_user = MagicMock()
        mock_user.pw_name = "testuser"
        mock_user.pw_dir = "/home/testuser"
        
        with patch("pwd.getpwall", return_value=[mock_user]):
            # Mock open to raise PermissionError
            with patch("builtins.open", side_effect=PermissionError("Permission denied")):
                # Mock Path.exists to return True
                with patch("pathlib.Path.exists", return_value=True):
                    results = gather_active_ssh_keys()
                    assert len(results) == 1
                    assert results[0]["key_type"] == "ERROR"
                    assert "ACCESS_DENIED_INVENTORY_FAULT" in results[0]["fingerprint"]

    def test_gather_system_persistence_faults(self):
        """Test gather_system_persistence handles permissions and directory reading issues."""
        from orin.collectors.persistence import gather_system_persistence
        
        # Mock iterdir to raise PermissionError
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.is_file", return_value=False):
                with patch("pathlib.Path.is_dir", return_value=True):
                    with patch("pathlib.Path.iterdir", side_effect=PermissionError("Denied")):
                        results = gather_system_persistence()
                        assert len(results) > 0
                        # Check that directory read error was captured
                        assert any("DIR_READ_ERROR" in r["content_hash"] for r in results)


# 4. Scanner Core Coverage
class TestScannerCoverage:
    """Test scanner edge cases."""
    
    @patch("orin.core.scanner.subprocess.Popen")
    def test_run_remote_scan_fallback_to_bash(self, mock_popen):
        """Test run_remote_scan falls back to bash executor when python executor fails."""
        from orin.core.scanner import run_remote_scan
        from orin.core.database import OrinStorage
        
        # First popen communication raises or returns non-zero code, second succeeds
        mock_proc_py = MagicMock()
        mock_proc_py.returncode = 1
        mock_proc_py.communicate.return_value = ("", "Python not found")
        
        mock_proc_bash = MagicMock()
        mock_proc_bash.returncode = 0
        mock_proc_bash.communicate.return_value = (json.dumps({"hostname": "target-host", "os_platform": "Linux", "processes": []}), "")
        
        mock_popen.side_effect = [mock_proc_py, mock_proc_bash]
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            db_path = Path(tmp_db.name)
            
        try:
            storage = OrinStorage(db_path)
            storage.initialize_db()
            
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.read_text", return_value="dummy agent code"):
                    metrics = run_remote_scan(
                        host="192.168.1.10",
                        user="root",
                        verify_signature=False,
                        db_path=db_path
                    )
                    assert metrics is not None
                    assert metrics.get("events_count") is not None
        finally:
            if db_path.exists():
                db_path.unlink()


# 5. Logging Module Coverage
class TestLoggingCoverage:
    """Test logging module edge cases."""
    
    def test_json_formatter_extra_fields(self):
        """Test JSONFormatter serialization of extra arguments (including non-serializable objects)."""
        import logging
        from orin.core.logging import JSONFormatter
        
        formatter = JSONFormatter(include_extra=True)
        
        class NonSerializable:
            def __str__(self):
                return "Non-Serializable Object"
                
        record = logging.LogRecord(
            name="orin-test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Log message",
            args=(),
            exc_info=None
        )
        record.non_serial = NonSerializable()
        
        formatted_str = formatter.format(record)
        formatted_json = json.loads(formatted_str)
        
        assert formatted_json["message"] == "Log message"
        assert formatted_json["extra"]["non_serial"] == "Non-Serializable Object"


# 6. Self-Verify Coverage
class TestSelfVerifyCoverage:
    """Test self-verify module edge cases."""
    
    def test_verify_checksum_with_read_error(self):
        """Test checksum verification with read errors."""
        from orin.core.self_verify import compute_file_sha256
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
            
        try:
            with patch("builtins.open", side_effect=IOError("Mocked IO Error")):
                with pytest.raises(IOError):
                    compute_file_sha256(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()


# 7. Scheduler Module Coverage
class TestSchedulerCoverage:
    """Test scheduler automation edge cases."""
    
    @patch("orin.core.scheduler.subprocess.Popen")
    @patch("orin.core.scheduler.subprocess.check_output")
    def test_install_schedule_user_crontab_error(self, mock_check_output, mock_popen):
        """Test install_schedule handling failures when writing to user crontab."""
        from orin.core.scheduler import install_schedule
        
        mock_check_output.return_value = b"# existing crontab\n"
        
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"permission denied crontab command")
        mock_popen.return_value = mock_proc
        
        with patch("os.path.exists", return_value=False):  # Skip system-wide /etc/cron.d
            with pytest.raises(SystemExit):
                install_schedule(Path("orin_vault.db"), 30)


# 8. Notifier Module Coverage
class TestNotifierCoverage:
    """Test notifier module edge cases."""
    
    @patch("urllib.request.urlopen")
    def test_alert_forwarder_webhook_exponential_backoff(self, mock_urlopen):
        """Test AlertForwarder handles HTTP errors and implements backoff retry bounds."""
        from orin.core.notifier import AlertForwarder, AlertNotification
        
        # URLOpen raising URLError to force retries
        mock_urlopen.side_effect = urllib.error.URLError("Server error")
        
        config = {
            "enabled": True,
            "min_severity": "low",
            "webhooks": [
                {
                    "name": "test-webhook",
                    "enabled": True,
                    "url": "http://127.0.0.1:9000/webhook",
                    "format": "slack"
                }
            ],
            "retry": {"max_attempts": 2, "backoff_seconds": 0.01},  # small backoff to keep tests fast
            "audit_log": "/dev/null"
        }
        
        forwarder = AlertForwarder(config)
        alert = AlertNotification(
            severity="critical",
            event_type="unexpected_port",
            description="Port 2222 open",
            hostname="test-host",
            snapshot_id=1
        )
        
        # Dispatch should run and absorb webhook errors internally without raising
        with patch("time.sleep") as mock_sleep:
            forwarder.dispatch([alert])
            # Verify retry was attempted once (total of 2 attempts, meaning 1 sleep)
            assert mock_sleep.call_count == 1


# 9. Generic Sigma and Yara Memory Coverage
class TestGenericSigmaAndYaraMemoryCoverage:
    """Test generic Sigma rules evaluation and process YARA memory scanning."""

    def test_evaluate_rule_against_event(self):
        """Test evaluate_rule_against_event with structured events and wildcards."""
        from orin.analysis.sigma import evaluate_rule_against_event
        
        # Test case 1: Dict event matching wildcards
        rule = {
            "title": "Suspicious eBPF Program",
            "detection": {
                "selection_prog": {
                    "name": ["*rootkit*", "*hide*"]
                },
                "condition": "selection_prog"
            }
        }
        event = {"name": "ebpf_rootkit_test"}
        assert evaluate_rule_against_event(event, rule) is True

        event_non_matching = {"name": "normal_program"}
        assert evaluate_rule_against_event(event_non_matching, rule) is False

        # Test case 2: GPL compatibility match
        rule_gpl = {
            "title": "Non-GPL eBPF",
            "detection": {
                "selection": {
                    "gpl_compatible": 0
                },
                "condition": "selection"
            }
        }
        event_gpl = {"gpl_compatible": 0}
        assert evaluate_rule_against_event(event_gpl, rule_gpl) is True
        
        event_gpl_ok = {"gpl_compatible": 1}
        assert evaluate_rule_against_event(event_gpl_ok, rule_gpl) is False

    def test_evaluate_rule_against_event_raw_log_fallback(self):
        """Test evaluate_rule_against_event when given a raw log line (str) and a dictionary selector."""
        from orin.analysis.sigma import evaluate_rule_against_event
        
        rule = {
            "title": "Find in Log",
            "detection": {
                "selection": {
                    "some_field": ["failed", "unauthorized"]
                },
                "condition": "selection"
            }
        }
        assert evaluate_rule_against_event("unauthorized login attempt", rule) is True
        assert evaluate_rule_against_event("successful login", rule) is False

    @patch("orin.analysis.yara_engine.YARA_AVAILABLE", True)
    def test_run_analysis_cycle_yara_memory_scan(self):
        """Test run_analysis_cycle executes YARA process memory scanning flow."""
        from orin.analysis.engine import run_analysis_cycle
        from orin.core.database import OrinStorage
        from orin.analysis.yara_engine import YaraEngine, YaraMatch
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            db_path = Path(tmp_db.name)
            
        try:
            storage = OrinStorage(db_path)
            storage.initialize_db()
            with storage.get_connection() as conn:
                snapshot_id = storage.create_snapshot(conn, hostname="test-host", os_platform="Linux")
                
                # Insert active processes (including a mock user-space process)
                conn.execute(
                    "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);",
                    (snapshot_id, 9999, 100, "suspicious_process", "/tmp/suspicious_process", "./suspicious_process")
                )
                conn.commit()

            # Mock YaraEngine methods
            mock_match = YaraMatch(
                rule_name="TestGoImplant",
                namespace="go_implants",
                matched_strings=["sliverpb"],
                tags=["malware"]
            )
            
            with patch("orin.analysis.yara_engine.YaraEngine.load_rules", return_value=1), \
                 patch("orin.analysis.yara_engine.YaraEngine.scan_process", return_value=[mock_match]), \
                 patch("orin.analysis.yara_engine.YaraEngine.scan_directory", return_value=MagicMock(total_matches=0, matches=[])):
                 
                results = run_analysis_cycle(db_path)
                assert results is not None
                assert results.get("events_count", 0) > 0
                
                with storage.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT event_type, description FROM security_events WHERE event_type = 'yara_malware_match';")
                    yara_events = cursor.fetchall()
                    assert len(yara_events) > 0
                    assert "TestGoImplant" in yara_events[0]["description"]
                    assert "PID 9999" in yara_events[0]["description"]
        finally:
            if db_path.exists():
                db_path.unlink()