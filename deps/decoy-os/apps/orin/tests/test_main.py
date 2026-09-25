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
from orin.main import main
from orin.orchestrator import (
    cmd_init, cmd_collect, cmd_analyze, cmd_report, cmd_serve, cmd_schedule
)

class TestMain(unittest.TestCase):
    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.orchestrator.gather_loaded_kernel_modules")
    @patch("orin.orchestrator.gather_system_accounts")
    def test_cmd_init_success(self, mock_users, mock_modules, mock_storage_cls):
        mock_storage = mock_storage_cls.return_value
        mock_conn = MagicMock()
        mock_storage.get_connection.return_value.__enter__.return_value = mock_conn
        
        mock_modules.return_value = [{"module_name": "ext4", "memory_size": 4000}]
        mock_users.return_value = [{
            "username": "root", "uid": 0, "gid": 0, "home_dir": "/root", "login_shell": "/bin/bash"
        }]
        
        args = MagicMock()
        args.database = "test_db.db"
        args.read_only = False
        
        with patch("sys.stdout") as mock_stdout:
            cmd_init(args)
            
        mock_storage.initialize_db.assert_called_once()
        mock_conn.executemany.assert_called()
        mock_conn.commit.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.orchestrator.gather_loaded_kernel_modules")
    def test_cmd_init_failure(self, mock_modules, mock_storage_cls):
        mock_modules.side_effect = Exception("DB init failure")
        
        args = MagicMock()
        args.database = "test_db.db"
        args.read_only = False
        
        with self.assertRaises(SystemExit) as cm:
            cmd_init(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.OrinStorage")
    @patch("pathlib.Path.exists")
    @patch("orin.orchestrator.gather_active_processes")
    @patch("orin.orchestrator.gather_listening_ports")
    @patch("orin.orchestrator.gather_outbound_connections")
    @patch("orin.orchestrator.gather_promisc_interfaces")
    @patch("orin.orchestrator.gather_loaded_kernel_modules")
    @patch("orin.orchestrator.gather_system_accounts")
    @patch("orin.orchestrator.gather_active_ssh_keys")
    @patch("orin.orchestrator.gather_crontabs")
    @patch("orin.orchestrator.gather_wtmp_sessions")
    @patch("orin.orchestrator.gather_lastlog_records")
    @patch("orin.orchestrator.gather_deleted_binaries")
    @patch("orin.orchestrator.gather_file_integrity_signatures")
    def test_cmd_collect_success(
        self, mock_fim, mock_deleted, mock_lastlog, mock_wtmp, mock_crontabs, mock_ssh, mock_users, mock_modules,
        mock_promisc, mock_outbound, mock_ports, mock_processes, mock_exists, mock_storage_cls
    ):
        mock_exists.return_value = True
        mock_storage = mock_storage_cls.return_value
        mock_conn = MagicMock()
        mock_storage.get_connection.return_value.__enter__.return_value = mock_conn
        mock_storage.create_snapshot.return_value = 42
        
        args = MagicMock()
        args.database = "test_db.db"
        args.vault_path = None
        args.read_only = False
        args.parallel = False
        args.workers = None
        args.timeout = 300.0
        
        with patch("sys.stdout") as mock_stdout:
            cmd_collect(args)
            
        mock_storage.create_snapshot.assert_called_once_with(mock_conn)
        mock_storage.store_processes.assert_called_once()
        mock_storage.store_file_hashes.assert_called_once()
        mock_conn.commit.assert_called_once()

    @patch("pathlib.Path.exists")
    def test_cmd_collect_no_db(self, mock_exists):
        mock_exists.return_value = False
        args = MagicMock()
        args.database = "missing_db.db"
        args.vault_path = None
        args.read_only = False
        args.parallel = False
        args.workers = None
        args.timeout = 300.0
        
        with self.assertRaises(SystemExit) as cm:
            cmd_collect(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.OrinStorage")
    @patch("pathlib.Path.exists")
    def test_cmd_collect_failure(self, mock_exists, mock_storage_cls):
        mock_exists.return_value = True
        mock_storage = mock_storage_cls.return_value
        mock_storage.get_connection.side_effect = Exception("Connection error")
        
        args = MagicMock()
        args.database = "test_db.db"
        args.vault_path = None
        args.read_only = False
        args.parallel = False
        args.workers = None
        args.timeout = 300.0
        
        with self.assertRaises(SystemExit) as cm:
            cmd_collect(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.run_analysis_cycle")
    @patch("pathlib.Path.exists")
    def test_cmd_analyze_success(self, mock_exists, mock_analyze_cycle):
        mock_exists.return_value = True
        mock_analyze_cycle.return_value = {
            "snapshot_id": 42,
            "risk_score": 85,
            "events_count": 5
        }
        
        args = MagicMock()
        args.database = "test_db.db"
        
        with patch("sys.stdout") as mock_stdout:
            cmd_analyze(args)
            
        mock_analyze_cycle.assert_called_once_with(Path("test_db.db"))

    @patch("pathlib.Path.exists")
    def test_cmd_analyze_no_db(self, mock_exists):
        mock_exists.return_value = False
        args = MagicMock()
        args.database = "missing_db.db"
        
        with self.assertRaises(SystemExit) as cm:
            cmd_analyze(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.run_analysis_cycle")
    @patch("pathlib.Path.exists")
    def test_cmd_analyze_failure(self, mock_exists, mock_analyze_cycle):
        mock_exists.return_value = True
        mock_analyze_cycle.side_effect = Exception("Analysis failure")
        args = MagicMock()
        args.database = "test_db.db"
        
        with self.assertRaises(SystemExit) as cm:
            cmd_analyze(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.compile_markdown_report")
    @patch("orin.orchestrator.compile_html_report")
    def test_cmd_report_success(self, mock_html, mock_md):
        args = MagicMock()
        args.database = "test_db.db"
        args.output = "report.html"
        
        # Test HTML format
        args.format = "html"
        cmd_report(args)
        mock_html.assert_called_once_with(Path("test_db.db"), Path("report.html"))
        
        # Test Markdown format
        args.format = "markdown"
        args.output = "report.md"
        cmd_report(args)
        mock_md.assert_called_once_with(Path("test_db.db"), Path("report.md"))

    def test_cmd_report_invalid_format(self):
        args = MagicMock()
        args.database = "test_db.db"
        args.output = "report.txt"
        args.format = "txt"
        
        with self.assertRaises(SystemExit) as cm:
            cmd_report(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.compile_html_report")
    def test_cmd_report_failure(self, mock_html):
        mock_html.side_effect = Exception("Report compilation error")
        args = MagicMock()
        args.database = "test_db.db"
        args.output = "report.html"
        args.format = "html"
        
        with self.assertRaises(SystemExit) as cm:
            cmd_report(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.main.parse_args")
    @patch("orin.main.run_orchestration")
    def test_main_routing_init(self, mock_run_orch, mock_parse_args):
        mock_args = MagicMock()
        mock_args.command = "init"
        mock_args.log_level = None
        mock_args.log_file = None
        mock_args.no_stderr_log = False
        mock_parse_args.return_value = mock_args
        
        main()
        mock_run_orch.assert_called_once_with(mock_args)

    @patch("orin.main.parse_args")
    @patch("orin.main.run_orchestration")
    def test_main_routing_collect(self, mock_run_orch, mock_parse_args):
        mock_args = MagicMock()
        mock_args.command = "collect"
        mock_args.log_level = None
        mock_args.log_file = None
        mock_args.no_stderr_log = False
        mock_parse_args.return_value = mock_args
        
        main()
        mock_run_orch.assert_called_once_with(mock_args)

    @patch("orin.main.parse_args")
    @patch("orin.main.run_orchestration")
    def test_main_routing_analyze(self, mock_run_orch, mock_parse_args):
        mock_args = MagicMock()
        mock_args.command = "analyze"
        mock_args.log_level = None
        mock_args.log_file = None
        mock_args.no_stderr_log = False
        mock_parse_args.return_value = mock_args
        
        main()
        mock_run_orch.assert_called_once_with(mock_args)

    @patch("orin.main.parse_args")
    @patch("orin.main.run_orchestration")
    def test_main_routing_report(self, mock_run_orch, mock_parse_args):
        mock_args = MagicMock()
        mock_args.command = "report"
        mock_args.log_level = None
        mock_args.log_file = None
        mock_args.no_stderr_log = False
        mock_parse_args.return_value = mock_args
        
        main()
        mock_run_orch.assert_called_once_with(mock_args)

    @patch("orin.core.server.start_server")
    def test_cmd_serve_success(self, mock_start_server):
        args = MagicMock()
        args.database = "test_db.db"
        args.host = "127.0.0.1"
        args.port = 8000
        args.port_opt = None
        args.username = None
        args.password = None
        args.cert = None
        args.key = None
        args.no_auth = False
        args.passphrase_file = None
        args.passphrase_prompt = False
        args.passphrase_env_var = None
        args.token_file = None
        
        cmd_serve(args)
        mock_start_server.assert_called_once_with(
            db_path=Path("test_db.db"),
            host="127.0.0.1",
            port=8000,
            username=None,
            password=None,
            cert_path=None,
            key_path=None,
            no_auth=False,
            passphrase_file=None,
            passphrase_prompt=False,
            passphrase_env_var=None,
            token_file=None
        )

    @patch("orin.core.server.start_server")
    def test_cmd_serve_port_override(self, mock_start_server):
        args = MagicMock()
        args.database = "test_db.db"
        args.host = "127.0.0.1"
        args.port = 8000
        args.port_opt = 9000
        args.username = "user"
        args.password = "pass"
        args.cert = "cert.pem"
        args.key = "key.pem"
        args.no_auth = False
        args.passphrase_file = None
        args.passphrase_prompt = False
        args.passphrase_env_var = None
        args.token_file = None
        
        cmd_serve(args)
        mock_start_server.assert_called_once_with(
            db_path=Path("test_db.db"),
            host="127.0.0.1",
            port=9000,
            username="user",
            password="pass",
            cert_path="cert.pem",
            key_path="key.pem",
            no_auth=False,
            passphrase_file=None,
            passphrase_prompt=False,
            passphrase_env_var=None,
            token_file=None
        )

    @patch("orin.core.server.start_server")
    def test_cmd_serve_failure(self, mock_start_server):
        mock_start_server.side_effect = Exception("Start failure")
        args = MagicMock()
        args.database = "test_db.db"
        args.host = "127.0.0.1"
        args.port = 8000
        args.port_opt = None
        args.username = None
        args.password = None
        args.cert = None
        args.key = None
        args.passphrase_file = None
        args.passphrase_prompt = False
        args.passphrase_env_var = None
        args.token_file = None
        
        with self.assertRaises(SystemExit) as cm:
            cmd_serve(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.main.parse_args")
    @patch("orin.main.run_orchestration")
    def test_main_routing_serve(self, mock_run_orch, mock_parse_args):
        mock_args = MagicMock()
        mock_args.command = "serve"
        mock_args.log_level = None
        mock_args.log_file = None
        mock_args.no_stderr_log = False
        mock_parse_args.return_value = mock_args
        
        main()
        mock_run_orch.assert_called_once_with(mock_args)

    @patch("orin.main.parse_args")
    @patch("orin.main.run_orchestration")
    def test_main_routing_schedule(self, mock_run_orch, mock_parse_args):
        mock_args = MagicMock()
        mock_args.command = "schedule"
        mock_args.log_level = None
        mock_args.log_file = None
        mock_args.no_stderr_log = False
        mock_parse_args.return_value = mock_args
        
        main()
        mock_run_orch.assert_called_once_with(mock_args)

    @patch("orin.core.scheduler.install_schedule")
    @patch("orin.core.scheduler.remove_schedule")
    @patch("orin.core.scheduler.show_schedule_status")
    def test_cmd_schedule_logic(self, mock_status, mock_remove, mock_install):
        args = MagicMock()
        args.database = "test_db.db"
        args.interval = 15
        
        # Test install path
        args.install = True
        args.remove = False
        args.status = False
        args.retention = None
        cmd_schedule(args)
        mock_install.assert_called_once_with(Path("test_db.db"), 15, retention_days=None)
        
        # Test remove path
        args.install = False
        args.remove = True
        args.status = False
        cmd_schedule(args)
        mock_remove.assert_called_once()
        
        # Test status path
        args.install = False
        args.remove = False
        args.status = True
        cmd_schedule(args)
        mock_status.assert_called_once()

        # Test default status fallback path
        args.install = False
        args.remove = False
        args.status = False
        cmd_schedule(args)
        self.assertEqual(mock_status.call_count, 2)


if __name__ == "__main__":
    unittest.main()
