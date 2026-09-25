# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
import sys
from unittest.mock import MagicMock

# Mock bcrypt before importing anything that depends on it
# sys.modules['bcrypt'] = MagicMock()

import unittest
import os
import json
from pathlib import Path
from unittest.mock import patch

from orin.cli import parse_args
from orin.orchestrator import (
    run_orchestration,
    cmd_self_defense,
    cmd_init,
    cmd_collect,
    cmd_analyze,
    cmd_report,
    cmd_serve,
    cmd_hub_serve,
    cmd_schedule,
    cmd_scan,
    cmd_baseline,
    cmd_correlate,
    cmd_delta,
    cmd_diff,
    cmd_export,
    cmd_verify,
    cmd_stream,
    cmd_vault,
    cmd_rules
)
from orin.core.hub_server import TenantManager

class TestCliCoverage(unittest.TestCase):
    def test_parse_args_all_commands(self):
        commands = [
            ["init", "--read-only"],
            ["collect", "--parallel", "--workers", "4", "--timeout", "10.0"],
            ["analyze"],
            ["report", "--format", "html", "--output", "r.html"],
            ["report", "--format", "markdown", "--output", "r.md"],
            ["serve", "--host", "127.0.0.1", "--port", "8080"],
            ["hub-serve", "--host", "127.0.0.1", "--port", "8080"],
            ["schedule", "--install"],
            ["schedule", "--remove"],
            ["schedule", "--status"],
            ["self-defense", "--action", "status"],
            ["self-defense", "--action", "watchdog", "--socket", "/var/run/sd.sock", "--interval", "5"],
            ["self-defense", "--action", "heartbeat", "--socket", "/var/run/sd.sock"],
            ["self-defense", "--action", "generate-profiles", "--output-dir", "/tmp"],
            ["scan", "--host", "127.0.0.1", "--user", "root"],
            ["baseline", "add", "--user", "testuser"],
            ["baseline", "refresh", "--force-overwrite"],
            ["correlate"],
            ["delta", "--base", "1", "--target", "2"],
            ["diff", "v1.json", "v2.json"],
            ["export", "--snapshot", "1", "--secret", "passpasspasspass"],
            ["verify", "--file", "f.enc", "--secret", "passpasspasspass"],
            ["stream"],
            ["rules", "update", "--sigma", "/tmp"],
            ["vault", "stats"],
            ["vault", "prune", "--older-than", "30", "--execute"]
        ]
        for cmd in commands:
            with patch("sys.argv", ["orin", "-d", "test.db"] + cmd):
                args = parse_args()
                self.assertIsNotNone(args)

class TestOrchestratorCoverage(unittest.TestCase):
    @patch("orin.orchestrator.cmd_init")
    @patch("orin.orchestrator.cmd_collect")
    @patch("orin.orchestrator.cmd_analyze")
    @patch("orin.orchestrator.cmd_report")
    @patch("orin.orchestrator.cmd_serve")
    @patch("orin.orchestrator.cmd_hub_serve")
    @patch("orin.orchestrator.cmd_schedule")
    @patch("orin.orchestrator.cmd_scan")
    @patch("orin.orchestrator.cmd_baseline")
    @patch("orin.orchestrator.cmd_correlate")
    @patch("orin.orchestrator.cmd_delta")
    @patch("orin.orchestrator.cmd_diff")
    @patch("orin.orchestrator.cmd_export")
    @patch("orin.orchestrator.cmd_verify")
    @patch("orin.orchestrator.cmd_stream")
    @patch("orin.orchestrator.cmd_vault")
    @patch("orin.orchestrator.cmd_rules")
    @patch("orin.orchestrator.SelfDefenseManager")
    def test_run_orchestration(self, mock_sd, mock_rules, mock_vault, mock_stream, mock_verify,
                               mock_export, mock_diff, mock_delta, mock_correlate, mock_baseline,
                               mock_scan, mock_schedule, mock_hub_serve, mock_serve, mock_report,
                               mock_analyze, mock_collect, mock_init):
        # 1. Simple commands
        simple_cmds = [
            ("init", mock_init),
            ("collect", mock_collect),
            ("analyze", mock_analyze),
            ("report", mock_report),
            ("serve", mock_serve),
            ("hub-serve", mock_hub_serve),
            ("schedule", mock_schedule),
            ("scan", mock_scan),
            ("baseline", mock_baseline),
            ("correlate", mock_correlate),
            ("stream", mock_stream),
            ("rules", mock_rules)
        ]
        for cmd_name, mock_fn in simple_cmds:
            args = MagicMock()
            args.command = cmd_name
            run_orchestration(args)
            mock_fn.assert_called_once_with(args)
            mock_fn.reset_mock()

        # 2. self-defense watchdog
        args = MagicMock()
        args.command = "self-defense"
        args.action = "watchdog"
        args.socket = "/tmp/sd.sock"
        args.interval = 1
        with patch("time.sleep", side_effect=KeyboardInterrupt):
            run_orchestration(args)
        mock_sd.assert_called_once()
        mock_sd.reset_mock()

        # 3. self-defense heartbeat
        args = MagicMock()
        args.command = "self-defense"
        args.action = "heartbeat"
        args.socket = "/tmp/sd.sock"
        mock_sd.return_value.send_heartbeat.return_value = True
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)
        mock_sd.reset_mock()

        # 4. self-defense generate-profiles
        args = MagicMock()
        args.command = "self-defense"
        args.action = "generate-profiles"
        args.output_dir = "/tmp/orin_test_profiles"
        with patch("pathlib.Path.mkdir"):
            run_orchestration(args)
        mock_sd.generate_seccomp_profile.assert_called_once()
        mock_sd.reset_mock()

        # 5. self-defense status
        args = MagicMock()
        args.command = "self-defense"
        args.action = "status"
        mock_sd.return_value.validate_security_profiles.return_value = {"status": "ok"}
        run_orchestration(args)
        mock_sd.return_value.validate_security_profiles.assert_called_once()
        mock_sd.reset_mock()

        # 6. delta, diff, export, verify, vault
        args = MagicMock()
        args.command = "delta"
        mock_delta.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "diff"
        mock_diff.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "export"
        mock_export.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "verify"
        mock_verify.return_value = 0
        with self.assertRaises(SystemExit) as cm:
            run_orchestration(args)
        self.assertEqual(cm.exception.code, 0)

        args.command = "vault"
        args.vault_command = "prune"
        args.execute = True
        run_orchestration(args)
        mock_vault.assert_called_once_with(args)
        self.assertFalse(args.dry_run)

    @patch("orin.core.self_defense.main")
    def test_cmd_self_defense(self, mock_sd_main):
        args = MagicMock()
        args._remaining_args = ["status"]
        cmd_self_defense(args)
        mock_sd_main.assert_called_once()

    @patch("orin.core.hub_server.start_server")
    def test_cmd_hub_serve(self, mock_start):
        args = MagicMock()
        args.database = "test.db"
        args.host = "127.0.0.1"
        args.port = 8080
        args.port_opt = None
        args.cert = None
        args.key = None
        args.no_auth = True
        cmd_hub_serve(args)
        mock_start.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.core.scanner.run_remote_scan")
    @patch("subprocess.Popen")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_scan(self, mock_exists, mock_popen, mock_scan, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_conn = MagicMock()
        for mock_storage_cls in (mock_db_storage, mock_orch_storage):
            mock_storage_cls.return_value.get_connection.return_value.__enter__.return_value = mock_conn

        args = MagicMock()
        args.database = "test.db"
        args.host = "127.0.0.1"
        args.port = 22
        args.init = True
        args.key = None
        args.user = "root"
        args.deploy_only = False
        args.scan_only = False

        # Test init path
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        mock_proc.communicate.return_value = ('{"hostname": "remote-host", "modules": [], "users": [], "suid": []}', '')
        mock_proc.returncode = 0

        with patch("pathlib.Path.read_text", return_value="agent_code"):
            cmd_scan(args)

        # Test scan path
        args.init = False
        mock_scan.return_value = {"snapshot_id": 1, "risk_score": 50, "events_count": 0}
        cmd_scan(args)
        mock_scan.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.os.path.exists")
    @patch("pathlib.Path.exists")
    def test_cmd_baseline(self, mock_path_exists, mock_exists, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_path_exists.return_value = True
        mock_conn = MagicMock()
        for mock_storage_cls in (mock_db_storage, mock_orch_storage):
            mock_storage_cls.return_value.get_connection.return_value.__enter__.return_value = mock_conn

        # Test "add" path
        args = MagicMock()
        args.database = "test.db"
        args.host = None
        args.baseline_command = "add"
        args.user = "testuser"
        args.module = None
        args.suid = None

        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.side_effect = [
            {"id": 1}, # snapshot_id
            {"username": "testuser", "uid": 1000, "gid": 1000, "home_dir": "/home/testuser", "login_shell": "/bin/bash"} # user info
        ]
        cmd_baseline(args)

        # Test "refresh" path
        args = MagicMock()
        args.database = "test.db"
        args.host = None
        args.baseline_command = "refresh"
        args.force_overwrite = True
        mock_cursor.fetchone.side_effect = [{"id": 1}]
        cmd_baseline(args)

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.os.path.exists")
    @patch("orin.analysis.ai.run_ai_correlation")
    def test_cmd_correlate(self, mock_ai, mock_exists, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_ai.return_value = "Correlation Briefing Details"
        args = MagicMock()
        args.database = "test.db"
        args.host = None
        args.url = None
        args.model = "ollama"
        args.output = None
        cmd_correlate(args)

    @patch("orin.analysis.timeline.calculate_snapshot_delta")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_delta(self, mock_exists, mock_calc_delta):
        mock_exists.return_value = True
        mock_calc_delta.return_value = {
            "added": [1],
            "removed": [2],
            "modified": [3]
        }
        args = MagicMock()
        args.database = "test.db"
        args.base = 1
        args.target = 2
        args.verbose = True
        cmd_delta(args)
        mock_calc_delta.assert_called_once_with("test.db", 1, 2)

    @patch("orin.analysis.diff.load_snapshot_data")
    @patch("orin.analysis.diff.compare_snapshots")
    def test_cmd_diff(self, mock_compare, mock_load):
        mock_load.side_effect = [{"host": "h1"}, {"host": "h2"}]
        mock_compare.return_value = {
            "total_changes": 5,
            "critical_changes": 1
        }
        args = MagicMock()
        args.base_file = "f1.json"
        args.target_file = "f2.json"
        args.secret = "secretkey"
        args.verbose = True
        cmd_diff(args)
        mock_compare.assert_called_once()

    @patch("orin.core.crypto.generate_signed_export")
    @patch("orin.core.crypto.generate_coc_manifest")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_export(self, mock_exists, mock_coc, mock_export_fn):
        mock_exists.return_value = True
        mock_export_fn.return_value = {"snapshot_id": 1, "data": "dummy"}
        mock_coc.return_value = {"evidence_count": 10}

        args = MagicMock()
        args.database = "test.db"
        args.snapshot = 1
        args.secret = "passpasspasspass"
        args.output = "output.json"

        with patch("builtins.open", unittest.mock.mock_open()):
            cmd_export(args)

        mock_export_fn.assert_called_once_with("test.db", 1, "passpasspasspass")

    @patch("orin.core.crypto.verify_signed_export")
    @patch("orin.orchestrator.os.path.exists")
    def test_cmd_verify(self, mock_exists, mock_verify_fn):
        mock_exists.return_value = True
        mock_verify_fn.return_value = {
            "valid": True,
            "snapshot_id": 1,
            "timestamp": "2026-06-11",
            "item_count": 42
        }

        args = MagicMock()
        args.file = "export.json"
        args.secret = "passpasspasspass"

        cmd_verify(args)
        mock_verify_fn.assert_called_once_with("export.json", "passpasspasspass")

    @patch("subprocess.run")
    @patch("pathlib.Path.exists")
    def test_cmd_stream(self, mock_exists, mock_run):
        mock_exists.return_value = True
        args = MagicMock()
        args.database = "test.db"
        args.verbose = True

        cmd_stream(args)
        mock_run.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.os.path.exists")
    @patch("pathlib.Path.exists")
    def test_cmd_vault(self, mock_path_exists, mock_exists, mock_db_storage, mock_orch_storage):
        mock_exists.return_value = True
        mock_path_exists.return_value = True
        mock_conn = MagicMock()

        for mock_storage_cls in (mock_db_storage, mock_orch_storage):
            mock_storage = mock_storage_cls.return_value
            mock_storage.get_connection.return_value.__enter__.return_value = mock_conn
            mock_storage.vault_stats.return_value = {
                'database_size_mb': 10.5,
                'database_size_bytes': 1024 * 1024 * 10,
                'snapshot_count': 5,
                'oldest_snapshot': '2026-06-10',
                'newest_snapshot': '2026-06-11',
                'table_counts': {'system_snapshots': 5}
            }
            mock_storage.vault_prune.return_value = {
                "mode": "legacy",
                "message": "Pruned 10 records"
            }

        # Test stats command
        args = MagicMock()
        args.database = "test.db"
        args.vault_command = "stats"
        cmd_vault(args)

        # Test prune legacy command
        args = MagicMock()
        args.database = "test.db"
        args.vault_command = "prune"
        args.execute = True
        args.policy_file = None
        args.older_than = 30
        cmd_vault(args)

    @patch("orin.analysis.sigma.validate_rules_directory")
    @patch("pathlib.Path.exists")
    def test_cmd_rules(self, mock_exists, mock_val_dir):
        mock_exists.return_value = True
        mock_val_dir.return_value = ([], [])
        args = MagicMock()
        args.database = "test.db"
        args.rules_command = "update"
        args.sigma = "/tmp"
        args.yara = None
        args.validate_only = True
        cmd_rules(args)
        mock_val_dir.assert_called_once()


class DummyArgs:
    def __init__(self, **kwargs):
        self.database = None
        self.vault_path = None
        self.read_only = False
        self.parallel = False
        self.workers = None
        self.timeout = 300.0
        self.output = None
        self.format = None
        self.host = None
        self.port = None
        self.port_opt = None
        self.username = None
        self.password = None
        self.cert = None
        self.key = None
        self.no_auth = False
        self.install = False
        self.remove = False
        self.status = False
        self.interval = 60
        self.retention = None
        self.user = None
        self.module = None
        self.suid = None
        self.baseline_command = None
        self.force_overwrite = False
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestDirectOrchestratorCommands(unittest.TestCase):
    def setUp(self):
        self.db_path = "boost_test.db"
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_cmd_init_readonly(self):
        args = DummyArgs(database=self.db_path, read_only=True)
        with self.assertRaises(SystemExit) as cm:
            cmd_init(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("orin.orchestrator.gather_loaded_kernel_modules")
    @patch("orin.orchestrator.gather_system_accounts")
    @patch("orin.orchestrator.gather_suid_binaries")
    def test_cmd_init_success(self, mock_suid, mock_users, mock_kernel):
        mock_kernel.return_value = [{"module_name": "m1", "memory_size": 100}]
        mock_users.return_value = [{"username": "u1", "uid": 1, "gid": 1, "home_dir": "/h", "login_shell": "/s"}]
        mock_suid.return_value = [{"file_path": "/p", "owner": "o", "grp": "g", "permissions": "p", "sha256": "s"}]

        args = DummyArgs(database=self.db_path, read_only=False)
        cmd_init(args)
        self.assertTrue(os.path.exists(self.db_path))

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
    @patch("orin.orchestrator.gather_suid_binaries")
    @patch("orin.orchestrator.gather_auth_logs")
    @patch("orin.orchestrator.gather_all_privilege_events")
    @patch("orin.orchestrator.gather_ebpf_programs")
    @patch("orin.orchestrator.gather_ebpf_pinned")
    @patch("orin.orchestrator.gather_ld_preload")
    @patch("orin.orchestrator.gather_special_fds")
    @patch("orin.orchestrator.gather_system_persistence")
    @patch("orin.orchestrator.gather_dns_queries")
    @patch("orin.orchestrator.gather_pkg_integrity_drift")
    @patch("orin.orchestrator.gather_kernel_symbols")
    @patch("orin.orchestrator.analyze_kernel_symbol_overrides")
    @patch("orin.orchestrator.check_for_unlinked_modules")
    def test_cmd_collect_sequential(self, mock_unlinked, mock_overrides, mock_symbols, mock_pkg, mock_dns, mock_persist, mock_fds, mock_preload, mock_pinned, mock_ebpf, mock_priv, mock_auth, mock_suid, mock_fim, mock_del, mock_lastlog, mock_wtmp, mock_cron, mock_keys, mock_users, mock_kernel, mock_promisc, mock_outbound, mock_ports, mock_processes):
        # Setup mock returns
        mock_processes.return_value = []
        mock_ports.return_value = []
        mock_outbound.return_value = []
        mock_promisc.return_value = []
        mock_kernel.return_value = []
        mock_users.return_value = []
        mock_keys.return_value = []
        mock_cron.return_value = []
        mock_wtmp.return_value = []
        mock_lastlog.return_value = []
        mock_del.return_value = []
        mock_fim.return_value = []
        mock_suid.return_value = []
        mock_auth.return_value = []
        mock_priv.return_value = {
            "privilege_escalation_events": [],
            "syscall_audit_events": [],
            "pam_authentication_events": [],
            "credential_access_events": []
        }
        mock_ebpf.return_value = []
        mock_pinned.return_value = []
        mock_preload.return_value = []
        mock_fds.return_value = []
        mock_persist.return_value = []
        mock_dns.return_value = []
        mock_pkg.return_value = []
        mock_symbols.return_value = []
        mock_overrides.return_value = {}
        mock_unlinked.return_value = []

        # Init DB first
        init_args = DummyArgs(database=self.db_path, read_only=False)
        cmd_init(init_args)

        # 1. Read-only collect
        collect_args = DummyArgs(database=self.db_path, read_only=True, parallel=False)
        cmd_collect(collect_args)

        # 2. Write collect
        collect_args = DummyArgs(database=self.db_path, read_only=False, parallel=False)
        cmd_collect(collect_args)

    @patch("orin.orchestrator.ParallelCollector")
    @patch("orin.orchestrator.gather_file_integrity_signatures")
    @patch("orin.orchestrator.gather_kernel_symbols")
    @patch("orin.orchestrator.analyze_kernel_symbol_overrides")
    @patch("orin.orchestrator.check_for_unlinked_modules")
    @patch("orin.orchestrator.gather_all_privilege_events")
    @patch("orin.orchestrator.gather_active_ssh_keys")
    @patch("orin.orchestrator.gather_pkg_integrity_drift")
    @patch("orin.orchestrator.analyze_dns_patterns")
    def test_cmd_collect_parallel(self, mock_dns_pat, mock_pkg, mock_keys, mock_priv, mock_unlinked, mock_overrides, mock_symbols, mock_fim, mock_parallel_cls):
        mock_parallel = mock_parallel_cls.return_value
        mock_parallel.get_successful_results.return_value = {
            "dns_queries": []
        }
        mock_parallel.get_failed_results.return_value = {"processes": "timeout"}
        mock_parallel.get_summary.return_value = {"successful": 1, "total_tasks": 2, "total_duration": 1.5}

        mock_fim.return_value = []
        mock_symbols.return_value = []
        mock_overrides.return_value = {}
        mock_unlinked.return_value = []
        mock_priv.return_value = {
            "privilege_escalation_events": [],
            "syscall_audit_events": [],
            "pam_authentication_events": [],
            "credential_access_events": []
        }
        mock_keys.return_value = []
        mock_pkg.return_value = []

        init_args = DummyArgs(database=self.db_path, read_only=False)
        cmd_init(init_args)

        collect_args = DummyArgs(database=self.db_path, read_only=False, parallel=True, workers=2, timeout=10.0)
        cmd_collect(collect_args)

    @patch("orin.orchestrator.run_analysis_cycle")
    def test_cmd_analyze(self, mock_cycle):
        mock_cycle.return_value = {"snapshot_id": 1, "risk_score": 75, "events_count": 3}
        args = DummyArgs(database=self.db_path)

        # Missing DB raises system exit
        with self.assertRaises(SystemExit) as cm:
            cmd_analyze(args)
        self.assertEqual(cm.exception.code, 1)

        # Create dummy file to pass exists check
        Path(self.db_path).touch()
        cmd_analyze(args)

    @patch("orin.orchestrator.compile_markdown_report")
    @patch("orin.orchestrator.compile_html_report")
    def test_cmd_report(self, mock_html, mock_md):
        args = DummyArgs(database=self.db_path, output="rep.md", format="markdown")
        cmd_report(args)
        mock_md.assert_called_once()

        args = DummyArgs(database=self.db_path, output="rep.html", format="html")
        cmd_report(args)
        mock_html.assert_called_once()

    @patch("orin.core.server.start_server")
    def test_cmd_serve(self, mock_start):
        args = DummyArgs(database=self.db_path, host="127.0.0.1", port=8080, username="user", password="pass")
        cmd_serve(args)
        mock_start.assert_called_once()

    @patch("orin.core.scheduler.install_schedule")
    @patch("orin.core.scheduler.remove_schedule")
    @patch("orin.core.scheduler.show_schedule_status")
    def test_cmd_schedule(self, mock_status, mock_remove, mock_install):
        args = DummyArgs(database=self.db_path, install=True, interval=60, retention=7)
        cmd_schedule(args)
        mock_install.assert_called_once()

        args = DummyArgs(database=self.db_path, remove=True)
        cmd_schedule(args)
        mock_remove.assert_called_once()

        args = DummyArgs(database=self.db_path, status=True)
        cmd_schedule(args)
        mock_status.assert_called_once()

    @patch("orin.core.database.OrinStorage")
    @patch("orin.orchestrator.platform.node", return_value="testnode")
    def test_cmd_baseline_add_and_refresh(self, mock_node, mock_storage_cls):
        mock_storage = mock_storage_cls.return_value
        mock_conn = MagicMock()
        mock_storage.get_connection.return_value.__enter__.return_value = mock_conn
        mock_cursor = mock_conn.cursor.return_value

        # Mock file exists
        Path(self.db_path).touch()

        # 1. Add User
        args = DummyArgs(database=self.db_path, baseline_command="add", user="testuser")
        mock_cursor.fetchone.side_effect = [
            {"id": 12}, # snapshot_id
            {"username": "testuser", "uid": 1000, "gid": 1000, "home_dir": "/h", "login_shell": "/s"} # user info
        ]
        cmd_baseline(args)

        # 2. Add Module
        args = DummyArgs(database=self.db_path, baseline_command="add", module="testmod")
        mock_cursor.fetchone.side_effect = [
            {"id": 12}, # snapshot_id
            {"module_name": "testmod", "memory_size": 200} # module info
        ]
        cmd_baseline(args)

        # 3. Add SUID
        args = DummyArgs(database=self.db_path, baseline_command="add", suid="/bin/suid")
        mock_cursor.fetchone.side_effect = [
            {"id": 12}, # snapshot_id
            {"file_path": "/bin/suid", "owner": "r", "grp": "r", "permissions": "x", "sha256": "h"} # suid info
        ]
        cmd_baseline(args)

        # 4. Refresh with force_overwrite = True
        args = DummyArgs(database=self.db_path, baseline_command="refresh", force_overwrite=True)
        mock_cursor.fetchone.side_effect = None
        mock_cursor.fetchone.return_value = {"id": 12}
        mock_cursor.fetchall.side_effect = [
            [{"module_name": "m1", "memory_size": 100}],
            [{"username": "u1", "uid": 1, "gid": 1, "home_dir": "/h", "login_shell": "/s"}],
            [{"file_path": "/p", "owner": "o", "grp": "g", "permissions": "p", "sha256": "s"}]
        ]
        cmd_baseline(args)

    @patch("orin.analysis.ai.run_ai_correlation")
    def test_cmd_correlate(self, mock_ai):
        mock_ai.return_value = "Correlation briefing briefing details"
        args = DummyArgs(database=self.db_path, host=["node1"], url="http://local", model="llama3", output="out.txt")
        with patch("builtins.open", unittest.mock.mock_open()):
            cmd_correlate(args)
        mock_ai.assert_called_once()

    @patch("orin.analysis.timeline.calculate_snapshot_delta")
    def test_cmd_delta(self, mock_delta):
        args = DummyArgs(database=self.db_path, base=1, target=2, verbose=True)
        # Touch file
        Path(self.db_path).touch()
        cmd_delta(args)
        mock_delta.assert_called_once()

    @patch("orin.analysis.diff.load_snapshot_data")
    @patch("orin.analysis.diff.compare_snapshots")
    def test_cmd_diff(self, mock_compare, mock_load):
        args = DummyArgs(base_file="f1.json", target_file="f2.json", secret="key", verbose=True)
        cmd_diff(args)
        mock_compare.assert_called_once()

    @patch("orin.core.crypto.generate_signed_export")
    @patch("orin.core.crypto.generate_coc_manifest")
    def test_cmd_export(self, mock_coc, mock_export):
        args = DummyArgs(database=self.db_path, snapshot=1, secret="pass", output="out.json")
        Path(self.db_path).touch()
        with patch("builtins.open", unittest.mock.mock_open()):
            cmd_export(args)

    @patch("orin.core.crypto.verify_signed_export")
    @patch("orin.orchestrator.os.path.exists", return_value=True)
    def test_cmd_verify(self, mock_exists, mock_verify):
        args = DummyArgs(file="export.json", secret="pass")
        cmd_verify(args)
        mock_verify.assert_called_once()

    @patch("subprocess.run")
    def test_cmd_stream(self, mock_run):
        args = DummyArgs(database=self.db_path, verbose=True)
        Path(self.db_path).touch()
        cmd_stream(args)
        mock_run.assert_called_once()

    @patch("orin.orchestrator.OrinStorage")
    def test_cmd_vault(self, mock_storage_cls):
        mock_storage = mock_storage_cls.return_value
        mock_conn = MagicMock()
        mock_storage.get_connection.return_value.__enter__.return_value = mock_conn
        mock_storage.vault_stats.return_value = {
            'database_size_mb': 10.5,
            'database_size_bytes': 1024 * 1024 * 10,
            'snapshot_count': 5,
            'oldest_snapshot': '2026-06-10',
            'newest_snapshot': '2026-06-11',
            'table_counts': {'system_snapshots': 5}
        }

        args = DummyArgs(database=self.db_path, vault_command="stats")
        Path(self.db_path).touch()
        cmd_vault(args)

        args = DummyArgs(database=self.db_path, vault_command="prune", execute=True, policy_file=None, older_than=30)
        cmd_vault(args)

    @patch("orin.core.scanner.run_remote_scan")
    @patch("subprocess.Popen")
    @patch("orin.orchestrator.OrinStorage")
    def test_cmd_scan(self, mock_storage_cls, mock_popen, mock_scan):
        # 1. init remote baseline scan
        args = DummyArgs(database=self.db_path, host="1.1.1.1", user="root", port=22, init=True, key=None)
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        mock_proc.communicate.return_value = ('{"hostname": "h", "modules": [], "users": [], "suid": []}', '')
        mock_proc.returncode = 0

        with patch("pathlib.Path.read_text", return_value="agent_code"):
            cmd_scan(args)

        # 2. regular scan
        args = DummyArgs(database=self.db_path, host="1.1.1.1", user="root", port=22, init=False, key=None, no_strict_host_keys=True, known_hosts_file=None)
        mock_scan.return_value = {"snapshot_id": 1, "risk_score": 50, "events_count": 0}
        cmd_scan(args)
        mock_scan.assert_called_once()


class TestHubServerCoverage(unittest.TestCase):
    def test_tenant_manager(self):
        db_file = "test_hub_tenants.db"
        if Path(db_file).exists():
            try:
                Path(db_file).unlink()
            except Exception:
                pass

        manager = TenantManager(db_file)
        self.assertEqual(len(manager.tenants), 0)

        # Cleanup
        if Path(db_file).exists():
            try:
                Path(db_file).unlink()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()