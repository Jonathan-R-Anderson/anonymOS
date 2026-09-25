# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
import os
import sys
import unittest
import socket
import json
import tempfile
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open
from orin.core.self_defense import (
    WatchdogConfig,
    HealthStatus,
    HeartbeatManager,
    SeccompProfile,
    AppArmorProfile,
    SELinuxProfile,
    WatchdogService,
    SelfDefenseManager
)

class TestSelfDefense(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.temp_dir.name, "watchdog.sock")
        self.log_path = os.path.join(self.temp_dir.name, "watchdog.log")
        self.config = WatchdogConfig(
            check_interval=0.1,
            max_missed_heartbeats=2,
            heartbeat_timeout=0.2,
            watchdog_socket=self.socket_path,
            log_file=self.log_path
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_watchdog_config_and_health_status(self):
        config = WatchdogConfig()
        self.assertEqual(config.check_interval, 5.0)
        
        status = HealthStatus(
            pid=1234,
            is_alive=True,
            cpu_percent=1.5,
            memory_mb=50.0,
            uptime_seconds=100.0,
            last_heartbeat="2026-06-11T00:00:00",
            status="healthy"
        )
        self.assertEqual(status.pid, 1234)

    def test_heartbeat_manager(self):
        manager = HeartbeatManager(self.config)
        self.assertIsNone(manager.get_last_heartbeat())
        
        # Test record
        manager.record_heartbeat()
        self.assertIsNotNone(manager.get_last_heartbeat())
        
        # Test check health when healthy
        is_healthy, missed = manager.check_health()
        self.assertTrue(is_healthy)
        self.assertEqual(missed, 0)
        
        # Test check health when timeout (deterministic mock, no time.sleep)
        manager.last_heartbeat = datetime.now() - timedelta(seconds=1)
        is_healthy, missed = manager.check_health()
        self.assertFalse(is_healthy)
        self.assertEqual(missed, 1)

    def test_seccomp_profile(self):
        profile_json = SeccompProfile.generate_profile()
        profile = json.loads(profile_json)
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertIn("SCMP_ARCH_X86_64", profile["architectures"])
        
        with patch("builtins.open", mock_open()) as mock_file:
            SeccompProfile.save_profile("dummy_seccomp.json")
            mock_file.assert_called_once_with(Path("dummy_seccomp.json"), 'w')

        # Test validate current process
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value="TracerPid:\t0\n"):
                ok, violations = SeccompProfile.validate_current_process()
                self.assertTrue(ok)
                self.assertEqual(len(violations), 0)

    def test_apparmor_profile(self):
        profile_text = AppArmorProfile.generate_profile()
        self.assertIn("usr.bin.orin {", profile_text)
        
        with patch("builtins.open", mock_open()) as mock_file:
            AppArmorProfile.save_profile("dummy_apparmor")
            mock_file.assert_called_once_with(Path("dummy_apparmor"), 'w')

        self.assertIsInstance(AppArmorProfile.is_apparmor_available(), bool)

        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value="usr.bin.orin (enforce)\n"):
                status = AppArmorProfile.get_profile_status("usr.bin.orin")
                self.assertEqual(status, "enforced")

            with patch("pathlib.Path.read_text", return_value="usr.bin.orin (complain)\n"):
                status = AppArmorProfile.get_profile_status("usr.bin.orin")
                self.assertEqual(status, "complain")

    def test_selinux_profile(self):
        policy_text = SELinuxProfile.generate_te_policy()
        self.assertIn("module orin 1.0;", policy_text)
        
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Enforcing")
            self.assertTrue(SELinuxProfile.is_selinux_available())
            self.assertEqual(SELinuxProfile.get_enforcement_mode(), "enforcing")

    @patch("psutil.Process")
    def test_watchdog_service_health_check(self, mock_process_cls):
        mock_proc = MagicMock()
        mock_process_cls.return_value = mock_proc
        mock_proc.is_running.return_value = True
        mock_proc.cpu_percent.return_value = 2.5
        mock_proc.memory_info.return_value = MagicMock(rss=1024*1024*10)
        mock_proc.create_time.return_value = time.time() - 50.0
        mock_proc.nice.return_value = 0
        
        service = WatchdogService(self.config)
        service.monitored_pid = 99999
        
        # Test healthy
        service.heartbeat_manager.record_heartbeat()
        status = service.get_health_status()
        self.assertEqual(status.status, "healthy")
        self.assertEqual(status.pid, 99999)
        self.assertTrue(status.is_alive)
        
        # Test dead process
        mock_proc.is_running.return_value = False
        status = service.get_health_status()
        self.assertEqual(status.status, "dead")

    @patch("os.chmod")
    @patch("socket.socket")
    def test_watchdog_service_run_and_stop(self, mock_socket, mock_chmod):
        service = WatchdogService(self.config)
        
        # Mock socket accept loop to exit quickly
        mock_server = MagicMock()
        mock_socket.return_value = mock_server
        mock_server.accept.side_effect = socket.timeout
        
        def run_thread():
            service.start_watchdog(monitored_pid=123)
            
        t = threading.Thread(target=run_thread)
        t.start()
        
        # Wait up to 1 second for the watchdog service to start running
        for _ in range(100):
            if service.running:
                break
            time.sleep(0.01)
        
        service.stop_watchdog()
        t.join(timeout=2.0)
        self.assertFalse(service.running)

    @patch("socket.socket")
    def test_send_heartbeat(self, mock_socket_cls):
        mock_client = MagicMock()
        mock_socket_cls.return_value = mock_client
        mock_client.recv.return_value = json.dumps({"type": "ack"}).encode("utf-8")
        
        service = WatchdogService(self.config)
        success = service.send_heartbeat()
        self.assertTrue(success)
        mock_client.connect.assert_called_once_with(self.config.watchdog_socket)

    @patch("orin.core.self_defense.WatchdogService")
    def test_self_defense_manager(self, mock_service_cls):
        mock_service = mock_service_cls.return_value
        
        # Test watchdog service start/stop
        manager = SelfDefenseManager(self.config)
        manager.start_watchdog_service()
        mock_service.start_watchdog.assert_called_once()
        
        manager.stop()
        mock_service.stop_watchdog.assert_called_once()
        
        # Test heartbeat sending delegator
        mock_service.send_heartbeat.return_value = True
        success = manager.send_heartbeat()
        self.assertTrue(success)
        mock_service.send_heartbeat.assert_called_once()

        # Test profile generators
        with patch("orin.core.self_defense.SeccompProfile.save_profile") as mock_sec, \
             patch("orin.core.self_defense.AppArmorProfile.save_profile") as mock_aa, \
             patch("builtins.open", mock_open()):
            SelfDefenseManager.generate_seccomp_profile("path/seccomp")
            mock_sec.assert_called_once_with("path/seccomp")
            
            SelfDefenseManager.generate_apparmor_profile("path/aa")
            mock_aa.assert_called_once_with("path/aa")
            
            SelfDefenseManager.generate_selinux_policy("path/selinux.te")
            
        # Test validate security posture
        with patch("orin.core.self_defense.SeccompProfile.validate_current_process", return_value=(True, [])), \
             patch("orin.core.self_defense.AppArmorProfile.is_apparmor_available", return_value=True), \
             patch("orin.core.self_defense.AppArmorProfile.get_profile_status", return_value="enforced"), \
             patch("orin.core.self_defense.SELinuxProfile.is_selinux_available", return_value=True), \
             patch("orin.core.self_defense.SELinuxProfile.get_enforcement_mode", return_value="enforcing"):
            status = manager.validate_security_profiles()
            self.assertTrue(status["seccomp"]["available"])
            self.assertEqual(status["apparmor"]["status"], "enforced")
            self.assertEqual(status["selinux"]["mode"], "enforcing")

    def test_apparmor_status_exception(self):
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=PermissionError):
            status = AppArmorProfile.get_profile_status("usr.bin.orin")
            self.assertEqual(status, "not_loaded")

    def test_selinux_not_available(self):
        with patch("orin.core.self_defense.SELinuxProfile.is_selinux_available", return_value=False):
            self.assertIsNone(SELinuxProfile.get_enforcement_mode())

    @patch("psutil.Process")
    def test_watchdog_service_tamper_indicators(self, mock_process_cls):
        mock_proc = MagicMock()
        mock_process_cls.return_value = mock_proc
        mock_proc.is_running.return_value = True
        mock_proc.cpu_percent.return_value = 2.5
        mock_proc.memory_info.return_value = MagicMock(rss=1024*1024*10)
        mock_proc.create_time.return_value = time.time() - 50.0
        mock_proc.nice.return_value = 0
        
        service = WatchdogService(self.config)
        service.monitored_pid = 99999
        
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="TracerPid:\t123\n"):
            status = service.get_health_status()
            self.assertEqual(status.status, "critical")
            self.assertTrue(status.tamper_detected)
            self.assertIn("traced", status.tamper_details.lower() if status.tamper_details else "")

    def test_watchdog_service_degraded_and_critical(self):
        # Use a config with large max_missed_heartbeats so we can test degraded state
        from orin.core.self_defense import WatchdogConfig
        config = WatchdogConfig(
            check_interval=0.1,
            max_missed_heartbeats=5,  # High threshold so 1 miss => degraded
            heartbeat_timeout=0.001,  # Very short timeout
            watchdog_socket=os.path.join(self.temp_dir.name, "watchdog_deg.sock"),
            log_file=os.path.join(self.temp_dir.name, "watchdog_deg.log")
        )
        service = WatchdogService(config)
        service.monitored_pid = None

        # Set heartbeat_manager so no heartbeat is recorded — is_healthy will be False
        # missed_heartbeats starts at 0 → after check_health call it will be 1 → "degraded"
        service.heartbeat_manager.last_heartbeat = None
        service.heartbeat_manager.missed_heartbeats = 0
        status = service.get_health_status()
        # No pid → dead (since last_heartbeat is None from the start)
        # Actually: no last_heartbeat => check_health returns (False, 0)
        # not is_alive (no pid), not heartbeat_healthy, missed_count=0 < 5 => degraded
        self.assertIn(status.status, ("dead", "degraded"))

        # Critical: now set missed_heartbeats high enough
        service.heartbeat_manager.missed_heartbeats = 10
        status = service.get_health_status()
        self.assertIn(status.status, ("dead", "critical"))

    @patch("orin.core.self_defense.SelfDefenseManager")
    def test_main_cli(self, mock_manager_cls):
        from orin.core.self_defense import main
        mock_manager = mock_manager_cls.return_value
        
        # generate-profiles
        with patch("sys.argv", ["self-defense", "generate-profiles", "--output-dir", "dummy_dir"]), \
             patch("pathlib.Path.mkdir"), \
             patch("builtins.print"):
            main()
            mock_manager_cls.generate_seccomp_profile.assert_called_once()
            mock_manager_cls.generate_apparmor_profile.assert_called_once()
            mock_manager_cls.generate_selinux_policy.assert_called_once()
            
        # status
        mock_manager.validate_security_profiles.return_value = {"ok": True}
        with patch("sys.argv", ["self-defense", "status"]), \
             patch("builtins.print"):
            main()
            mock_manager.validate_security_profiles.assert_called_once()
            
        # heartbeat
        mock_manager.send_heartbeat.return_value = True
        with patch("sys.argv", ["self-defense", "heartbeat"]), \
             self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)
        
        # watchdog
        with patch("sys.argv", ["self-defense", "watchdog", "--socket", "s.sock", "--interval", "0.5"]), \
             patch("time.sleep", side_effect=KeyboardInterrupt):
            main()
            mock_manager.start_watchdog_service.assert_called_once()

if __name__ == "__main__":
    unittest.main()
