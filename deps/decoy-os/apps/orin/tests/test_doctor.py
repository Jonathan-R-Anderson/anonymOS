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
# tests/test_doctor.py
"""Unit tests for orin.core.doctor module."""
import unittest
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from orin.core.doctor import (
    CheckResult,
    _validate_config_schema,
    run_diagnostics,
    cmd_doctor
)

class TestDoctorConfigSchema(unittest.TestCase):
    """Test schema validation logic for configuration files."""

    def test_valid_config_passes(self):
        """Verify valid configurations produce zero schema warnings."""
        valid_config = {
            "expected_ports": [80, 443],
            "whitelisted_processes": ["nginx"],
            "critical_paths": ["/etc/passwd"],
            "critical_dirs": ["/etc/cron.d"],
            "vault_encryption": {
                "enabled": True,
                "passphrase_env": "ENV_PASSPHRASE",
                "min_passphrase_length": 16
            },
            "logging": {
                "enabled": True,
                "level": "DEBUG",
                "format": "json",
                "output_stderr": True,
                "max_bytes": 1000,
                "backup_count": 2
            },
            "collectors": {
                "parallel_enabled": True,
                "default_timeout": 120.0,
                "max_workers": 4,
                "per_collector_timeouts": {
                    "processes": 10.0
                }
            }
        }
        warnings = _validate_config_schema(valid_config)
        self.assertEqual(len(warnings), 0)

    def test_invalid_types_produce_warnings(self):
        """Verify invalid schema parameter types produce warnings."""
        invalid_config = {
            "expected_ports": "not-a-list",
            "whitelisted_processes": [123],
            "vault_encryption": "not-a-dict",
            "logging": {
                "enabled": "not-a-bool",
                "level": "INVALID_LEVEL",
                "max_bytes": "not-an-int"
            },
            "collectors": {
                "max_workers": "not-an-int",
                "per_collector_timeouts": "not-a-dict"
            },
            "unrecognized_key": "some-value"
        }
        warnings = _validate_config_schema(invalid_config)
        self.assertGreater(len(warnings), 0)
        
        # Check some expected warnings are present
        warnings_str = " ".join(warnings)
        self.assertIn("expected_ports", warnings_str)
        self.assertIn("whitelisted_processes", warnings_str)
        self.assertIn("vault_encryption", warnings_str)
        self.assertIn("logging.enabled", warnings_str)
        self.assertIn("logging.level", warnings_str)
        self.assertIn("logging.max_bytes", warnings_str)
        self.assertIn("collectors.max_workers", warnings_str)
        self.assertIn("collectors.per_collector_timeouts", warnings_str)
        self.assertIn("unrecognized_key", warnings_str)

    def test_invalid_port_list_elements(self):
        """Verify non-integer elements in expected_ports produce warnings."""
        invalid_ports = {
            "expected_ports": [80, "443"]
        }
        warnings = _validate_config_schema(invalid_ports)
        self.assertEqual(len(warnings), 1)
        self.assertIn("expected_ports[1]", warnings[0])


class TestDoctorRunDiagnostics(unittest.TestCase):
    """Test full verification diagnostic run path under mock system conditions."""

    def setUp(self):
        self.is_file_patcher = patch("orin.core.doctor.Path.is_file", return_value=True)
        self.is_file_patcher.start()

    def tearDown(self):
        self.is_file_patcher.stop()

    @patch("orin.core.doctor.os.geteuid")
    @patch("orin.core.doctor.platform.system")
    @patch("orin.core.doctor.platform.release")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.Path.read_text")
    @patch("orin.core.doctor.ctypes.CDLL")
    @patch("orin.core.doctor.shutil.disk_usage")
    @patch("orin.core.doctor.os.access")
    @patch("orin.core.doctor.sqlite3.connect")
    @patch("orin.core.doctor.open", new_callable=mock_open)
    def test_all_checks_pass_cleanly(
        self, mock_file_open, mock_sqlite_connect, mock_access, mock_disk, mock_cdll,
        mock_read_text, mock_path_exists, mock_release, mock_system, mock_geteuid
    ):
        """Verify run_diagnostics generates PASS checks for healthy environments."""
        mock_geteuid.return_value = 0
        mock_system.return_value = "Linux"
        mock_release.return_value = "5.15.0-generic"
        
        # Use lists for side_effect to prevent parameter count errors
        mock_path_exists.side_effect = [True, True, True, True, True, True]
        mock_read_text.return_value = "1"
        mock_cdll.return_value = MagicMock()
        mock_disk.return_value = MagicMock(free=1024 * 1024 * 1024, total=5000, used=1000)
        mock_access.return_value = True

        # Mock sqlite connection
        mock_conn = MagicMock()
        mock_sqlite_connect.return_value = mock_conn
        mock_cursor = MagicMock()
        mock_conn.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = ("ok",)

        # Mock config file contents
        mock_file_open.return_value.read.return_value = "{}"

        # Run checks
        results = run_diagnostics()
        self.assertGreater(len(results), 0)

        # Verify no check failed
        for r in results:
            self.assertNotEqual(r.status, "FAIL", f"Check {r.name} failed: {r.detail}")

    @patch("orin.core.doctor.os.geteuid")
    @patch("orin.core.doctor.platform.system")
    @patch("orin.core.doctor.platform.release")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.ctypes.CDLL")
    @patch("orin.core.doctor.os.access")
    @patch("orin.core.doctor.sqlite3.connect")
    def test_diagnostics_unsupported_os(
        self, mock_sqlite_connect, mock_access, mock_cdll, mock_path_exists,
        mock_release, mock_system, mock_geteuid
    ):
        """Verify diagnostics fails when running on unsupported OS."""
        mock_geteuid.return_value = 1000
        mock_system.return_value = "Windows"
        mock_release.return_value = "10"
        mock_path_exists.side_effect = [False, False, False, False, False, False]
        mock_access.return_value = False

        results = run_diagnostics()
        os_results = [r for r in results if r.name == "Operating System"]
        self.assertEqual(len(os_results), 1)
        self.assertEqual(os_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid")
    @patch("orin.core.doctor.platform.system")
    @patch("orin.core.doctor.platform.release")
    @patch("orin.core.doctor.Path.exists")
    def test_diagnostics_outdated_kernel(
        self, mock_path_exists, mock_release, mock_system, mock_geteuid
    ):
        """Verify diagnostics fails on severely outdated kernels."""
        mock_geteuid.return_value = 0
        mock_system.return_value = "Linux"
        mock_release.return_value = "3.10.0-generic"
        mock_path_exists.side_effect = [False, False, False, False, False, False]

        results = run_diagnostics()
        kernel_results = [r for r in results if r.name == "Kernel Version"]
        self.assertEqual(len(kernel_results), 1)
        self.assertEqual(kernel_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid")
    @patch("orin.core.doctor.platform.system")
    @patch("orin.core.doctor.platform.release")
    @patch("orin.core.doctor.Path.exists")
    def test_diagnostics_warning_kernel(
        self, mock_path_exists, mock_release, mock_system, mock_geteuid
    ):
        """Verify diagnostics warns on kernels meeting minimum but not recommended version."""
        mock_geteuid.return_value = 0
        mock_system.return_value = "Linux"
        mock_release.return_value = "4.15.0-generic"
        mock_path_exists.side_effect = [False, False, False, False, False, False]

        results = run_diagnostics()
        kernel_results = [r for r in results if r.name == "Kernel Version"]
        self.assertEqual(len(kernel_results), 1)
        self.assertEqual(kernel_results[0].status, "WARNING")

    @patch("orin.core.doctor.os.geteuid")
    @patch("orin.core.doctor.platform.system")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.ctypes.CDLL")
    def test_diagnostics_missing_libbpf(
        self, mock_cdll, mock_path_exists, mock_system, mock_geteuid
    ):
        """Verify diagnostics warns when libbpf is missing."""
        mock_geteuid.return_value = 0
        mock_system.return_value = "Linux"
        mock_path_exists.side_effect = [False, False, False, False, False, False]
        mock_cdll.side_effect = OSError("not found")

        results = run_diagnostics()
        libbpf_results = [r for r in results if r.name == "Dependency: libbpf"]
        self.assertEqual(len(libbpf_results), 1)
        self.assertEqual(libbpf_results[0].status, "WARNING")

    @patch("orin.core.doctor.os.geteuid")
    @patch("orin.core.doctor.platform.system")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.os.access")
    @patch("orin.core.doctor.sqlite3.connect")
    def test_diagnostics_database_integrity_failure(
        self, mock_sqlite_connect, mock_access, mock_path_exists, mock_system, mock_geteuid
    ):
        """Verify diagnostics fails when database integrity verification fails."""
        mock_geteuid.return_value = 0
        mock_system.return_value = "Linux"
        
        # Path exists matches vault db exists
        mock_path_exists.side_effect = [True, True, True, True, True, True]
        mock_access.return_value = True

        # Mock corrupt database
        mock_conn = MagicMock()
        mock_sqlite_connect.return_value = mock_conn
        mock_cursor = MagicMock()
        mock_conn.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = ("corrupted",)

        results = run_diagnostics()
        db_results = [r for r in results if r.name == "Vault Database Integrity"]
        self.assertEqual(len(db_results), 1)
        self.assertEqual(db_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.ctypes.CDLL")
    @patch("orin.core.doctor.os.access", return_value=True)
    def test_diagnostics_missing_optional_packages(self, mock_access, mock_cdll, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics reports warnings when optional dependencies are missing."""
        mock_exists.side_effect = [True, True, True, True, True, True]
        
        # Hide optional modules yara and scapy to trigger ImportError path
        with patch.dict("sys.modules", {"yara": None, "scapy": None}):
            results = run_diagnostics()
            
            # yara warning
            yara_results = [r for r in results if "yara" in r.name]
            self.assertEqual(len(yara_results), 1)
            self.assertEqual(yara_results[0].status, "WARNING")
            
            # scapy warning
            scapy_results = [r for r in results if "scapy" in r.name]
            self.assertEqual(len(scapy_results), 1)
            self.assertEqual(scapy_results[0].status, "WARNING")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.shutil.disk_usage")
    @patch("orin.core.doctor.os.access", return_value=True)
    @patch("psutil.virtual_memory")
    def test_diagnostics_low_memory_and_disk(self, mock_vm, mock_access, mock_disk, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics warns when system RAM or disk space is low."""
        mock_exists.side_effect = [True, True, True, True, True, True]
        
        # 128 MB RAM (less than 256MB)
        mock_vm.return_value = MagicMock(total=128 * 1024 * 1024)
        # 50 MB Disk free (less than 100MB)
        mock_disk.return_value = MagicMock(free=50 * 1024 * 1024)
        
        results = run_diagnostics()
        
        ram_results = [r for r in results if r.name == "System RAM"]
        self.assertEqual(len(ram_results), 1)
        self.assertEqual(ram_results[0].status, "WARNING")
        
        disk_results = [r for r in results if r.name == "System Disk Space"]
        self.assertEqual(len(disk_results), 1)
        self.assertEqual(disk_results[0].status, "WARNING")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.os.access")
    def test_diagnostics_vault_directory_not_writable(self, mock_access, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics fails if the vault database path directory is not writable when DB doesn't exist."""
        # DB doesn't exist
        mock_exists.side_effect = [False, False, False, False, False, False]
        # Directory not writable
        mock_access.return_value = False
        
        results = run_diagnostics()
        db_results = [r for r in results if r.name == "Vault Database"]
        self.assertEqual(len(db_results), 1)
        self.assertEqual(db_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.os.access", return_value=True)
    @patch("orin.core.doctor.sqlite3.connect")
    def test_diagnostics_vault_connection_error(self, mock_connect, mock_access, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics fails if connection to vault database throws operational exception."""
        mock_exists.side_effect = [True, True, True, True, True, True]
        mock_connect.side_effect = sqlite3.OperationalError("Unable to open database file")
        
        results = run_diagnostics()
        db_results = [r for r in results if r.name == "Vault Database Integrity"]
        self.assertEqual(len(db_results), 1)
        self.assertEqual(db_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.os.access", return_value=True)
    @patch("orin.core.doctor.open", new_callable=mock_open)
    def test_diagnostics_config_corrupt_json(self, mock_file_open, mock_access, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics fails if the configuration JSON is malformed."""
        mock_exists.side_effect = [True, True, True, True, True, True]
        mock_file_open.return_value.read.return_value = "{ corrupt json"
        
        results = run_diagnostics()
        config_results = [r for r in results if r.name == "Configuration Syntax"]
        self.assertEqual(len(config_results), 1)
        self.assertEqual(config_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.os.access")
    def test_diagnostics_config_not_readable(self, mock_access, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics fails if the configuration file exists but cannot be read."""
        # File exists
        mock_exists.side_effect = [True, True, True, True, True, True]
        # File not readable
        mock_access.return_value = False
        
        results = run_diagnostics()
        config_results = [r for r in results if r.name == "Configuration File Permissions"]
        self.assertEqual(len(config_results), 1)
        self.assertEqual(config_results[0].status, "FAIL")

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.Path.read_text")
    def test_diagnostics_jit_read_exception(self, mock_read_text, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics handles exceptions when reading the BPF JIT status file."""
        mock_exists.side_effect = [False, True, True, True, True, True]
        mock_read_text.side_effect = OSError("Permission denied")
        
        results = run_diagnostics()
        jit_results = [r for r in results if r.name == "BPF JIT Compiler"]
        self.assertEqual(len(jit_results), 1)
        self.assertEqual(jit_results[0].status, "WARNING")
        self.assertIn("Permission denied", jit_results[0].detail)

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="5.15.0-generic")
    @patch("orin.core.doctor.Path.exists")
    @patch("orin.core.doctor.Path.read_text")
    def test_diagnostics_jit_value_disabled(self, mock_read_text, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics warns if the BPF JIT status value is 0."""
        mock_exists.side_effect = [False, True, True, True, True, True]
        mock_read_text.return_value = "0"
        
        results = run_diagnostics()
        jit_results = [r for r in results if r.name == "BPF JIT Compiler"]
        self.assertEqual(len(jit_results), 1)
        self.assertEqual(jit_results[0].status, "WARNING")
        self.assertIn("disabled", jit_results[0].detail)

    @patch("orin.core.doctor.os.geteuid", return_value=0)
    @patch("orin.core.doctor.platform.system", return_value="Linux")
    @patch("orin.core.doctor.platform.release", return_value="malformed-version")
    @patch("orin.core.doctor.Path.exists", return_value=False)
    def test_diagnostics_malformed_kernel_format(self, mock_exists, mock_release, mock_system, mock_geteuid):
        """Verify diagnostics handles malformed kernel version parsing gracefully."""
        mock_exists.side_effect = [False, False, False, False, False, False]
        results = run_diagnostics()
        kernel_results = [r for r in results if r.name == "Kernel Version"]
        self.assertEqual(len(kernel_results), 1)
        self.assertEqual(kernel_results[0].status, "PASS")
        self.assertIn("malformed-version", kernel_results[0].detail)


class TestDoctorCLI(unittest.TestCase):
    """Test CLI subcommand dispatch wrapper."""

    @patch("orin.core.doctor.run_diagnostics")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_cmd_doctor_exits_0_on_success(self, mock_print, mock_exit, mock_run):
        """Verify cmd_doctor exits with status code 0 when all checks pass."""
        mock_run.return_value = [
            CheckResult("Test Check", "PASS", "all good")
        ]
        
        args = MagicMock(database=None, strict=False)
        cmd_doctor(args)

        mock_exit.assert_called_once_with(0)

    @patch("orin.core.doctor.run_diagnostics")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_cmd_doctor_exits_1_on_failure(self, mock_print, mock_exit, mock_run):
        """Verify cmd_doctor exits with status code 1 when any check fails."""
        mock_run.return_value = [
            CheckResult("Test Check", "FAIL", "broken", "fix it")
        ]
        
        args = MagicMock(database=None, strict=False)
        cmd_doctor(args)

        mock_exit.assert_called_once_with(1)

    @patch("orin.core.doctor.run_diagnostics")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_cmd_doctor_strict_exits_1_on_warning(self, mock_print, mock_exit, mock_run):
        """Verify cmd_doctor strict mode exits with 1 when warning is raised."""
        mock_run.return_value = [
            CheckResult("Test Check", "WARNING", "minor issue", "fix it")
        ]
        
        # Test strict=True
        args_strict = MagicMock(database=None, strict=True)
        cmd_doctor(args_strict)
        mock_exit.assert_called_with(1)

        # Test strict=False (should pass with warnings)
        mock_exit.reset_mock()
        args_normal = MagicMock(database=None, strict=False)
        cmd_doctor(args_normal)
        mock_exit.assert_called_with(0)


if __name__ == "__main__":
    unittest.main()
