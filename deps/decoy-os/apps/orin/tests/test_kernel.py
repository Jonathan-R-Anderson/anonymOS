import unittest
from unittest.mock import patch, mock_open
import errno
from pathlib import Path
from orin.collectors.kernel import (
    gather_loaded_kernel_modules,
    gather_kernel_symbols,
    analyze_kernel_symbol_overrides,
    check_for_unlinked_modules
)

class TestKernel(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_loaded_kernel_modules_success(self, mock_file_open, mock_exists):
        mock_exists.return_value = True

        modules_content = (
            "ext4 400000 2 - Live 0xffffffff\n"
            "\n"
            "nfsd 150000 0 - Live 0xffffffff\n"
        )
        mock_file_open.return_value = mock_open(read_data=modules_content).return_value

        res = gather_loaded_kernel_modules()
        self.assertEqual(len(res), 2)

        ext4_res = res[0]
        self.assertEqual(ext4_res["module_name"], "ext4")
        self.assertEqual(ext4_res["memory_size"], 400000)
        self.assertEqual(ext4_res["instances_loaded"], 2)

        nfsd_res = res[1]
        self.assertEqual(nfsd_res["module_name"], "nfsd")
        self.assertEqual(nfsd_res["memory_size"], 150000)
        self.assertEqual(nfsd_res["instances_loaded"], 0)

    @patch("pathlib.Path.exists")
    def test_gather_loaded_kernel_modules_no_file(self, mock_exists):
        mock_exists.return_value = False
        res = gather_loaded_kernel_modules()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_loaded_kernel_modules_malformed_and_errors(self, mock_file_open, mock_exists):
        mock_exists.return_value = True

        # Line 1: Malformed (less than 3 fields)
        # Line 2: Invalid memory_size cast (ValueError)
        modules_content = (
            "short_module 100\n"
            "bad_cast invalid_size 2 - Live\n"
        )
        mock_file_open.return_value = mock_open(read_data=modules_content).return_value

        res = gather_loaded_kernel_modules()
        self.assertEqual(len(res), 2)

        self.assertEqual(res[0]["module_name"], "ERROR_LINE_1")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Malformed kernel module line layout", res[0]["anomaly_reason"])

        self.assertEqual(res[1]["module_name"], "ERROR_INVALID_CAST_bad_cast")
        self.assertEqual(res[1]["anomaly_detected"], 1)
        self.assertIn("Type validation fault on row 2", res[1]["anomaly_reason"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    def test_gather_loaded_kernel_modules_permission_denied(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        mock_file_open.side_effect = PermissionError("Permission denied")

        res = gather_loaded_kernel_modules()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["module_name"], "ERROR_PROC_MODULES_IO_FAULT")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Failed to access virtual filesystem descriptor node", res[0]["anomaly_reason"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_kernel_symbols_success(self, mock_file_open, mock_exists):
        """Test successful parsing of /proc/kallsyms"""
        mock_exists.return_value = True

        symbols_content = (
            "ffffffff81000000 T startup_64\n"
            "ffffffff81001000 T _stext\n"
            "short\n"
            "ffffffff81002000 t some_internal_func [ext4]\n"
            "ffffffff81003000 D __start___param\n"
        )
        mock_file_open.return_value = mock_open(read_data=symbols_content).return_value

        res = gather_kernel_symbols()
        self.assertEqual(len(res), 4)

        # Test first symbol (no module)
        self.assertEqual(res[0]["address"], "ffffffff81000000")
        self.assertEqual(res[0]["symbol_type"], "T")
        self.assertEqual(res[0]["symbol_name"], "startup_64")
        self.assertIsNone(res[0]["module_name"])
        self.assertFalse(res[0]["is_critical"])
        self.assertFalse(res[0]["suspicious"])

        # Test third symbol (with module) - now index 2 since short line is skipped
        self.assertEqual(res[2]["symbol_name"], "some_internal_func")
        self.assertEqual(res[2]["module_name"], "ext4")

    @patch("pathlib.Path.exists")
    def test_gather_kernel_symbols_no_file(self, mock_exists):
        """Test when /proc/kallsyms doesn't exist"""
        mock_exists.return_value = False
        res = gather_kernel_symbols()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    def test_gather_kernel_symbols_permission_denied(self, mock_file_open, mock_exists):
        """Test permission denied when reading kallsyms"""
        mock_exists.return_value = True
        mock_file_open.side_effect = PermissionError("Permission denied")

        res = gather_kernel_symbols()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["symbol_name"], "ERROR_KALLSYMS_ACCESS_FAULT")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Failed to access kernel symbols", res[0]["anomaly_reason"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_kernel_symbols_detects_critical_symbols(self, mock_file_open, mock_exists):
        """Test detection of critical kernel symbols"""
        mock_exists.return_value = True

        symbols_content = (
            "ffffffff81000000 T sys_open\n"
            "ffffffff81001000 T commit_creds\n"
            "ffffffff81002000 T prepare_kernel_cred\n"
            "ffffffff81003000 T normal_function\n"
        )
        mock_file_open.return_value = mock_open(read_data=symbols_content).return_value

        res = gather_kernel_symbols()

        # sys_open should be critical
        sys_open = next(s for s in res if s["symbol_name"] == "sys_open")
        self.assertTrue(sys_open["is_critical"])

        # commit_creds should be critical
        commit_creds = next(s for s in res if s["symbol_name"] == "commit_creds")
        self.assertTrue(commit_creds["is_critical"])

        # normal_function should not be critical
        normal = next(s for s in res if s["symbol_name"] == "normal_function")
        self.assertFalse(normal["is_critical"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_kernel_symbols_detects_suspicious_rootkit_patterns(self, mock_file_open, mock_exists):
        """Test detection of suspicious rootkit patterns"""
        mock_exists.return_value = True

        symbols_content = (
            "ffffffff81000000 T diamorphine_init\n"
            "ffffffff81001000 T reptile_hook\n"
            "ffffffff81002000 T normal_func\n"
        )
        mock_file_open.return_value = mock_open(read_data=symbols_content).return_value

        res = gather_kernel_symbols()

        diamorphine = next(s for s in res if s["symbol_name"] == "diamorphine_init")
        self.assertTrue(diamorphine["suspicious"])
        self.assertIn("rootkit pattern", diamorphine["anomaly_reason"].lower())

        reptile = next(s for s in res if s["symbol_name"] == "reptile_hook")
        self.assertTrue(reptile["suspicious"])

        normal = next(s for s in res if s["symbol_name"] == "normal_func")
        self.assertFalse(normal["suspicious"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_kernel_symbols_detects_syscall_in_third_party_module(self, mock_file_open, mock_exists):
        """Test detection of system call handlers in third-party modules"""
        mock_exists.return_value = True

        symbols_content = (
            "ffffffff81000000 T sys_custom [malicious_module]\n"
            "ffffffff81001000 T sys_open\n"
        )
        mock_file_open.return_value = mock_open(read_data=symbols_content).return_value

        res = gather_kernel_symbols()

        sys_custom = next(s for s in res if s["symbol_name"] == "sys_custom")
        self.assertTrue(sys_custom["suspicious"])
        self.assertEqual(sys_custom["module_name"], "malicious_module")
        self.assertIn("third-party module", sys_custom["anomaly_reason"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_kernel_symbols_detects_cred_manipulation_in_module(self, mock_file_open, mock_exists):
        """Test detection of credential manipulation symbols in modules"""
        mock_exists.return_value = True

        symbols_content = (
            "ffffffff81000000 T commit_creds [suspicious_module]\n"
            "ffffffff81001000 T prepare_kernel_cred [another_module]\n"
        )
        mock_file_open.return_value = mock_open(read_data=symbols_content).return_value

        res = gather_kernel_symbols()

        for sym_name in ["commit_creds", "prepare_kernel_cred"]:
            sym = next(s for s in res if s["symbol_name"] == sym_name)
            self.assertTrue(sym["suspicious"])
            self.assertIn("Credential manipulation", sym["anomaly_reason"])

    def test_analyze_kernel_symbol_overrides_empty(self):
        """Test analysis with empty symbol list"""
        result = analyze_kernel_symbol_overrides([])

        self.assertEqual(result["total_symbols"], 0)
        self.assertEqual(result["critical_symbols"], 0)
        self.assertEqual(result["suspicious_symbols"], 0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["potential_rootkit_indicators"], [])

    def test_analyze_kernel_symbol_overrides_low_risk(self):
        """Test analysis with no suspicious symbols"""
        symbols = [
            {"symbol_name": "normal_func", "is_critical": False, "suspicious": False, "address": "0x1"},
            {"symbol_name": "another_func", "is_critical": True, "suspicious": False, "address": "0x2"},
        ]
        result = analyze_kernel_symbol_overrides(symbols)

        self.assertEqual(result["total_symbols"], 2)
        self.assertEqual(result["critical_symbols"], 1)
        self.assertEqual(result["suspicious_symbols"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_analyze_kernel_symbol_overrides_medium_risk(self):
        """Test analysis with 1-2 suspicious symbols"""
        symbols = [
            {"symbol_name": "normal_func", "is_critical": False, "suspicious": False, "address": "0x1"},
            {"symbol_name": "suspect1", "is_critical": False, "suspicious": True, "address": "0x2", "anomaly_reason": "test"},
            {"symbol_name": "suspect2", "is_critical": False, "suspicious": True, "address": "0x3", "anomaly_reason": "test"},
        ]
        result = analyze_kernel_symbol_overrides(symbols)

        self.assertEqual(result["suspicious_symbols"], 2)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(len(result["potential_rootkit_indicators"]), 2)

    def test_analyze_kernel_symbol_overrides_high_risk(self):
        """Test analysis with 3-5 suspicious symbols"""
        symbols = [
            {"symbol_name": f"suspect{i}", "is_critical": False, "suspicious": True, "address": f"0x{i}", "anomaly_reason": "test"}
            for i in range(4)
        ]
        result = analyze_kernel_symbol_overrides(symbols)

        self.assertEqual(result["suspicious_symbols"], 4)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_analyze_kernel_symbol_overrides_critical_risk(self):
        """Test analysis with more than 5 suspicious symbols"""
        symbols = [
            {"symbol_name": f"suspect{i}", "is_critical": False, "suspicious": True, "address": f"0x{i}", "anomaly_reason": "test"}
            for i in range(7)
        ]
        result = analyze_kernel_symbol_overrides(symbols)

        self.assertEqual(result["suspicious_symbols"], 7)
        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_analyze_kernel_symbol_overrides_cred_manipulation_escalation(self):
        """Test risk escalation when credential manipulation is detected"""
        symbols = [
            {"symbol_name": "suspect1", "is_critical": False, "suspicious": True, "address": "0x1", "anomaly_reason": "credential manipulation detected"},
            {"symbol_name": "suspect2", "is_critical": False, "suspicious": True, "address": "0x2", "anomaly_reason": "other issue"},
        ]
        result = analyze_kernel_symbol_overrides(symbols)

        # Should escalate from MEDIUM to HIGH due to credential manipulation
        self.assertEqual(result["risk_level"], "HIGH")

    def test_analyze_kernel_symbol_overrides_syscall_severity(self):
        """Test that syscall hooks have HIGH severity in indicators"""
        symbols = [
            {"symbol_name": "sys_evil", "is_critical": False, "suspicious": True, "address": "0x1", "anomaly_reason": "test", "module_name": "evil"},
        ]
        result = analyze_kernel_symbol_overrides(symbols)

        self.assertEqual(len(result["potential_rootkit_indicators"]), 1)
        self.assertEqual(result["potential_rootkit_indicators"][0]["severity"], "HIGH")

    def test_check_for_unlinked_modules_empty(self):
        """Test unlinked module detection with empty inputs"""
        result = check_for_unlinked_modules([], [])
        self.assertEqual(result, [])

    def test_check_for_unlinked_modules_all_visible(self):
        """Test when all modules are visible in /proc/modules"""
        modules = [
            {"module_name": "ext4"},
            {"module_name": "nfsd"},
        ]
        symbols = [
            {"symbol_name": "func1", "module_name": "ext4", "suspicious": False},
            {"symbol_name": "func2", "module_name": "ext4", "suspicious": False},
            {"symbol_name": "func3", "module_name": "ext4", "suspicious": False},
        ]
        result = check_for_unlinked_modules(modules, symbols)
        self.assertEqual(result, [])

    def test_check_for_unlinked_modules_detects_hidden(self):
        """Test detection of hidden modules"""
        modules = [
            {"module_name": "ext4"},
        ]
        symbols = [
            {"symbol_name": "func1", "module_name": "ext4", "suspicious": False},
            {"symbol_name": "hidden1", "module_name": "rootkit_mod", "suspicious": False},
            {"symbol_name": "hidden2", "module_name": "rootkit_mod", "suspicious": False},
            {"symbol_name": "hidden3", "module_name": "rootkit_mod", "suspicious": False},
        ]
        result = check_for_unlinked_modules(modules, symbols)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["module_name"], "rootkit_mod")
        self.assertEqual(result[0]["symbol_count"], 3)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_check_for_unlinked_modules_ignores_few_symbols(self):
        """Test that modules with <=2 symbols are not flagged"""
        modules = [
            {"module_name": "ext4"},
        ]
        symbols = [
            {"symbol_name": "func1", "module_name": "ext4", "suspicious": False},
            {"symbol_name": "hidden1", "module_name": "tiny_mod", "suspicious": False},
            {"symbol_name": "hidden2", "module_name": "tiny_mod", "suspicious": False},
        ]
        result = check_for_unlinked_modules(modules, symbols)
        # tiny_mod has only 2 symbols, should not be flagged
        self.assertEqual(result, [])

    def test_check_for_unlinked_modules_ignores_kernel_vmlinux(self):
        """Test that kernel and vmlinux are not flagged as hidden"""
        modules = []
        symbols = [
            {"symbol_name": "func1", "module_name": "kernel", "suspicious": False},
            {"symbol_name": "func2", "module_name": "vmlinux", "suspicious": False},
            {"symbol_name": "func3", "module_name": "kernel", "suspicious": False},
        ]
        result = check_for_unlinked_modules(modules, symbols)
        self.assertEqual(result, [])

    def test_check_for_unlinked_modules_ignores_error_modules(self):
        """Test that error entries in modules list are ignored"""
        modules = [
            {"module_name": "ERROR_PROC_MODULES_IO_FAULT"},
        ]
        symbols = [
            {"symbol_name": "func1", "module_name": "real_mod", "suspicious": False},
            {"symbol_name": "func2", "module_name": "real_mod", "suspicious": False},
            {"symbol_name": "func3", "module_name": "real_mod", "suspicious": False},
        ]
        result = check_for_unlinked_modules(modules, symbols)
        # real_mod should be flagged since ERROR_* modules are ignored
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["module_name"], "real_mod")

if __name__ == "__main__":
    unittest.main()