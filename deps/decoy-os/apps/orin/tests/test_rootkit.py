# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.analysis.rootkit
"""
import os
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

from orin.analysis.rootkit import (
    RootkitIndicator,
    CrossViewProcessAnalyzer,
    CrossViewNetworkAnalyzer,
    eBPFProbeAnalyzer,
    KernelSymbolIntegrityChecker,
    run_rootkit_detection,
)


class TestRootkitIndicator(unittest.TestCase):
    def test_creation(self):
        ind = RootkitIndicator(
            indicator_type="test_type",
            severity="HIGH",
            description="Test description",
            evidence={"key": "val"},
            mitigation="fix it",
            confidence=0.8,
        )
        self.assertEqual(ind.indicator_type, "test_type")
        self.assertEqual(ind.severity, "HIGH")
        self.assertAlmostEqual(ind.confidence, 0.8)

    def test_default_values(self):
        ind = RootkitIndicator(
            indicator_type="t",
            severity="LOW",
            description="d",
        )
        self.assertEqual(ind.evidence, {})
        self.assertEqual(ind.mitigation, "")
        self.assertAlmostEqual(ind.confidence, 0.0)


class TestCrossViewProcessAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CrossViewProcessAnalyzer()

    def test_get_proc_pids_no_proc(self):
        with patch.object(Path, "exists", return_value=False):
            pids = self.analyzer.get_proc_pids()
        self.assertEqual(pids, set())

    def test_get_proc_pids_with_entries(self):
        mock_entries = [
            MagicMock(is_dir=lambda: True, name="1234"),
            MagicMock(is_dir=lambda: True, name="5678"),
            MagicMock(is_dir=lambda: True, name="notapid"),
            MagicMock(is_dir=lambda: False, name="9999"),
        ]
        # Make name an actual attribute, not a method
        for e in mock_entries:
            e.name = e.name

        def make_dir_mock(name, is_dir_val):
            m = MagicMock()
            m.name = name
            m.is_dir.return_value = is_dir_val
            return m

        entries = [
            make_dir_mock("1234", True),
            make_dir_mock("5678", True),
            make_dir_mock("notapid", True),
            make_dir_mock("file.txt", False),
        ]

        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "iterdir", return_value=iter(entries)):
            pids = self.analyzer.get_proc_pids()

        self.assertIn(1234, pids)
        self.assertIn(5678, pids)
        self.assertNotIn(0, pids)

    def test_get_proc_pids_permission_error(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "iterdir", side_effect=PermissionError):
            pids = self.analyzer.get_proc_pids()
        self.assertEqual(pids, set())

    def test_get_max_pid_default(self):
        with patch.object(Path, "exists", return_value=False):
            max_pid = self.analyzer._get_max_pid()
        self.assertEqual(max_pid, 32768)

    def test_get_max_pid_from_proc(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value="131072\n"):
            max_pid = self.analyzer._get_max_pid()
        self.assertEqual(max_pid, 131072)

    def test_get_max_pid_bad_value(self):
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value="not_a_number"):
            max_pid = self.analyzer._get_max_pid()
        self.assertEqual(max_pid, 32768)

    def test_get_netlink_pids_no_proc_net(self):
        with patch.object(Path, "exists", return_value=False):
            pids = self.analyzer.get_netlink_pids()
        self.assertEqual(pids, set())

    def test_get_netlink_pids_parse_error(self):
        """Should return empty set if /proc/net/netlink can't be read."""
        with patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", side_effect=OSError("no permission")):
            pids = self.analyzer.get_netlink_pids()
        self.assertEqual(pids, set())

    def test_find_pid_by_socket_inode_no_proc(self):
        with patch.object(Path, "exists", return_value=False):
            pids = self.analyzer._find_pid_by_socket_inode("12345")
        self.assertEqual(pids, set())

    def test_analyze_no_hidden_processes(self):
        """When scheduler and proc views match, no indicators returned."""
        proc_pids = {1, 2, 100, 200}
        with patch.object(CrossViewProcessAnalyzer, "get_proc_pids", return_value=proc_pids), \
             patch.object(CrossViewProcessAnalyzer, "get_scheduler_pids", return_value=proc_pids), \
             patch.object(CrossViewProcessAnalyzer, "get_netlink_pids", return_value=set()):
            indicators = self.analyzer.analyze()
        self.assertEqual(indicators, [])

    def test_analyze_detects_hidden_process(self):
        """Process visible in scheduler but not in /proc => CRITICAL indicator."""
        proc_pids = {1, 2}
        scheduler_pids = {1, 2, 999}  # PID 999 is hidden from /proc

        def fake_kill(pid, sig):
            if pid == 999:
                return  # Still alive
            raise ProcessLookupError

        proc_999_exists = MagicMock(return_value=False)

        with patch.object(CrossViewProcessAnalyzer, "get_proc_pids", return_value=proc_pids), \
             patch.object(CrossViewProcessAnalyzer, "get_scheduler_pids", return_value=scheduler_pids), \
             patch.object(CrossViewProcessAnalyzer, "get_netlink_pids", return_value=set()), \
             patch("os.kill", side_effect=fake_kill), \
             patch.object(Path, "exists", return_value=False):
            indicators = self.analyzer.analyze()

        # Should find PID 999 as hidden
        self.assertTrue(any(i.indicator_type == "hidden_process_scheduler" for i in indicators))

    def test_analyze_netlink_hidden_process(self):
        """Process in netlink but not in /proc => HIGH indicator."""
        proc_pids = {1, 2}
        scheduler_pids = {1, 2}
        netlink_pids = {1, 2, 777}

        with patch.object(CrossViewProcessAnalyzer, "get_proc_pids", return_value=proc_pids), \
             patch.object(CrossViewProcessAnalyzer, "get_scheduler_pids", return_value=scheduler_pids), \
             patch.object(CrossViewProcessAnalyzer, "get_netlink_pids", return_value=netlink_pids):
            indicators = self.analyzer.analyze()

        self.assertTrue(any(i.indicator_type == "hidden_process_netlink" for i in indicators))


class TestCrossViewNetworkAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CrossViewNetworkAnalyzer()

    def test_parse_proc_net_missing_path(self):
        """Should return empty list if proto path doesn't exist."""
        result = self.analyzer.parse_proc_net("nonexistent_proto")
        self.assertEqual(result, [])

    def test_parse_proc_net_tcp(self):
        tcp_data = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n"
        )
        with patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data=tcp_data)):
            result = self.analyzer.parse_proc_net("tcp")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["protocol"], "tcp")
        self.assertEqual(result[0]["inode"], "12345")

    def test_parse_proc_net_oserror(self):
        with patch.object(Path, "exists", return_value=True), \
             patch("builtins.open", side_effect=OSError):
            result = self.analyzer.parse_proc_net("tcp")
        self.assertEqual(result, [])

    def test_get_socket_inodes_no_proc(self):
        with patch.object(Path, "exists", return_value=False):
            inodes = self.analyzer.get_socket_inodes_from_procs()
        self.assertEqual(inodes, set())

    def test_analyze_no_hidden_sockets(self):
        """Small discrepancy below threshold => no indicators."""
        with patch.object(CrossViewNetworkAnalyzer, "parse_proc_net", return_value=[
                {"inode": "11111"}, {"inode": "22222"}
             ]), \
             patch.object(CrossViewNetworkAnalyzer, "get_socket_inodes_from_procs",
                          return_value={"11111", "22222", "33333"}):  # Only 1 hidden
            indicators = self.analyzer.analyze()
        # 1 hidden socket is below threshold of 5
        self.assertEqual(indicators, [])

    def test_analyze_detects_hidden_sockets(self):
        """More than 5 hidden socket inodes => HIGH indicator."""
        proc_net_inodes = [{"inode": str(i)} for i in range(10)]
        fd_inodes = {str(i) for i in range(20)}  # 10 extra hidden sockets

        with patch.object(CrossViewNetworkAnalyzer, "parse_proc_net", return_value=proc_net_inodes), \
             patch.object(CrossViewNetworkAnalyzer, "get_socket_inodes_from_procs", return_value=fd_inodes):
            indicators = self.analyzer.analyze()

        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].indicator_type, "hidden_network_sockets")
        self.assertEqual(indicators[0].severity, "HIGH")


class TestEBPFProbeAnalyzer(unittest.TestCase):
    def test_no_programs(self):
        analyzer = eBPFProbeAnalyzer([], [])
        indicators = analyzer.analyze()
        self.assertEqual(indicators, [])

    def test_detects_malicious_program_name(self):
        programs = [{"name": "triplecross_hook", "tag": "abc", "type": "kprobe", "bpf_id": 1}]
        analyzer = eBPFProbeAnalyzer(programs, [])
        indicators = analyzer.analyze()
        self.assertTrue(any(i.indicator_type == "malicious_ebpf_program" for i in indicators))
        malicious = [i for i in indicators if i.indicator_type == "malicious_ebpf_program"]
        self.assertEqual(malicious[0].severity, "CRITICAL")

    def test_detects_ebpfkit(self):
        programs = [{"name": "ebpfkit_helper", "tag": "", "type": "tracepoint", "bpf_id": 2}]
        analyzer = eBPFProbeAnalyzer(programs, [])
        indicators = analyzer.analyze()
        types = [i.indicator_type for i in indicators]
        self.assertIn("malicious_ebpf_program", types)

    def test_detects_suspicious_kprobe(self):
        # kprobe type + suspicious hook point name
        programs = [{"name": "sys_enter_getdents64", "tag": "", "type": "kprobe", "bpf_id": 3}]
        analyzer = eBPFProbeAnalyzer(programs, [])
        indicators = analyzer.analyze()
        types = [i.indicator_type for i in indicators]
        self.assertIn("suspicious_ebpf_hook", types)

    def test_benign_program_no_alert(self):
        programs = [{"name": "tcp_monitor", "tag": "", "type": "socket_filter", "bpf_id": 10}]
        analyzer = eBPFProbeAnalyzer(programs, [])
        indicators = analyzer.analyze()
        self.assertEqual(indicators, [])

    def test_detects_malicious_pinned_object(self):
        pinned = [{"path": "/sys/fs/bpf/hide_pid_map"}]
        analyzer = eBPFProbeAnalyzer([], pinned)
        indicators = analyzer.analyze()
        types = [i.indicator_type for i in indicators]
        self.assertIn("malicious_ebpf_pinned", types)
        self.assertEqual(indicators[0].severity, "CRITICAL")

    def test_benign_pinned_object(self):
        pinned = [{"path": "/sys/fs/bpf/xdp_monitor"}]
        analyzer = eBPFProbeAnalyzer([], pinned)
        indicators = analyzer.analyze()
        self.assertEqual(indicators, [])


class TestKernelSymbolIntegrityChecker(unittest.TestCase):
    def test_no_baseline_no_indicators(self):
        symbols = [{"symbol_name": "sys_call_table", "address": "0xffffffff81800000"}]
        checker = KernelSymbolIntegrityChecker(symbols, baseline_symbols=None)
        indicators = checker.check_symbol_addresses()
        self.assertEqual(indicators, [])

    def test_detects_changed_critical_symbol(self):
        symbols = [
            {"symbol_name": "sys_call_table", "address": "0xdeadbeef"},
            {"symbol_name": "commit_creds", "address": "0xffffffff81234567"},
        ]
        baseline = {
            "sys_call_table": {"address": "0xffffffff81800000"},
            "commit_creds": {"address": "0xffffffff81234567"},
        }
        checker = KernelSymbolIntegrityChecker(symbols, baseline_symbols=baseline)
        indicators = checker.check_symbol_addresses()
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].indicator_type, "critical_symbol_address_change")
        self.assertEqual(indicators[0].severity, "CRITICAL")

    def test_no_change_no_indicators(self):
        addr = "0xffffffff81800000"
        symbols = [{"symbol_name": "sys_call_table", "address": addr}]
        baseline = {"sys_call_table": {"address": addr}}
        checker = KernelSymbolIntegrityChecker(symbols, baseline_symbols=baseline)
        indicators = checker.check_symbol_addresses()
        self.assertEqual(indicators, [])

    def test_detects_anomalous_hook_symbol(self):
        # Pattern: "h_" prefix which matches h_[a-z_]+
        symbols = [
            {"symbol_name": "h_sys_read", "address": "0xdeadbeef",
             "module_name": "suspicious_mod", "suspicious": False}
        ]
        checker = KernelSymbolIntegrityChecker(symbols)
        indicators = checker.check_anomalous_symbols()
        types = [i.indicator_type for i in indicators]
        self.assertIn("anomalous_kernel_symbol", types)

    def test_anomalous_pattern_kernel_module_ignored(self):
        """Symbols from 'kernel' module should not trigger anomalous alert."""
        symbols = [
            {"symbol_name": "h_sys_read", "address": "0x123",
             "module_name": "kernel", "suspicious": False}
        ]
        checker = KernelSymbolIntegrityChecker(symbols)
        indicators = checker.check_anomalous_symbols()
        self.assertEqual(indicators, [])

    def test_suspicious_symbols_skipped(self):
        """Symbols flagged as suspicious=True should not appear in checker's symbol set."""
        symbols = [
            {"symbol_name": "h_sys_open", "address": "0xdeadbeef",
             "module_name": "bad_mod", "suspicious": True}
        ]
        checker = KernelSymbolIntegrityChecker(symbols)
        # The symbol is filtered out by __init__ because suspicious=True
        self.assertNotIn("h_sys_open", checker.current_symbols)


class TestRunRootkitDetection(unittest.TestCase):
    def test_clean_system_returns_none_risk(self):
        """When no rootkits found, overall_risk should be NONE."""
        with patch.object(CrossViewProcessAnalyzer, "analyze", return_value=[]), \
             patch.object(CrossViewNetworkAnalyzer, "analyze", return_value=[]), \
             patch.object(eBPFProbeAnalyzer, "analyze", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_symbol_addresses", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_anomalous_symbols", return_value=[]):
            result = run_rootkit_detection([], [], [], [])
        self.assertEqual(result["overall_risk_level"], "NONE")
        self.assertEqual(result["total_indicators"], 0)
        self.assertIn("layers_executed", result)

    def test_critical_indicator_sets_critical_risk(self):
        critical_ind = RootkitIndicator("test", "CRITICAL", "desc")
        with patch.object(CrossViewProcessAnalyzer, "analyze", return_value=[critical_ind]), \
             patch.object(CrossViewNetworkAnalyzer, "analyze", return_value=[]), \
             patch.object(eBPFProbeAnalyzer, "analyze", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_symbol_addresses", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_anomalous_symbols", return_value=[]):
            result = run_rootkit_detection([], [], [], [])
        self.assertEqual(result["overall_risk_level"], "CRITICAL")
        self.assertEqual(result["total_indicators"], 1)

    def test_high_indicator_no_critical(self):
        high_ind = RootkitIndicator("test", "HIGH", "desc")
        with patch.object(CrossViewProcessAnalyzer, "analyze", return_value=[]), \
             patch.object(CrossViewNetworkAnalyzer, "analyze", return_value=[high_ind]), \
             patch.object(eBPFProbeAnalyzer, "analyze", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_symbol_addresses", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_anomalous_symbols", return_value=[]):
            result = run_rootkit_detection([], [], [], [])
        self.assertEqual(result["overall_risk_level"], "HIGH")

    def test_medium_indicator_no_higher(self):
        med_ind = RootkitIndicator("test", "MEDIUM", "desc")
        with patch.object(CrossViewProcessAnalyzer, "analyze", return_value=[]), \
             patch.object(CrossViewNetworkAnalyzer, "analyze", return_value=[med_ind]), \
             patch.object(eBPFProbeAnalyzer, "analyze", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_symbol_addresses", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_anomalous_symbols", return_value=[]):
            result = run_rootkit_detection([], [], [], [])
        self.assertEqual(result["overall_risk_level"], "MEDIUM")

    def test_result_structure(self):
        with patch.object(CrossViewProcessAnalyzer, "analyze", return_value=[]), \
             patch.object(CrossViewNetworkAnalyzer, "analyze", return_value=[]), \
             patch.object(eBPFProbeAnalyzer, "analyze", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_symbol_addresses", return_value=[]), \
             patch.object(KernelSymbolIntegrityChecker, "check_anomalous_symbols", return_value=[]):
            result = run_rootkit_detection([], [], [], [])
        expected_keys = {
            "detection_timestamp", "overall_risk_level", "total_indicators",
            "severity_breakdown", "indicators", "layers_executed"
        }
        self.assertEqual(set(result.keys()), expected_keys)
        self.assertIn("cross_view_process", result["layers_executed"])
        self.assertIn("ebpf_probe_analysis", result["layers_executed"])


if __name__ == "__main__":
    unittest.main()
