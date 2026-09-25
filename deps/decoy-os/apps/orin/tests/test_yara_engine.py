# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.analysis.yara_engine
"""
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

from orin.analysis.yara_engine import YaraMatch, YaraScanResult, YaraEngine, YARA_AVAILABLE


class TestYaraMatch(unittest.TestCase):
    def test_to_dict(self):
        match = YaraMatch(
            rule_name="TestRule",
            namespace="test_ns",
            matched_strings=["string1"],
            tags=["malware"],
            meta={"author": "tester"},
            file_path="/tmp/test.exe",
            process_pid=1234,
            match_context="context_str",
        )
        d = match.to_dict()
        self.assertEqual(d["rule_name"], "TestRule")
        self.assertEqual(d["namespace"], "test_ns")
        self.assertEqual(d["file_path"], "/tmp/test.exe")
        self.assertEqual(d["process_pid"], 1234)

    def test_default_values(self):
        match = YaraMatch(rule_name="R", namespace="ns")
        self.assertEqual(match.matched_strings, [])
        self.assertEqual(match.tags, [])
        self.assertIsNone(match.file_path)
        self.assertIsNone(match.process_pid)
        self.assertIsNone(match.match_context)


class TestYaraScanResult(unittest.TestCase):
    def test_default_values(self):
        r = YaraScanResult()
        self.assertEqual(r.total_files_scanned, 0)
        self.assertEqual(r.total_matches, 0)
        self.assertEqual(r.matches, [])
        self.assertEqual(r.scan_errors, [])
        self.assertEqual(r.rules_loaded, 0)

    def test_to_dict(self):
        match = YaraMatch(rule_name="R", namespace="ns")
        r = YaraScanResult(
            total_files_scanned=5,
            total_matches=1,
            matches=[match],
            scan_errors=["error1"],
            rules_loaded=10,
        )
        d = r.to_dict()
        self.assertEqual(d["total_files_scanned"], 5)
        self.assertEqual(d["total_matches"], 1)
        self.assertEqual(len(d["matches"]), 1)
        self.assertEqual(d["scan_errors"], ["error1"])
        self.assertEqual(d["rules_loaded"], 10)


class TestYaraEngineInitialization(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_init_with_custom_dirs(self):
        dirs = [Path("/tmp/rules")]
        engine = YaraEngine(rules_dirs=dirs)
        self.assertEqual(engine.rules_dirs, dirs)
        self.assertIsNone(engine.compiled_rules)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_init_uses_default_dirs(self):
        engine = YaraEngine()
        self.assertIsNotNone(engine.rules_dirs)
        self.assertGreater(len(engine.rules_dirs), 0)

    def test_init_raises_without_yara(self):
        """When YARA is not available, should raise RuntimeError."""
        with patch("orin.analysis.yara_engine.YARA_AVAILABLE", False):
            with self.assertRaises(RuntimeError):
                YaraEngine()


class TestYaraEngineComputeRulesHash(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_hash_is_deterministic(self):
        engine = YaraEngine(rules_dirs=[])
        content = {"rule_a": "rule A {}", "rule_b": "rule B {}"}
        h1 = engine._compute_rules_hash(content)
        h2 = engine._compute_rules_hash(content)
        self.assertEqual(h1, h2)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_different_content_different_hash(self):
        engine = YaraEngine(rules_dirs=[])
        h1 = engine._compute_rules_hash({"a": "rule A {}"})
        h2 = engine._compute_rules_hash({"a": "rule B {}"})
        self.assertNotEqual(h1, h2)


class TestYaraEngineLoadRules(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_no_dirs(self):
        """No directories => 0 rules loaded."""
        engine = YaraEngine(rules_dirs=[Path("/nonexistent_empty_dir_xyz")])
        count = engine.load_rules()
        self.assertEqual(count, 0)
        self.assertIsNone(engine.compiled_rules)


    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_dir_not_exist(self):
        engine = YaraEngine(rules_dirs=[Path("/nonexistent")])
        count = engine.load_rules()
        self.assertEqual(count, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_caches_if_unchanged(self):
        """If rules hash is unchanged, should skip recompilation."""
        import yara
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        engine._rules_hash = "abc123"
        engine.loaded_rules_count = 5

        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "glob", return_value=[Path("/fake/rule.yar")]), \
             patch.object(Path, "read_text", return_value="rule test {}"), \
             patch.object(engine, "_compute_rules_hash", return_value="abc123"):
            count = engine.load_rules()
        self.assertEqual(count, 5)  # Returned cached count


class TestYaraEngineScanFile(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_no_rules_loaded(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = None
        result = engine.scan_file(Path("/some/file.exe"))
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_not_exists(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        with patch.object(Path, "exists", return_value=False):
            result = engine.scan_file(Path("/nonexistent.exe"))
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_returns_matches(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()

        # Mock a yara match object
        mock_match = MagicMock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "test"
        mock_match.strings = []
        mock_match.tags = ["malware"]
        mock_match.meta = {}

        mock_compiled.match.return_value = [mock_match]
        engine.compiled_rules = mock_compiled

        with patch.object(Path, "exists", return_value=True):
            results = engine.scan_file(Path("/some/malware.exe"))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].rule_name, "TestRule")
        self.assertEqual(results[0].tags, ["malware"])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_handles_timeout(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = yara.TimeoutError
        engine.compiled_rules = mock_compiled

        with patch.object(Path, "exists", return_value=True):
            result = engine.scan_file(Path("/slow_file.bin"))
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_file_handles_exception(self):
        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = Exception("unexpected error")
        engine.compiled_rules = mock_compiled

        with patch.object(Path, "exists", return_value=True):
            result = engine.scan_file(Path("/some/file.bin"))
        self.assertEqual(result, [])


class TestYaraEngineScanData(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_no_rules(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = None
        result = engine.scan_data(b"some data")
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_returns_matches(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()

        mock_match = MagicMock()
        mock_match.rule = "MemRule"
        mock_match.namespace = "mem"
        mock_match.strings = []
        mock_match.tags = []
        mock_match.meta = {}

        mock_compiled.match.return_value = [mock_match]
        engine.compiled_rules = mock_compiled

        results = engine.scan_data(b"\x4d\x5a\x90\x00", "pid_1234")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].rule_name, "MemRule")
        self.assertEqual(results[0].process_pid, 1234)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_timeout_handled(self):
        import yara

        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = yara.TimeoutError
        engine.compiled_rules = mock_compiled

        result = engine.scan_data(b"data", "memory_dump")
        self.assertEqual(result, [])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_data_exception_handled(self):
        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = RuntimeError("boom")
        engine.compiled_rules = mock_compiled

        result = engine.scan_data(b"data")
        self.assertEqual(result, [])


class TestYaraEngineExtractMatchContext(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_empty_strings(self):
        engine = YaraEngine(rules_dirs=[])
        result = engine._extract_match_context(b"some data", [])
        self.assertIsNone(result)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_returns_text(self):
        engine = YaraEngine(rules_dirs=[])
        data = b"Hello, MALWARE, World!"

        mock_instance = MagicMock()
        mock_instance.offset = 7
        mock_instance.matched_data = b"MALWARE"

        mock_string = MagicMock()
        mock_string.instances = [mock_instance]

        result = engine._extract_match_context(data, [mock_string], context_bytes=5)
        self.assertIsNotNone(result)
        self.assertIn("MALWARE", result)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_handles_exception(self):
        engine = YaraEngine(rules_dirs=[])
        # Pass a broken string object that will raise an exception
        result = engine._extract_match_context(b"data", [object()])
        self.assertIsNone(result)


class TestYaraEngineScanDirectory(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_no_rules_loaded(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = None
        result = engine.scan_directory(Path("/some/dir"))
        self.assertIn("No YARA rules loaded", result.scan_errors)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_not_exists(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        with patch.object(Path, "exists", return_value=False):
            result = engine.scan_directory(Path("/nonexistent"))
        self.assertEqual(len(result.scan_errors), 1)
        self.assertIn("does not exist", result.scan_errors[0])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_empty(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "rglob", return_value=iter([])):
            result = engine.scan_directory(Path("/empty_dir"))
        self.assertEqual(result.total_files_scanned, 0)
        self.assertEqual(result.total_matches, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_with_filters(self):
        engine = YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        engine.scan_file = MagicMock(return_value=[YaraMatch(rule_name="R", namespace="ns")])

        # Mocking 4 files
        file1 = MagicMock(spec=Path)
        file1.is_file.return_value = True
        file1.name = "malware.exe"
        file1.stat.return_value.st_size = 1000

        file2 = MagicMock(spec=Path)
        file2.is_file.return_value = True
        file2.name = "log.txt"
        file2.stat.return_value.st_size = 500

        file3 = MagicMock(spec=Path)
        file3.is_file.return_value = True
        file3.name = "huge.bin"
        file3.stat.return_value.st_size = 99999999  # Too large

        file4 = MagicMock(spec=Path)
        file4.is_file.return_value = True
        file4.name = "skipped.txt"
        file4.stat.return_value.st_size = 100

        file5 = MagicMock(spec=Path)
        file5.is_file.return_value = True
        file5.name = "image.png"
        file5.stat.return_value.st_size = 200

        files = [file1, file2, file3, file4, file5]

        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "glob", return_value=iter(files)):
            # Scan with recursive=False, max_file_size=1000000, file_patterns=["*.exe", "*.txt"], exclude_patterns=["*skipped*"]
            result = engine.scan_directory(
                Path("/some_dir"),
                recursive=False,
                file_patterns=["*.exe", "*.txt"],
                exclude_patterns=["*skipped*"],
                max_file_size=1000000
            )

        self.assertEqual(result.total_files_scanned, 2)  # file1 and file2 should match
        self.assertEqual(result.total_matches, 2)


class TestYaraEngineSeverityAndAttck(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_get_severity_for_match(self):
        engine = YaraEngine(rules_dirs=[])

        # Metadata severity
        m1 = YaraMatch("R", "ns", meta={"severity": "CRITICAL"})
        self.assertEqual(engine.get_severity_for_match(m1), "critical")

        # Tags severity map
        m2 = YaraMatch("R", "ns", tags=["trojan"])
        self.assertEqual(engine.get_severity_for_match(m2), "high")

        # Keywords in rule name
        m3 = YaraMatch("APT_Malware_Detected", "ns")
        self.assertEqual(engine.get_severity_for_match(m3), "critical")

        m4 = YaraMatch("Generic_infostealer", "ns")
        self.assertEqual(engine.get_severity_for_match(m4), "high")

        m5 = YaraMatch("Miner_XMRig", "ns")
        self.assertEqual(engine.get_severity_for_match(m5), "medium")

        # Default
        m6 = YaraMatch("UnknownRule", "ns")
        self.assertEqual(engine.get_severity_for_match(m6), "medium")

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_get_attck_techniques(self):
        engine = YaraEngine(rules_dirs=[])

        # Attack in metadata as string
        m1 = YaraMatch("R", "ns", meta={"attack": "T1059.001"})
        self.assertEqual(engine.get_attck_techniques(m1), ["T1059.001"])

        # Attack in metadata as list
        m2 = YaraMatch("R", "ns", meta={"attack": ["T1059", "T1055"]})
        self.assertEqual(sorted(engine.get_attck_techniques(m2)), ["T1055", "T1059"])

        # Attack in tags
        m3 = YaraMatch("R", "ns", tags=["T1014", "not-attack-tag"])
        self.assertEqual(engine.get_attck_techniques(m3), ["T1014"])


class TestYaraEngineHelpers(unittest.TestCase):
    def test_create_sample_yara_rules(self):
        import tempfile
        import shutil
        temp_dir = tempfile.mkdtemp()
        try:
            from orin.analysis.yara_engine import create_sample_yara_rules
            count = create_sample_yara_rules(Path(temp_dir))
            self.assertGreater(count, 0)
            self.assertTrue((Path(temp_dir) / "webshells.yar").exists())
        finally:
            shutil.rmtree(temp_dir)

    def test_run_yara_scan_not_available(self):
        from orin.analysis.yara_engine import run_yara_scan
        with patch("orin.analysis.yara_engine.YARA_AVAILABLE", False):
            result = run_yara_scan(Path("/some/path"))
            self.assertIn("YARA library not available", result.scan_errors)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_run_yara_scan_no_rules_loaded(self):
        from orin.analysis.yara_engine import run_yara_scan
        with patch("orin.analysis.yara_engine.YaraEngine.load_rules", return_value=0):
            result = run_yara_scan(Path("/some/path"))
            self.assertIn("No YARA rules could be loaded", result.scan_errors)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_run_yara_scan_file(self):
        from orin.analysis.yara_engine import run_yara_scan
        mock_file = MagicMock(spec=Path)
        mock_file.is_file.return_value = True
        mock_file.is_dir.return_value = False

        with patch("orin.analysis.yara_engine.YaraEngine.load_rules", return_value=5), \
             patch("orin.analysis.yara_engine.YaraEngine.scan_file", return_value=[YaraMatch("R", "ns")]):
            result = run_yara_scan(mock_file, scan_type="file")
            self.assertEqual(result.total_files_scanned, 1)
            self.assertEqual(result.total_matches, 1)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_run_yara_scan_directory(self):
        from orin.analysis.yara_engine import run_yara_scan
        mock_dir = MagicMock(spec=Path)
        mock_dir.is_file.return_value = False
        mock_dir.is_dir.return_value = True

        expected_result = YaraScanResult(total_files_scanned=2, total_matches=1)
        with patch("orin.analysis.yara_engine.YaraEngine.load_rules", return_value=5), \
             patch("orin.analysis.yara_engine.YaraEngine.scan_directory", return_value=expected_result):
            result = run_yara_scan(mock_dir, scan_type="directory")
            self.assertEqual(result.total_files_scanned, 2)
            self.assertEqual(result.total_matches, 1)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_run_yara_scan_invalid_path(self):
        from orin.analysis.yara_engine import run_yara_scan
        mock_path = MagicMock(spec=Path)
        mock_path.is_file.return_value = False
        mock_path.is_dir.return_value = False
        with patch("orin.analysis.yara_engine.YaraEngine.load_rules", return_value=5):
            res = run_yara_scan(mock_path, scan_type="auto")
            self.assertEqual(len(res.scan_errors), 1)
            self.assertIn("Invalid target path", res.scan_errors[0])

    def test_import_error_yara_unavailable(self):
        import sys
        import importlib
        from unittest.mock import patch

        # Force ImportError on yara
        with patch.dict(sys.modules, {"yara": None}):
            import orin.analysis.yara_engine
            importlib.reload(orin.analysis.yara_engine)
            self.assertFalse(orin.analysis.yara_engine.YARA_AVAILABLE)

        # Restore
        importlib.reload(orin.analysis.yara_engine)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_is_dir_false(self):
        engine = YaraEngine(rules_dirs=[])
        mock_dir = MagicMock(spec=Path)
        mock_dir.exists.return_value = True
        mock_dir.is_dir.return_value = False
        count = engine.load_rules(rules_dirs=[mock_dir])
        self.assertEqual(count, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_read_exception(self):
        engine = YaraEngine(rules_dirs=[])
        mock_dir = MagicMock(spec=Path)
        mock_dir.exists.return_value = True
        mock_dir.is_dir.return_value = True
        
        mock_file = MagicMock(spec=Path)
        mock_file.stem = "rule-a"
        mock_file.read_text.side_effect = PermissionError("access denied")
        
        mock_dir.glob.return_value = [mock_file]
        
        count = engine.load_rules(rules_dirs=[mock_dir])
        self.assertEqual(count, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_load_rules_compilation_failures(self):
        import yara
        engine = YaraEngine(rules_dirs=[])
        mock_dir = MagicMock(spec=Path)
        mock_dir.exists.return_value = True
        mock_dir.is_dir.return_value = True
        
        mock_file = MagicMock(spec=Path)
        mock_file.stem = "rule-a"
        mock_file.read_text.return_value = "rule a {}"
        mock_dir.glob.return_value = [mock_file]
        
        # 1. SyntaxError
        with patch("yara.compile", side_effect=yara.SyntaxError("syntax error")):
            with self.assertRaises(RuntimeError) as ctx:
                engine.load_rules(rules_dirs=[mock_dir])
            self.assertIn("YARA rule compilation failed", str(ctx.exception))

        # 2. General Exception
        with patch("yara.compile", side_effect=ValueError("some error")):
            with self.assertRaises(RuntimeError) as ctx:
                engine.load_rules(rules_dirs=[mock_dir])
            self.assertIn("YARA compilation error", str(ctx.exception))

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_decode_exception_fallbacks(self):
        import yara
        engine = YaraEngine(rules_dirs=[])
        
        class BrokenDecodeBytes:
            def decode(self, *args, **kwargs):
                raise ValueError("decode fail")
            def hex(self):
                return "fffefd"
        
        # Mocking string match instances where matched_data.decode raises UnicodeDecodeError
        mock_instance = MagicMock()
        mock_instance.offset = 0
        type(mock_instance).matched_data = PropertyMock(return_value=BrokenDecodeBytes())
        
        mock_string = MagicMock()
        mock_string.instances = [mock_instance]
        
        mock_match = MagicMock()
        mock_match.rule = "Rule"
        mock_match.namespace = "ns"
        mock_match.strings = [mock_string]
        mock_match.tags = []
        mock_match.meta = {}
        
        mock_compiled = MagicMock()
        mock_compiled.match.return_value = [mock_match]
        engine.compiled_rules = mock_compiled
        
        # 1. scan_file decode fallback
        with patch.object(Path, "exists", return_value=True):
            res = engine.scan_file(Path("/fake.exe"))
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0].matched_strings, ["fffefd"])  # hex fallback
            
        # 2. scan_data decode fallback
        res_data = engine.scan_data(b"\xff\xfe\xfd")
        self.assertEqual(len(res_data), 1)
        self.assertEqual(res_data[0].matched_strings, ["fffefd"])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_no_instances(self):
        engine = YaraEngine(rules_dirs=[])
        mock_string = MagicMock()
        mock_string.instances = []
        res = engine._extract_match_context(b"data", [mock_string])
        self.assertIsNone(res)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_extract_context_decode_error_fallback(self):
        engine = YaraEngine(rules_dirs=[])
        mock_instance = MagicMock()
        mock_instance.offset = 0
        type(mock_instance).matched_data = PropertyMock(return_value=b"\xff\xfe")
        mock_string = MagicMock()
        mock_string.instances = [mock_instance]
        
        class BrokenData:
            def __len__(self):
                return 10
            def __getitem__(self, item):
                return self
            def decode(self, *args, **kwargs):
                raise RuntimeError("decode fail")
            def hex(self):
                return "fffe"

        res = engine._extract_match_context(BrokenData(), [mock_string])
        self.assertEqual(res, "fffe")

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_stat_exception(self):
        import orin.analysis.yara_engine
        engine = orin.analysis.yara_engine.YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        
        mock_file = MagicMock(spec=Path)
        mock_file.is_file.return_value = True
        mock_file.stat.side_effect = OSError("permission denied")
        
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "glob", return_value=[mock_file]):
            res = engine.scan_directory(Path("/dir"), recursive=False)
            self.assertEqual(res.total_files_scanned, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_directory_scan_file_exception(self):
        import orin.analysis.yara_engine
        engine = orin.analysis.yara_engine.YaraEngine(rules_dirs=[])
        engine.compiled_rules = MagicMock()
        
        mock_file = MagicMock(spec=Path)
        mock_file.is_file.return_value = True
        mock_file.stat.return_value.st_size = 100
        mock_file.name = "test.txt"
        
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "glob", return_value=[mock_file]), \
             patch("orin.analysis.yara_engine.YaraEngine.scan_file", side_effect=Exception("scan error")):
            res = engine.scan_directory(Path("/dir"), recursive=False)
            self.assertEqual(len(res.scan_errors), 1)
            self.assertIn("Error scanning", res.scan_errors[0])

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_create_sample_yara_rules_write_exception(self):
        from orin.analysis.yara_engine import create_sample_yara_rules
        mock_dir = MagicMock(spec=Path)
        mock_path = MagicMock(spec=Path)
        mock_dir.__truediv__.return_value = mock_path
        mock_path.write_text.side_effect = IOError("write error")
        
        created = create_sample_yara_rules(mock_dir)
        self.assertEqual(created, 0)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_main_block_execution(self):
        import runpy
        # Mock Path methods to prevent creating directories or files, and return empty globs
        with patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.glob", return_value=[]), \
             patch("pathlib.Path.rglob", return_value=[]):
            runpy.run_path("src/orin/analysis/yara_engine.py")


class TestYaraEngineScanProcess(unittest.TestCase):
    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_process_native_success(self):
        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()

        mock_match = MagicMock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "test_ns"
        mock_match.tags = ["tag1"]
        mock_match.meta = {"desc": "Test"}

        mock_instance = MagicMock()
        mock_instance.matched_data = b"malicious_payload"
        mock_string = MagicMock()
        mock_string.instances = [mock_instance]
        mock_match.strings = [mock_string]

        mock_compiled.match.return_value = [mock_match]
        engine.compiled_rules = mock_compiled

        results = engine.scan_process(1234)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].rule_name, "TestRule")
        self.assertEqual(results[0].process_pid, 1234)
        self.assertEqual(results[0].matched_strings, ["malicious_payload"])
        mock_compiled.match.assert_called_with(pid=1234, timeout=30)

    @unittest.skipUnless(YARA_AVAILABLE, "yara-python not installed")
    def test_scan_process_fallback_success(self):
        engine = YaraEngine(rules_dirs=[])
        mock_compiled = MagicMock()
        mock_compiled.match.side_effect = Exception("ptrace error")
        engine.compiled_rules = mock_compiled

        maps_content = "55b9a8cfd000-55b9a8cff000 r-xp 00000000 08:02 1234567 /usr/bin/bash\n"

        from unittest.mock import mock_open, patch

        def side_effect_open(path, mode="r", *args, **kwargs):
            if "maps" in str(path):
                return mock_open(read_data=maps_content).return_value
            elif "mem" in str(path):
                mem_mock = MagicMock()
                mem_mock.read.return_value = b"test_malware_miner_data"
                mem_mock.__enter__.return_value = mem_mock
                return mem_mock
            raise FileNotFoundError()

        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", side_effect=side_effect_open), \
             patch.object(engine, "scan_data") as mock_scan_data:

             mock_yara_match = YaraMatch(
                 rule_name="CryptoMiner_XMRig_Generic",
                 namespace="crypto_miners",
                 matched_strings=["xmrig"],
                 process_pid=1234
             )
             mock_scan_data.return_value = [mock_yara_match]

             results = engine.scan_process(1234)
             self.assertEqual(len(results), 1)
             self.assertEqual(results[0].rule_name, "CryptoMiner_XMRig_Generic")
             self.assertEqual(results[0].process_pid, 1234)
             mock_scan_data.assert_called()


if __name__ == "__main__":
    unittest.main()
