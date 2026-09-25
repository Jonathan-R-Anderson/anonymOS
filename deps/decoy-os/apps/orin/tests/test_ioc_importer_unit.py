# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.intel.ioc_importer – IOCImporter and Indicator dataclass.
Covers: detect_ioc_type, load_txt_blocklist, load_stix_json, _parse_stix_pattern,
load_csv_feed, _load_json_list, _build_blocklists, get_summary, match_*, export_blocklist,
load_all_intel, create_sample_intel_files.
"""
import csv
import json
import os
import tempfile
import unittest
from pathlib import Path

from orin.intel.ioc_importer import IOCImporter, Indicator, create_sample_intel_files


class TestIndicatorDataclass(unittest.TestCase):
    def test_to_dict(self):
        ind = Indicator(id="1", type="ip-addr", value="1.2.3.4", confidence=80)
        d = ind.to_dict()
        self.assertEqual(d["id"], "1")
        self.assertEqual(d["type"], "ip-addr")
        self.assertEqual(d["value"], "1.2.3.4")
        self.assertEqual(d["confidence"], 80)

    def test_defaults(self):
        ind = Indicator(id="x", type="domain", value="evil.com")
        self.assertEqual(ind.confidence, 50)
        self.assertEqual(ind.severity, "medium")
        self.assertFalse(ind.revoked)
        self.assertEqual(ind.tags, [])


class TestDetectIocType(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()

    def test_detect_ipv4(self):
        self.assertEqual(self.importer.detect_ioc_type("192.168.1.1"), "ip-addr")
        self.assertEqual(self.importer.detect_ioc_type("10.0.0.1"), "ip-addr")

    def test_detect_cidr(self):
        self.assertEqual(self.importer.detect_ioc_type("10.0.0.0/24"), "ip-addr")

    def test_detect_domain(self):
        self.assertEqual(self.importer.detect_ioc_type("evil.com"), "domain")
        self.assertEqual(self.importer.detect_ioc_type("malware.example.org"), "domain")

    def test_detect_md5(self):
        md5 = "a" * 32
        self.assertEqual(self.importer.detect_ioc_type(md5), "file-hash-md5")

    def test_detect_sha1(self):
        sha1 = "b" * 40
        self.assertEqual(self.importer.detect_ioc_type(sha1), "file-hash-sha1")

    def test_detect_sha256(self):
        sha256 = "c" * 64
        self.assertEqual(self.importer.detect_ioc_type(sha256), "file-hash-sha256")

    def test_detect_url(self):
        self.assertEqual(self.importer.detect_ioc_type("http://evil.com/payload"), "url")
        self.assertEqual(self.importer.detect_ioc_type("https://c2.example.com"), "url")

    def test_detect_email(self):
        self.assertEqual(self.importer.detect_ioc_type("attacker@evil.com"), "email")

    def test_detect_unknown(self):
        self.assertEqual(self.importer.detect_ioc_type("not_an_ioc_!!"), "unknown")

    def test_whitespace_stripped(self):
        self.assertEqual(self.importer.detect_ioc_type("  192.168.1.1  "), "ip-addr")


class TestLoadTxtBlocklist(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()

    def test_nonexistent_file_returns_empty(self):
        result = self.importer.load_txt_blocklist(Path("/no/such/file.txt"))
        self.assertEqual(result, [])

    def test_basic_blocklist(self):
        content = "192.168.1.1 # C2 server\nevil.com\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = Path(f.name)
        try:
            indicators = self.importer.load_txt_blocklist(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 2)
        self.assertEqual(indicators[0].type, "ip-addr")
        self.assertEqual(indicators[0].description, "C2 server")
        self.assertEqual(indicators[1].type, "domain")

    def test_skips_blank_lines_and_comments(self):
        content = "\n# This is a comment\n\n10.0.0.1\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = Path(f.name)
        try:
            indicators = self.importer.load_txt_blocklist(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)

    def test_skips_unknown_type(self):
        content = "not_an_ioc_value\n10.0.0.1\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = Path(f.name)
        try:
            indicators = self.importer.load_txt_blocklist(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)


class TestLoadStixJson(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()

    def test_nonexistent_file_returns_empty(self):
        result = self.importer.load_stix_json(Path("/no/such/stix.json"))
        self.assertEqual(result, [])

    def test_stix_bundle_with_ip(self):
        stix = {
            "type": "bundle",
            "objects": [{
                "type": "indicator",
                "id": "indicator--abc",
                "pattern": "[ipv4:addr:value = '203.0.113.1']",
                "labels": ["high"],
                "confidence": 80,
                "description": "APT infra",
            }]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(stix, f)
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].type, "ip-addr")
        self.assertEqual(indicators[0].severity, "high")
        self.assertEqual(indicators[0].confidence, 80)

    def test_stix_bundle_with_domain_critical(self):
        stix = {
            "type": "bundle",
            "objects": [{
                "type": "indicator",
                "id": "indicator--def",
                "pattern": "[domain-name:value = 'phish.com']",
                "labels": ["critical"],
            }]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(stix, f)
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].severity, "critical")

    def test_stix_revoked_indicators_skipped(self):
        stix = {
            "type": "bundle",
            "objects": [{
                "type": "indicator",
                "id": "indicator--rev",
                "revoked": True,
                "pattern": "[ipv4:addr:value = '1.2.3.4']",
            }]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(stix, f)
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 0)

    def test_stix_non_indicator_type_skipped(self):
        stix = {"type": "bundle", "objects": [{"type": "malware", "name": "BadApp"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(stix, f)
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 0)

    def test_stix_invalid_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("NOT JSON!!")
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(indicators, [])

    def test_stix_single_indicator(self):
        obj = {
            "type": "indicator",
            "id": "indicator--xyz",
            "pattern": "[ipv4:addr:value = '10.10.10.10']",
            "labels": ["low"],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(obj, f)
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].severity, "low")

    def test_stix_list_of_objects(self):
        data = [{"type": "indicator", "id": "i1", "pattern": "[ipv4:addr:value = '5.5.5.5']"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        try:
            indicators = self.importer.load_stix_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)


class TestParseStixPattern(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()

    def test_ipv4_pattern(self):
        result = self.importer._parse_stix_pattern("[ipv4:addr:value = '192.168.1.1']")
        self.assertIn(("192.168.1.1", "ip-addr"), result)

    def test_domain_pattern(self):
        result = self.importer._parse_stix_pattern("[domain-name:value = 'evil.com']")
        self.assertIn(("evil.com", "domain"), result)

    def test_sha256_pattern(self):
        sha256 = "a" * 64
        result = self.importer._parse_stix_pattern(f"[file:hashes.'SHA-256' = '{sha256}']")
        self.assertIn((sha256, "file-hash-sha256"), result)

    def test_md5_pattern(self):
        md5 = "f" * 32
        result = self.importer._parse_stix_pattern(f"[file:hashes.MD5 = '{md5}']")
        self.assertIn((md5, "file-hash-md5"), result)

    def test_url_pattern(self):
        result = self.importer._parse_stix_pattern("[url:value = 'http://evil.com/dl']")
        self.assertIn(("http://evil.com/dl", "url"), result)

    def test_email_pattern(self):
        result = self.importer._parse_stix_pattern("[email-addr:value = 'attacker@evil.com']")
        self.assertIn(("attacker@evil.com", "email"), result)

    def test_empty_pattern_returns_empty(self):
        result = self.importer._parse_stix_pattern("")
        self.assertEqual(result, [])


class TestLoadCsvFeed(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()

    def test_nonexistent_file_returns_empty(self):
        result = self.importer.load_csv_feed(Path("/no/such/file.csv"))
        self.assertEqual(result, [])

    def test_csv_with_column_mapping(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "description"])
            writer.writerow(["10.0.0.1", "C2 Server"])
            path = Path(f.name)
        try:
            indicators = self.importer.load_csv_feed(path, column_mapping={"ip": "ip-addr"})
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].type, "ip-addr")
        self.assertEqual(indicators[0].value, "10.0.0.1")

    def test_csv_auto_detect(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ioc"])
            writer.writerow(["evil.com"])
            path = Path(f.name)
        try:
            indicators = self.importer.load_csv_feed(path)
        finally:
            os.unlink(path)
        # Should detect "evil.com" as domain
        self.assertTrue(any(i.type == "domain" for i in indicators))


class TestLoadJsonList(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()

    def test_json_list_of_strings(self):
        data = ["10.0.0.1", "evil.com"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        try:
            indicators = self.importer._load_json_list(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 2)

    def test_json_list_of_dicts(self):
        data = [{"value": "192.168.1.100", "type": "ip-addr", "description": "test"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        try:
            indicators = self.importer._load_json_list(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].value, "192.168.1.100")

    def test_json_skips_unknown_type(self):
        data = ["not_an_ioc"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        try:
            indicators = self.importer._load_json_list(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(indicators), 0)

    def test_invalid_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("BROKEN JSON")
            path = Path(f.name)
        try:
            indicators = self.importer._load_json_list(path)
        finally:
            os.unlink(path)
        self.assertEqual(indicators, [])


class TestBuildBlocklistsAndMatching(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()
        self.importer.indicators = [
            Indicator(id="1", type="ip-addr", value="10.0.0.1"),
            Indicator(id="2", type="domain", value="evil.com"),
            Indicator(id="3", type="file-hash-sha256", value="a" * 64),
            Indicator(id="4", type="url", value="http://evil.com/payload"),
            Indicator(id="5", type="ip-addr", value="10.0.0.2", revoked=True),
        ]
        self.importer._build_blocklists()

    def test_ip_blocklist_built(self):
        self.assertIn("10.0.0.1", self.importer.ip_blocklist)
        # Revoked indicator should be excluded
        self.assertNotIn("10.0.0.2", self.importer.ip_blocklist)

    def test_domain_blocklist_built(self):
        self.assertIn("evil.com", self.importer.domain_blocklist)

    def test_hash_blocklist_built(self):
        self.assertIn("a" * 64, self.importer.hash_blocklist)

    def test_url_blocklist_built(self):
        self.assertIn("http://evil.com/payload", self.importer.url_blocklist)

    def test_match_ip_success(self):
        result = self.importer.match_ip("10.0.0.1")
        self.assertIsNotNone(result)
        self.assertEqual(result.value, "10.0.0.1")

    def test_match_ip_miss(self):
        result = self.importer.match_ip("8.8.8.8")
        self.assertIsNone(result)

    def test_match_domain_success(self):
        result = self.importer.match_domain("evil.com")
        self.assertIsNotNone(result)

    def test_match_domain_case_insensitive(self):
        result = self.importer.match_domain("EVIL.COM")
        self.assertIsNotNone(result)

    def test_match_domain_miss(self):
        result = self.importer.match_domain("google.com")
        self.assertIsNone(result)

    def test_match_hash_success(self):
        result = self.importer.match_hash("a" * 64)
        self.assertIsNotNone(result)

    def test_match_hash_miss(self):
        result = self.importer.match_hash("b" * 64)
        self.assertIsNone(result)


class TestGetSummary(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()
        self.importer.indicators = [
            Indicator(id="1", type="ip-addr", value="1.2.3.4", severity="high"),
            Indicator(id="2", type="domain", value="x.com", severity="medium"),
            Indicator(id="3", type="ip-addr", value="5.5.5.5", severity="high", revoked=True),
        ]
        self.importer._build_blocklists()

    def test_summary_counts(self):
        summary = self.importer.get_summary()
        self.assertEqual(summary["total_indicators"], 3)
        self.assertEqual(summary["active_indicators"], 2)
        self.assertEqual(summary["by_type"]["ip-addr"], 1)  # Only non-revoked
        self.assertEqual(summary["by_type"]["domain"], 1)
        self.assertEqual(summary["by_severity"]["high"], 1)
        self.assertEqual(summary["ip_count"], 1)
        self.assertEqual(summary["domain_count"], 1)


class TestExportBlocklist(unittest.TestCase):
    def setUp(self):
        self.importer = IOCImporter()
        self.importer.indicators = [
            Indicator(id="1", type="ip-addr", value="10.0.0.1", description="C2", source="test"),
            Indicator(id="2", type="domain", value="evil.com", description="Phishing", source="test"),
        ]
        self.importer._build_blocklists()

    def test_export_txt(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = Path(f.name)
        try:
            self.importer.export_blocklist(path, format="txt")
            content = path.read_text()
            self.assertIn("10.0.0.1", content)
            self.assertIn("evil.com", content)
        finally:
            os.unlink(path)

    def test_export_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        try:
            self.importer.export_blocklist(path, format="json")
            data = json.loads(path.read_text())
            self.assertIn("indicators", data)
            self.assertIn("summary", data)
        finally:
            os.unlink(path)

    def test_export_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = Path(f.name)
        try:
            self.importer.export_blocklist(path, format="csv")
            rows = path.read_text().splitlines()
            self.assertIn("type", rows[0])
            self.assertTrue(len(rows) > 1)
        finally:
            os.unlink(path)


class TestLoadAllIntel(unittest.TestCase):
    def test_load_all_from_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a txt blocklist
            txt = Path(tmpdir) / "blocklist.txt"
            txt.write_text("10.0.0.1 # C2\nevil.com\n")
            # Create a JSON blocklist
            json_data = ["5.5.5.5"]
            json_file = Path(tmpdir) / "blocklist.json"
            json_file.write_text(json.dumps(json_data))

            importer = IOCImporter(intel_dir=Path(tmpdir))
            indicators = importer.load_all_intel()

        self.assertTrue(len(indicators) > 0)

    def test_nonexistent_intel_dir(self):
        importer = IOCImporter(intel_dir=Path("/no/such/intel/dir"))
        result = importer.load_all_intel()
        self.assertEqual(result, [])


class TestCreateSampleIntelFiles(unittest.TestCase):
    def test_creates_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            intel_dir = create_sample_intel_files(Path(tmpdir))
            files = list(intel_dir.iterdir())
        self.assertTrue(len(files) > 0)
        names = [f.name for f in files]
        self.assertIn("sample_blocklist.txt", names)
        self.assertIn("sample_stix.json", names)
        self.assertIn("sample_feed.csv", names)


if __name__ == "__main__":
    unittest.main()
