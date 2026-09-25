"""
Unit tests for Spectre HIDS modules
"""

import json
import os

# Import Spectre modules
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from spectre.alerts import Alert, format_process_resource_tree
from spectre.detectors import DetectionEngine
from spectre.graph import ProcessResourceGraph
from spectre.mitigation import Container
from spectre.rules import DEFAULT_RULES, BehavioralRule, MitreMapping, load_rules_from_file
from spectre.rules.compiler import SigmaCompiler
from spectre.rules.field_mapper import extract_mitre_from_tags, map_sigma_field
from spectre.rules.sigma_parser import SigmaParser, SigmaRule
from spectre.scanner import YaraScanner
from spectre.sensor import ProcessSensor
from spectre.storage import SpectreDB


class TestRules:
    """Test rule dataclasses and loading"""

    def test_mitre_mapping_creation(self):
        mapping = MitreMapping(
            tactic="Execution",
            technique_id="T1059.004",
            technique_name="Command and Scripting Interpreter: Unix Shell",
        )
        assert mapping.tactic == "Execution"
        assert mapping.technique_id == "T1059.004"

    def test_mitre_mapping_from_dict(self):
        data = {
            "tactic": "Execution",
            "technique_id": "T1059.004",
            "technique_name": "Unix Shell",
        }
        mapping = MitreMapping.from_dict(data)
        assert mapping.tactic == "Execution"

    def test_behavioral_rule_creation(self):
        rule = BehavioralRule(
            id="test_rule",
            name="Test Rule",
            score=10,
            description="Test description",
            parent_names=["nginx"],
            child_names=["bash"],
            mitre_attack=[
                MitreMapping("Execution", "T1059.004", "Unix Shell"),
            ],
        )
        assert rule.id == "test_rule"
        assert rule.score == 10
        assert "T1059.004" in rule.get_mitre_str()

    def test_behavioral_rule_from_dict(self):
        data = {
            "id": "test_rule",
            "name": "Test Rule",
            "score": 15,
            "description": "Test",
            "parent_names": ["nginx"],
            "child_names": ["bash"],
            "mitre_attack": [
                {
                    "tactic": "Execution",
                    "technique_id": "T1059.004",
                    "technique_name": "Unix Shell",
                },
            ],
        }
        rule = BehavioralRule.from_dict(data)
        assert rule.id == "test_rule"
        assert len(rule.mitre_attack) == 1

    def test_load_rules_from_file(self):
        # Create temp rules file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                [
                    {
                        "id": "temp_rule",
                        "name": "Temp Rule",
                        "score": 5,
                        "description": "Temp",
                    },
                ],
                f,
            )
            temp_path = f.name

        try:
            rules = load_rules_from_file(temp_path)
            assert len(rules) == 1
            assert rules[0].id == "temp_rule"
        finally:
            os.unlink(temp_path)

    def test_load_rules_nonexistent_file(self):
        rules = load_rules_from_file("/nonexistent/path.json")
        # Should fall back to DEFAULT_RULES
        assert len(rules) == len(DEFAULT_RULES)

    def test_default_rules_exist(self):
        assert len(DEFAULT_RULES) >= 4
        rule_ids = {r.id for r in DEFAULT_RULES}
        assert "web_server_shell" in rule_ids
        assert "shell_network_tool" in rule_ids


class TestSigmaParser:
    """Test Sigma rule parsing"""

    def test_parse_valid_sigma(self):
        sigma_yaml = """
title: Test Rule
id: test-rule-001
description: Test description
status: stable
author: Test
date: 2024-01-01
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/bash'
    condition: selection
level: medium
tags:
    - attack.t1059.004
"""
        parser = SigmaParser()
        rule = parser.parse_string(sigma_yaml)

        assert isinstance(rule, SigmaRule)
        assert rule.title == "Test Rule"
        assert rule.id == "test-rule-001"
        assert rule.logsource["category"] == "process_creation"
        assert "selection" in rule.detection

    def test_parse_missing_required_fields(self):
        sigma_yaml = """
title: Test Rule
# missing id and detection
"""
        parser = SigmaParser()
        with pytest.raises(ValueError):
            parser.parse_string(sigma_yaml)

    def test_parse_invalid_yaml(self):
        parser = SigmaParser()
        with pytest.raises(ValueError):
            parser.parse_string("invalid: yaml: [")

    def test_extract_mitre_tags(self):
        tags = [
            "attack.t1059.004",
            "attack.t1505.003",
            "attack.execution",
            "other.tag",
        ]
        mitre = extract_mitre_from_tags(tags)
        assert len(mitre) == 2
        assert mitre[0]["technique_id"] == "T1059.004"
        assert mitre[1]["technique_id"] == "T1505.003"


class TestFieldMapper:
    """Test Sigma to Spectre field mapping"""

    def test_map_process_fields(self):
        mapping = map_sigma_field("Image|endswith")
        assert mapping is not None
        assert mapping.spectre_field == "name"
        assert mapping.operator == "endswith"

    def test_map_commandline_fields(self):
        mapping = map_sigma_field("CommandLine|contains")
        assert mapping is not None
        assert mapping.spectre_field == "cmdline"
        assert mapping.operator == "contains"

    def test_map_file_fields(self):
        mapping = map_sigma_field("TargetFilename|endswith")
        assert mapping is not None
        assert mapping.spectre_field == "file_path"
        assert mapping.operator == "endswith"

    def test_map_network_fields(self):
        mapping = map_sigma_field("DestinationIp|cidr")
        assert mapping is not None
        assert mapping.spectre_field == "dest_ip"
        assert mapping.operator == "cidr"

    def test_unknown_field(self):
        mapping = map_sigma_field("UnknownField")
        assert mapping is None


class TestSigmaCompiler:
    """Test Sigma to Spectre compilation"""

    def test_compile_webshell_rule(self):
        sigma_yaml = """
title: Web Server Spawning Shell
id: test-webshell-001
description: Web server spawning shell
status: stable
author: Test
date: 2024-01-01
logsource:
    category: process_creation
    product: linux
detection:
    selection_webserver:
        ParentImage|endswith:
            - '/nginx'
            - '/apache2'
    selection_shell:
        Image|endswith:
            - '/bash'
            - '/sh'
    condition: selection_webserver and selection_shell
level: high
tags:
    - attack.t1059.004
    - attack.t1505.003
"""
        parser = SigmaParser()
        sigma_rule = parser.parse_string(sigma_yaml)

        compiler = SigmaCompiler()
        result = compiler.compile(sigma_rule)

        assert result.rule is not None
        assert result.rule.id == "test-webshell-001"
        assert result.rule.score == 20  # high level
        assert "/nginx" in result.rule.parent_names
        assert "/bash" in result.rule.child_names
        assert result.rule.mitre_attack is not None
        assert len(result.rule.mitre_attack) == 2

    def test_compile_file_event_rule(self):
        sigma_yaml = """
title: Shadow File Read
id: test-shadow-read
description: Reading /etc/shadow
status: stable
author: Test
date: 2024-01-01
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename: '/etc/shadow'
    condition: selection
level: critical
tags:
    - attack.t1003.008
"""
        parser = SigmaParser()
        sigma_rule = parser.parse_string(sigma_yaml)

        compiler = SigmaCompiler()
        result = compiler.compile(sigma_rule)

        assert result.rule is not None
        assert result.rule.score == 25  # critical level
        assert "/etc/shadow" in result.rule.file_paths
        assert "READ" in result.rule.file_events or "WRITE" in result.rule.file_events


class TestSensor:
    """Test process sensor"""

    def test_sensor_initialization(self):
        sensor = ProcessSensor(interval=0.1)
        assert sensor.interval == 0.1
        assert isinstance(sensor.known_processes, dict)

    def test_is_ignored_process(self):
        sensor = ProcessSensor()

        # Test with mock process
        class MockProc:
            def name(self):
                return "test"

            def cmdline(self):
                return ["test"]

        assert not sensor._is_ignored_process(MockProc())

        class MockIDEProc:
            def name(self):
                return "language_server"

            def cmdline(self):
                return ["language_server"]

        assert sensor._is_ignored_process(MockIDEProc())


class TestGraph:
    """Test process resource graph"""

    def test_graph_initialization(self):
        graph = ProcessResourceGraph(window_size=30.0)
        assert graph.window_size == 30.0
        assert graph.graph.number_of_nodes() == 0

    def test_add_chain(self):
        graph = ProcessResourceGraph()
        chain = [
            {
                "pid": 100,
                "create_time": 1000.0,
                "name": "nginx",
                "cmdline": ["nginx"],
                "files": [],
                "connections": [],
            },
            {
                "pid": 101,
                "create_time": 1001.0,
                "name": "bash",
                "cmdline": ["bash"],
                "files": [],
                "connections": [],
            },
        ]
        graph.add_chain(chain)

        assert graph.graph.number_of_nodes() == 2
        assert graph.graph.number_of_edges() == 1  # SPAWN edge

    def test_add_chain_with_resources(self):
        graph = ProcessResourceGraph()
        chain = [
            {
                "pid": 100,
                "create_time": 1000.0,
                "name": "bash",
                "cmdline": ["bash"],
                "files": [{"path": "/etc/passwd", "event": "READ"}],
                "connections": [
                    {"raddr": "192.168.1.1:443", "event": "CONNECT", "status": "ESTABLISHED"},
                ],
            },
        ]
        graph.add_chain(chain)

        assert graph.graph.number_of_nodes() == 3  # process + file + socket
        assert graph.graph.number_of_edges() == 2  # READ + CONNECT

    def test_expire_old_events(self):
        graph = ProcessResourceGraph(window_size=1.0)
        chain = [
            {
                "pid": 100,
                "create_time": 1000.0,
                "name": "bash",
                "cmdline": ["bash"],
                "files": [],
                "connections": [],
            },
        ]
        graph.add_chain(chain)

        # Manually set old timestamps
        import time

        old_time = time.time() - 10
        for node in graph.graph.nodes:
            graph.graph.nodes[node]["last_seen"] = old_time
        for u, v in graph.graph.edges:
            graph.graph[u][v]["timestamp"] = old_time
        # Also set active_processes to old time so they're not considered alive
        for key in graph.active_processes:
            graph.active_processes[key] = old_time

        graph.expire_old_events()
        # Nodes should be cleaned up
        assert graph.graph.number_of_nodes() == 0


class TestDetectors:
    """Test detection engine"""

    def test_evaluate_chain_webshell(self):
        rules = DEFAULT_RULES
        engine = DetectionEngine(rules)

        chain = [
            {
                "pid": 100,
                "create_time": 1000.0,
                "name": "nginx",
                "cmdline": ["nginx"],
                "files": [],
                "connections": [],
            },
            {
                "pid": 101,
                "create_time": 1001.0,
                "name": "bash",
                "cmdline": ["bash"],
                "files": [],
                "connections": [],
            },
        ]

        matches = engine.evaluate_chain(chain)
        assert len(matches) > 0
        # Should match web_server_shell rule
        rule_ids = [m[0].id for m in matches]
        assert "web_server_shell" in rule_ids

    def test_evaluate_chain_shell_downloader(self):
        rules = DEFAULT_RULES
        engine = DetectionEngine(rules)

        chain = [
            {
                "pid": 100,
                "create_time": 1000.0,
                "name": "bash",
                "cmdline": ["bash"],
                "files": [],
                "connections": [],
            },
            {
                "pid": 101,
                "create_time": 1001.0,
                "name": "curl",
                "cmdline": ["curl", "http://example.com"],
                "files": [],
                "connections": [],
            },
        ]

        matches = engine.evaluate_chain(chain)
        rule_ids = [m[0].id for m in matches]
        assert "shell_downloader" in rule_ids


class TestAlerts:
    """Test alert formatting and logging"""

    def test_format_process_resource_tree(self):
        chain = [
            {
                "pid": 100,
                "create_time": 1000.0,
                "name": "nginx",
                "cmdline": ["nginx"],
                "files": [],
                "connections": [],
            },
            {
                "pid": 101,
                "create_time": 1001.0,
                "name": "bash",
                "cmdline": ["bash"],
                "files": [{"path": "/tmp/test", "event": "WRITE"}],
                "connections": [],
            },
        ]

        lines = format_process_resource_tree(chain)
        assert len(lines) > 0
        assert "nginx" in lines[0]
        assert "bash" in lines[1]

    def test_alert_creation(self):
        chain = [{"pid": 100, "name": "test"}]
        alert = Alert(
            rule_id="test",
            rule_name="Test Alert",
            score=10,
            chain=chain,
            explanation="Test explanation",
        )
        assert alert.rule_id == "test"
        assert alert.score == 10


class TestStorage:
    """Test SQLite storage"""

    def test_db_initialization(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = SpectreDB(db_path)
            stats = db.get_stats()
            assert "total_events" in stats
            assert "total_alerts" in stats
            assert "total_sessions" in stats
            db.close()
        finally:
            os.unlink(db_path)

    def test_insert_event(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = SpectreDB(db_path)
            event_id = db.insert_event(
                event_type="test_rule",
                proc_pid=100,
                proc_name="test",
                detail="Test detail",
                mitre="T1059.004",
            )
            assert event_id > 0

            events = db.query_events(limit=1)
            assert len(events) == 1
            assert events[0]["event_type"] == "test_rule"
            db.close()
        finally:
            os.unlink(db_path)

    def test_upsert_session(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = SpectreDB(db_path)
            db.upsert_session(100, "nginx", 1000.0, 25)
            sessions = db.query_sessions(limit=1)
            assert len(sessions) == 1
            assert sessions[0]["total_score"] == 25
            db.close()
        finally:
            os.unlink(db_path)


class TestScanner:
    """Test YARA scanner"""

    def test_scanner_initialization(self):
        scanner = YaraScanner("/nonexistent/path")
        # Should not crash even if yara not available
        assert scanner is not None

    def test_get_file_hash(self):
        scanner = YaraScanner("/tmp")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            hash_val = scanner.get_file_hash(temp_path)
            assert hash_val is not None
            assert len(hash_val) == 64  # SHA256
        finally:
            os.unlink(temp_path)


class TestMitigation:
    """Test containment"""

    def test_container_none_action(self):
        container = Container(action="none")
        result = container.mitigate(999999, "test")
        assert result is False

    def test_container_invalid_action(self):
        container = Container(action="invalid")
        result = container.mitigate(999999, "test")
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
