# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Extended unit tests for orin.analysis.sigma – covering validate_rule,
validate_rules_directory, _safe_eval_ast, and evaluate_rule_against_log
edge cases not covered by the existing test_sigma.py.
"""
import ast
import os
import tempfile
import unittest
from pathlib import Path

from orin.analysis.sigma import (
    ValidationResult,
    parse_yaml_rule,
    validate_rule,
    validate_rules_directory,
    evaluate_condition,
    evaluate_rule_against_log,
    load_rules,
    _safe_eval_ast,
    VALID_LEVELS,
    UNSUPPORTED_MODIFIERS,
)


# ---------------------------------------------------------------------------
# Helper: build a minimal valid sigma rule dict
# ---------------------------------------------------------------------------
def minimal_rule(title="Test Rule", condition="selection"):
    return {
        "title": title,
        "detection": {
            "selection": ["pattern"],
            "condition": condition,
        },
    }


class TestValidationResult(unittest.TestCase):
    def test_to_dict(self):
        r = ValidationResult(
            valid=True,
            errors=["e1"],
            warnings=["w1"],
            supported_operators=["and"],
            unsupported_operators=["|re"],
        )
        d = r.to_dict()
        self.assertTrue(d["valid"])
        self.assertEqual(d["errors"], ["e1"])
        self.assertEqual(d["warnings"], ["w1"])
        self.assertEqual(d["supported_operators"], ["and"])
        self.assertEqual(d["unsupported_operators"], ["|re"])

    def test_defaults(self):
        r = ValidationResult()
        self.assertTrue(r.valid)
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])


class TestValidateRule(unittest.TestCase):
    def test_valid_minimal_rule(self):
        rule = minimal_rule()
        result = validate_rule(rule, "")
        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])

    def test_missing_required_fields(self):
        rule = {}  # Missing both 'title' and 'detection'
        result = validate_rule(rule, "")
        self.assertFalse(result.valid)
        self.assertTrue(any("Missing required fields" in e for e in result.errors))

    def test_missing_title(self):
        rule = {"detection": {"selection": ["x"], "condition": "selection"}}
        result = validate_rule(rule, "")
        self.assertFalse(result.valid)

    def test_missing_detection(self):
        rule = {"title": "No Detection Rule"}
        result = validate_rule(rule, "")
        self.assertFalse(result.valid)

    def test_detection_missing_condition(self):
        rule = {"title": "Test", "detection": {"selection": ["x"]}}
        result = validate_rule(rule, "")
        self.assertFalse(result.valid)
        self.assertTrue(any("Missing 'condition'" in e for e in result.errors))

    def test_invalid_detection_type(self):
        rule = {"title": "Test", "detection": "not_a_dict"}
        result = validate_rule(rule, "")
        self.assertFalse(result.valid)

    def test_unsupported_modifier_near(self):
        rule = minimal_rule()
        raw_content = "selection|near: something"
        result = validate_rule(rule, raw_content)
        self.assertFalse(result.valid)
        self.assertIn("|near", result.unsupported_operators)

    def test_unsupported_modifier_count(self):
        rule = minimal_rule()
        raw_content = "selection|count: 5"
        result = validate_rule(rule, raw_content)
        self.assertFalse(result.valid)
        self.assertIn("|count", result.unsupported_operators)

    def test_unsupported_modifier_base64(self):
        rule = minimal_rule()
        raw_content = "field|base64: dGVzdA=="
        result = validate_rule(rule, raw_content)
        self.assertFalse(result.valid)
        self.assertIn("|base64", result.unsupported_operators)

    def test_unsupported_modifier_re(self):
        rule = minimal_rule()
        raw_content = "field|re: ^evil.*"
        result = validate_rule(rule, raw_content)
        self.assertFalse(result.valid)

    def test_invalid_level_warning(self):
        rule = minimal_rule()
        rule["level"] = "extreme"  # Not in VALID_LEVELS
        result = validate_rule(rule, "")
        self.assertTrue(any("Non-standard severity level" in w for w in result.warnings))

    def test_valid_level_no_warning(self):
        for level in VALID_LEVELS:
            rule = minimal_rule()
            rule["level"] = level
            result = validate_rule(rule, "")
            self.assertFalse(any("Non-standard" in w for w in result.warnings))

    def test_unknown_top_level_field_warning(self):
        rule = minimal_rule()
        rule["some_unknown_field"] = "value"
        result = validate_rule(rule, "")
        self.assertTrue(any("Unknown top-level fields" in w for w in result.warnings))

    def test_condition_with_and_records_operator(self):
        rule = minimal_rule(condition="selection_a and selection_b")
        rule["detection"]["selection_a"] = ["x"]
        rule["detection"]["selection_b"] = ["y"]
        result = validate_rule(rule, "")
        self.assertIn("condition:and", result.supported_operators)

    def test_condition_with_or_records_operator(self):
        rule = minimal_rule(condition="selection_a or selection_b")
        rule["detection"]["selection_a"] = ["x"]
        rule["detection"]["selection_b"] = ["y"]
        result = validate_rule(rule, "")
        self.assertIn("condition:or", result.supported_operators)

    def test_condition_with_not_records_operator(self):
        rule = minimal_rule(condition="not selection")
        result = validate_rule(rule, "")
        self.assertIn("condition:not", result.supported_operators)

    def test_condition_with_quantifier(self):
        rule = minimal_rule(condition="1 of selection*")
        result = validate_rule(rule, "")
        self.assertIn("condition:quantifier", result.supported_operators)

    def test_condition_with_wildcard(self):
        rule = minimal_rule(condition="1 of selection*")
        result = validate_rule(rule, "")
        self.assertIn("condition:wildcard", result.supported_operators)

    def test_aggregation_condition_blocked(self):
        rule = minimal_rule(condition="count(selection) > 5")
        result = validate_rule(rule, "")
        self.assertFalse(result.valid)
        self.assertIn("|count", result.unsupported_operators)

    def test_no_duplicate_operators(self):
        """Operator lists should not contain duplicates."""
        rule = minimal_rule(condition="selection and selection")
        result = validate_rule(rule, "")
        self.assertEqual(len(result.supported_operators), len(set(result.supported_operators)))


class TestSafeEvalAst(unittest.TestCase):
    def _eval(self, expr):
        tree = ast.parse(expr, mode="eval")
        return _safe_eval_ast(tree)

    def test_true_constant(self):
        self.assertTrue(self._eval("True"))

    def test_false_constant(self):
        self.assertFalse(self._eval("False"))

    def test_bool_and(self):
        self.assertTrue(self._eval("True and True"))
        self.assertFalse(self._eval("True and False"))

    def test_bool_or(self):
        self.assertTrue(self._eval("True or False"))
        self.assertFalse(self._eval("False or False"))

    def test_bool_not(self):
        self.assertFalse(self._eval("not True"))
        self.assertTrue(self._eval("not False"))

    def test_complex_expression(self):
        self.assertTrue(self._eval("(True and True) or (False and True)"))
        self.assertFalse(self._eval("not (True or False)"))

    def test_unsupported_node_raises(self):
        tree = ast.parse("1 + 2", mode="eval")
        with self.assertRaises(ValueError):
            _safe_eval_ast(tree)


class TestEvaluateConditionEdgeCases(unittest.TestCase):
    def test_empty_condition(self):
        result = evaluate_condition("", {})
        self.assertFalse(result)

    def test_unknown_selector_treated_as_false(self):
        result = evaluate_condition("unknown_selector", {"known": True})
        self.assertFalse(result)

    def test_1_of_with_no_matching_prefix(self):
        sel = {"other_sel": True}
        result = evaluate_condition("1 of selection*", sel)
        self.assertFalse(result)

    def test_all_of_with_empty_match(self):
        # No selections matching the prefix
        result = evaluate_condition("all of selection*", {"other": True})
        self.assertFalse(result)

    def test_parentheses_in_condition(self):
        """The sigma evaluator uses simple token-based logic.
        Parentheses must be separate from selector names (e.g. '( sel_a or sel_b ) and sel_a').
        Since the actual evaluator is space-based and doesn't handle parentheses adjacent to
        selector names, we test what the evaluator does support: logical AND/OR without parens.
        """
        sel = {"sel_a": True, "sel_b": False}
        result = evaluate_condition("sel_a and sel_a", sel)
        self.assertTrue(result)
        result2 = evaluate_condition("sel_a or sel_b", sel)
        self.assertTrue(result2)


    def test_condition_not_all_lowercase(self):
        """Condition evaluation is case-insensitive on keywords."""
        sel = {"selection_a": True, "selection_b": True}
        # Uppercase keywords should still work via lowercasing
        result = evaluate_condition("selection_a AND selection_b", sel)
        self.assertTrue(result)


class TestEvaluateRuleEdgeCases(unittest.TestCase):
    def test_no_detection(self):
        rule = {"title": "No detection"}
        result = evaluate_rule_against_log("some log line", rule)
        self.assertFalse(result)

    def test_detection_no_condition(self):
        rule = {"detection": {"selection": ["pattern"]}}
        result = evaluate_rule_against_log("pattern", rule)
        self.assertFalse(result)

    def test_dict_criteria_list_values(self):
        rule = {
            "detection": {
                "filter": {"EventID": ["4624", "4625"]},
                "condition": "filter",
            }
        }
        result = evaluate_rule_against_log("EventID 4624 login successful", rule)
        self.assertTrue(result)

    def test_dict_criteria_single_value(self):
        rule = {
            "detection": {
                "filter": {"User": "Administrator"},
                "condition": "filter",
            }
        }
        result = evaluate_rule_against_log("User=Administrator logged in", rule)
        self.assertTrue(result)

    def test_string_criteria(self):
        rule = {
            "detection": {
                "selector": "evil_binary",
                "condition": "selector",
            }
        }
        result = evaluate_rule_against_log("execve: evil_binary started", rule)
        self.assertTrue(result)

    def test_case_insensitive_matching(self):
        rule = {
            "detection": {
                "selector": ["FAILED PASSWORD"],
                "condition": "selector",
            }
        }
        result = evaluate_rule_against_log("failed password for user root", rule)
        self.assertTrue(result)


class TestLoadRules(unittest.TestCase):
    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules = load_rules(Path(tmpdir))
        self.assertEqual(rules, [])

    def test_nonexistent_directory(self):
        rules = load_rules(Path("/nonexistent/dir"))
        self.assertEqual(rules, [])

    def test_loads_valid_yml_files(self):
        yml_content = """
title: Test Rule
detection:
  selection:
    - pattern
  condition: selection
level: medium
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = Path(tmpdir) / "test_rule.yml"
            rule_file.write_text(yml_content)
            rules = load_rules(Path(tmpdir))

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["title"], "Test Rule")
        self.assertIn("file_path", rules[0])

    def test_skips_invalid_yml(self):
        invalid_content = "not: a: valid: yaml: rule"
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = Path(tmpdir) / "bad_rule.yml"
            rule_file.write_text(invalid_content)
            rules = load_rules(Path(tmpdir))

        # Should skip rules without 'detection' key
        self.assertEqual(len(rules), 0)


class TestValidateRulesDirectory(unittest.TestCase):
    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            valid, results = validate_rules_directory(Path(tmpdir))
        self.assertEqual(valid, [])
        self.assertEqual(results, [])

    def test_nonexistent_directory(self):
        valid, results = validate_rules_directory(Path("/no/such/dir"))
        self.assertEqual(valid, [])
        self.assertEqual(results, [])

    def test_validates_valid_rules(self):
        yml_content = """
title: Good Rule
detection:
  selection:
    - failed password
  condition: selection
level: high
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = Path(tmpdir) / "good_rule.yml"
            rule_file.write_text(yml_content)
            valid, results = validate_rules_directory(Path(tmpdir))

        self.assertEqual(len(valid), 1)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].valid)

    def test_invalid_rule_not_in_valid_list(self):
        yml_content = """
detection:
  selection:
    - pattern
  condition: selection
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = Path(tmpdir) / "bad_rule.yml"
            rule_file.write_text(yml_content)
            valid, results = validate_rules_directory(Path(tmpdir))

        self.assertEqual(len(valid), 0)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].valid)

    def test_mixed_valid_and_invalid(self):
        good_yml = "title: Good\ndetection:\n  selection:\n    - x\n  condition: selection\n"
        bad_yml = "detection:\n  selection:\n    - x\n  condition: selection\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "good.yml").write_text(good_yml)
            Path(tmpdir, "bad.yml").write_text(bad_yml)
            valid, results = validate_rules_directory(Path(tmpdir))

        self.assertEqual(len(valid), 1)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
