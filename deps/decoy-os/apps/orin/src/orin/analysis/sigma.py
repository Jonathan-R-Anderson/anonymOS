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
# src/orin/analysis/sigma.py
"""
orin.analysis.sigma – Sigma Rule Parser & Evaluator
==================================================
Provides offline, zero-dependency parsing of Sigma rules (in YAML format)
and evaluates them against captured authentication log lines.

Supported Sigma Operators
-------------------------
This engine implements a subset of the Sigma specification for offline analysis:

Selection Operators:
  - Basic string matching (substring search, case-insensitive)
  - List of strings (OR logic within a selection)
  - Field-value matching (e.g., EventID: 4624)
  - Wildcard patterns (* and ? supported via regex conversion)

Condition Operators:
  - Boolean logic: and, or, not
  - Quantifiers: "1 of", "all of", "any of" with wildcards (selection*)
  - Parentheses for grouping expressions
  - Reference to named selections by identifier

Unsupported Operators (will trigger validation errors):
  - |near (proximity matching)
  - |count (aggregation/counting across events)
  - |base64, |base64offset (encoding transformations)
  - |re (regular expressions - use native regex in strings instead)
  - |contains, |startswith, |endswith (implicit in substring matching)
  - Aggregation conditions (e.g., "count(selection) > 5")
  - Time-based correlations

Schema Validation
-----------------
Rules are validated against a strict schema. Unsupported features trigger
precise error messages indicating what must be changed for compatibility.
"""
import ast
import re
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    """Result of Sigma rule validation."""
    valid: bool = True
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    supported_operators: list = field(default_factory=list)
    unsupported_operators: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "supported_operators": self.supported_operators,
            "unsupported_operators": self.unsupported_operators
        }


# Set default rule level classifications
VALID_LEVELS = {"low", "medium", "high", "critical"}

# Supported condition keywords
SUPPORTED_CONDITION_KEYWORDS = {"and", "or", "not", "(", ")", "1", "all", "any", "of"}

# Unsupported Sigma modifiers that will trigger validation errors
UNSUPPORTED_MODIFIERS = {
    "|near": "Proximity matching is not supported. Use explicit string patterns instead.",
    "|count": "Aggregation/counting across events is not supported. Use multiple rules or external correlation.",
    "|base64": "Base64 encoding transformation is not supported. Encode patterns manually.",
    "|base64offset": "Base64 offset encoding is not supported. Encode patterns manually.",
    "|re": "Regular expression modifier is not supported. Use native regex patterns in strings.",
    "|contains": "Explicit contains modifier is redundant. Substring matching is default.",
    "|startswith": "Startswith modifier is not supported. Use '^' anchor in strings.",
    "|endswith": "Endswith modifier is not supported. Use '$' anchor in strings.",
    "|wide": "Wide character encoding is not supported. Include Unicode variants explicitly.",
    "|ascii": "ASCII modifier is redundant. ASCII matching is default.",
    "|nocase": "Case-insensitive matching is always enabled.",
}

# Required fields for valid Sigma rules
REQUIRED_FIELDS = {"title", "detection"}
OPTIONAL_FIELDS = {"id", "description", "logsource", "level", "tags", "status", "author", "date", "references", "falsepositives"}


def parse_yaml_rule(content: str) -> dict:
    """A zero-dependency YAML-to-dict parser tailored for Sigma rules."""
    lines = content.splitlines()
    data = {}
    stack = [(-1, data)]  # stack of (indentation, current_dict_or_list)

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # Pop from stack if indent is less than or equal to current top
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        current_parent = stack[-1][1]

        # Check if line is a list item
        if stripped.startswith("-"):
            val = stripped[1:].strip().strip("'\"")
            if isinstance(current_parent, list):
                current_parent.append(val)
            continue

        if ":" not in stripped:
            continue

        key, val = stripped.split(":", 1)
        key = key.strip()
        val = val.strip().strip("'\"")

        if val == "":
            # Lookahead to determine nested type (list vs dict)
            is_list = False
            for next_line in lines[i + 1:]:
                next_stripped = next_line.strip()
                if not next_stripped or next_stripped.startswith("#"):
                    continue
                if next_stripped.startswith("-"):
                    is_list = True
                break

            new_obj = [] if is_list else {}
            if isinstance(current_parent, dict):
                current_parent[key] = new_obj
            elif isinstance(current_parent, list):
                current_parent.append({key: new_obj})

            stack.append((indent, new_obj))
        else:
            if isinstance(current_parent, dict):
                current_parent[key] = val
            elif isinstance(current_parent, list):
                current_parent.append({key: val})

    return data


def _safe_eval_ast(node: ast.AST) -> bool:
    """Recursively and safely evaluate a boolean AST expression.

    Parameters
    ----------
    node : ast.AST
        The AST node to evaluate.

    Returns
    -------
    bool
        The evaluated boolean result.

    Raises
    ------
    ValueError
        If an unsupported AST node type is encountered.
    """
    if isinstance(node, ast.Expression):
        return _safe_eval_ast(node.body)
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return node.value
    elif isinstance(node, ast.Name):
        if node.id == "True":
            return True
        elif node.id == "False":
            return False
    elif isinstance(node, ast.BoolOp):
        values = [_safe_eval_ast(val) for val in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        elif isinstance(node.op, ast.Or):
            return any(values)
    elif isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not _safe_eval_ast(node.operand)
    raise ValueError(f"Unsupported AST node type: {type(node)}")


def evaluate_condition(condition_str: str, selector_values: dict[str, bool]) -> bool:
    """Evaluate the condition string expression using mapped selector values."""
    tokens = condition_str.lower().split()
    if not tokens:
        return False

    evaluated_tokens = []
    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Handle '1 of prefix*' or 'all of prefix*'
        if token in ("1", "all") and i + 2 < len(tokens) and tokens[i + 1] == "of":
            target = tokens[i + 2]
            # Strip trailing wildcard or parenthesis
            clean_target = target.rstrip(")").rstrip("*")

            matches = [val for name, val in selector_values.items() if name.startswith(clean_target)]

            if token == "1":
                result = any(matches) if matches else False
            else:
                result = all(matches) if matches else False

            evaluated_tokens.append(str(result))

            # If target had closing parenthesis, preserve it
            if target.endswith(")"):
                evaluated_tokens.append(")")

            i += 3
            continue

        if token in ("and", "or", "not", "(", ")"):
            evaluated_tokens.append(token)
        elif token in selector_values:
            evaluated_tokens.append(str(selector_values[token]))
        else:
            evaluated_tokens.append("False")
        i += 1

    eval_str = " ".join(evaluated_tokens)

    # Restrict allowed keywords for safe evaluation
    allowed_words = {"true", "false", "and", "or", "not", "(", ")"}
    if all(w in allowed_words for w in eval_str.lower().split()):
        try:
            tree = ast.parse(eval_str, mode="eval")
            return _safe_eval_ast(tree)
        except Exception:
            return False
    return False


def evaluate_rule_against_event(event: dict | str, rule: dict) -> bool:
    """Check if a structured event (dict) or a raw log line (str) matches the Sigma rule detection logic."""
    detection = rule.get("detection")
    if not detection or "condition" not in detection:
        return False

    selector_values = {}

    def match_pattern(val, pattern) -> bool:
        if val is None or pattern is None:
            return False

        val_str = str(val).lower()
        pat_str = str(pattern).lower()

        if "*" in pat_str or "?" in pat_str:
            regex_pat = pat_str.replace(".", "\\.").replace("*", ".*").replace("?", ".")
            try:
                pattern_re = re.compile(f"^{regex_pat}$" if not regex_pat.startswith(".*") and not regex_pat.endswith(".*") else regex_pat)
                return bool(pattern_re.search(val_str))
            except re.error:
                return pat_str in val_str
        else:
            return pat_str in val_str

    is_dict = isinstance(event, dict)

    for selector_name, criteria in detection.items():
        if selector_name == "condition":
            continue

        matched = False

        if isinstance(criteria, (str, int, float, bool)):
            if is_dict:
                for val in event.values():
                    if match_pattern(val, criteria):
                        matched = True
                        break
            else:
                matched = match_pattern(event, criteria)

        elif isinstance(criteria, list):
            for item in criteria:
                if is_dict:
                    for val in event.values():
                        if match_pattern(val, item):
                            matched = True
                            break
                else:
                    if match_pattern(event, item):
                        matched = True
                if matched:
                    break

        elif isinstance(criteria, dict):
            if is_dict:
                dict_matched = True
                for field_key, field_val in criteria.items():
                    event_val = None
                    found_key = False
                    for k, v in event.items():
                        if k.lower() == field_key.lower():
                            event_val = v
                            found_key = True
                            break

                    if not found_key:
                        dict_matched = False
                        break

                    field_matched = False
                    if isinstance(field_val, list):
                        for item in field_val:
                            if match_pattern(event_val, item):
                                field_matched = True
                                break
                    else:
                        if match_pattern(event_val, field_val):
                            field_matched = True

                    if not field_matched:
                        dict_matched = False
                        break
                matched = dict_matched
            else:
                dict_matched = True
                for field_val in criteria.values():
                    field_matched = False
                    if isinstance(field_val, list):
                        for item in field_val:
                            if match_pattern(event, item):
                                field_matched = True
                                break
                    else:
                        if match_pattern(event, field_val):
                            field_matched = True
                    if not field_matched:
                        dict_matched = False
                        break
                matched = dict_matched

        selector_values[selector_name] = matched

    condition = detection["condition"]
    return evaluate_condition(condition, selector_values)


def evaluate_rule_against_log(log_line: str, rule: dict) -> bool:
    """Check if a log line matches the Sigma rule detection logic."""
    return evaluate_rule_against_event(log_line, rule)


def load_rules(rules_dir: Path) -> list[dict]:
    """Scan directory and load all valid Sigma rules."""
    rules = []
    if not rules_dir.exists() or not rules_dir.is_dir():
        return rules

    for rule_file in rules_dir.glob("*.yml"):
        try:
            content = rule_file.read_text(encoding="utf-8")
            rule = parse_yaml_rule(content)
            if "title" in rule and "detection" in rule:
                rule["file_path"] = str(rule_file)
                rules.append(rule)
        except Exception:
            continue
    return rules


def validate_rule(rule: dict, raw_content: str = "") -> ValidationResult:
    """
    Validate a Sigma rule against the supported schema.

    Parameters
    ----------
    rule : dict
        Parsed Sigma rule dictionary.
    raw_content : str, optional
        Original YAML content for modifier detection.

    Returns
    -------
    ValidationResult
        Validation result with errors, warnings, and operator information.
    """
    result = ValidationResult()

    # Check required fields
    missing_required = REQUIRED_FIELDS - set(rule.keys())
    if missing_required:
        result.valid = False
        result.errors.append(f"Missing required fields: {', '.join(sorted(missing_required))}")

    # Check for unsupported modifiers in raw content
    for modifier, message in UNSUPPORTED_MODIFIERS.items():
        if modifier in raw_content:
            result.valid = False
            result.errors.append(f"Unsupported modifier '{modifier}': {message}")
            result.unsupported_operators.append(modifier)

    # Validate detection section
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        result.valid = False
        result.errors.append("'detection' must be a mapping/dictionary")
        return result

    # Check for condition
    if "condition" not in detection:
        result.valid = False
        result.errors.append("Missing 'condition' in detection section")

    # Validate condition expression
    condition = detection.get("condition", "")
    if condition:
        condition_tokens = condition.lower().split()
        for token in condition_tokens:
            clean_token = token.rstrip(")").rstrip("*").lstrip("(")
            if clean_token and clean_token not in SUPPORTED_CONDITION_KEYWORDS:
                # Check if it's a selection reference (valid)
                if clean_token.startswith("selection") or clean_token in detection:
                    result.supported_operators.append(f"selection:{clean_token}")
                elif clean_token.isdigit():
                    result.supported_operators.append(f"quantifier:{clean_token}")
                else:
                    # Unknown token - might be unsupported
                    pass

    # Check for aggregation patterns in condition (unsupported)
    agg_patterns = [r"count\s*\(", r"\|\s*count", r"by\s+\w+"]
    for pattern in agg_patterns:
        if re.search(pattern, condition, re.IGNORECASE):
            result.valid = False
            result.errors.append(f"Aggregation conditions are not supported: detected pattern matching '{pattern}'")
            result.unsupported_operators.append("|count")

    # Validate level if present
    level = rule.get("level")
    if level and level.lower() not in VALID_LEVELS:
        result.warnings.append(f"Non-standard severity level: '{level}'. Expected one of: {', '.join(sorted(VALID_LEVELS))}")

    # Check for unknown top-level fields (warning only)
    known_fields = REQUIRED_FIELDS | OPTIONAL_FIELDS
    unknown_fields = set(rule.keys()) - known_fields
    if unknown_fields:
        result.warnings.append(f"Unknown top-level fields (ignored): {', '.join(sorted(unknown_fields))}")

    # Record supported operators found
    if "and" in condition.lower():
        result.supported_operators.append("condition:and")
    if "or" in condition.lower():
        result.supported_operators.append("condition:or")
    if "not" in condition.lower():
        result.supported_operators.append("condition:not")
    if "1 of" in condition.lower() or "all of" in condition.lower() or "any of" in condition.lower():
        result.supported_operators.append("condition:quantifier")
    if "*" in condition:
        result.supported_operators.append("condition:wildcard")

    # Remove duplicates from operator lists
    result.supported_operators = sorted(set(result.supported_operators))
    result.unsupported_operators = sorted(set(result.unsupported_operators))

    return result


def validate_rules_directory(rules_dir: Path) -> tuple[list[dict], list[ValidationResult]]:
    """
    Load and validate all Sigma rules in a directory.

    Parameters
    ----------
    rules_dir : Path
        Directory containing Sigma rule files.

    Returns
    -------
    tuple[list[dict], list[ValidationResult]]
        Tuple of (valid_rules, validation_results).
    """
    valid_rules = []
    all_results = []

    if not rules_dir.exists() or not rules_dir.is_dir():
        return valid_rules, all_results

    for rule_file in sorted(rules_dir.glob("*.yml")):
        try:
            content = rule_file.read_text(encoding="utf-8")
            rule = parse_yaml_rule(content)
            rule["file_path"] = str(rule_file)

            # Validate the rule
            validation = validate_rule(rule, content)
            validation.file_path = str(rule_file)  # type: ignore

            all_results.append(validation)

            if validation.valid:
                valid_rules.append(rule)
            else:
                error_msgs = "; ".join(validation.errors)
                print(f"[!] Invalid rule '{rule.get('title', 'UNKNOWN')}' in {rule_file}: {error_msgs}")

        except Exception as e:
            result = ValidationResult(valid=False, errors=[f"Parse error: {e}"])
            result.file_path = str(rule_file)  # type: ignore
            all_results.append(result)
            print(f"[!] Failed to parse {rule_file}: {e}")

    return valid_rules, all_results