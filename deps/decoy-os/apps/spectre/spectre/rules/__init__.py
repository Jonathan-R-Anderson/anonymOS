"""
Spectre Rules Package - Behavioral Detection Rules
"""

from .compiler import (
    CompilationResult,
    SigmaCompiler,
    compile_sigma_file,
    compile_sigma_rule,
    compile_sigma_string,
)
from .core import (
    DEFAULT_RULES,
    BehavioralRule,
    MitreMapping,
    load_rules_from_file,
)
from .field_mapper import SIGMA_TO_SPECTRE_FIELDS, extract_mitre_from_tags, map_sigma_field

# Phase 1: Sigma integration
from .sigma_parser import SigmaParser, SigmaRule, parse_sigma_file, parse_sigma_string

__all__ = [
    "MitreMapping",
    "BehavioralRule",
    "DEFAULT_RULES",
    "load_rules_from_file",
    # Sigma integration
    "SigmaParser",
    "SigmaRule",
    "parse_sigma_file",
    "parse_sigma_string",
    "map_sigma_field",
    "extract_mitre_from_tags",
    "SIGMA_TO_SPECTRE_FIELDS",
    "SigmaCompiler",
    "compile_sigma_rule",
    "compile_sigma_file",
    "compile_sigma_string",
    "CompilationResult",
]
