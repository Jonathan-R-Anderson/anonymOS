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
"""
orin.analysis – Threat Detection & Reporting Layer
===================================================
Consumes the raw telemetry stored in the Orin SQLite vault and produces
structured security findings, drift reports, and human-readable output.

Modules
-------
engine      – Core rules-based analysis cycle that emits ``security_events``.
diff        – Cross-file snapshot comparator (supports both SQLite and signed
              JSON export inputs).
reporter    – Markdown and HTML report compilers for audit briefings.
timeline    – Point-in-time delta calculator between two snapshot IDs.
sigma       – Sigma rule parser and evaluator for log analysis.
yara_engine – Embedded YARA pattern matching engine for malware detection.
"""


from .yara_engine import (
    YaraEngine,
    YaraMatch,
    YaraScanResult,
    run_yara_scan,
    create_sample_yara_rules,
)

__all__ = [
    "YaraEngine",
    "YaraMatch",
    "YaraScanResult",
    "run_yara_scan",
    "create_sample_yara_rules",
]