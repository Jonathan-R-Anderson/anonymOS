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
# src/orin/main.py
"""
Orin – Production-Grade Offline Forensic Investigation & Integrity Engine
========================================================================
Main CLI entrypoint coordinating initialization, telemetry collection,
threat rules analysis, and server management.
"""
import sys
from orin.core.logging import configure_logging, get_logger, INFO
from orin.core.config import load_config
from orin.cli import parse_args
from orin.orchestrator import run_orchestration

# Import orchestrator functions to maintain backward compatibility in case they are imported from main
from orin.orchestrator import (
    cmd_init,
    cmd_collect,
    cmd_analyze,
    cmd_report,
    cmd_serve,
    cmd_schedule,
    cmd_self_defense,
    cmd_scan,
    cmd_baseline,
    cmd_correlate,
    cmd_delta,
    cmd_diff,
    cmd_export,
    cmd_verify,
    cmd_stream,
    cmd_vault,
    cmd_rules,
    cmd_doctor,
    cmd_collectors
)

# Reference them to prevent pyflakes unused import warnings
_unused_exports = (
    cmd_init,
    cmd_collect,
    cmd_analyze,
    cmd_report,
    cmd_serve,
    cmd_schedule,
    cmd_self_defense,
    cmd_scan,
    cmd_baseline,
    cmd_correlate,
    cmd_delta,
    cmd_diff,
    cmd_export,
    cmd_verify,
    cmd_stream,
    cmd_vault,
    cmd_rules,
    cmd_doctor,
    cmd_collectors
)


__all__ = [
    'cmd_init',
    'cmd_collect',
    'cmd_analyze',
    'cmd_report',
    'cmd_serve',
    'cmd_schedule',
    'cmd_self_defense',
    'cmd_scan',
    'cmd_baseline',
    'cmd_correlate',
    'cmd_delta',
    'cmd_diff',
    'cmd_export',
    'cmd_verify',
    'cmd_stream',
    'cmd_vault',
    'cmd_rules',
    'cmd_doctor',
    'cmd_collectors',
    'main'
]

def main():
    # Load configuration and initialize structured logging
    config = load_config()
    args = parse_args()

    log_config = config.get("logging", {})
    log_level_str = args.log_level or log_config.get("level", "INFO")
    log_level = getattr(sys.modules['logging'], log_level_str, INFO)
    output_file = args.log_file if args.log_file is not None else log_config.get("output_file")
    output_stderr = not args.no_stderr_log and log_config.get("output_stderr", True)

    configure_logging(
        level=log_level,
        output_stderr=output_stderr,
        output_file=output_file,
        max_bytes=log_config.get("max_bytes", 10485760),
        backup_count=log_config.get("backup_count", 5)
    )

    logger = get_logger()
    logger.info("Orin engine starting", component="main")

    run_orchestration(args)

if __name__ == "__main__":
    main()