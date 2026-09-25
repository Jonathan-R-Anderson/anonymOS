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
# src/orin/cli.py
"""
orin.cli – Command Line Interface argument parser
=================================================
"""
import argparse

def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="Orin Engine – Fully Offline Forensic Collection & Threat Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Global top-level arguments shared across commands
    parser.add_argument(
        "-d", "--database",
        default="orin_vault.db",
        help="Path location to the localized Orin SQLite vault engine file"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Override logging level from config file"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Override log file path from config file"
    )
    parser.add_argument(
        "--no-stderr-log",
        action="store_true",
        default=False,
        help="Disable stderr logging output"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, title="Engine Core Commands")

    # 1. 'init' command mapping
    init_parser = subparsers.add_parser("init", help="Establish secure vault and register initial system baselines")
    init_parser.add_argument(
        "--read-only",
        action="store_true",
        default=False,
        help="Enable read-only mode (prevents any writes to the vault)"
    )

    # 2. 'collect' command mapping
    collect_parser = subparsers.add_parser("collect", help="Execute an out-of-band granular telemetry capture iteration loop")
    collect_parser.add_argument(
        "--read-only",
        action="store_true",
        default=False,
        help="Enable forensic acquisition mode on write-protected systems (no data stored to vault)"
    )
    collect_parser.add_argument(
        "--vault-path",
        type=str,
        default=None,
        help="Override the default vault/database path for this operation"
    )
    collect_parser.add_argument(
        "--parallel",
        action="store_true",
        default=False,
        help="Enable parallel collection using thread pool for independent collectors"
    )
    collect_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker threads for parallel collection (default: CPU count + 4, max 32)"
    )
    collect_parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Timeout in seconds per collector in parallel mode (default: 300s)"
    )
    collect_parser.add_argument(
        "--privilege",
        choices=["user", "root"],
        default=None,
        help="Only run collectors requiring this privilege level or lower"
    )
    collect_parser.add_argument(
        "--max-impact",
        choices=["low", "medium", "high"],
        default=None,
        help="Only run collectors with this runtime impact score or lower"
    )

    # 3. 'analyze' command mapping
    subparsers.add_parser("analyze", help="Evaluate the current snapshot against threat models and calculate risk indexing")

    # 4. 'report' command mapping
    report_parser = subparsers.add_parser("report", help="Generate standalone offline human-readable briefs")
    report_parser.add_argument(
        "-o", "--output",
        required=True,
        help="Target filesystem path where the briefing will be compiled"
    )
    report_parser.add_argument(
        "-f", "--format",
        choices=["markdown", "html"],
        default="html",
        help="Target output design language rendering template"
    )

    # 5. 'serve' command mapping
    serve_parser = subparsers.add_parser("serve", help="Launch the localized HTTP dashboard server console")
    serve_parser.add_argument(
        "port",
        type=int,
        nargs="?",
        default=8000,
        help="Port to bind the HTTP server (default: 8000)"
    )
    serve_parser.add_argument(
        "--port",
        dest="port_opt",
        type=int,
        default=None,
        help="Port to bind the HTTP server (overrides positional port)"
    )
    serve_parser.add_argument(
        "-H", "--host",
        default="127.0.0.1",
        help="Host address to bind the HTTP server"
    )
    serve_parser.add_argument(
        "--cert",
        default=None,
        help="Path to SSL certificate for HTTPS"
    )
    serve_parser.add_argument(
        "--key",
        default=None,
        help="Path to SSL private key for HTTPS"
    )
    serve_parser.add_argument(
        "--username",
        default=None,
        help="Username for Basic Authentication (alternative to auto-token)"
    )
    serve_parser.add_argument(
        "--password",
        default=None,
        help="Password for Basic Authentication (alternative to auto-token)"
    )
    serve_parser.add_argument(
        "--no-auth",
        dest="no_auth",
        action="store_true",
        default=False,
        help="Disable authentication entirely (use only on trusted private networks)"
    )
    # Vault passphrase loading options
    serve_parser.add_argument(
        "--passphrase-file",
        dest="passphrase_file",
        default=None,
        help="Path to file containing vault passphrase (reduces shell history exposure)"
    )
    serve_parser.add_argument(
        "--passphrase-prompt",
        dest="passphrase_prompt",
        action="store_true",
        default=False,
        help="Interactively prompt for vault passphrase with masked input"
    )
    serve_parser.add_argument(
        "--passphrase-env-var",
        dest="passphrase_env_var",
        default=None,
        help="Custom environment variable name for vault passphrase (default: ORIN_VAULT_PASSPHRASE)"
    )
    # Session token file storage option
    serve_parser.add_argument(
        "--token-file",
        dest="token_file",
        default=None,
        help="Path to save/load session token file with restricted permissions (0600)"
    )

    # 5b. 'hub-serve' command mapping (Centralized air-gapped fleet hub)
    hub_serve_parser = subparsers.add_parser("hub-serve", help="Launch centralized air-gapped fleet hub server for multi-tenant forensic management")
    hub_serve_parser.add_argument(
        "port",
        type=int,
        nargs="?",
        default=8000,
        help="Port to bind the Hub server (default: 8000)"
    )
    hub_serve_parser.add_argument(
        "--port",
        dest="port_opt",
        type=int,
        default=None,
        help="Port to bind the Hub server (overrides positional port)"
    )
    hub_serve_parser.add_argument(
        "-H", "--host",
        default="0.0.0.0",
        help="Host address to bind the Hub server (default: 0.0.0.0)"
    )
    hub_serve_parser.add_argument(
        "--cert",
        default=None,
        help="Path to SSL certificate for HTTPS"
    )
    hub_serve_parser.add_argument(
        "--key",
        default=None,
        help="Path to SSL private key for HTTPS"
    )
    hub_serve_parser.add_argument(
        "--no-auth",
        dest="no_auth",
        action="store_true",
        default=False,
        help="Disable authentication entirely (use only on trusted private networks)"
    )
    # Vault passphrase loading options
    hub_serve_parser.add_argument(
        "--passphrase-file",
        dest="passphrase_file",
        default=None,
        help="Path to file containing vault passphrase"
    )
    hub_serve_parser.add_argument(
        "--passphrase-prompt",
        dest="passphrase_prompt",
        action="store_true",
        default=False,
        help="Interactively prompt for vault passphrase with masked input"
    )
    hub_serve_parser.add_argument(
        "--passphrase-env-var",
        dest="passphrase_env_var",
        default=None,
        help="Custom environment variable name for vault passphrase"
    )
    hub_serve_parser.add_argument(
        "--token-file",
        dest="token_file",
        default=None,
        help="Path to save/load session token file with restricted permissions (0600)"
    )

    # 6. 'schedule' command mapping
    schedule_parser = subparsers.add_parser("schedule", help="Manage automated recurring forensic collection scheduling")
    schedule_group = schedule_parser.add_mutually_exclusive_group()
    schedule_group.add_argument(
        "--install",
        action="store_true",
        help="Install recurring cron task to automate collect and analyze operations"
    )
    schedule_group.add_argument(
        "--remove",
        action="store_true",
        help="Remove active Orin collection automation schedules"
    )
    schedule_group.add_argument(
        "--status",
        action="store_true",
        help="Query current scheduling status and active cron configuration logs"
    )
    schedule_parser.add_argument(
        "-i", "--interval",
        type=int,
        default=10,
        help="Execution interval in minutes (only applicable with --install)"
    )
    schedule_parser.add_argument(
        "--retention",
        type=str,
        default=None,
        help="Automatic vault retention policy (e.g., '30d' for 30 days). Enables automatic pruning after each collection."
    )

    # 7. 'scan' command mapping
    scan_parser = subparsers.add_parser("scan", help="Execute an agentless remote SSH security scan")
    scan_parser.add_argument(
        "--host",
        required=True,
        help="Target hostname or IP address to connect to"
    )
    scan_parser.add_argument(
        "--user",
        required=True,
        help="SSH username for authentication"
    )
    scan_parser.add_argument(
        "--key",
        help="Path to private SSH key for authentication"
    )
    scan_parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="SSH port of the remote host"
    )
    scan_parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize baseline for the remote host instead of scanning for drift"
    )
    scan_parser.add_argument(
        "--no-strict-host-keys",
        action="store_true",
        help="Disable SSH host key verification (NOT recommended for production). Default: strict verification enabled."
    )
    scan_parser.add_argument(
        "--known-hosts-file",
        help="Custom path to SSH known_hosts file. Uses default ~/.ssh/known_hosts if not specified."
    )

    # 8. 'baseline' command mapping
    baseline_parser = subparsers.add_parser("baseline", help="Manage system configuration baselines")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command", required=True)

    # baseline add
    add_parser = baseline_subparsers.add_parser("add", help="Add a specific resource to the trusted baseline")
    add_group = add_parser.add_mutually_exclusive_group(required=True)
    add_group.add_argument("--user", help="Username of the user account to baseline")
    add_group.add_argument("--module", help="Name of the kernel module to baseline")
    add_group.add_argument("--suid", help="File path of the SUID/SGID binary to baseline")
    add_parser.add_argument("--host", help="Target hostname to apply baseline change (defaults to local host)")

    # baseline refresh
    refresh_parser = baseline_subparsers.add_parser("refresh", help="Refresh baseline configuration using the latest snapshot state")
    refresh_parser.add_argument("--host", help="Target hostname to refresh (defaults to local host)")
    refresh_parser.add_argument("--force-overwrite", action="store_true", help="Overwrite the baseline completely instead of appending")

    # diff parser
    parser_diff = subparsers.add_parser('diff', help='Compare two database files or exports')
    parser_diff.add_argument('base_file', help='Base snapshot file (.db or .json)')
    parser_diff.add_argument('target_file', help='Target snapshot file (.db or .json)')
    parser_diff.add_argument('--secret', help='Passphrase for signed JSON exports (insecure command line)')
    parser_diff.add_argument('--secret-file', help='Path to file containing passphrase for signed JSON exports')
    parser_diff.add_argument('--secret-prompt', action='store_true', help='Interactively prompt for passphrase')
    parser_diff.add_argument('--secret-env-var', help='Custom environment variable name containing passphrase (default: ORIN_EXPORT_SECRET)')
    parser_diff.add_argument('-v', '--verbose', action='store_true', help='Show full report')

    # delta parser
    parser_delta = subparsers.add_parser('delta', help='Compare two snapshots by ID')
    parser_delta.add_argument('--base', required=True, help='Base snapshot ID')
    parser_delta.add_argument('--target', required=True, help='Target snapshot ID')
    parser_delta.add_argument('--database', help='Path to database file')
    parser_delta.add_argument('-v', '--verbose', action='store_true', help='Show full diff')

    # export parser
    parser_export = subparsers.add_parser('export', help='Export snapshot to signed JSON')
    parser_export.add_argument('--snapshot', required=True, help='Snapshot ID to export')
    parser_export.add_argument('--secret', help='Passphrase for signing (insecure command line)')
    parser_export.add_argument('--secret-file', help='Path to file containing passphrase for signing')
    parser_export.add_argument('--secret-prompt', action='store_true', help='Interactively prompt for passphrase')
    parser_export.add_argument('--secret-env-var', help='Custom environment variable name containing passphrase (default: ORIN_EXPORT_SECRET)')
    parser_export.add_argument('--output', '-o', help='Output file path')
    parser_export.add_argument('--database', help='Path to database file')

    # verify parser
    parser_verify = subparsers.add_parser('verify', help='Verify signed export bundle')
    parser_verify.add_argument('--file', '-f', required=True, help='Export file to verify')
    parser_verify.add_argument('--secret', help='Passphrase for verification (insecure command line)')
    parser_verify.add_argument('--secret-file', help='Path to file containing passphrase for verification')
    parser_verify.add_argument('--secret-prompt', action='store_true', help='Interactively prompt for passphrase')
    parser_verify.add_argument('--secret-env-var', help='Custom environment variable name containing passphrase (default: ORIN_EXPORT_SECRET)')

    # 'self-defense' command mapping
    self_defense_parser = subparsers.add_parser("self-defense", help="Manage Orin agent self-defense mechanisms (watchdog, seccomp, AppArmor, SELinux)")
    self_defense_parser.add_argument(
        "--action",
        choices=["watchdog", "heartbeat", "generate-profiles", "status"],
        default="status",
        help="Self-defense action to perform"
    )
    self_defense_parser.add_argument(
        "--socket",
        default="/var/run/orin/watchdog.sock",
        help="Unix socket path for watchdog communication"
    )
    self_defense_parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Health check interval in seconds"
    )
    self_defense_parser.add_argument(
        "--output-dir",
        default="/etc/orin/security",
        help="Output directory for security profiles"
    )

    # 'correlate' command mapping
    correlate_parser = subparsers.add_parser("correlate", help="Run local AI multi-host triage and correlation")
    correlate_parser.add_argument(
        "--host",
        nargs="+",
        help="List of hostnames to correlate (default: all hosts in snapshot DB)"
    )
    correlate_parser.add_argument(
        "--url",
        default="http://127.0.0.1:11434",
        help="Ollama API base URL"
    )
    correlate_parser.add_argument(
        "--model",
        default="gemma3:1b",
        help="Ollama model name to run"
    )
    correlate_parser.add_argument(
        "-o", "--output",
        help="Path to save the generated Markdown report"
    )

    # 'stream' command mapping - eBPF Real-Time Streamer
    stream_parser = subparsers.add_parser("stream", help="Launch eBPF real-time telemetry streaming via ring buffer")
    stream_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug output"
    )

    # 'vault' command mapping - Vault Lifecycle Management
    vault_parser = subparsers.add_parser("vault", help="Manage forensic vault lifecycle (prune, stats)")
    vault_subparsers = vault_parser.add_subparsers(dest="vault_command", required=True)

    # vault stats - stats command handled inline
    vault_subparsers.add_parser("stats", help="Display vault statistics (size, snapshot count, age)")

    # vault prune
    vault_prune_parser = vault_subparsers.add_parser("prune", help="Delete old snapshots and related data")
    vault_prune_group = vault_prune_parser.add_mutually_exclusive_group(required=True)
    vault_prune_group.add_argument(
        "--older-than",
        type=int,
        help="[Legacy mode] Delete snapshots older than this many days"
    )
    vault_prune_group.add_argument(
        "--policy-file",
        type=str,
        metavar="POLICY_JSON",
        help="[Granular mode] Path to JSON file defining per-type retention policies"
    )
    vault_prune_group.add_argument(
        "--keep-last",
        type=int,
        help="[Count-based mode] Keep only the latest N snapshots per host and delete older ones"
    )
    vault_prune_parser.add_argument(
        "--no-preserve-critical",
        dest="preserve_critical",
        action="store_false",
        default=True,
        help="Disable critical alert preservation during pruning"
    )
    vault_prune_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be deleted without actually deleting"
    )
    vault_prune_parser.add_argument(
        "--execute",
        dest="execute",
        action="store_true",
        default=False,
        help="Actually execute the deletion (default: dry-run mode)"
    )

    # Rules management command
    rules_parser = subparsers.add_parser("rules", help="Manage Sigma and YARA rule repositories")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)

    # orin rules update --sigma <path> | --yara <path>
    rules_update_parser = rules_subparsers.add_parser("update", help="Update rules from offline directory")
    rules_update_parser.add_argument(
        "--sigma",
        type=str,
        metavar="SIGMA_DIR",
        help="Path to directory containing Sigma rules (.yml files)"
    )
    rules_update_parser.add_argument(
        "--yara",
        type=str,
        metavar="YARA_DIR",
        help="Path to directory containing YARA rules (.yar files)"
    )
    rules_update_parser.add_argument(
        "--validate-only",
        action="store_true",
        default=False,
        help="Only validate rules without installing them"
    )

    # orin rules list --sigma | --yara
    rules_list_parser = rules_subparsers.add_parser("list", help="List active rules with descriptions")
    rules_list_parser.add_argument(
        "--sigma",
        action="store_true",
        default=False,
        help="List Sigma rules"
    )
    rules_list_parser.add_argument(
        "--yara",
        action="store_true",
        default=False,
        help="List YARA rules"
    )
    rules_list_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show detailed information including operators and MITRE mappings"
    )

    # orin rules validate --sigma <path> | --yara <path>
    rules_validate_parser = rules_subparsers.add_parser("validate", help="Validate rule syntax and schema")
    rules_validate_parser.add_argument(
        "--sigma",
        type=str,
        metavar="SIGMA_PATH",
        help="Path to Sigma rule file or directory to validate"
    )
    rules_validate_parser.add_argument(
        "--yara",
        type=str,
        metavar="YARA_PATH",
        help="Path to YARA rule file or directory to validate"
    )
    rules_validate_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Fail on warnings in addition to errors"
    )

    # Version command with --sbom flag
    version_parser = subparsers.add_parser("version", help="Display Orin version information")
    version_parser.add_argument(
        "--sbom",
        action="store_true",
        default=False,
        help="Display embedded Software Bill of Materials (SBOM)"
    )
    version_parser.add_argument(
        "--self-check",
        action="store_true",
        default=False,
        help="Perform self-integrity check against embedded signatures"
    )
    version_parser.add_argument(
        "--generate-manifest",
        action="store_true",
        default=False,
        help="Generate a release manifest with SHA-256 hashes"
    )
    version_parser.add_argument(
        "--sign-manifest",
        type=str,
        metavar="MANIFEST_PATH",
        help="Sign a release manifest with GPG"
    )
    version_parser.add_argument(
        "--verify-manifest",
        type=str,
        metavar="MANIFEST_PATH",
        help="Verify a release manifest against GPG signature"
    )

    # Doctor command
    doctor_parser = subparsers.add_parser("doctor", help="Execute host environment verification diagnostics")
    doctor_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Fail on warning checks in addition to errors"
    )

    # Collectors command
    collectors_parser = subparsers.add_parser("collectors", help="Query and list telemetry collectors and their requirements")
    collectors_subparsers = collectors_parser.add_subparsers(dest="subcommand", required=True, title="Collector Subcommands")

    list_parser = collectors_subparsers.add_parser("list", help="List all registered collectors, privilege levels, and runtime impact")
    list_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format template"
    )

    show_parser = collectors_subparsers.add_parser("show", help="Show detailed metadata about a specific collector")
    show_parser.add_argument(
        "collector_name",
        type=str,
        help="Name of the collector to query"
    )

    return parser.parse_args(args)
