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
# src/orin/orchestrator.py
"""
orin.orchestrator – Workflow Orchestrator
=========================================
Coordinating initialization, telemetry collection, threat rules analysis,
forensic reporting, and server management.
"""
import re
import os
import sys
import time
from pathlib import Path
import platform
import json

# Core database and configuration imports
from orin.analysis.sigma import parse_yaml_rule
from orin.core.database import OrinStorage

# Collector module imports
from orin.collectors.processes import gather_active_processes
from orin.collectors.connections import gather_listening_ports, gather_outbound_connections
from orin.collectors.kernel import (
    gather_loaded_kernel_modules,
    gather_kernel_symbols,
    analyze_kernel_symbol_overrides,
    check_for_unlinked_modules
)
from orin.collectors.users import gather_system_accounts
from orin.collectors.persistence import gather_active_ssh_keys
from orin.collectors.integrity import gather_file_integrity_signatures
from orin.collectors.deleted_binaries import gather_deleted_binaries
from orin.collectors.promisc import gather_promisc_interfaces
from orin.collectors.crontabs import gather_crontabs
from orin.collectors.session_audit import gather_wtmp_sessions, gather_lastlog_records
from orin.collectors.suid import gather_suid_binaries
from orin.collectors.logs import gather_auth_logs
from orin.collectors.ebpf import (
    gather_ebpf_programs,
    gather_ebpf_pinned,
    gather_ld_preload,
    gather_special_fds
)
from orin.collectors.privilege_audit import gather_all_privilege_events
from orin.collectors.services import gather_active_services
from orin.collectors.parallel import ParallelCollector
from orin.collectors.registry import (
    get_registered_collectors,
    check_privilege_satisfaction,
    COLLECTOR_REGISTRY
)

# Analysis and Reporting imports
from orin.analysis.engine import run_analysis_cycle
from orin.analysis.reporter import compile_markdown_report, compile_html_report
from orin.collectors.pkg_integrity import gather_pkg_integrity_drift
from orin.collectors.persistence import gather_system_persistence
from orin.collectors.dns_forensics import (
    gather_dns_queries,
    analyze_dns_patterns
)
from orin.core.self_defense import (
    SelfDefenseManager,
    WatchdogConfig,
)




def cmd_doctor(args):
    """Execute host environment health check diagnostics."""
    from orin.core.doctor import cmd_doctor as doctor_main
    doctor_main(args)


def cmd_self_defense(args):
    """Manage Orin agent self-defense mechanisms."""
    from orin.core.self_defense import main as self_defense_main

    # Delegate to self_defense module's CLI
    sys.argv = ['orin', 'self-defense'] + args._remaining_args if hasattr(args, '_remaining_args') else sys.argv[:2]
    self_defense_main()


def cmd_init(args):
    """Establish the local secure database architecture and capture trusted baselines."""
    db_path = Path(args.database)
    if getattr(args, 'read_only', False):
        print("[!] Read-only mode enabled - init operation skipped (cannot modify vault)", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Initializing Orin forensic vault at: {db_path}")

    storage = OrinStorage(db_path)
    storage.initialize_db()

    # Capture system baselines
    print("[*] Recording pristine system configuration baselines...")
    try:
        kernel_modules = gather_loaded_kernel_modules()
        system_users = gather_system_accounts()
        suid_binaries = gather_suid_binaries()
        hostname = platform.node() or "unknown_host"

        with storage.get_connection() as conn:
            if kernel_modules:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(hostname, m["module_name"], m["memory_size"]) for m in kernel_modules]
                )
            if system_users:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in system_users]
                )
            if suid_binaries:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in suid_binaries]
                )
            conn.commit()

        print(f"🟢 Success: Baseline initialized. Recorded {len(kernel_modules)} modules, {len(system_users)} accounts, and {len(suid_binaries)} SUID/SGID binaries.")
    except Exception as e:
        print(f"❌ Error: Baseline serialization failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_collect(args):
    """Execute a transaction-isolated telemetry acquisition sequence.

    Supports both sequential (default) and parallel collection modes.
    Use --parallel flag to enable concurrent collector execution with
    configurable worker threads and timeouts.
    """
    db_path = Path(args.database)

    # Support --vault-path override
    if hasattr(args, 'vault_path') and args.vault_path:
        db_path = Path(args.vault_path)

    read_only = getattr(args, 'read_only', False)
    use_parallel = getattr(args, 'parallel', False)
    max_workers = getattr(args, 'workers', None)
    collector_timeout = getattr(args, 'timeout', 300.0)

    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)

    if read_only:
        print(f"[*] Initiating READ-ONLY telemetry acquisition (forensic mode) on database: {db_path}")
    else:
        print(f"[*] Initiating telemetry acquisition phase on database: {db_path}")

    storage = OrinStorage(db_path)

    try:
        # 1. Open database connection handle and register system snapshot record
        with storage.get_connection() as conn:
            if not read_only:
                snapshot_id = storage.create_snapshot(conn)
                print(f"[+] Snapshot record assigned ID: #{snapshot_id}")
            else:
                # In read-only mode, get the latest snapshot ID for reference only
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(id) FROM system_snapshots;")
                result = cursor.fetchone()
                snapshot_id = result[0] if result and result[0] else None
                if snapshot_id:
                    print(f"[*] Using latest snapshot ID for reference: #{snapshot_id}")
                else:
                    print("[!] No snapshots exist in database - running in read-only forensics mode")
                snapshot_id = None  # Don't store new data against any snapshot in read-only mode

            # Retrieve active/allowed collectors based on user filters
            privilege_filter = getattr(args, 'privilege', None)
            max_impact_filter = getattr(args, 'max_impact', None)
            allowed_collectors_meta = get_registered_collectors(privilege_level=privilege_filter, max_impact=max_impact_filter)
            allowed_collector_names = {c.name for c in allowed_collectors_meta}

            skipped_count = len(COLLECTOR_REGISTRY) - len(allowed_collector_names)
            if skipped_count > 0:
                print(f"[*] Filtering enabled: skipped {skipped_count} collectors based on privilege/impact limits.")

            runs_log = {}

            # Helper to run sequential collector and log details
            def run_seq_collector(name, func, *args_func, **kwargs_func):
                if name not in allowed_collector_names:
                    return {} if name == "privilege_events" else []
                start_time = time.perf_counter()
                meta = COLLECTOR_REGISTRY.get(name)
                priv_level = meta.privilege_requirements if meta else "user"
                impact = meta.runtime_impact if meta else "low"
                try:
                    data = func(*args_func, **kwargs_func)
                    duration = time.perf_counter() - start_time
                    
                    if hasattr(data, '__len__'):
                        if isinstance(data, dict):
                            items_collected = sum(len(v) for v in data.values() if isinstance(v, list))
                        else:
                            items_collected = len(data)
                    else:
                        items_collected = 1

                    runs_log[name] = {
                        "collector_name": name,
                        "success": True,
                        "duration": duration,
                        "error_message": None,
                        "items_collected": items_collected,
                        "privilege_level": priv_level,
                        "runtime_impact": impact
                    }
                    return data
                except Exception as e:
                    duration = time.perf_counter() - start_time
                    runs_log[name] = {
                        "collector_name": name,
                        "success": False,
                        "duration": duration,
                        "error_message": f"{type(e).__name__}: {str(e)}",
                        "items_collected": 0,
                        "privilege_level": priv_level,
                        "runtime_impact": impact
                    }
                    return {} if name == "privilege_events" else []

            # Initialize all collector results
            processes = []
            ports = []
            outbound = []
            promisc = []
            modules = []
            symbols = []
            symbol_analysis = {"total_symbols": 0, "critical_symbols": 0, "suspicious_symbols": 0, "risk_level": "UNKNOWN"}
            unlinked_modules = []
            users = []
            ssh_keys = []
            crontabs = []
            wtmp = []
            lastlog = []
            deleted = []
            fim = []
            suid = []
            auth_logs = []
            privilege_escalation = []
            syscall_audit = []
            pam_events = []
            credential_access = []
            ebpf_programs = []
            ebpf_pinned = []
            ld_preload = []
            special_fds = []
            persistence_configs = []
            dns_connections = []

            # 2. Execute parallel/sequential collector sweeps
            if use_parallel:
                # Parallel collection mode using thread pool
                print(f"    -> Starting PARALLEL collection with {max_workers or 'auto'} workers (timeout={collector_timeout}s)...")

                def progress_callback(name, completed, total):
                    print(f"       [{completed}/{total}] Completed: {name}")

                # Run independent collectors in parallel
                parallel_collectors = {
                    "processes": gather_active_processes,
                    "listening_ports": gather_listening_ports,
                    "outbound_connections": gather_outbound_connections,
                    "promisc_interfaces": gather_promisc_interfaces,
                    "kernel_modules": gather_loaded_kernel_modules,
                    "system_users": gather_system_accounts,
                    "crontabs": gather_crontabs,
                    "wtmp_sessions": gather_wtmp_sessions,
                    "lastlog_records": gather_lastlog_records,
                    "deleted_binaries": gather_deleted_binaries,
                    "suid_binaries": gather_suid_binaries,
                    "auth_logs": gather_auth_logs,
                    "ebpf_programs": gather_ebpf_programs,
                    "ebpf_pinned": gather_ebpf_pinned,
                    "ld_preload": gather_ld_preload,
                    "special_fds": gather_special_fds,
                    "persistence_configs": gather_system_persistence,
                    "dns_queries": gather_dns_queries,
                    "services": gather_active_services,
                }

                # Filter parallel collectors
                active_parallel_collectors = {
                    k: v for k, v in parallel_collectors.items() if k in allowed_collector_names
                }

                parallel = ParallelCollector(max_workers=max_workers, default_timeout=collector_timeout)

                for name, func in active_parallel_collectors.items():
                    parallel.add_task(name, func, timeout=collector_timeout)

                if active_parallel_collectors:
                    parallel.run(progress_callback=progress_callback)

                # Extract successful results
                successful_data = parallel.get_successful_results()
                failed_data = parallel.get_failed_results()

                # Assign to individual variables
                processes = successful_data.get("processes", [])
                ports = successful_data.get("listening_ports", [])
                outbound = successful_data.get("outbound_connections", [])
                promisc = successful_data.get("promisc_interfaces", [])
                modules = successful_data.get("kernel_modules", [])
                users = successful_data.get("system_users", [])
                crontabs = successful_data.get("crontabs", [])
                wtmp = successful_data.get("wtmp_sessions", [])
                lastlog = successful_data.get("lastlog_records", [])
                deleted = successful_data.get("deleted_binaries", [])
                suid = successful_data.get("suid_binaries", [])
                auth_logs = successful_data.get("auth_logs", [])
                ebpf_programs = successful_data.get("ebpf_programs", [])
                ebpf_pinned = successful_data.get("ebpf_pinned", [])
                ld_preload = successful_data.get("ld_preload", [])
                special_fds = successful_data.get("special_fds", [])
                persistence_configs = successful_data.get("persistence_configs", [])
                dns_connections = successful_data.get("dns_queries", [])
                services = successful_data.get("services", [])

                # Log parallel execution results to runs_log
                for name, res in parallel.results.items():
                    meta = COLLECTOR_REGISTRY.get(name)
                    priv_level = meta.privilege_requirements if meta else "user"
                    impact = meta.runtime_impact if meta else "low"
                    runs_log[name] = {
                        "collector_name": name,
                        "success": res.success,
                        "duration": res.duration,
                        "error_message": res.error,
                        "items_collected": len(res.data) if res.success and hasattr(res.data, '__len__') else 0,
                        "privilege_level": priv_level,
                        "runtime_impact": impact
                    }

                # Report failures
                if failed_data:
                    print("\n    [!] Warning: Some collectors failed:")
                    for name, error in failed_data.items():
                        print(f"        - {name}: {error}")

                # Get summary statistics
                if active_parallel_collectors:
                    summary = parallel.get_summary()
                    print(f"\n    Parallel collection summary: {summary['successful']}/{summary['total_tasks']} successful in {summary['total_duration']:.2f}s")
                else:
                    print("\n    No parallel collectors were selected.")

                # Sequential collectors that need DB connection or have dependencies
                print("\n    -> Running sequential collectors with dependencies...")
                fim = run_seq_collector("file_integrity", gather_file_integrity_signatures, db_conn=conn)

                symbols = run_seq_collector("kernel_symbols", gather_kernel_symbols)
                if "kernel_symbols" in runs_log and runs_log["kernel_symbols"]["success"]:
                    symbol_analysis = analyze_kernel_symbol_overrides(symbols)
                    unlinked_modules = check_for_unlinked_modules(modules, symbols)

                privilege_data = run_seq_collector("privilege_events", gather_all_privilege_events)
                privilege_escalation = privilege_data.get("privilege_escalation_events", []) if privilege_data else []
                syscall_audit = privilege_data.get("syscall_audit_events", []) if privilege_data else []
                pam_events = privilege_data.get("pam_authentication_events", []) if privilege_data else []
                credential_access = privilege_data.get("credential_access_events", []) if privilege_data else []

                if "dns_queries" in runs_log and runs_log["dns_queries"]["success"] and dns_connections:
                    print("    -> Analyzing DNS patterns...")
                    analyze_dns_patterns(dns_connections)

                ssh_keys = run_seq_collector("ssh_keys", gather_active_ssh_keys)

            else:
                # Sequential collection mode
                processes = run_seq_collector("processes", gather_active_processes)

                print("    -> Enumerating open listening sockets and network states...")
                ports = run_seq_collector("listening_ports", gather_listening_ports)
                outbound = run_seq_collector("outbound_connections", gather_outbound_connections)
                promisc = run_seq_collector("promisc_interfaces", gather_promisc_interfaces)

                print("    -> Parsing kernel loadable module configurations...")
                modules = run_seq_collector("kernel_modules", gather_loaded_kernel_modules)

                print("    -> Analyzing kernel symbols for rootkit indicators...")
                symbols = run_seq_collector("kernel_symbols", gather_kernel_symbols)
                if "kernel_symbols" in runs_log and runs_log["kernel_symbols"]["success"]:
                    symbol_analysis = analyze_kernel_symbol_overrides(symbols)
                    unlinked_modules = check_for_unlinked_modules(modules, symbols)

                print("    -> Investigating system accounts and active SSH public keys...")
                users = run_seq_collector("system_users", gather_system_accounts)
                ssh_keys = run_seq_collector("ssh_keys", gather_active_ssh_keys)

                print("    -> Inspecting crontabs and persistence profiles...")
                crontabs = run_seq_collector("crontabs", gather_crontabs)

                print("    -> Auditing binary log lifecycles (WTMP and Lastlog)...")
                wtmp = run_seq_collector("wtmp_sessions", gather_wtmp_sessions)
                lastlog = run_seq_collector("lastlog_records", gather_lastlog_records)

                print("    -> Sweeping process execution trees for running deleted binaries...")
                deleted = run_seq_collector("deleted_binaries", gather_deleted_binaries)

                print("    -> Calculating file integrity check signatures (FIM)...")
                fim = run_seq_collector("file_integrity", gather_file_integrity_signatures, db_conn=conn)

                print("    -> Discovering SUID/SGID binaries...")
                suid = run_seq_collector("suid_binaries", gather_suid_binaries)

                print("    -> Gathering system authentication logs...")
                auth_logs = run_seq_collector("auth_logs", gather_auth_logs)

                print("    -> Tracking identity, access & privilege events...")
                privilege_data = run_seq_collector("privilege_events", gather_all_privilege_events)
                privilege_escalation = privilege_data.get("privilege_escalation_events", []) if privilege_data else []
                syscall_audit = privilege_data.get("syscall_audit_events", []) if privilege_data else []
                pam_events = privilege_data.get("pam_authentication_events", []) if privilege_data else []
                credential_access = privilege_data.get("credential_access_events", []) if privilege_data else []

                print("    -> Auditing loaded eBPF programs and map pins...")
                ebpf_programs = run_seq_collector("ebpf_programs", gather_ebpf_programs)
                ebpf_pinned = run_seq_collector("ebpf_pinned", gather_ebpf_pinned)

                print("    -> Auditing dynamic linker preload overrides...")
                ld_preload = run_seq_collector("ld_preload", gather_ld_preload)

                print("    -> Auditing special process file descriptors...")
                special_fds = run_seq_collector("special_fds", gather_special_fds)
                print("    -> Harvesting system persistence configuration artifacts...")
                persistence_configs = run_seq_collector("persistence_configs", gather_system_persistence)

                print("    -> Collecting DNS forensics and tunneling indicators...")
                dns_connections = run_seq_collector("dns_queries", gather_dns_queries)

                print("    -> Enumerating system services...")
                services = run_seq_collector("services", gather_active_services)
                if "dns_queries" in runs_log and runs_log["dns_queries"]["success"] and dns_connections:
                    analyze_dns_patterns(dns_connections)

            # 3. Stream collected telemetry blocks into relational tables inside a unified transaction
            if not read_only:
                storage.store_processes(conn, snapshot_id, processes)
                storage.store_ports(conn, snapshot_id, ports)
                storage.store_outbound_connections(conn, snapshot_id, outbound)
                storage.store_promisc_interfaces(conn, snapshot_id, promisc)
                storage.store_kernel_modules(conn, snapshot_id, modules)
                storage.store_kernel_symbols(conn, snapshot_id, symbols)

                # Prepare kernel analysis with hidden modules
                kernel_analysis = symbol_analysis.copy()
                kernel_analysis["hidden_modules"] = unlinked_modules
                kernel_analysis["hidden_module_count"] = len(unlinked_modules)
                storage.store_kernel_analysis(conn, snapshot_id, kernel_analysis)

                storage.store_users(conn, snapshot_id, users)
                storage.store_ssh_keys(conn, snapshot_id, ssh_keys)
                storage.store_crontabs(conn, snapshot_id, crontabs)
                storage.store_wtmp_sessions(conn, snapshot_id, wtmp)
                storage.store_lastlog_records(conn, snapshot_id, lastlog)
                storage.store_deleted_binaries(conn, snapshot_id, deleted)
                storage.store_file_hashes(conn, snapshot_id, fim)
                storage.store_suid_binaries(conn, snapshot_id, suid)
                storage.store_auth_logs(conn, snapshot_id, auth_logs)
                storage.store_privilege_events(conn, snapshot_id, privilege_escalation)
                storage.store_privilege_events(conn, snapshot_id, syscall_audit)
                storage.store_privilege_events(conn, snapshot_id, pam_events)
                storage.store_privilege_events(conn, snapshot_id, credential_access)
                storage.store_ebpf_programs(conn, snapshot_id, ebpf_programs)
                storage.store_ebpf_pinned(conn, snapshot_id, ebpf_pinned)
                storage.store_ld_preload(conn, snapshot_id, ld_preload)
                storage.store_special_fds(conn, snapshot_id, special_fds)
                storage.store_persistence_configs(conn, snapshot_id, persistence_configs)
                storage.store_services(conn, snapshot_id, services)

                # Store DNS forensics data
                if dns_connections:
                    storage.store_dns_queries(conn, snapshot_id, dns_connections)
                    print(f"       Recorded {len(dns_connections)} DNS connections")

                total_privilege_events = len(privilege_escalation) + len(syscall_audit) + len(pam_events) + len(credential_access)
                print(f"       Recorded {total_privilege_events} privilege/authentication events")

                print("    -> Verifying package integrity against dpkg records...")
                pkg_drift = run_seq_collector("package_drift", gather_pkg_integrity_drift)
                storage.store_pkg_integrity(conn, snapshot_id, pkg_drift)
                print(f"       Recorded {len(pkg_drift)} package integrity checks")

                # Store collector execution run metadata
                storage.store_collector_runs(conn, snapshot_id, list(runs_log.values()))
                print(f"       Recorded execution metadata for {len(runs_log)} collectors")

                conn.commit()

            print(f"🟢 Success: Snapshot acquisition complete. Mapped {len(processes)} processes, {len(fim)} file nodes, and {len(suid)} SUID/SGID binaries.")
    except Exception as e:
        print(f"❌ Error: Critical failure during execution phase: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_analyze(args):
    """Trigger threat detection rules evaluation loops against the latest snapshot data."""
    db_path = Path(args.database)
    if not db_path.exists():
        print("❌ Error: Database vault missing. Run 'orin collect' first.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Running threat intelligence metrics engine on database: {db_path}")
    try:
        metrics = run_analysis_cycle(db_path)
        print("\n" + "="*50)
        print("                 ORIN POSTURE ASSESSMENT")
        print("="*50)
        print(f"Associated Snapshot ID : #{metrics['snapshot_id']}")
        print(f"Calculated Risk Score  : {metrics['risk_score']} / 100")
        print(f"Unresolved Security Anomaly Count: {metrics['events_count']}")
        print("="*50 + "\n")

        if metrics['risk_score'] > 70:
            print("[⚠️] Warning: Host risk assessment indicates critical anomalies exist on this box.")

        # --- Alert Forwarding ---
        if metrics['events_count'] > 0:
            try:
                from orin.core.notifier import build_forwarder_from_config, alerts_from_db_rows
                from orin.core.config import load_config
                from orin.core.database import OrinStorage

                cfg = load_config()
                forwarder = build_forwarder_from_config(cfg)

                # Fetch the alerts for this snapshot from the DB
                storage = OrinStorage(db_path)
                with storage.get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute(
                        """SELECT event_type, severity, description,
                                  attck_technique, attck_tactic,
                                  hostname, ? as snapshot_id
                           FROM security_events
                           WHERE resolved = 0 AND suppressed = 0
                             AND (hostname IS NOT NULL)
                           ORDER BY id DESC LIMIT 500;""",
                        (metrics['snapshot_id'],)
                    )
                    rows = [dict(r) for r in cur.fetchall()]
                storage.close_pool()

                alert_objs = alerts_from_db_rows(rows)
                forwarder.dispatch(alert_objs)
                if cfg.get("notifications", {}).get("enabled", False):
                    print(f"[+] Alert forwarding: dispatched {len(alert_objs)} alert(s).")
            except Exception as fwd_exc:
                # Forwarding failure must never abort the analysis
                print(f"[!] Alert forwarding error (non-fatal): {fwd_exc}", file=sys.stderr)

    except Exception as e:
        print(f"❌ Error: Threat rules evaluation process aborted: {e}", file=sys.stderr)
        sys.exit(1)



def cmd_report(args):
    """Compile human-readable Markdown or HTML forensic dashboard outputs."""
    db_path = Path(args.database)
    output_path = Path(args.output)
    fmt = args.format.lower()

    print(f"[*] Compiling forensic briefing report target destination: {output_path}")
    try:
        if fmt == "markdown":
            compile_markdown_report(db_path, output_path)
        elif fmt == "html":
            compile_html_report(db_path, output_path)
        else:
            print(f"❌ Error: Unsupported documentation layout syntax: {fmt}", file=sys.stderr)
            sys.exit(1)
        print(f"🟢 Success: Documentation generated successfully at: {output_path.resolve()}")
    except Exception as e:
        print(f"❌ Error: Documentation rendering engine failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_serve(args):
    """Launch the localized HTTP dashboard server console."""
    from orin.core.server import start_server
    db_path = Path(args.database)

    port = args.port
    if args.port_opt is not None:
        port = args.port_opt

    try:
        start_server(
            db_path=db_path,
            host=args.host,
            port=port,
            username=args.username,
            password=args.password,
            cert_path=args.cert,
            key_path=args.key,
            no_auth=args.no_auth,
            passphrase_file=getattr(args, 'passphrase_file', None),
            passphrase_prompt=getattr(args, 'passphrase_prompt', False),
            passphrase_env_var=getattr(args, 'passphrase_env_var', None),
            token_file=getattr(args, 'token_file', None)
        )
    except Exception as e:
        print(f"❌ Error: Web console server failed to start: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_hub_serve(args):
    """Launch the centralized air-gapped fleet hub server for multi-tenant forensic management."""
    from orin.core.hub_server import start_server
    db_path = Path(args.database)

    port = args.port
    if args.port_opt is not None:
        port = args.port_opt

    try:
        start_server(
            db_path=db_path,
            host=args.host,
            port=port,
            cert_path=args.cert,
            key_path=args.key,
            no_auth=args.no_auth,
            passphrase_file=getattr(args, 'passphrase_file', None),
            passphrase_prompt=getattr(args, 'passphrase_prompt', False),
            passphrase_env_var=getattr(args, 'passphrase_env_var', None),
            token_file=getattr(args, 'token_file', None)
        )
    except Exception as e:
        print(f"❌ Error: Hub server failed to start: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_schedule(args):
    """Manage the automated telemetry collection cron schedule."""
    from orin.core.scheduler import install_schedule, remove_schedule, show_schedule_status

    if args.install:
        retention_days = getattr(args, 'retention', None)
        install_schedule(Path(args.database), args.interval, retention_days=retention_days)
    elif args.remove:
        remove_schedule()
    elif args.status:
        show_schedule_status()
    else:
        # Default behavior: show status
        show_schedule_status()


def cmd_scan(args):
    """Execute a remote security scan over SSH, or baseline a target host."""
    from orin.core.scanner import run_remote_scan
    from orin.core.database import OrinStorage
    import subprocess
    import json

    db_path = Path(args.database)
    port = args.port if args.port is not None else 22

    if args.init:
        print(f"[*] Initializing baseline for remote host: {args.host}")
        current_dir = Path(__file__).resolve().parent
        agent_path = current_dir / "collectors" / "remote_agent.py"
        if not agent_path.exists():
            print(f"❌ Error: Remote agent script missing at: {agent_path}", file=sys.stderr)
            sys.exit(1)

        remote_agent_code = agent_path.read_text(encoding="utf-8")

        # Load SSH security configuration from config
        from orin.core.config import load_config
        config = load_config()
        ssh_config = config.get("ssh", {})
        strict_host_checking = ssh_config.get("strict_host_key_checking", "ask")
        known_hosts_file = ssh_config.get("known_hosts_file")
        connection_timeout = ssh_config.get("connection_timeout", 30)
        max_retries = ssh_config.get("max_retries", 3)

        # Construct SSH command with configurable security options
        ssh_cmd = ["ssh", "-o", f"StrictHostKeyChecking={strict_host_checking}"]

        # Add custom known_hosts file if specified
        if known_hosts_file:
            ssh_cmd.extend(["-o", f"UserKnownHostsFile={known_hosts_file}"])

        # Add connection timeout
        ssh_cmd.extend(["-o", f"ConnectTimeout={connection_timeout}"])

        # Add retry limit (via ConnectionAttempts)
        ssh_cmd.extend(["-o", f"ConnectionAttempts={max_retries}"])

        if port:
            ssh_cmd.extend(["-p", str(port)])
        if args.key:
            ssh_cmd.extend(["-i", str(args.key)])

        agent_config = {
            "critical_paths": [],
            "critical_dirs": []
        }
        config_json_str = json.dumps(agent_config)
        ssh_cmd.extend([f"{args.user}@{args.host}", f"python3 - '{config_json_str}'"])

        try:
            proc = subprocess.Popen(
                ssh_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=remote_agent_code)
        except Exception as e:
            print(f"❌ Error: Failed to run remote baseline command: {e}", file=sys.stderr)
            sys.exit(1)

        if proc.returncode != 0:
            print(f"❌ Error: SSH baseline collection failed: {stderr}", file=sys.stderr)
            sys.exit(1)

        try:
            telemetry = json.loads(stdout.strip())
        except json.JSONDecodeError as e:
            print(f"❌ Error: Failed to parse baseline telemetry: {e}", file=sys.stderr)
            sys.exit(1)

        remote_hostname = telemetry.get("hostname", args.host)

        storage = OrinStorage(db_path)
        if not db_path.exists():
            storage.initialize_db()

        with storage.get_connection() as conn:
            conn.execute("DELETE FROM baseline_kernel_modules WHERE hostname = ?;", (remote_hostname,))
            conn.execute("DELETE FROM baseline_users WHERE hostname = ?;", (remote_hostname,))
            conn.execute("DELETE FROM baseline_suid_binaries WHERE hostname = ?;", (remote_hostname,))

            if "modules" in telemetry:
                conn.executemany(
                    "INSERT OR IGNORE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(remote_hostname, m["module_name"], m["memory_size"]) for m in telemetry["modules"]]
                )
            if "users" in telemetry:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(remote_hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in telemetry["users"]]
                )
            if "suid" in telemetry:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    [(remote_hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in telemetry["suid"]]
                )
            conn.commit()

        print(f"🟢 Success: Baseline initialized for remote host {remote_hostname}.")
    else:
        print(f"[*] Executing remote SSH security scan on {args.host}...")
        try:
            # Configure strict host key verification
            strict_host_keys = not args.no_strict_host_keys

            metrics = run_remote_scan(
                host=args.host,
                user=args.user,
                key_path=args.key,
                port=port,
                db_path=db_path,
                strict_host_keys=strict_host_keys,
                known_hosts_file=args.known_hosts_file
            )
            print("\n" + "="*50)
            print(f"            REMOTE POSTURE ASSESSMENT: {args.host}")
            print("="*50)
            print(f"Associated Snapshot ID : #{metrics['snapshot_id']}")
            print(f"Calculated Risk Score  : {metrics['risk_score']} / 100")
            print(f"Unresolved Security Anomaly Count: {metrics['events_count']}")
            print("="*50 + "\n")

            if metrics['risk_score'] > 70:
                print("[⚠️] Warning: Remote host risk assessment indicates critical anomalies exist.")
        except Exception as e:
            print(f"❌ Error: Remote scan failed: {e}", file=sys.stderr)
            sys.exit(1)


def cmd_baseline(args):
    """Manage trusted system baselines (users, kernel modules, SUID binaries)."""
    from orin.core.database import OrinStorage
    import platform
    import sys

    db_path = Path(args.database)
    storage = OrinStorage(db_path)
    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)

    hostname = args.host if args.host else (platform.node() or "unknown_host")

    if args.baseline_command == "add":
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots WHERE hostname = ? ORDER BY id DESC LIMIT 1;", (hostname,))
            snap_row = cursor.fetchone()
            if not snap_row:
                print(f"❌ Error: No snapshot found for host '{hostname}' in vault. Run 'orin collect' or 'orin scan' first.", file=sys.stderr)
                sys.exit(1)

            snapshot_id = snap_row["id"]

            if args.user:
                username = args.user
                cursor.execute(
                    "SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ? AND username = ? LIMIT 1;",
                    (snapshot_id, username)
                )
                user_row = cursor.fetchone()
                if not user_row:
                    print(f"❌ Error: User '{username}' not found in the latest collected snapshot #{snapshot_id} for host '{hostname}'.", file=sys.stderr)
                    sys.exit(1)

                conn.execute(
                    "INSERT OR REPLACE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
                    (hostname, user_row["username"], user_row["uid"], user_row["gid"], user_row["home_dir"], user_row["login_shell"])
                )
                conn.commit()
                print(f"🟢 Success: Added user '{username}' to baseline for host '{hostname}'.")

            elif args.module:
                module_name = args.module
                cursor.execute(
                    "SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ? AND module_name = ? LIMIT 1;",
                    (snapshot_id, module_name)
                )
                mod_row = cursor.fetchone()
                if not mod_row:
                    print(f"❌ Error: Kernel module '{module_name}' not found in the latest collected snapshot #{snapshot_id} for host '{hostname}'.", file=sys.stderr)
                    sys.exit(1)

                conn.execute(
                    "INSERT OR REPLACE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    (hostname, mod_row["module_name"], mod_row["memory_size"])
                )
                conn.commit()
                print(f"🟢 Success: Added kernel module '{module_name}' to baseline for host '{hostname}'.")

            elif args.suid:
                suid_path = args.suid
                cursor.execute(
                    "SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ? AND file_path = ? LIMIT 1;",
                    (snapshot_id, suid_path)
                )
                suid_row = cursor.fetchone()
                if not suid_row:
                    print(f"❌ Error: SUID binary '{suid_path}' not found in the latest collected snapshot #{snapshot_id} for host '{hostname}'.", file=sys.stderr)
                    sys.exit(1)

                conn.execute(
                    "INSERT OR REPLACE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                    (hostname, suid_row["file_path"], suid_row["owner"], suid_row["grp"], suid_row["permissions"], suid_row["sha256"])
                )
                conn.commit()
                print(f"🟢 Success: Added SUID binary '{suid_path}' to baseline for host '{hostname}'.")

    elif args.baseline_command == "refresh":
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots WHERE hostname = ? ORDER BY id DESC LIMIT 1;", (hostname,))
            snap_row = cursor.fetchone()
            if not snap_row:
                print(f"❌ Error: No snapshot found for host '{hostname}' in vault. Run 'orin collect' or 'orin scan' first.", file=sys.stderr)
                sys.exit(1)

            snapshot_id = snap_row["id"]

            if args.force_overwrite:
                conn.execute("DELETE FROM baseline_kernel_modules WHERE hostname = ?;", (hostname,))
                conn.execute("DELETE FROM baseline_users WHERE hostname = ?;", (hostname,))
                conn.execute("DELETE FROM baseline_suid_binaries WHERE hostname = ?;", (hostname,))

            # 1. Refresh kernel modules
            cursor.execute("SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ?;", (snapshot_id,))
            modules = cursor.fetchall()
            if modules:
                conn.executemany(
                    "INSERT OR REPLACE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                    [(hostname, m["module_name"], m["memory_size"]) for m in modules]
                )

            # 2. Refresh users
            cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snapshot_id,))
            users = cursor.fetchall()
            if users:
                conn.executemany(
                    "INSERT OR REPLACE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
                    [(hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in users]
                )

            # 3. Refresh SUIDs
            cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ?;", (snapshot_id,))
            suids = cursor.fetchall()
            if suids:
                conn.executemany(
                    "INSERT OR REPLACE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
                    [(hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in suids]
                )

            conn.commit()
            action_str = "Overwrote and set" if args.force_overwrite else "Appended to"
            print(f"🟢 Success: {action_str} baseline for host '{hostname}' using snapshot #{snapshot_id} ({len(modules)} modules, {len(users)} users, {len(suids)} SUIDs).")


def cmd_correlate(args):
    """Query unresolved security events and query Ollama to identify multi-host correlations."""
    from orin.analysis.ai import run_ai_correlation
    import sys

    db_path = Path(args.database)
    hostnames = args.host
    url = args.url
    model = args.model
    output_path = Path(args.output) if args.output else None

    try:
        print(f"[*] Analyzing multi-host telemetry and querying local AI model '{model}'...")
        analysis = run_ai_correlation(db_path, hostnames=hostnames, url=url, model=model)

        print("\n" + "="*50)
        print("          LOCAL AI CORRELATION BRIEFING")
        print("="*50 + "\n")
        print(analysis)
        print("\n" + "="*50)

        if output_path:
            output_path.write_text(analysis, encoding="utf-8")
            print(f"🟢 Success: AI Triage briefing written to: {output_path}")

    except Exception as e:
        print(f"❌ Error: AI Correlation failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_delta(args):
    db_path = args.database or "orin_vault.db"
    if not os.path.exists(db_path):
        print(f"Error: Database not found: {db_path}")
        return 1

    from orin.analysis.timeline import calculate_snapshot_delta

    try:
        delta = calculate_snapshot_delta(db_path, args.base, args.target)
        # Print formatted output
        print(f"Delta between snapshot {args.base} and {args.target}:")
        print(f"  Added: {len(delta.get('added', []))}")
        print(f"  Removed: {len(delta.get('removed', []))}")
        print(f"  Modified: {len(delta.get('modified', []))}")

        if args.verbose:
            import json
            print(json.dumps(delta, indent=2))
        return 0
    except Exception as e:
        print(f"Error calculating delta: {e}")
        return 1


def resolve_export_secret(args) -> str:
    """Resolve the secret passphrase for signing/verification from various sources."""
    from orin.core.credentials import CredentialManager
    from orin.core.credentials import SecureCredential
    import sys

    # Initialize CredentialManager with default min length of 12
    mgr = CredentialManager(min_passphrase_length=12)

    # 1. From CLI directly (insecure, warn user)
    if getattr(args, 'secret', None):
        print("[!] Warning: Passing secrets directly on the command line is insecure.", file=sys.stderr)
        return SecureCredential(args.secret).get_value()

    # 2. From file
    if getattr(args, 'secret_file', None):
        secret_cred = mgr.load_vault_passphrase_from_file(args.secret_file, required=True)
        if secret_cred:
            return secret_cred.get_value()

    # 3. From interactive prompt
    if getattr(args, 'secret_prompt', False):
        secret_cred = mgr.load_vault_passphrase_from_prompt(prompt="Enter signing/verification secret: ", required=True)
        if secret_cred:
            return secret_cred.get_value()

    # 4. From environment variable (default custom or ORIN_EXPORT_SECRET)
    env_var_name = getattr(args, 'secret_env_var', None) or "ORIN_EXPORT_SECRET"
    secret_cred = mgr.load_vault_passphrase_from_env_var_name(env_var_name, required=False)
    if secret_cred:
        return secret_cred.get_value()

    # If no options were provided, return None
    return None


def cmd_diff(args):
    from orin.analysis.diff import load_snapshot_data, compare_snapshots
    from orin.core.crypto import zero_memory

    secret = resolve_export_secret(args)
    try:
        base_data = load_snapshot_data(args.base_file, secret=secret)
        target_data = load_snapshot_data(args.target_file, secret=secret)

        report = compare_snapshots(base_data, target_data)

        print("Drift Report:")
        print(f"  Total changes: {report.get('total_changes', 0)}")
        print(f"  Critical changes: {report.get('critical_changes', 0)}")

        if args.verbose:
            import json
            print(json.dumps(report, indent=2))
        return 0
    except Exception as e:
        print(f"Error comparing snapshots: {e}")
        return 1
    finally:
        if secret:
            zero_memory(secret)


def cmd_export(args):
    db_path = args.database or "orin_vault.db"
    if not os.path.exists(db_path):
        print(f"Error: Database not found: {db_path}")
        return 1

    secret = resolve_export_secret(args)
    if not secret:
        print("Error: A secret key is required for signing. Specify one of: --secret, --secret-file, --secret-prompt, or set ORIN_EXPORT_SECRET environment variable.")
        return 1

    from orin.core.crypto import generate_signed_export, generate_coc_manifest, zero_memory

    try:
        export_data = generate_signed_export(db_path, args.snapshot, secret)

        output_file = args.output or f"export_{args.snapshot}.json"
        with open(output_file, 'w') as f:
            import json
            json.dump(export_data, f, indent=2)

        # Generate Chain-of-Custody manifest
        output_dir = os.path.dirname(output_file) or "."
        coc_manifest = generate_coc_manifest(db_path, args.snapshot, output_dir)
        coc_file = os.path.join(output_dir, f"coc_manifest_{args.snapshot}.json")

        print(f"Exported snapshot {args.snapshot} to {output_file}")
        print(f"Generated Chain-of-Custody manifest: {coc_file}")
        print("Signature algorithm: HMAC-SHA256")
        print(f"Evidence items in manifest: {coc_manifest['evidence_count']}")
        return 0
    except Exception as e:
        print(f"Error exporting snapshot: {e}")
        return 1
    finally:
        if secret:
            zero_memory(secret)


def cmd_verify(args):
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        return 1

    secret = resolve_export_secret(args)
    if not secret:
        print("Error: A secret key is required for verification. Specify one of: --secret, --secret-file, --secret-prompt, or set ORIN_EXPORT_SECRET environment variable.")
        return 1

    from orin.core.crypto import verify_signed_export, zero_memory

    try:
        payload = verify_signed_export(args.file, secret)

        if isinstance(payload, dict):
            print("✅ Verification successful!")
            print(f"   Snapshot ID: {payload.get('snapshot_id', 'unknown')}")
            metadata = payload.get('metadata', {})
            timestamp = metadata.get('timestamp') or payload.get('timestamp', 'unknown')
            print(f"   Timestamp: {timestamp}")
            item_count = payload.get('item_count')
            if item_count is None:
                item_count = sum(len(payload.get(k, [])) for k in [
                    'processes', 'ports', 'outbound', 'kernel_modules', 'ssh_keys', 'users',
                    'file_hashes', 'deleted_binaries', 'promisc_interfaces', 'wtmp_sessions',
                    'lastlog_records', 'pkg_integrity', 'crontabs'
                ])
            print(f"   Items verified: {item_count}")
            return 0
        else:
            print("❌ Verification FAILED - Tamper detected!")
            return 1
    except Exception as e:
        print(f"Error verifying export: {e}")
        return 1
    finally:
        if secret:
            zero_memory(secret)


def cmd_stream(args):
    """Launch the eBPF real-time streaming consumer."""
    from pathlib import Path
    import subprocess

    # Try multiple possible locations for the ebpf consumer
    possible_paths = [
        Path(__file__).parent.parent / "ebpf" / "consumer.py",  # src/orin -> ebpf/consumer.py
        Path(__file__).parent / ".." / ".." / "ebpf" / "consumer.py",  # Alternative relative path
        Path("/workspace/orin/ebpf/consumer.py"),  # Absolute dev path
    ]

    consumer_path = None
    for p in possible_paths:
        if p.exists():
            consumer_path = p.resolve()
            break

    if not consumer_path:
        print(f"❌ Error: eBPF consumer script not found. Searched: {possible_paths}")
        sys.exit(1)

    print("[*] Launching Orin eBPF Real-Time Streamer...")
    print(f"[*] Consumer script: {consumer_path}")

    # Execute the consumer script with the same arguments
    cmd = [sys.executable, str(consumer_path)]
    if args.verbose:
        cmd.append("--verbose")

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: eBPF streamer failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stream interrupted by user.")
        sys.exit(0)


def cmd_rules(args):
    """Manage Sigma and YARA rule repositories."""
    from orin.analysis.sigma import validate_rule, validate_rules_directory, load_rules as load_sigma_rules
    from orin.analysis.yara_engine import YaraEngine, YARA_AVAILABLE

    if args.rules_command == "update":
        sigma_dir = args.sigma
        yara_dir = args.yara

        if not sigma_dir and not yara_dir:
            print("❌ Error: Must specify --sigma or --yara directory", file=sys.stderr)
            sys.exit(1)

        if sigma_dir:
            sigma_path = Path(sigma_dir)
            if not sigma_path.exists():
                print(f"❌ Error: Sigma rules directory not found: {sigma_path}", file=sys.stderr)
                sys.exit(1)

            print(f"[*] Validating Sigma rules in: {sigma_path}")
            valid_rules, results = validate_rules_directory(sigma_path)

            total = len(results)
            valid_count = sum(1 for r in results if r.valid)
            invalid_count = total - valid_count

            print(f"\n{'='*60}")
            print("\nSigma Rules Validation Summary")
            print(f"{'='*60}")
            print(f"Total rules scanned  : {total}")
            print(f"Valid rules          : {valid_count}")
            print(f"Invalid rules        : {invalid_count}")

            if args.validate_only:
                print("\n[!] Validation-only mode: rules NOT installed")
            else:
                # Install valid rules to default location
                default_sigma_dir = Path("/var/lib/orin/rules/sigma")
                default_sigma_dir.mkdir(parents=True, exist_ok=True)

                installed = 0
                for rule in valid_rules:
                    try:
                        src = Path(rule["file_path"])
                        dst = default_sigma_dir / src.name
                        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                        installed += 1
                    except Exception as e:
                        print(f"[!] Failed to install {rule.get('title', 'UNKNOWN')}: {e}")

                print(f"\n[+] Installed {installed} valid Sigma rules to: {default_sigma_dir}")

            # Show validation errors
            if invalid_count > 0:
                print("\n[!] Invalid rules:")
                for result in results:
                    if not result.valid:
                        fp = getattr(result, 'file_path', 'unknown')
                        errs = "; ".join(result.errors)
                        print(f"    - {fp}: {errs}")

        if yara_dir:
            yara_path = Path(yara_dir)
            if not yara_path.exists():
                print(f"❌ Error: YARA rules directory not found: {yara_path}", file=sys.stderr)
                sys.exit(1)

            print(f"\n[*] Validating YARA rules in: {yara_path}")

            if not YARA_AVAILABLE:
                print("[!] Warning: yara-python not installed. Skipping syntax validation.")

            yar_files = list(yara_path.glob("*.yar"))
            valid_count = 0
            invalid_count = 0

            for yar_file in yar_files:
                try:
                    content = yar_file.read_text(encoding="utf-8")
                    # Basic syntax check - look for rule definitions
                    if re.search(r'rule\s+\w+', content):
                        valid_count += 1
                        print(f"    ✓ {yar_file.name}")
                    else:
                        print(f"    ✗ {yar_file.name}: No valid rule definitions found")
                        invalid_count += 1
                except Exception as e:
                    print(f"    ✗ {yar_file.name}: {e}")
                    invalid_count += 1

            print(f"\n{'='*60}")
            print("YARA Rules Validation Summary")
            print(f"{'='*60}")
            print(f"Total rules scanned  : {len(yar_files)}")
            print(f"Valid rules          : {valid_count}")
            print(f"Invalid rules        : {invalid_count}")

            if not args.validate_only:
                # Install valid rules to default location
                default_yara_dir = Path("/var/lib/orin/rules/yara")
                default_yara_dir.mkdir(parents=True, exist_ok=True)

                installed = 0
                for yar_file in yar_files:
                    try:
                        src = yar_file
                        dst = default_yara_dir / yar_file.name
                        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                        installed += 1
                    except Exception as e:
                        print(f"[!] Failed to install {yar_file.name}: {e}")

                print(f"\n[+] Installed {installed} YARA rules to: {default_yara_dir}")

    elif args.rules_command == "list":
        show_sigma = args.sigma
        show_yara = args.yara
        verbose = args.verbose

        if not show_sigma and not show_yara:
            show_sigma = show_yara = True

        if show_sigma:
            print(f"\n{'='*70}")
            print("ACTIVE SIGMA RULES")
            print(f"{'='*70}")

            import sys
            # Check default locations
            raw_dirs = [
                Path("./rules"),
                Path("/var/lib/orin/rules/sigma"),
                Path(__file__).resolve().parents[2] / "rules",
            ]
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                raw_dirs.append(Path(sys._MEIPASS) / "rules")

            # Deduplicate by resolving absolute paths
            default_dirs = []
            seen_dirs = set()
            for d in raw_dirs:
                if d.exists():
                    try:
                        resolved = d.resolve()
                        if resolved not in seen_dirs:
                            seen_dirs.add(resolved)
                            default_dirs.append(resolved)
                    except Exception:
                        if d not in seen_dirs:
                            seen_dirs.add(d)
                            default_dirs.append(d)

            all_rules = []
            seen_rule_ids = set()
            for d in default_dirs:
                for rule in load_sigma_rules(d):
                    rule_id = rule.get("id")
                    if rule_id not in seen_rule_ids:
                        seen_rule_ids.add(rule_id)
                        all_rules.append(rule)

            if not all_rules:
                print("No Sigma rules found in default locations.")
            else:
                for i, rule in enumerate(all_rules, 1):
                    desc = rule.get("description", "No description")
                    level = rule.get("level", "unknown")
                    rule_id = rule.get("id", "N/A")
                    tags = rule.get("tags", [])

                    print(f"\n[{i}] {rule.get('title', 'Untitled')}")
                    print(f"    ID: {rule_id}")
                    print(f"    Level: {level}")
                    print(f"    Description: {desc}")
                    if tags:
                        print(f"    Tags: {', '.join(tags)}")

                    if verbose:
                        detection = rule.get("detection", {})
                        condition = detection.get("condition", "")
                        selections = [k for k in detection.keys() if k != "condition"]
                        print(f"    Condition: {condition}")
                        print(f"    Selections: {', '.join(selections)}")

                        # Parse MITRE ATT&CK from tags
                        attck_tags = [t for t in tags if t.startswith("attack.")]
                        if attck_tags:
                            print(f"    MITRE ATT&CK: {', '.join(attck_tags)}")

            print(f"\nTotal Sigma rules: {len(all_rules)}")

        if show_yara:
            print(f"\n{'='*70}")
            print("ACTIVE YARA RULES")
            print(f"{'='*70}")

            raw_yara_dirs = [
                Path("./rules/yara"),
                Path("/var/lib/orin/rules/yara"),
            ]
            default_yara_dirs = []
            seen_yara_dirs = set()
            for d in raw_yara_dirs:
                if d.exists():
                    try:
                        resolved = d.resolve()
                        if resolved not in seen_yara_dirs:
                            seen_yara_dirs.add(resolved)
                            default_yara_dirs.append(resolved)
                    except Exception:
                        if d not in seen_yara_dirs:
                            seen_yara_dirs.add(d)
                            default_yara_dirs.append(d)

            yar_files = []
            for d in default_yara_dirs:
                yar_files.extend(d.glob("*.yar"))

            if not yar_files:
                print("No YARA rules found in default locations.")
            else:
                for i, yar_file in enumerate(sorted(yar_files), 1):
                    try:
                        content = yar_file.read_text(encoding="utf-8")
                        # Extract rule names
                        rule_names = re.findall(r'rule\s+(\w+)', content)

                        print(f"\n[{i}] {yar_file.name}")
                        print(f"    Rules: {', '.join(rule_names[:5])}" + ("..." if len(rule_names) > 5 else ""))

                        if verbose:
                            # Extract metadata
                            metas = re.findall(r'meta:\s*\n((?:\s+\w+\s*=\s*".*?"\s*\n)+)', content)
                            if metas:
                                meta_text = metas[0]
                                desc_match = re.search(r'description\s*=\s*"([^"]+)"', meta_text)
                                author_match = re.search(r'author\s*=\s*"([^"]+)"', meta_text)
                                severity_match = re.search(r'severity\s*=\s*"([^"]+)"', meta_text)
                                attack_match = re.search(r'attack\s*=\s*"([^"]+)"', meta_text)

                                if desc_match:
                                    print(f"    Description: {desc_match.group(1)}")
                                if author_match:
                                    print(f"    Author: {author_match.group(1)}")
                                if severity_match:
                                    print(f"    Severity: {severity_match.group(1)}")
                                if attack_match:
                                    print(f"    MITRE ATT&CK: {attack_match.group(1)}")
                    except Exception as e:
                        print(f"\n[{i}] {yar_file.name}: Error reading - {e}")

            print(f"\nTotal YARA files: {len(yar_files)}")

    elif args.rules_command == "validate":
        sigma_path = args.sigma
        yara_path = args.yara
        strict = args.strict

        exit_code = 0

        if sigma_path:
            path = Path(sigma_path)
            print(f"[*] Validating Sigma: {path}")

            if path.is_file():
                content = path.read_text(encoding="utf-8")
                rule = parse_yaml_rule(content)
                result = validate_rule(rule, content)

                if result.valid:
                    print(f"    ✓ {path.name}: VALID")
                    if verbose := getattr(args, 'verbose', False):
                        for op in result.supported_operators:
                            print(f"      Supported: {op}")
                else:
                    print(f"    ✗ {path.name}: INVALID")
                    for err in result.errors:
                        print(f"      Error: {err}")
                    exit_code = 1

                if strict and result.warnings:
                    print(f"    ! Warnings ({len(result.warnings)}):")
                    for warn in result.warnings:
                        print(f"      - {warn}")
                    exit_code = 1

            elif path.is_dir():
                valid_rules, results = validate_rules_directory(path)

                total = len(results)
                valid_count = sum(1 for r in results if r.valid)
                invalid_count = total - valid_count

                print(f"\n{'='*60}")
                print(f"Validation Results: {valid_count}/{total} valid")
                print(f"{'='*60}")

                if invalid_count > 0:
                    exit_code = 1
                    for result in results:
                        if not result.valid:
                            fp = getattr(result, 'file_path', 'unknown')
                            for err in result.errors:
                                print(f"  ✗ {fp}: {err}")

                if strict:
                    for result in results:
                        if result.warnings:
                            fp = getattr(result, 'file_path', 'unknown')
                            for warn in result.warnings:
                                print(f"  ! {fp}: {warn}")
                            exit_code = 1

        if yara_path:
            if not YARA_AVAILABLE:
                print("[!] Warning: yara-python not installed. Cannot validate YARA syntax.")
                return

            path = Path(yara_path)
            print(f"\n[*] Validating YARA: {path}")

            try:
                engine = YaraEngine()
                if path.is_file():
                    engine.load_rules(rules_dirs=[path.parent])
                    print(f"    ✓ {path.name}: VALID")
                elif path.is_dir():
                    count = engine.load_rules(rules_dirs=[path])
                    print(f"    ✓ Loaded {count} rules from directory")
            except Exception as e:
                print(f"    ✗ Validation failed: {e}")
                exit_code = 1

        sys.exit(exit_code)


def cmd_vault(args):
    """Manage the forensic vault lifecycle (prune, stats)."""
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"❌ Error: Database vault missing at '{db_path}'. Run 'orin init' first.", file=sys.stderr)
        sys.exit(1)

    storage = OrinStorage(db_path)

    if args.vault_command == "stats":
        try:
            with storage.get_connection() as conn:
                stats = storage.vault_stats(conn)
            print("\n" + "=" * 50)
            print("              ORIN VAULT STATISTICS")
            print("=" * 50)
            print(f"Database Path       : {db_path.resolve()}")
            print(f"Database Size       : {stats['database_size_mb']} MB ({stats['database_size_bytes']:,} bytes)")
            print(f"Total Snapshots     : {stats['snapshot_count']}")
            print(f"Oldest Snapshot     : {stats['oldest_snapshot'] or 'N/A'}")
            print(f"Newest Snapshot     : {stats['newest_snapshot'] or 'N/A'}")
            print("-" * 50)
            print("Records by Table:")
            for table, count in sorted(stats['table_counts'].items()):
                print(f"  {table:30s} : {count:,}")
            print("=" * 50 + "\n")
        except Exception as e:
            print(f"❌ Error: Failed to retrieve vault statistics: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.vault_command == "prune":
        import json

        dry_run = not args.execute  # Default to dry-run unless --execute is specified
        retention_policies = None
        older_than_days = args.older_than
        keep_last = getattr(args, "keep_last", None)
        preserve_critical = getattr(args, "preserve_critical", True)

        # Determine mode: legacy (--older-than), granular (--policy-file), or count-based (--keep-last)
        if args.policy_file:
            # Granular mode: load retention policies from JSON file
            policy_path = Path(args.policy_file)
            if not policy_path.exists():
                print(f"❌ Error: Policy file not found: {policy_path}", file=sys.stderr)
                sys.exit(1)

            try:
                with open(policy_path, 'r') as f:
                    retention_policies = json.load(f)

                # Validate the policy structure
                if not isinstance(retention_policies, dict):
                    raise ValueError("Policy file must contain a JSON object")

                # Ensure there's a default policy
                if "default" not in retention_policies and older_than_days is None:
                    retention_policies["default"] = 30  # Default fallback

                mode_description = "granular per-type retention"
                print(f"[*] Using {mode_description} from: {policy_path}")

            except json.JSONDecodeError as e:
                print(f"❌ Error: Invalid JSON in policy file: {e}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error: Failed to load retention policy: {e}", file=sys.stderr)
                sys.exit(1)
        elif keep_last is not None:
            mode_description = f"count-based retention (keep last {keep_last} snapshots per host)"
            print(f"[*] Using {mode_description}")
        else:
            # Legacy mode: single threshold for all data
            if older_than_days is None:
                print("❌ Error: Either --older-than, --policy-file, or --keep-last must be specified", file=sys.stderr)
                sys.exit(1)
            mode_description = f"legacy single-threshold ({older_than_days} days)"
            print(f"[*] Using {mode_description}")

        if preserve_critical:
            print("[*] Critical alert preservation is ENABLED. Snapshots with active critical alerts will not be deleted.")
        else:
            print("[*] Critical alert preservation is DISABLED.")

        action = "Would delete" if dry_run else "Deleting"
        print(f"[*] {action} based on retention policy...\n")

        try:
            with storage.get_connection() as conn:
                result = storage.vault_prune(
                    conn,
                    older_than_days=older_than_days,
                    dry_run=dry_run,
                    retention_policies=retention_policies,
                    keep_last=keep_last,
                    preserve_critical=preserve_critical
                )

            if "message" in result:
                print(f"🟢 {result['message']}")
            else:
                print(f"\n{'=' * 50}")
                print(f"           VAULT PRUNING {'(DRY RUN)' if dry_run else 'COMPLETE'}")
                print('=' * 50)
                print(f"Mode                : {result.get('mode', 'unknown').upper()}")

                if result.get('retention_policies_applied'):
                    print("\nRetention Policies Applied:")
                    for table, days in sorted(result['retention_policies_applied'].items()):
                        print(f"  {table:35s} : {days} days")

                if 'cutoff_date' in result:
                    print(f"\nLegacy Cutoff Date  : {result['cutoff_date']}")

                if 'deleted_snapshots' in result:
                    print(f"Snapshots {'to be ' if dry_run else ''}deleted   : {result['deleted_snapshots']}")

                if result.get('preserved_by_alerts_count'):
                    print(f"Snapshots preserved by critical alerts: {result['preserved_by_alerts_count']}")

                if 'deleted_orphaned_snapshots' in result:
                    print(f"Orphaned snapshots cleaned: {result['deleted_orphaned_snapshots']}")

                print("-" * 50)
                print("Records by Table:")
                if result['deleted_by_table']:
                    for table, count in sorted(result['deleted_by_table'].items()):
                        print(f"  {table:30s} : {count:,}")
                else:
                    print("  No records matched the retention criteria.")
                print('=' * 50 + "\n")

                if dry_run:
                    print("Note: This was a dry run. Add --execute to actually delete data.")
        except Exception as e:
            print(f"❌ Error: Vault pruning failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("❌ Error: Unknown vault command. Use 'stats' or 'prune'.", file=sys.stderr)
        sys.exit(1)


def cmd_collectors(args):
    """Query and list metadata of telemetry collectors."""
    if args.subcommand == "list":
        collectors = get_registered_collectors()
        collectors.sort(key=lambda c: c.name)

        if args.format == "json":
            data = [
                {
                    "name": c.name,
                    "description": c.description,
                    "privilege_requirements": c.privilege_requirements,
                    "required_capabilities": c.required_capabilities,
                    "runtime_impact": c.runtime_impact,
                    "impact_reason": c.impact_reason,
                    "privilege_satisfied": check_privilege_satisfaction(c)
                }
                for c in collectors
            ]
            print(json.dumps(data, indent=2))
        elif args.format == "csv":
            print("Name,Description,Privilege Requirements,Runtime Impact,Privilege Satisfied")
            for c in collectors:
                satisfied = "YES" if check_privilege_satisfaction(c) else "NO"
                desc = c.description.replace('"', '""')
                print(f'"{c.name}","{desc}","{c.privilege_requirements}","{c.runtime_impact}","{satisfied}"')
        else:
            headers = ["Collector Name", "Description", "Privilege", "Impact", "Privilege Satisfied"]
            widths = [20, 50, 10, 8, 20]
            fmt = f"%-{widths[0]}s | %-{widths[1]}s | %-{widths[2]}s | %-{widths[3]}s | %-{widths[4]}s"
            print(fmt % tuple(headers))
            print("-" * (sum(widths) + 12))
            for c in collectors:
                satisfied = "🟢 YES" if check_privilege_satisfaction(c) else "🔴 NO"
                desc = c.description
                if len(desc) > widths[1]:
                    desc = desc[:widths[1]-3] + "..."
                print(fmt % (c.name, desc, c.privilege_requirements, c.runtime_impact, satisfied))
    elif args.subcommand == "show":
        name = args.collector_name
        if name not in COLLECTOR_REGISTRY:
            print(f"❌ Error: Collector '{name}' not found in registry.", file=sys.stderr)
            sys.exit(1)
            return
        c = COLLECTOR_REGISTRY[name]
        satisfied = "🟢 YES" if check_privilege_satisfaction(c) else "🔴 NO"
        print(f"Collector Details: {c.name}")
        print("=" * (19 + len(c.name)))
        print(f"Name:                   {c.name}")
        print(f"Description:            {c.description}")
        print(f"Privilege Required:     {c.privilege_requirements}")
        print(f"Privilege Satisfied:    {satisfied}")
        print(f"Required Capabilities:  {', '.join(c.required_capabilities) if c.required_capabilities else 'None'}")
        print(f"Runtime Impact:         {c.runtime_impact}")
        print(f"Impact Rationale:       {c.impact_reason}")


def run_orchestration(args):
    """Primary routing mechanism maps arguments directly to operational functions."""
    if args.command == "init":
        cmd_init(args)
    elif args.command == "collect":
        cmd_collect(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "serve":
        cmd_serve(args)
    elif args.command == "hub-serve":
        cmd_hub_serve(args)
    elif args.command == "schedule":
        cmd_schedule(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "baseline":
        cmd_baseline(args)
    elif args.command == "self-defense":
        if args.action == "watchdog":
            config = WatchdogConfig(
                watchdog_socket=args.socket,
                check_interval=args.interval
            )
            manager = SelfDefenseManager(config)
            manager.start_watchdog_service()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                manager.stop()
        elif args.action == "heartbeat":
            manager = SelfDefenseManager()
            success = manager.send_heartbeat(args.socket)
            sys.exit(0 if success else 1)
        elif args.action == "generate-profiles":
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            SelfDefenseManager.generate_seccomp_profile(str(output_dir / 'orin-seccomp.json'))
            SelfDefenseManager.generate_apparmor_profile(str(output_dir / 'orin-apparmor'))
            SelfDefenseManager.generate_selinux_policy(str(output_dir / 'orin-selinux.te'))
            print(f"Security profiles generated in {output_dir}")
        elif args.action == "status":
            manager = SelfDefenseManager()
            status = manager.validate_security_profiles()
            print(json.dumps(status, indent=2))
    elif args.command == "correlate":
        cmd_correlate(args)
    elif args.command == "delta":
        sys.exit(cmd_delta(args))
    elif args.command == "diff":
        sys.exit(cmd_diff(args))
    elif args.command == "export":
        sys.exit(cmd_export(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "stream":
        cmd_stream(args)
    elif args.command == "vault":
        if args.vault_command == "prune":
            if args.execute:
                args.dry_run = False
            else:
                args.dry_run = True
        cmd_vault(args)
    elif args.command == "rules":
        cmd_rules(args)
    elif args.command == "doctor":
        cmd_doctor(args)
    elif args.command == "collectors":
        cmd_collectors(args)

