#!/usr/bin/env python3
"""
Spectre HIDS - CLI Entry Point
Behavioral Host Intrusion Detection System with Active Containment
"""

import json
import os
import sys
import traceback
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cli.rule_cli import rule as rule_group
from cli.test_cli import test as test_group
from spectre import main as spectre_main

console = Console()


@click.group(invoke_without_command=True)
@click.version_option(version="10.0.0", prog_name="spectre")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def app(ctx, verbose):
    """
    Spectre HIDS - Behavioral Host Intrusion Detection System

    Instead of asking "Is this file known?", Spectre asks "Does this
    sequence of actions make sense?"

    Tracks process lineages, monitors file and network I/O, evaluates
    threats in real-time, provides MITRE ATT&CK context, scans payloads
    via YARA, and can actively quarantine or terminate malicious process
    trees.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if ctx.invoked_subcommand is None:
        # Show help if no subcommand
        click.echo(ctx.get_help())
        console.print(
            "\n[dim]Run 'spectre COMMAND --help' for more information on a command.[/dim]",
        )
        console.print("\n[bold cyan]Quick Start:[/bold cyan]")
        console.print(
            "  [green]spectre run --contain kill --api[/green]  "
            "# Full monitoring with containment & dashboard",
        )
        console.print(
            "  [green]spectre run --verbose[/green]            # Verbose mode for debugging",
        )
        console.print(
            "  [green]spectre rules list[/green]               # List loaded detection rules",
        )
        console.print(
            "  [green]spectre rule list[/green]                # List rule packs",
        )
        console.print(
            "  [green]spectre rule install webshell[/green]    # Install webshell rule pack",
        )
        console.print(
            "  [green]spectre test rule rules/packs/webshell/*.yml[/green]  # Test rules",
        )


# Add subcommand groups
app.add_command(rule_group, name="rule")
app.add_command(test_group, name="test")


@app.command()
@click.option("--interval", default=0.5, help="Polling interval in seconds")
@click.option("--window-size", "-w", default=60.0, help="Sliding window size in seconds")
@click.option("--threshold", "-t", default=15, help="Threat score threshold for alerts")
@click.option("--rules", "-r", default="rules.json", help="Path to rules JSON file")
@click.option("--log-file", default="/var/log/spectre/alerts.log", help="Alert log file path")
@click.option("--db", default="/var/lib/spectre/spectre.db", help="SQLite database path")
@click.option("--yara-rules", default="/usr/share/spectre/yara_rules", help="YARA rules directory")
@click.option(
    "--contain",
    type=click.Choice(["none", "stop", "kill"]),
    default="kill",
    help="Containment action",
)
@click.option("--api/--no-api", default=True, help="Enable REST API and dashboard")
@click.option("--api-port", default=8000, help="API server port")
@click.option("--verbose/--quiet", "-v/-q", default=False, help="Verbose output")
def run(  # noqa: PLR0913, PLR0917
    interval,
    window_size,
    threshold,
    rules,
    log_file,
    db,
    yara_rules,
    contain,
    api,
    api_port,
    verbose,
):
    """Run Spectre HIDS monitoring"""
    # Build sys.argv for main.py compatibility
    sys.argv = [
        "spectre",
        "--interval",
        str(interval),
        "--window-size",
        str(window_size),
        "--threshold",
        str(threshold),
        "--rules",
        rules,
        "--log-file",
        log_file,
        "--db",
        db,
        "--yara-rules",
        yara_rules,
        "--contain",
        contain,
    ]
    if api:
        sys.argv.append("--api")
    sys.argv.extend(["--api-port", str(api_port)])
    if verbose:
        sys.argv.append("--verbose")

    console.print(
        Panel.fit(
            "[bold cyan]Spectre HIDS v10.0.0[/bold cyan]\n"
            "[dim]Behavioral Host Intrusion Detection System[/dim]",
            border_style="cyan",
        ),
    )

    try:
        spectre_main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        if verbose:
            console.print(traceback.format_exc())
        sys.exit(1)


@app.command()
@click.option(
    "--format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def rules(format):
    """List loaded detection rules"""
    from spectre.rules import DEFAULT_RULES, load_rules_from_file  # noqa: PLC0415

    # Try to load from default locations
    rules = None
    for path in ["rules.json", "/etc/spectre/rules.json", "/usr/share/spectre/rules.json"]:
        if Path(path).exists():
            rules = load_rules_from_file(path)
            break

    if rules is None:
        rules = DEFAULT_RULES
        console.print("[yellow]Using default built-in rules[/yellow]")

    if format == "json":
        data = []
        for r in rules:
            data.append(
                {
                    "id": r.id,
                    "name": r.name,
                    "score": r.score,
                    "description": r.description,
                    "parent_names": r.parent_names,
                    "child_names": r.child_names,
                    "ancestor_names": r.ancestor_names,
                    "descendant_names": r.descendant_names,
                    "process_names": r.process_names,
                    "file_paths": r.file_paths,
                    "file_events": r.file_events,
                    "socket_events": r.socket_events,
                    "mitre_attack": [
                        {
                            "tactic": m.tactic,
                            "technique_id": m.technique_id,
                            "technique_name": m.technique_name,
                        }
                        for m in (r.mitre_attack or [])
                    ],
                },
            )
        console.print_json(json.dumps(data, indent=2))
    else:
        table = Table(title="Spectre Detection Rules", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="green")
        table.add_column("Name", style="white")
        table.add_column("Score", justify="right", style="yellow")
        table.add_column("MITRE ATT&CK", style="blue")
        table.add_column("Description", style="dim")

        for r in rules:
            mitre_str = r.get_mitre_str() or "—"
            table.add_row(
                r.id,
                r.name,
                str(r.score),
                mitre_str,
                r.description[:60] + "..." if len(r.description) > 60 else r.description,
            )

        console.print(table)
        console.print(f"\n[bold]Total:[/bold] {len(rules)} rules")


@app.command()
def stats():
    """Show database statistics"""
    from spectre.storage import SpectreDB  # noqa: PLC0415

    db_paths = ["/var/lib/spectre/spectre.db", "spectre.db", "./spectre.db"]
    db_path = None
    for p in db_paths:
        if Path(p).exists():
            db_path = p
            break

    if not db_path:
        console.print("[red]No database found[/red]")
        return

    db = SpectreDB(db_path)
    stats = db.get_stats()
    db.close()

    table = Table(title="Spectre Database Statistics", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")

    for key, value in stats.items():
        table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)


@app.command()
@click.option("--host", default="0.0.0.0", help="API host")  # noqa: S104
@click.option("--port", default=8000, help="API port")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def api(host, port, reload):
    """Run the REST API server standalone"""
    import uvicorn  # noqa: PLC0415

    from spectre.api import create_api  # noqa: PLC0415
    from spectre.storage import SpectreDB  # noqa: PLC0415

    db = SpectreDB("/var/lib/spectre/spectre.db")
    app = create_api(db)

    console.print(f"[cyan]Starting API server on {host}:{port}[/cyan]")
    uvicorn.run(app, host=host, port=port, reload=reload)


@app.command()
def doctor():
    """Run system diagnostics"""
    console.print("[bold]Spectre System Diagnostics[/bold]\n")

    checks = []

    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(("Python Version", py_ver, "✓" if sys.version_info >= (3, 8) else "✗"))

    # Dependencies
    deps = ["psutil", "networkx", "fastapi", "uvicorn", "yaml", "click", "rich"]
    for dep in deps:
        try:
            __import__(dep)
            checks.append((f"Module: {dep}", "OK", "✓"))
        except ImportError:
            checks.append((f"Module: {dep}", "MISSING", "✗"))

    # Optional deps
    try:
        import yara  # noqa: PLC0415

        _ = yara  # suppress unused warning
        checks.append(("Module: yara", "OK", "✓"))
    except ImportError:
        checks.append(("Module: yara", "Not installed (optional)", "○"))

    # System
    checks.append(("OS", f"{os.uname().sysname} {os.uname().release}", "✓"))
    checks.append(
        (
            "Root",
            "Yes" if os.geteuid() == 0 else "No (required for full monitoring)",
            "✓" if os.geteuid() == 0 else "⚠",
        ),
    )

    # Paths
    paths = [
        ("/proc", "Process filesystem"),
        ("/etc/spectre", "Config directory"),
        ("/var/log/spectre", "Log directory"),
        ("/var/lib/spectre", "Data directory"),
        ("/usr/share/spectre/yara_rules", "YARA rules"),
    ]
    for path, desc in paths:
        exists = Path(path).exists()
        checks.append((desc, path, "✓" if exists else "✗"))

    table = Table(show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Status", justify="center")

    for check in checks:
        table.add_row(check[0], check[1], check[2])

    console.print(table)


if __name__ == "__main__":
    app()
