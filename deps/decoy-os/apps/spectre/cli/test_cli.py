"""
Test CLI - Rule testing framework for Spectre HIDS
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from spectre.rules.compiler import compile_sigma_rule  # noqa: PLC0415
from spectre.rules.sigma_parser import SigmaParser  # noqa: PLC0415

console = Console()


@click.group()
def test():
    """Rule testing commands"""
    pass


@test.command("rule")
@click.argument("rule_files", nargs=-1, type=click.Path(exists=True))
@click.option("--pcap", type=click.Path(exists=True), help="PCAP file for network-based rules")
@click.option("--trace", type=click.Path(exists=True), help="Trace file for replay testing")
@click.option(
    "--format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def test_rule(rule_files, pcap, trace, format):
    """Test detection rules against test data"""
    if not rule_files:
        console.print("[red]Error:[/red] No rule files specified")
        return

    console.print(
        Panel.fit(
            "[bold cyan]Spectre Rule Test Framework[/bold cyan]\n"
            "[dim]Phase 1 implementation - Sigma conversion and replay[/dim]",
            border_style="cyan",
        ),
    )

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Testing rules...", total=len(rule_files))

        for rule_file in rule_files:
            progress.update(task, description=f"Testing {rule_file}")

            # Load and validate rule
            result = _test_single_rule(rule_file, pcap, trace)
            results.append(result)

            progress.advance(task)
            time.sleep(0.1)

    # Display results
    _display_results(results, format)


@test.command("technique")
@click.argument("technique_id")
@click.option(
    "--atomic-path",
    default="~/atomic-red-team",
    help="Path to Atomic Red Team repository",
)
@click.option(
    "--format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def test_technique(technique_id, atomic_path, format):
    """Test detection against ATT&CK technique using Atomic Red Team"""
    console.print(f"[cyan]Testing technique: {technique_id}[/cyan]")
    console.print("[dim]Phase 1 implementation - Atomic Red Team integration[/dim]")

    # Placeholder for Atomic Red Team integration
    console.print("\n[yellow]Atomic Red Team integration will be implemented in Phase 1[/yellow]")
    console.print(f"Technique: {technique_id}")
    console.print(f"Atomic path: {atomic_path}")


@test.command("replay")
@click.argument("trace_file", type=click.Path(exists=True))
@click.option("--rules", default="rules.json", help="Rules file to test against")
@click.option(
    "--format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def test_replay(trace_file, rules, format):
    """Replay a trace file through the detection engine"""
    console.print(f"[cyan]Replaying trace: {trace_file}[/cyan]")
    console.print("[dim]Phase 1 implementation - Trace replay engine[/dim]")

    # Placeholder for trace replay
    console.print("\n[yellow]Trace replay engine will be implemented in Phase 1[/yellow]")
    console.print(f"Trace: {trace_file}")
    console.print(f"Rules: {rules}")


@test.command("coverage")
@click.option("--rules", default="rules.json", help="Rules file to analyze")
@click.option(
    "--format",
    type=click.Choice(["table", "json", "matrix"]),
    default="matrix",
    help="Output format",
)
def test_coverage(rules, format):
    """Show ATT&CK coverage for loaded rules"""
    console.print("[cyan]ATT&CK Coverage Analysis[/cyan]")
    console.print("[dim]Phase 1 implementation[/dim]")

    # Placeholder
    console.print("\n[yellow]Coverage analysis will be implemented in Phase 1[/yellow]")


def _test_single_rule(rule_file: str, pcap: str | None, trace: str | None) -> dict:
    """Test a single rule file"""
    result: dict = {
        "rule": rule_file,
        "valid": False,
        "errors": [],
        "warnings": [],
        "sigma_conversion": None,
    }

    try:
        # Try to parse as Sigma YAML

        with Path(rule_file).open() as f:
            content = f.read()

        data = yaml.safe_load(content)

        # Basic Sigma validation
        required = ["title", "id", "detection"]
        for field in required:
            if field not in data:
                result["errors"].append(f"Missing required field: {field}")

        if "condition" not in data.get("detection", {}):
            result["errors"].append("Missing 'condition' in detection")

        if not result["errors"]:
            result["valid"] = True

            # Try Sigma conversion
            try:
                parser = SigmaParser()
                sigma_rule = parser.parse_string(content)
                compile_result = compile_sigma_rule(sigma_rule)

                if compile_result.rule:
                    result["sigma_conversion"] = {
                        "spectre_id": compile_result.rule.id,
                        "score": compile_result.rule.score,
                        "mitre": compile_result.rule.get_mitre_str(),
                    }
                else:
                    result["errors"].extend(compile_result.errors)
                    result["warnings"].extend(compile_result.warnings)

            except Exception as e:
                result["warnings"].append(f"Sigma conversion not available: {e}")

    except yaml.YAMLError as e:
        result["errors"].append(f"Invalid YAML: {e}")
    except Exception as e:
        result["errors"].append(f"Error: {e}")

    return result


def _display_results(results: list[dict], format: str):
    """Display test results"""
    if format == "json":
        console.print_json(json.dumps(results, indent=2))
        return

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r["valid"] and not r["errors"])
    failed = total - passed

    console.print(f"\n[bold]Results:[/bold] {passed}/{total} passed, {failed} failed\n")

    # Detailed table
    table = Table(title="Rule Test Results", show_header=True)
    table.add_column("Rule", style="cyan")
    table.add_column("Valid", justify="center")
    table.add_column("Sigma Conversion", justify="center")
    table.add_column("Errors", style="red")
    table.add_column("Warnings", style="yellow")

    for r in results:
        valid = "[green]✓[/green]" if r["valid"] else "[red]✗[/red]"
        sigma = "[green]✓[/green]" if r["sigma_conversion"] else "[dim]-[/dim]"
        errors = "\n".join(r["errors"]) if r["errors"] else "—"
        warnings = "\n".join(r["warnings"]) if r["warnings"] else "—"

        table.add_row(
            Path(r["rule"]).name,
            valid,
            sigma,
            errors,
            warnings,
        )

    console.print(table)

    # Show Sigma conversion details
    for r in results:
        if r["sigma_conversion"]:
            conv = r["sigma_conversion"]
            console.print(f"\n[bold]Sigma Conversion for {Path(r['rule']).name}:[/bold]")
            console.print(f"  Spectre ID: {conv['spectre_id']}")
            console.print(f"  Score: {conv['score']}")
            console.print(f"  MITRE: {conv['mitre']}")


if __name__ == "__main__":
    test()
