"""
Rule CLI - Rule management commands for Spectre HIDS
"""

from __future__ import annotations

import json
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Rule pack registry
RULE_PACKS = {
    "webshell": {
        "name": "Web Shell Detection",
        "description": "Detects web server compromises, shell spawns, and post-exploitation",
        "rules": [
            "web_server_shell.yml",
            "web_server_compiler.yml",
            "shell_network_tool.yml",
            "shell_downloader.yml",
            "python_hosts_read.yml",
            "python_outbound.yml",
        ],
        "tags": ["webshell", "rce", "post-exploitation"],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "Detects sudo abuse, SUID exploitation, kernel exploits, and persistence",
        "rules": [
            "sudo_heuristic.yml",
            "suid_binary.yml",
            "kernel_exploit_compile.yml",
            "ld_preload.yml",
            "cron_modification.yml",
            "systemd_modification.yml",
        ],
        "tags": ["privilege-escalation", "persistence"],
    },
    "credential_access": {
        "name": "Credential Access",
        "description": (
            "Detects access to shadow files, SSH keys, browser credentials, and cloud secrets"
        ),
        "rules": [
            "shadow_file_access.yml",
            "ssh_key_access.yml",
            "browser_creds.yml",
            "gpg_key_access.yml",
            "aws_creds.yml",
            "docker_creds.yml",
        ],
        "tags": ["credential-access", "secrets"],
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "description": "Detects SSH, RDP, SMB, WMI, and pass-the-hash lateral movement",
        "rules": [
            "ssh_lateral.yml",
            "pass_the_hash.yml",
            "remote_service.yml",
            "smb_admin_share.yml",
            "rdp_lateral.yml",
            "wmi_winrm.yml",
        ],
        "tags": ["lateral-movement", "pivoting"],
    },
}

PACKS_DIR = Path(__file__).parent.parent / "spectre" / "rules" / "packs"
REGISTRY_FILE = PACKS_DIR / "registry.json"


def get_installed_packs() -> list[str]:
    """Get list of installed rule packs"""
    if REGISTRY_FILE.exists():
        with REGISTRY_FILE.open() as f:
            data = json.load(f)
            installed = data.get("installed", [])
            if isinstance(installed, list):
                return [str(x) for x in installed]
    return []


def save_installed_packs(packs: list[str]):
    """Save installed packs to registry"""
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with REGISTRY_FILE.open("w") as f:
        json.dump({"installed": packs}, f, indent=2)


def install_pack(pack_name: str, force: bool = False) -> bool:
    """Install a rule pack"""
    if pack_name not in RULE_PACKS:
        console.print(f"[red]Unknown pack: {pack_name}[/red]")
        console.print(f"Available: {', '.join(RULE_PACKS.keys())}")
        return False

    installed = get_installed_packs()
    if pack_name in installed and not force:
        console.print(
            f"[yellow]Pack '{pack_name}' already installed. Use --force to reinstall.[/yellow]",
        )
        return False

    pack_info = RULE_PACKS[pack_name]
    pack_dir = PACKS_DIR / pack_name

    if not pack_dir.exists():
        console.print(f"[red]Pack directory not found: {pack_dir}[/red]")
        return False

    # Verify rules exist
    missing = []
    for rule_file in pack_info["rules"]:
        if not (pack_dir / rule_file).exists():
            missing.append(rule_file)

    if missing:
        console.print(f"[red]Missing rule files: {missing}[/red]")
        return False

    # Add to installed
    if pack_name not in installed:
        installed.append(pack_name)
        save_installed_packs(installed)

    console.print(f"[green]Installed pack: {pack_name}[/green]")
    return True


def uninstall_pack(pack_name: str) -> bool:
    """Uninstall a rule pack"""
    installed = get_installed_packs()
    if pack_name not in installed:
        console.print(f"[yellow]Pack '{pack_name}' not installed[/yellow]")
        return False

    installed.remove(pack_name)
    save_installed_packs(installed)
    console.print(f"[green]Uninstalled pack: {pack_name}[/green]")
    return True


def list_packs(verbose: bool = False):
    """List available and installed rule packs"""
    installed = get_installed_packs()

    table = Table(title="Spectre Rule Packs", show_header=True)
    table.add_column("Pack", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Description")
    table.add_column("Rules", justify="right")
    table.add_column("Tags")

    for pack_id, info in RULE_PACKS.items():
        status = "[green]Installed[/green]" if pack_id in installed else "[dim]Available[/dim]"
        tags = ", ".join(info["tags"])
        desc = str(info["description"])
        table.add_row(
            pack_id,
            status,
            desc,
            str(len(info["rules"])),
            tags,
        )

    console.print(table)


def update_packs():
    """Update all installed packs"""
    installed = get_installed_packs()
    for pack in installed:
        console.print(f"[cyan]Updating {pack}...[/cyan]")
        install_pack(pack, force=True)
    console.print("[green]All packs updated[/green]")


@click.group()
def rule():
    """Rule pack management commands"""
    pass


@rule.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
def rule_list(verbose):
    """List available rule packs"""
    list_packs(verbose)


@rule.command("install")
@click.argument("pack_name")
@click.option("--force", "-f", is_flag=True, help="Force reinstall")
def rule_install(pack_name, force):
    """Install a rule pack"""
    install_pack(pack_name, force)


@rule.command("uninstall")
@click.argument("pack_name")
def rule_uninstall(pack_name):
    """Uninstall a rule pack"""
    uninstall_pack(pack_name)


@rule.command("update")
def rule_update():
    """Update all installed rule packs"""
    update_packs()


@rule.command("info")
@click.argument("pack_name")
def rule_info(pack_name):
    """Show detailed information about a rule pack"""
    if pack_name not in RULE_PACKS:
        console.print(f"[red]Unknown pack: {pack_name}[/red]")
        return

    info = RULE_PACKS[pack_name]
    installed = pack_name in get_installed_packs()

    console.print(
        Panel.fit(
            f"[bold cyan]{info['name']}[/bold cyan]\n"
            f"[bold]ID:[/bold] {pack_name}\n"
            f"[bold]Status:[/bold] {'Installed' if installed else 'Not Installed'}\n"
            f"[bold]Description:[/bold] {info['description']}\n"
            f"[bold]Tags:[/bold] {', '.join(info['tags'])}\n"
            f"[bold]Rules ({len(info['rules'])}):[/bold]",
            border_style="cyan",
        ),
    )

    table = Table(show_header=True)
    table.add_column("Rule File", style="green")
    table.add_column("Description")

    for rule_file in info["rules"]:
        rule_path = PACKS_DIR / pack_name / rule_file
        desc = "Unknown"
        if rule_path.exists():
            try:
                with rule_path.open() as f:
                    data = yaml.safe_load(f)
                    desc = str(data.get("description", "No description"))
            except Exception as e:  # noqa: S110
                _ = e
                pass
        table.add_row(rule_file, desc)

    console.print(table)


# Registry initialization
def init_registry():
    """Initialize rule pack registry"""
    if not REGISTRY_FILE.exists():
        save_installed_packs([])
