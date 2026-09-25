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
# src/orin/core/scanner.py
"""
orin.core.scanner – Agentless SSH Scanner Core
=============================================
Manages execution of the self-contained remote telemetry agent on target nodes
over SSH, extracts telemetry payloads, stores them in the SQLite vault, and
invokes the threat-rules analyzer cycle.

Agent Script Signing Integration
--------------------------------
Before executing the remote agent script, the scanner verifies its integrity
using HMAC-SHA256 signatures to ensure only trusted, unmodified code is deployed.
"""
import sys
import os
import json
import subprocess
from pathlib import Path
from orin.core.database import OrinStorage
from orin.core.config import load_config
from orin.core.credentials import CredentialManager
from orin.analysis.engine import run_analysis_cycle
from orin.core.agent_signing import AgentSigner
from orin.core.rate_limiter import create_rate_limiter_from_config


def run_remote_scan(
    host: str,
    user: str,
    key_path: str = None,
    port: int = 22,
    db_path: Path = Path("orin_vault.db"),
    config: dict = None,
    signing_secret: str = None,
    verify_signature: bool = True,
    strict_host_keys: bool = True,
    known_hosts_file: str = None
) -> dict:
    """Execute remote telemetry gathering over SSH and run the threat rules analysis.

    Parameters
    ----------
    host : str
        Target hostname or IP address.
    user : str
        SSH user account name.
    key_path : str, optional
        Path to the private SSH key file.
    port : int, optional
        SSH port to connect on (default 22).
    db_path : Path, optional
        Path to local Orin SQLite database.
    config : dict, optional
        Local config overrides. Loaded from config module if None.
    signing_secret : str, optional
        HMAC passphrase for agent script signing verification.
        If None, falls back to ORIN_AGENT_SIGNING_KEY environment variable.
    verify_signature : bool, optional
        Enable agent signature verification before execution (default True).

    Returns
    -------
    dict
        The risk metrics and analysis results from the analysis cycle.
    """
    if config is None:
        config = load_config()

    # Initialize SSH rate limiter from configuration
    rate_limiter = create_rate_limiter_from_config(config)
    rate_limit_enabled = config.get("ssh", {}).get("rate_limit", {}).get("enabled", True)

    if rate_limit_enabled:
        print(f"[*] SSH rate limiting enabled (max concurrent: {rate_limiter.max_concurrent}, "
              f"max scans/min: {rate_limiter.max_scans_per_minute})")

    # Locate the remote_agent.py script path dynamically
    # Expecting it in orin/collectors/remote_agent.py
    current_dir = Path(__file__).resolve().parent
    agent_path = current_dir.parent / "collectors" / "remote_agent.py"
    agent_bash_path = current_dir.parent / "collectors" / "remote_agent.sh"

    if not agent_path.exists():
        raise FileNotFoundError(f"Remote agent script not found at {agent_path}")

    # Sign and verify the agent script before transmission
    if verify_signature:
        # Load signing secret from parameter or environment
        if signing_secret is None:
            signing_secret = os.environ.get("ORIN_AGENT_SIGNING_KEY")

        if signing_secret:
            print("[*] Signing and verifying agent script integrity...")

            # Create signer instance
            signer = AgentSigner(secret_key=signing_secret)

            # Sign the agent script
            bundle = signer.sign(agent_path, metadata={
                "source_path": str(agent_path),
                "scan_target": host,
                "initiated_by": user
            })

            # Verify the signature immediately after signing
            is_valid, message = signer.verify(bundle)

            if not is_valid:
                raise RuntimeError(f"Agent signature verification failed: {message}")

            print(f"[+] {message}")

            # Use the signed content for transmission
            remote_agent_code = bundle["content"]
        else:
            # No signing key provided - read agent normally but warn
            remote_agent_code = agent_path.read_text(encoding="utf-8")
            print("[!] WARNING: Agent signing disabled - no signing key provided")
            print("    Set ORIN_AGENT_SIGNING_KEY environment variable or pass signing_secret parameter")
    else:
        # Signature verification disabled
        remote_agent_code = agent_path.read_text(encoding="utf-8")
        print("[!] Agent signature verification disabled by configuration")

    remote_agent_bash_code = None
    if agent_bash_path.exists():
        remote_agent_bash_code = agent_bash_path.read_text(encoding="utf-8")

    # Serialize configuration values needed by the remote FIM and SUID check
    agent_config = {
        "critical_paths": config.get("critical_paths", []),
        "critical_dirs": config.get("critical_dirs", []),
        "vault_path": config.get("vault_path", "/var/lib/orin/vault")
    }
    config_json_str = json.dumps(agent_config)

    # Load SSH security configuration from config
    ssh_config = config.get("ssh", {}) if config else {}
    strict_host_checking = ssh_config.get("strict_host_key_checking", "ask")
    if known_hosts_file is None:
        known_hosts_file = ssh_config.get("known_hosts_file")
    connection_timeout = ssh_config.get("connection_timeout", 30)
    max_retries = ssh_config.get("max_retries", 3)

    # Implement Trust-On-First-Use (TOFU)
    if not strict_host_keys:
        strict_host_checking = "no"
    elif strict_host_checking == "ask":
        strict_host_checking = "accept-new"

    # Construct the SSH subprocess execution command list with configurable security options
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
    if key_path:
        ssh_cmd.extend(["-i", str(key_path)])

    print(f"[*] Connecting to remote host {user}@{host}:{port} via SSH...")

    # Use rate limiter to control SSH connection if enabled
    if rate_limit_enabled:
        connection_context = rate_limiter.acquire_connection(host)
    else:
        # Dummy context manager if rate limiting disabled
        from contextlib import nullcontext
        connection_context = nullcontext()

    with connection_context:
        # Try Python first, fall back to bash if Python is unavailable
        telemetry = None

        # Attempt 1: Python agent
        ssh_cmd_py = ssh_cmd + [f"{user}@{host}", f"python3 - '{config_json_str}'"]
        try:
            proc = subprocess.Popen(
                ssh_cmd_py,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=remote_agent_code)

            if proc.returncode == 0:
                try:
                    telemetry = json.loads(stdout.strip())
                    print("[+] Remote agent: Python executor")
                except json.JSONDecodeError:
                    telemetry = None
        except Exception as e:
            sys.stderr.write(f"[-] Python agent execution failed: {e}\n")
            telemetry = None

        # Attempt 2: Bash fallback if Python failed
        if telemetry is None and remote_agent_bash_code is not None:
            print("[*] Python not available or failed, falling back to bash agent...")
            ssh_cmd_bash = ssh_cmd + [f"{user}@{host}", "bash -s"]
            try:
                proc = subprocess.Popen(
                    ssh_cmd_bash,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(input=remote_agent_bash_code)

                if proc.returncode == 0:
                    try:
                        telemetry = json.loads(stdout.strip())
                        print("[+] Remote agent: Bash fallback executor")
                    except json.JSONDecodeError as json_error:
                        sys.stderr.write(f"[-] Raw Response (stdout):\n{stdout}\n")
                        sys.stderr.write(f"[-] Error Output (stderr):\n{stderr}\n")
                        raise RuntimeError(f"Failed to parse remote telemetry JSON from bash agent: {json_error}")
                else:
                    sys.stderr.write(f"[-] Bash Execution Failed (code {proc.returncode}):\n{stderr}\n")
                    raise RuntimeError(f"Remote command execution failed over SSH (bash fallback): {stderr.strip()}")
            except Exception as e:
                raise RuntimeError(f"Failed to spawn SSH subprocess pipeline for bash agent: {e}")
        elif telemetry is None:
            raise RuntimeError("Both Python and bash agents failed. Bash agent script not found.")

    # Record success or failure with rate limiter
    if rate_limit_enabled:
        if telemetry is not None:
            rate_limiter.record_success(host)
        else:
            rate_limiter.record_failure(host)

    # Extract target host details
    remote_hostname = telemetry.get("hostname", host)
    remote_os = telemetry.get("os_platform", "Linux")

    print(f"[+] Remote telemetry acquired for host: {remote_hostname} ({remote_os})")

    # Determine encryption passphrase from config/environment using CredentialManager
    config = config or load_config()
    vault_config = config.get("vault_encryption", {})
    encryption_passphrase = None

    if vault_config.get("enabled", False):
        passphrase_env = vault_config.get("passphrase_env", "ORIN_VAULT_PASSPHRASE")
        min_length = vault_config.get("min_passphrase_length", 12)

        # Use CredentialManager for secure passphrase loading
        cred_manager = CredentialManager(
            vault_passphrase_env=passphrase_env,
            min_passphrase_length=min_length
        )

        passphrase_cred = cred_manager.load_vault_passphrase(required=False)

        if passphrase_cred:
            encryption_passphrase = passphrase_cred.get_value()
            print("[+] Evidence vault encryption enabled (AES-256-GCM)")
        else:
            print("[!] Vault encryption enabled but passphrase not found in environment")
            print(f"    Set {passphrase_env} environment variable to enable encryption")

    # Write snapshot to DB
    storage = OrinStorage(db_path, encryption_passphrase=encryption_passphrase)
    with storage.get_connection() as conn:
        snapshot_id = storage.create_snapshot(conn, hostname=remote_hostname, os_platform=remote_os)
        print(f"[+] Assigned Snapshot ID #{snapshot_id} in vault")

        # Persist all collected datasets in database
        if "processes" in telemetry:
            storage.store_processes(conn, snapshot_id, telemetry["processes"])
        if "ports" in telemetry:
            storage.store_ports(conn, snapshot_id, telemetry["ports"])
        if "outbound" in telemetry:
            storage.store_outbound_connections(conn, snapshot_id, telemetry["outbound"])
        if "promisc" in telemetry:
            storage.store_promisc_interfaces(conn, snapshot_id, telemetry["promisc"])
        if "modules" in telemetry:
            storage.store_kernel_modules(conn, snapshot_id, telemetry["modules"])
        if "kernel_symbols" in telemetry:
            storage.store_kernel_symbols(conn, snapshot_id, telemetry["kernel_symbols"])
        if "kernel_analysis" in telemetry:
            storage.store_kernel_analysis(conn, snapshot_id, telemetry["kernel_analysis"])
        if "users" in telemetry:
            storage.store_users(conn, snapshot_id, telemetry["users"])
        if "ssh_keys" in telemetry:
            storage.store_ssh_keys(conn, snapshot_id, telemetry["ssh_keys"])
        if "crontabs" in telemetry:
            storage.store_crontabs(conn, snapshot_id, telemetry["crontabs"])
        if "wtmp" in telemetry:
            storage.store_wtmp_sessions(conn, snapshot_id, telemetry["wtmp"])
        if "lastlog" in telemetry:
            storage.store_lastlog_records(conn, snapshot_id, telemetry["lastlog"])
        if "deleted" in telemetry:
            storage.store_deleted_binaries(conn, snapshot_id, telemetry["deleted"])
        if "fim" in telemetry:
            storage.store_file_hashes(conn, snapshot_id, telemetry["fim"])
        if "suid" in telemetry:
            storage.store_suid_binaries(conn, snapshot_id, telemetry["suid"])
        if "pkg_integrity" in telemetry:
            storage.store_pkg_integrity(conn, snapshot_id, telemetry["pkg_integrity"])
        if "auth_logs" in telemetry:
            storage.store_auth_logs(conn, snapshot_id, telemetry["auth_logs"])
        if "ebpf_programs" in telemetry:
            storage.store_ebpf_programs(conn, snapshot_id, telemetry["ebpf_programs"])
        if "ebpf_pinned" in telemetry:
            storage.store_ebpf_pinned(conn, snapshot_id, telemetry["ebpf_pinned"])
        if "ld_preload" in telemetry:
            storage.store_ld_preload(conn, snapshot_id, telemetry["ld_preload"])
        if "special_fds" in telemetry:
            storage.store_special_fds(conn, snapshot_id, telemetry["special_fds"])
        if "privilege_events" in telemetry:
            storage.store_privilege_events(conn, snapshot_id, telemetry["privilege_events"])

        conn.commit()

    print("[*] Telemetry saved. Executing posture threat assessment cycle...")
    metrics = run_analysis_cycle(db_path)
    return metrics