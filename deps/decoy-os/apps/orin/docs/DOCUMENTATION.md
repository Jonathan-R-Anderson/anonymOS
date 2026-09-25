# Orin — Practitioner's Guide

> Full architecture reference, workflow documentation, and module internals for Orin v1.2.0.

---

## Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Core Workflows](#5-core-workflows)
6. [Module Internals — Core](#6-module-internals--core)
7. [Module Internals — Collectors](#7-module-internals--collectors)
8. [Module Internals — Analysis](#8-module-internals--analysis)
9. [Threat Detection](#9-threat-detection)
10. [Evidence Handling](#10-evidence-handling)
11. [Security Model](#11-security-model)
12. [Performance](#12-performance)
13. [Operations](#13-operations)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Overview

Orin is a point-in-time forensic snapshot platform for Linux. It captures complete system state, compares snapshots against trusted baselines, evaluates the delta against a threat detection rule engine, and produces tamper-evident evidence bundles — with no network access, telemetry, cloud connectivity, or third-party runtime dependencies.

### Design Goals

**Zero external dependencies.** All collectors read directly from kernel interfaces (`/proc`, `/sys`, `/var/log`). The entire runtime operates on the Python standard library. The only optional dependency is the system `libbpf` shared library, required only for real-time eBPF streaming.

**Forensic integrity.** Every evidence export is signed with HMAC-SHA256. The vault supports AES-256-GCM encryption at rest. Exports carry a verifiable chain of custody that does not require an external PKI.

**Air-gap compatibility.** Orin never attempts outbound connections. No licenses are checked, no telemetry is emitted, no update checks are performed. All threat intelligence (STIX, TAXII, CSV) is imported offline.

**Minimal footprint.** Orin does not install a persistent daemon. Collection is triggered manually or via a cron job; analysis and reporting are discrete operations. The process exits cleanly after each run.

### Canonical Workflow

```
orin init
    └─ Creates the SQLite vault
    └─ Records trusted baselines (kernel modules, accounts, SUID binaries)

orin collect
    └─ Harvests full system state snapshot → persists to vault

orin analyze
    └─ Evaluates snapshot against threat detection rules
    └─ Produces severity-tiered risk score (0–100)
    └─ Triggers alert forwarding if configured

orin report
    └─ Compiles forensic briefing from latest snapshot and unresolved alerts
    └─ Outputs HTML or Markdown
```

---

## 2. Architecture

### 2.1 Layer Model

Orin is organized into three functional layers inside `src/orin/`:

```
core/          Infrastructure: storage, HTTP, SSH, scheduling, crypto, config
collectors/    Data acquisition: reads live kernel state into snapshot records
analysis/      Reasoning: evaluates snapshots, detects threats, generates reports
```

Supporting directories:

```
web/           Static web assets (dashboard)
scripts/       Shell utilities (eBPF build, remote Bash agent)
```

### 2.2 Data Flow

```
Kernel interfaces          Collectors              Vault (SQLite)
─────────────────    →    ──────────────    →    ──────────────────
/proc/[pid]/...            processes.py           snapshots table
/proc/net/tcp              connections.py         alerts table
/proc/modules              kernel.py              baselines table
/etc/passwd                users.py               ebpf_events table
/var/log/auth.log          logs.py                ...
inotify / eBPF ring buf    ebpf.py
```

```
Vault (SQLite)             Analysis               Output
──────────────    →    ──────────────────    →    ──────────────
Latest snapshot            engine.py              alerts (SQLite)
Previous snapshots         diff.py                risk score
Baselines                  timeline.py            HTML / Markdown report
                           unhide.py              HMAC-signed JSON export
```

### 2.3 Storage Model

All state is kept in a single SQLite database at `/var/lib/orin/orin_vault.db` by default. The database operates in WAL mode for concurrent read access during serving. A connection pool manages handle reuse across modules.

When vault encryption is enabled, snapshot payloads are encrypted with AES-256-GCM before being stored. The encryption key is derived from the passphrase using PBKDF2-HMAC-SHA256 (600,000 iterations). Unencrypted operation is the default and retains full backward compatibility.

### 2.4 Privilege Model

Most collectors read privileged kernel interfaces and require root. Specific operations that mandate root:

- `/proc/kallsyms` (kernel symbol table, rootkit analysis)
- `/proc/[pid]/exe`, `/proc/[pid]/maps` (process binary inspection)
- `/var/log/auth.log`, `/var/log/wtmp`, `/var/log/lastlog`
- `eBPF program loading` (requires `CAP_BPF` or root)
- SSH key and shadow file inspection

Non-privileged operations (usable without root):

- `orin diff` (compares two database files)
- `orin verify` (validates an export file's HMAC)
- `orin report` (reads vault, generates report)

---

## 3. Installation

### 3.1 Requirements

- Python ≥ 3.10
- Linux kernel ≥ 4.18 (kernel ≥ 5.8 recommended for eBPF ring buffer support)
- Root access for privileged collection
- Optional: system `libbpf` (≥ 0.6) for real-time eBPF streaming

### 3.2 Install Methods

**Automated installer (recommended for production)**

```bash
chmod +x install.sh && sudo ./install.sh
```

The installer places the `orin` binary on `$PATH`, creates `/var/lib/orin/` with appropriate permissions, and optionally installs the cron job.

**System-wide pip install**

```bash
sudo pip install . --break-system-packages
```

**Development mode**

```bash
pip install -e .
PYTHONPATH=src python -m orin.main <subcommand>
```

Development mode is useful for iterating on collectors or rules without reinstalling. The `PYTHONPATH` prefix is required because `src/` layout is not automatically on the module search path.

### 3.3 eBPF Setup

**Runtime hosts (streaming consumer only)**

Install the system `libbpf` shared library. No compiler or kernel headers are required.

```bash
# Debian / Ubuntu
sudo apt-get install libbpf1

# RHEL / Rocky / Alma
sudo dnf install libbpf
```

**Development hosts (recompiling the eBPF program)**

```bash
sudo ./scripts/setup_ebpf.sh --build
```

This script installs `clang`, `llvm`, `linux-headers`, and the `libbpf` development package, then compiles the eBPF C source to a BTF-annotated object file. The compiled object is embedded at runtime; distribution hosts do not need a compiler.

Refer to [EBPF_TROUBLESHOOTING.md](EBPF_TROUBLESHOOTING.md) for BTF prerequisites, kernel version constraints, and common error messages.

---

## 4. Configuration

### 4.1 Config File

Orin searches for `orin_config.json` in `./` then `/etc/orin/`, falling back to built-in defaults. All keys are optional; omitted keys inherit their defaults.

```json
{
  "vault_path": "/var/lib/orin/orin_vault.db",
  "log_path": "/var/log/orin/orin.log",
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome", "language_server"],
  "critical_paths": [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/crontab"
  ],
  "critical_dirs": [
    "/etc/cron.d",
    "/etc/systemd/system"
  ],
  "fim_paths": ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"],
  "fim_exclude_patterns": ["*.pyc", "*.log", "*.tmp"],
  "risk_score_thresholds": {
    "low": 20,
    "medium": 50,
    "high": 75,
    "critical": 90
  }
}
```

The config loader uses a deep-copy merge so partial configs do not silently inherit stale nested values from a previous load. Each key documented in full in [CONFIGURATION.md](CONFIGURATION.md).

### 4.2 Encrypted Vault

```bash
export ORIN_VAULT_PASSPHRASE="your-strong-passphrase"
sudo orin init
sudo orin collect
```

Once initialized with a passphrase, all subsequent operations that read or write snapshot data must supply the same credential. The vault header stores the PBKDF2 salt and AES-GCM nonce; the passphrase itself is never stored.

Passphrase input methods (in order of preference for scripted environments):

```bash
--secret-file /path/to/pass.txt     # File must have mode 0600
--secret-prompt                      # Interactive masked prompt; suitable for manual runs
--secret-env-var MY_CUSTOM_VAR       # Read from a named environment variable
ORIN_VAULT_PASSPHRASE=...            # Default environment variable name
```

### 4.3 Alert Forwarding

Forwarding executes automatically after every `orin analyze`. Failed deliveries retry with exponential backoff and are recorded in a JSONL audit log; they never abort the analysis cycle.

```json
{
  "notifications": {
    "enabled": true,
    "min_severity": "high",
    "syslog": {
      "enabled": true,
      "facility": "LOG_LOCAL0",
      "tag": "orin-alert"
    },
    "webhooks": [
      {
        "name": "ops-slack",
        "url": "http://192.168.1.10:8080/slack-webhook",
        "format": "slack",
        "min_severity": "critical",
        "timeout_seconds": 10,
        "enabled": true
      },
      {
        "name": "teams-soc",
        "url": "http://192.168.1.20:8080/teams-webhook",
        "format": "teams",
        "min_severity": "high",
        "timeout_seconds": 10,
        "enabled": true
      }
    ],
    "retry": {
      "max_attempts": 3,
      "backoff_seconds": 5
    },
    "audit_log": "/var/log/orin/notification_audit.log"
  }
}
```

Supported webhook formats: `slack` (Block Kit), `teams` (Adaptive Cards), `json` (generic POST). All delivery is via `urllib.request` — no third-party HTTP library is required.

---

## 5. Core Workflows

### 5.1 `orin init`

Creates the SQLite vault and records immutable baselines for:

- **Kernel modules** — the set of loaded LKMs at initialization time, used to detect subsequent unauthorized loads.
- **User accounts** — `/etc/passwd` snapshot, used to detect account creation or UID changes.
- **SUID/SGID binaries** — filesystem scan for setuid/setgid binaries, used to detect privilege escalation backdoors.

```bash
sudo orin init
sudo orin init --vault /custom/path/orin.db
```

`init` is idempotent on re-runs against an existing vault: it updates baselines without destroying existing snapshot history. To fully reset, delete the vault file and re-run.

### 5.2 `orin collect`

Harvests a full system state snapshot and persists it to the vault. Runs all enabled collector modules sequentially (default) or concurrently.

```bash
sudo orin collect
sudo orin collect --parallel --workers 4
```

**Sequential collection** is the safe default. Each collector runs to completion before the next starts; resource contention is minimal.

**Parallel collection** uses `ThreadPoolExecutor` via `core/parallel.py`. Collectors are grouped into tiers by dependency: collectors with no inter-dependencies run concurrently within a tier; dependent collectors run in a subsequent tier. Benchmark: approximately 15× faster on a system with ≥ 4 cores. See [PARALLEL_COLLECTION_FEATURE.md](PARALLEL_COLLECTION_FEATURE.md).

Each snapshot is assigned a monotonically incrementing ID. Snapshots accumulate in the vault until pruned with `orin vault prune`.

### 5.3 `orin analyze`

Evaluates the latest snapshot against all active threat detection rules. Produces a severity-tiered risk score (0–100) and persists alerts to the vault.

```bash
sudo orin analyze
```

The analysis pipeline:

1. Load the latest snapshot from the vault.
2. Evaluate all rules in `analysis/engine.py` against the snapshot data.
3. Run YARA signatures against collected file hashes and memory regions.
4. Run Sigma rules against parsed log entries.
5. Cross-reference with any loaded offline threat intelligence (STIX/CSV).
6. Compute a composite risk score weighted by alert severity.
7. Auto-resolve alerts that are no longer present (e.g., a suspicious process that has exited).
8. Trigger alert forwarding for any new alerts above the configured `min_severity`.

### 5.4 `orin report`

Compiles a forensic briefing from the latest snapshot and all unresolved alerts.

```bash
sudo orin report --format html --output /tmp/orin_report.html
sudo orin report --format markdown --output /tmp/orin_report.md
```

Report contents:

- Executive summary with risk score and alert counts by severity
- Timeline of significant events since the last clean baseline
- Per-alert details: affected artifact, detection rule, MITRE ATT&CK mapping, recommended action
- System state summary: active network connections, running processes, loaded kernel modules, recent authentication events
- File integrity violations with before/after hashes
- Snapshot metadata: collection timestamp, hostname, kernel version, Orin version

### 5.5 `orin stream`

Launches the eBPF real-time telemetry consumer. Requires `libbpf`.

```bash
sudo orin stream
sudo orin stream --verbose
```

The eBPF program instruments three syscall entry points:

- `execve` — records process execution events (binary path, arguments, UID, PID, parent PID)
- `connect` — records outbound TCP/UDP connection attempts (destination IP, port, PID)
- `openat` — records file open events on monitored paths (filename, flags, PID)

Events flow from the kernel via a ring buffer to the userspace consumer in `collectors/ebpf.py`, which writes them to the `ebpf_events` table in the vault. The streaming loop runs until interrupted. Events are queryable via the dashboard and included in subsequent `analyze` runs.

### 5.6 `orin scan`

Agentless remote scan over SSH. Transfers and executes a collection agent on the target host, then retrieves the resulting snapshot.

```bash
sudo orin scan --host 192.168.1.50 --user root --key ~/.ssh/id_ed25519
sudo orin scan --host 192.168.1.50 --user root --init
sudo orin scan --host 192.168.1.50 --user root --password
sudo orin scan --host 192.168.1.50 --user analyst --key ~/.ssh/id_ed25519 --sudo
```

**Agent selection:**

1. If Python ≥ 3.10 is present on the target, `collectors/remote_agent.py` (stdlib-only) is transferred and executed.
2. If Python is absent or below the minimum version, `scripts/remote_agent.sh` (pure Bash) is used as a fallback.

The remote agent collects a subset of the full local collector suite (processes, connections, users, kernel modules, file hashes for `/etc` and critical binaries). Results are returned as a signed JSON payload. The HMAC signature is verified by `core/ssh/agent_signing.py` before the snapshot is written to the vault.

Host key verification is enforced by default. On first connection, the host key is recorded in the vault and subsequent connections are verified against it. See [SSH_GUIDE.md](SSH_GUIDE.md).

Rate limiting is applied per target host. Repeated scan failures trigger exponential backoff to prevent accidental lockout. See [SSH_GUIDE.md](SSH_GUIDE.md) and `core/ssh/rate_limiter.py`.

### 5.7 `orin schedule`

Installs or removes the automated `collect → analyze` cron job.

```bash
sudo orin schedule --install                  # Default: every 10 minutes
sudo orin schedule --install --interval 30    # Every 30 minutes
sudo orin schedule --status                   # Show current cron entry
sudo orin schedule --remove
```

The cron job is written to `/etc/cron.d/orin`. Alert forwarding (if configured) fires automatically after each scheduled analysis cycle. For continuous real-time coverage, combine `orin schedule` (periodic full snapshots) with `orin stream` (live eBPF event capture).

### 5.8 `orin vault`

Manage snapshot lifecycle.

```bash
sudo orin vault stats                                 # Show snapshot count, size, oldest/newest
sudo orin vault prune --older-than 30 --dry-run       # Preview: delete snapshots older than 30 days
sudo orin vault prune --older-than 30 --execute       # Execute the prune
sudo orin vault prune --keep-last 10 --execute        # Keep only the 10 most recent snapshots
sudo orin vault prune --keep-last 10 --no-preserve-critical --execute
```

By default, `prune` preserves snapshots that have unresolved critical alerts attached, regardless of age. The `--no-preserve-critical` flag overrides this behaviour. Pruning is permanent; take an export first if long-term retention is required.

### 5.9 `orin delta` and `orin diff`

`orin delta` compares two snapshots within the same vault by ID:

```bash
sudo orin delta --base 1 --target 3
```

Output: a structured diff of every changed collection domain (processes added/removed, new network connections, modified files, changed kernel modules, account changes).

`orin diff` compares two separate vault database files:

```bash
orin diff /backups/orin_day1.db /var/lib/orin/orin_vault.db
```

Useful for comparing a clean baseline vault (stored offline) against a current operational vault without loading both into the same instance.

### 5.10 `orin export` and `orin verify`

Export a snapshot as a tamper-evident signed JSON bundle:

```bash
sudo orin export --snapshot 2 --secret "passphrase"
```

This produces `orin_export_snap_2.json` containing the snapshot data and an HMAC-SHA256 signature computed over the canonical JSON serialization.

Verify a previously exported bundle:

```bash
orin verify --file orin_export_snap_2.json --secret "passphrase"
```

Verification re-derives the HMAC from the bundle content using the provided secret and compares it against the stored signature. A mismatch indicates the bundle has been modified. Verification does not require vault access and can be run on an analyst workstation with no other Orin state.

### 5.11 `orin serve`

Starts a local forensic web console at `127.0.0.1:8000`.

```bash
sudo orin serve
sudo orin serve --port 9090
sudo orin serve --no-auth          # Trusted isolated networks only
```

On each start, a one-time session token is printed to the terminal. The token is a cryptographically random value that expires when the server process exits. It must be supplied as a Bearer token in the `Authorization` header for all API requests. The dashboard JavaScript handles this automatically when opened from the terminal-printed URL.

The dashboard provides: snapshot browser, alert timeline, process tree viewer, network connection map, FIM change log, eBPF event stream (live), and report generation.

See [DASHBOARD_GUIDE.md](DASHBOARD_GUIDE.md) for the full API reference and JavaScript function documentation.

### 5.12 `orin hub-serve`

Starts the centralized fleet hub for multi-tenant forensic management.

```bash
sudo orin hub-serve 8000 --host 0.0.0.0 --cert /path/to/cert.pem --key /path/to/key.pem
```

The hub aggregates snapshots and alerts from multiple remote Orin instances. Each remote agent authenticates with an HMAC-signed payload; the hub validates signatures before accepting data. TLS is required for production deployments — the `--cert` and `--key` flags are mandatory when binding to a non-loopback address.

---

## 6. Module Internals — Core

### `core/config.py`

Loads `orin_config.json` from the search path (`./`, `/etc/orin/`), merges it against built-in defaults using a deep-copy strategy, and exposes a typed config object to all other modules. The deep-copy merge ensures that a partial config file cannot accidentally inherit stale nested structures from a prior load (relevant in test environments where the module may be imported multiple times).

### `core/credentials.py`

Centralizes all passphrase resolution logic. Implements the four resolution strategies in priority order: `--secret-file`, `--secret-prompt`, `--secret-env-var`, `ORIN_VAULT_PASSPHRASE`. Enforces file mode check (0600) when reading from a secret file. Masks the prompt when reading interactively. Returns a normalized `bytes` credential regardless of source.

### `core/storage/crypto.py`

All cryptographic primitives:

- **HMAC-SHA256 signing**: computes and verifies message authentication codes for export bundles and remote agent payloads.
- **AES-256-GCM encryption**: encrypts and decrypts snapshot payloads for the encrypted vault. Each operation generates a fresh 96-bit random nonce. The authentication tag is stored alongside the ciphertext; tampered ciphertexts raise `InvalidTag` on decryption.
- **PBKDF2-HMAC-SHA256 key derivation**: 600,000 iterations, 32-byte output, random 16-byte salt generated at init time and stored in the vault header.

All operations use the Python `hashlib`, `hmac`, and `secrets` standard library modules. No third-party cryptography library is required.

### `core/storage/database.py`

SQLite ORM and connection management:

- **WAL mode**: `PRAGMA journal_mode=WAL` enables concurrent readers during `orin serve` without blocking writers.
- **Connection pool**: a `threading.local` pool maintains per-thread connections; long-lived background threads (scheduler, eBPF consumer) hold their connections for the duration.
- **Schema migration**: version-tagged migrations applied at open time; forward-only.
- **Encrypted writes**: if a vault passphrase is configured, `crypto.py` is called to encrypt payload columns before `INSERT` and decrypt after `SELECT`.

Full schema documented in [SCHEMA.md](SCHEMA.md).

### `core/server/server.py`

Single-process HTTP server built on `http.server.BaseHTTPRequestHandler`. Serves:

- The dashboard SPA from `web/dashboard.html`
- A REST API for all dashboard data (snapshots, alerts, processes, connections, FIM events, eBPF events)
- Static assets

Authentication: Bearer token checked on every non-static request. Token is generated at startup using `secrets.token_urlsafe(32)` and printed to stdout. The `--no-auth` flag disables token checking; only use on physically isolated networks.

### `core/server/hub_server.py`

Extended server variant for fleet hub operation. Adds:

- Multi-tenant namespace isolation: each remote agent registers with a unique identity and its data is partitioned in the vault.
- HMAC signature validation on all inbound agent payloads before they are written.
- TLS wrapping via `ssl.wrap_socket` when `--cert` and `--key` are provided.
- A fleet-level dashboard view aggregating alerts across all registered agents.

### `core/server/health.py`

Exposes three endpoints on the same server port:

- `GET /health` — liveness probe; returns `{"status": "ok"}` if the server is running.
- `GET /ready` — readiness probe; returns `{"status": "ready"}` only if the vault is accessible and the last snapshot is not older than the configured staleness threshold.
- `GET /api/metrics` — Prometheus-compatible text metrics: snapshot count, alert counts by severity, last collection timestamp, vault size in bytes.

### `core/logging.py`

Structured JSON log output with automatic rotation. Each log entry contains: timestamp (ISO 8601), log level, module name, message, and any extra fields passed by the caller. Rotation is configured by size (default: 10 MB per file, 5 files retained). All Orin modules obtain their logger via `core.logging.get_logger(__name__)`.

### `core/notifier.py`

Alert forwarding engine. Called by `engine.py` after each analysis cycle. Iterates configured webhook destinations, formats the alert payload for the target format (Slack Block Kit, Teams Adaptive Cards, or generic JSON), and POSTs via `urllib.request`. Implements retry with exponential backoff (default: 3 attempts, 5-second initial delay). All delivery attempts (success and failure) are appended to the JSONL audit log at the configured `audit_log` path. Failed deliveries after all retries are logged but do not raise exceptions; the analysis cycle continues.

Syslog delivery uses the `syslog` standard library module and writes to the local syslog socket. Syslog entries are formatted as: `orin-alert: [SEVERITY] rule_name — artifact`.

### `core/parallel.py`

`ThreadPoolExecutor`-based collection orchestration. Collectors are organized into dependency tiers. Within each tier, all collectors submit to the executor simultaneously. The tier completes when all futures resolve. If a collector raises an exception, it is caught, logged, and the tier continues with the remaining collectors; a partial snapshot is preferable to a failed one. Worker count defaults to `min(len(collectors_in_tier), os.cpu_count())` and is overridable with `--workers`.

### `core/scheduler.py`

Cron job lifecycle management. Reads and writes `/etc/cron.d/orin`. The generated cron entry runs `orin collect && orin analyze` as root at the specified interval. Status reporting parses the existing cron file and reports the next scheduled execution time. Removal deletes the `/etc/cron.d/orin` file.

### `core/ssh/scanner.py`

Orchestrates the full remote scan lifecycle:

1. Establish SSH connection (paramiko-free; uses subprocess with the system `ssh` binary).
2. Detect Python version on the target.
3. Transfer the appropriate agent (`remote_agent.py` or `remote_agent.sh`).
4. Execute the agent with appropriate privilege escalation if `--sudo` is specified.
5. Retrieve the signed JSON payload over stdout.
6. Verify the HMAC signature via `agent_signing.py`.
7. Write the verified snapshot to the local vault.
8. Clean up the transferred agent file from the target.

### `core/ssh/agent_signing.py`

HMAC-SHA256 signing and verification for remote agent payloads. The signing key is derived from the configured vault passphrase (or a dedicated agent signing key if separately configured). Payloads are canonical-JSON serialized before signing to prevent signature bypass via field reordering. See [AGENT_SIGNING_GUIDE.md](AGENT_SIGNING_GUIDE.md).

### `core/ssh/rate_limiter.py`

Per-host SSH rate limiter with exponential backoff. Maintains a per-host failure counter and last-attempt timestamp. After `N` consecutive failures (default: 3), subsequent attempts to the same host are blocked for `2^N × base_delay` seconds (default base: 30 seconds, maximum backoff: 1 hour). State is held in memory for the duration of the process; it does not persist across Orin restarts.

### `core/self_defense.py`

Runtime hardening applied at startup when running as root:

- **AppArmor**: loads a profile that restricts Orin to its required filesystem paths if AppArmor is available.
- **SELinux**: applies a transitional context if SELinux is enforcing.
- **Seccomp**: installs a syscall allowlist using `prctl(PR_SET_SECCOMP)` via `ctypes`, limiting the process to syscalls required for collection and vault operations.

### `core/self_verify.py`

Computes a SHA-256 hash of all Orin Python source files at startup and compares against a stored manifest. If any source file has been modified since the manifest was recorded (typically at install time), a warning is emitted. This is a tamper-detection mechanism, not an access control; a determined attacker with write access to the Orin source can also modify the manifest. Its value is in detecting accidental corruption or unsophisticated tampering.

### `core/validators.py`

Input validation and sanitization for all externally-sourced data: config file values, CLI arguments, webhook URLs, SSH hostnames, snapshot IDs. Prevents path traversal in file arguments, validates port ranges, sanitizes process names before inclusion in reports, and enforces allow-list validation on format strings passed to the report engine.

---

## 7. Module Internals — Collectors

### `collectors/processes.py` — Process Tree Harvester

Enumerates all running processes by iterating `/proc/[0-9]*/` entries. For each PID, reads:

- `cmdline` — full command line (null-byte delimited)
- `status` — name, state, UID, GID, parent PID, memory stats
- `exe` — symlink to the on-disk binary (may be `(deleted)` for in-memory-only executables)
- `maps` — memory map entries (used by `deleted_binaries.py`)
- `fd/` — open file descriptor count

Produces a process tree by linking each process to its parent via PPID. Anomalous relationships (e.g., a web server process with a shell child) are flagged during analysis.

### `collectors/connections.py` — Network Socket Auditor

Parses `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` to enumerate all active TCP and UDP sockets. Fields extracted: local address, local port, remote address, remote port, state, owning UID, inode. Inodes are cross-referenced against `/proc/[pid]/fd/` entries to associate sockets with PIDs. Listening ports outside `expected_ports` are flagged during analysis.

### `collectors/kernel.py` — Kernel Module & Symbol Auditor

**Module enumeration**: reads `/proc/modules` to list all loaded LKMs. Compares against the baseline recorded at `orin init`. New modules not present in the baseline are flagged.

**kallsyms analysis**: reads `/proc/kallsyms` (requires root) to enumerate exported kernel symbols. Checks for symbol names associated with known rootkit families, hooking frameworks, and syscall table manipulations. Symbols that should not be present in a stock kernel are flagged as critical indicators.

### `collectors/users.py` — User & SSH Key Inventory

Parses `/etc/passwd` to enumerate all local user accounts (UID, GID, home directory, shell). Compares against the baseline. New accounts, UID 0 accounts other than root, and accounts with unusual shells (e.g., `/bin/bash` for service accounts) are flagged.

For each user with a home directory, reads `~/.ssh/authorized_keys` and `~/.ssh/authorized_keys2` if present. SSH key drift (additions or removals since baseline) triggers a high-severity alert.

### `collectors/integrity.py` — File Integrity Monitor

Computes SHA-256 hashes for all files under the monitored paths (`fim_paths` in config). Uses a two-stage cache strategy:

1. **Stat cache**: reads `os.stat()` metadata (`mtime`, `ctime`, `size`, `inode`). If all four fields match the stored baseline record, the file is considered unchanged and its hash is not recomputed.
2. **Hash computation**: only performed for files whose stat metadata has changed. This eliminates redundant I/O on large filesystems where most files are stable.

The FIM database records the baseline hash, the current hash, the stat metadata, and the timestamp of the last change. Files present in the baseline but absent from the current scan are recorded as deletions.

### `collectors/logs.py` — Auth Log Parser & Sigma Engine

Reads authentication events from `/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL/Rocky), as well as from `journald` via `journalctl` subprocess where available. Parses structured fields from syslog-format entries: timestamp, hostname, process, PID, message.

Applies the embedded Sigma rule set to parsed log entries. Sigma rules are evaluated as pattern-match predicates against structured log fields. Matching entries are tagged with the matching rule name and MITRE ATT&CK technique ID.

### `collectors/ebpf.py` — eBPF Program, Pinned Map & ld.so.preload Auditor

Two distinct functions:

**eBPF map auditor**: enumerates pinned eBPF maps in `/sys/fs/bpf/` and loaded eBPF programs via `/proc/[pid]/fdinfo/`. Unexpected programs (those not belonging to Orin itself or whitelisted system tools) are flagged as potential rootkit indicators.

**ld.so.preload auditor**: reads `/etc/ld.so.preload`. Any entry in this file indicates a globally injected shared library — a common rootkit and credential-harvesting technique. Any non-empty `ld.so.preload` is flagged as a critical finding.

The `stream` subcommand's runtime consumer (also in this module) attaches the compiled eBPF program to the kernel ring buffer and reads events in a loop.

### `collectors/session_audit.py` — Binary Session Auditor & Anti-Forensics Detector

**Session auditing**: parses `/var/log/wtmp` and `/var/log/lastlog` to enumerate login/logout sessions. Records: username, terminal, source IP, login time, logout time.

**Anti-forensics detection**: cross-references parsed session records against running processes. Specifically detects:

- Gaps or zero-timestamps in wtmp/lastlog that indicate deliberate record clearing.
- Discrepancies between wtmp login records and active sessions visible in `/proc` — a technique used to hide interactive sessions from `who` and `last`.
- Truncated or rotated wtmp at unexpected times.

### `collectors/deleted_binaries.py` — In-Memory Executable Recovery

Inspects `/proc/[pid]/maps` for each running process. Entries ending with `(deleted)` indicate that the backing file on disk has been removed — a common technique for hiding malware from filesystem scans (load binary into memory, delete the on-disk copy). For each such mapping, reads the memory region via `/proc/[pid]/mem` and saves a copy to the vault for later YARA analysis and manual inspection.

### `collectors/promisc.py` — Promiscuous Mode Auditor

Reads the `IFF_PROMISC` flag from each network interface via `SIOCGIFFLAGS` ioctl (via `socket` stdlib). Any interface in promiscuous mode indicates a packet sniffer is active — expected on dedicated capture hosts, anomalous elsewhere. Flagged as high severity.

### `collectors/pkg_integrity.py` — Package Integrity Engine

**dpkg verification** (Debian/Ubuntu): reads `/var/lib/dpkg/info/*.md5sums` for all installed packages and recomputes checksums for the listed files. Uses a two-stage strategy: MD5 is checked first (fast, using the stored value); SHA-256 is computed only on confirmed MD5 mismatch, eliminating redundant hashing on clean systems. Modified package files are flagged.

**RPM verification** (RHEL/Rocky): uses `rpm -Va` subprocess output parsing where RPM is available.

### `collectors/crontabs.py` — Scheduled Task Harvester & Anomaly Detector

Harvests cron job definitions from:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/var/spool/cron/crontabs/*` (per-user crontabs)
- `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`

Also reads systemd timer units from `/etc/systemd/system/*.timer` and `/usr/lib/systemd/system/*.timer`.

Anomaly detection: cron jobs with unusual execution paths (e.g., running from `/tmp`, `/dev/shm`), base64-encoded commands, wget/curl downloads, or reverse shell patterns are flagged.

### `collectors/privilege_audit.py` — Privilege & Identity Tracker

**PAM brute force detection**: analyzes parsed auth log entries for authentication failure sequences against the same account. Configurable failure thresholds trigger medium (5 failures) and high (20 failures) severity alerts.

**Sudo abuse detection**: parses `sudo` log entries for unusual patterns: sudo to non-root users, sudo execution of shells, sudo with environment variable overrides.

**eBPF privilege escalation tracking** (when streaming is active): monitors `setuid`, `setgid`, `capset` syscalls to detect runtime privilege escalation not visible in log files.

### `collectors/dns_forensics.py` — DNS Forensics & Tunneling Detection

Reads DNS query records from available sources: `/var/log/syslog` DNS entries, `systemd-resolved` journal entries, `/etc/hosts` modifications.

**Tunneling detection**: applies heuristics to detected query strings — high-entropy subdomains, unusually long labels, high query frequency to a single domain, and TXT record query anomalies are indicative of DNS tunneling (e.g., `iodine`, `dnscat2`).

**DGA detection**: applies n-gram frequency analysis against a trained character distribution model to identify algorithmically generated domain names used by malware C2 frameworks.

### `collectors/triggered_pcap.py` — Triggered PCAP Capture

When a forensic trigger condition is detected during collection (e.g., an unknown process with an active external connection, or promiscuous mode on a non-capture interface), initiates a short packet capture using a `tcpdump` subprocess. Captures are time-limited (default: 30 seconds) and stored as compressed PCAP files in the vault directory. Only metadata (source/dest, ports, protocols, packet counts) is indexed in SQLite; raw PCAP files are referenced by path.

### `collectors/persistence.py` — Persistence Mechanism Detection

Systematically enumerates persistence locations beyond cron:

- Systemd unit files in user and system paths (`/etc/systemd/system/`, `~/.config/systemd/user/`)
- `/etc/rc.local` and `/etc/init.d/` legacy init scripts
- `/etc/profile.d/` and shell RC files (`.bashrc`, `.bash_profile`, `.zshrc`)
- XDG autostart entries (`~/.config/autostart/*.desktop`)
- PAM module configuration (`/etc/pam.d/`)
- `/etc/modules-load.d/` — modules configured to load at boot
- Dynamic linker configuration files beyond `/etc/ld.so.preload`

### `collectors/suid.py` — SUID/SGID Discovery & Baselining

Walks the filesystem (respecting `fim_paths` bounds) looking for files with the setuid or setgid bit set. Compares against the baseline recorded at `orin init`. New SUID/SGID binaries not present in the baseline are flagged as high severity; they represent potential privilege escalation backdoors.

### `collectors/remote_agent.py` — Stdlib-Only Remote Collection Agent

A self-contained, single-file Python script deployable to any Python ≥ 3.10 host with zero dependencies. Collects a subset of the full Orin collector suite (processes, network connections, user accounts, kernel modules, critical file hashes). Returns a canonical JSON payload signed with HMAC-SHA256 using a shared key established at scan time. Designed to produce minimal artefacts on the target host and clean up after itself.

---

## 8. Module Internals — Analysis

### `analysis/engine.py` — Threat Detection Rules Engine

The central analysis loop. Each detection rule is implemented as a predicate function that receives the full snapshot object and returns zero or more `Alert` objects. Rules are organized by domain and severity. The engine:

1. Iterates all registered rules.
2. Collects emitted alerts.
3. Deduplicates alerts by `(rule_name, artifact_id)` to prevent duplicate entries across consecutive runs.
4. Computes a composite risk score: a weighted sum of alert severities normalized to 0–100.
5. Auto-resolves previously open alerts whose triggering condition is no longer present.
6. Calls `core/notifier.py` with new alerts above the notification threshold.

Each alert carries: rule name, severity, affected artifact, description, MITRE ATT&CK technique ID(s), and recommended remediation step.

### `analysis/diff.py` — Snapshot Comparator

Computes a structured diff between two snapshots (identified by ID or loaded from separate vault files). For each collection domain, produces: added items, removed items, and changed items with before/after values. Diff output is structured for machine consumption (used by `orin delta`) and human consumption (used in reports).

### `analysis/reporter.py` — Markdown & HTML Report Generator

Accepts the latest snapshot, alert list, risk score, and timeline delta, and produces a complete forensic report in the requested format. The HTML template is self-contained (no external CSS or JS dependencies; all styles are inlined). Reports are structured for readability by both technical analysts and non-technical stakeholders. The executive summary section is intentionally brief and non-technical; technical detail is in the per-alert sections.

### `analysis/timeline.py` — Timeline Delta Calculator

Constructs a chronological event timeline from all data sources: parsed log timestamps, snapshot collection times, eBPF event timestamps, PCAP capture times, and alert generation times. Used to reconstruct the sequence of events during an incident. Exported as a JSON array of time-ordered event objects, suitable for import into external timeline tools.

### `analysis/unhide.py` — Hidden Process Detector

Detects processes that are visible via direct `/proc` enumeration but absent from higher-level process listing utilities — a technique used by userspace rootkits that hook `readdir` or `getdents64`.

Compares:
1. PIDs found by iterating `/proc/[0-9]*/` directly.
2. PIDs returned by the system `ps` command (subprocess).
3. PIDs returned by parsing `/proc/[pid]/status` for all entries in (1).

Discrepancies between (1) and (2) indicate a process hidden from `ps`. This module reads live kernel state; it should be invoked during collection, not post-hoc analysis. The placement in `analysis/` reflects its current usage (called during `orin analyze`); a future refactor may move it to `collectors/` and invoke it during `orin collect`.

---

## 9. Threat Detection

### Rule Domains

Full rule catalogue in [THREAT_DETECTION.md](THREAT_DETECTION.md). Summary by domain:

**Process & Execution Anomalies**
- Kernel thread masquerade: userspace process with a name matching a known kernel thread pattern (`kworker/`, `ksoftirqd/`)
- Volatile-path execution: process running from `/tmp`, `/dev/shm`, `/var/tmp`, or a deleted binary
- Reverse shell indicators: process with a network connection and `bash`/`sh`/`python` in the command line
- Unusual parent-child relationships: web server spawning a shell, cron spawning a network client

**Kernel & Rootkit Indicators**
- Unauthorized kernel module load (module not in baseline)
- Suspicious kallsyms entries (symbol names associated with known rootkit families)
- eBPF program presence not attributable to whitelisted tools
- Non-empty `/etc/ld.so.preload`

**Persistence Mechanisms**
- SSH key drift (additions or removals from baseline)
- New user accounts or UID changes
- New cron jobs or systemd timers not in baseline
- New SUID/SGID binaries
- New PAM module configuration
- New autostart entries

**Network & Communications**
- Listening port outside `expected_ports`
- Network interface in promiscuous mode
- DNS tunneling indicators (high-entropy subdomains, excessive TXT queries)
- DGA domain detection
- Outbound connection to known-malicious IP (from loaded threat intel)
- C2 beaconing: regular periodic connections to a single external host

**File Integrity & Tampering**
- FIM violation: file hash mismatch from baseline
- Package integrity violation: installed binary differs from package checksum
- YARA signature match (against file hashes or recovered memory)
- Deleted binary running in memory

**Identity & Privilege Escalation**
- PAM authentication failure threshold exceeded
- Sudo shell execution
- Unexpected UID 0 process ancestry
- Privilege escalation via setuid/setgid syscall (eBPF, when streaming)
- wtmp/lastlog tampering or gap

### Severity Tiers

| Tier | Score Weight | Examples |
|---|---|---|
| `info` | 1 | Unusual but benign observations |
| `low` | 3 | Minor configuration drift |
| `medium` | 10 | Brute force threshold, unexpected cron job |
| `high` | 25 | SUID binary added, SSH key drift, promiscuous mode |
| `critical` | 50 | Rootkit indicator, deleted binary in memory, ld.so.preload populated |

### MITRE ATT&CK Mapping

Each detection rule is mapped to one or more ATT&CK technique IDs. The mapping is included in alert records, report output, and hub aggregations. See [THREAT_DETECTION.md](THREAT_DETECTION.md) for the per-rule mapping table.

### Offline Threat Intelligence

STIX 2.x bundles, TAXII exports, and plain CSV indicator lists can be imported into the vault for offline use:

```bash
sudo orin intel import --file indicators.stix.json
sudo orin intel import --file malicious_ips.csv --type ip
sudo orin intel list
sudo orin intel prune --older-than 90
```

During analysis, IP addresses in network connection records and domain names in DNS records are cross-referenced against the loaded indicators. Matches generate `critical` severity alerts with the indicator source and confidence level.

---

## 10. Evidence Handling

### Export Format

A signed export bundle is a JSON document with two top-level keys:

```json
{
  "payload": { ... },
  "signature": "hex-encoded HMAC-SHA256"
}
```

The `payload` contains the full snapshot data in canonical form. The signature is computed over `json.dumps(payload, sort_keys=True, separators=(',', ':'))` — canonical JSON serialization ensures the signature is stable regardless of key ordering in the source data.

### Verification

```bash
orin verify --file orin_export_snap_2.json --secret "passphrase"
```

Output on success:
```
✔ Signature valid. Snapshot #2 collected at 2025-11-14T09:32:17Z on host prod-web-01.
```

Output on tamper detection:
```
✘ Signature mismatch. Bundle has been modified or wrong secret provided.
```

### Chain of Custody

For formal chain-of-custody requirements:

1. Run `orin export` immediately after collection on the target system.
2. Record the export filename, snapshot ID, collection timestamp, and the hex signature in your evidence log.
3. Transfer the export file via an authenticated channel (SCP with host key verification, for example).
4. Run `orin verify` on the receiving system and record the verification result.
5. Store the export file and verification record together.

The HMAC-SHA256 signature provides integrity assurance but not non-repudiation (any party with the secret can produce a valid signature). For non-repudiation, sign the export file additionally with a PKI key outside Orin.

---

## 11. Security Model

### Threat Model

Orin is designed to operate in an environment where:

- The collection host may have been compromised at the OS level.
- The Orin binary and source may be targeted for tampering.
- Physical access by the attacker to the collection host is possible.
- The vault storage medium may be seized.

Given these assumptions:

- **Self-verification** (`core/self_verify.py`) detects source-level tampering on the Orin installation itself.
- **Vault encryption** (AES-256-GCM) protects snapshot data at rest in the event of vault seizure.
- **HMAC-signed exports** provide integrity assurance for data in transit or in long-term storage.
- **Seccomp / AppArmor / SELinux hardening** (`core/self_defense.py`) limits the blast radius if Orin itself is compromised via a vulnerability.

### What Orin Cannot Guarantee

- If the collecting host is compromised at the kernel level (kernel rootkit), collection results may be incomplete or falsified. The `unhide.py` hidden process detector and `kallsyms` auditor mitigate this but cannot provide absolute guarantees.
- HMAC-SHA256 provides integrity, not confidentiality, for export bundles. Use `--secret` with a strong passphrase for the signing key.
- The session token for `orin serve` is in-memory only; it does not persist across restarts. If the Orin process is killed and restarted, a new token is generated.

### Network Isolation

Orin never initiates outbound connections. The only inbound network surface is:

- `orin serve`: HTTP server bound to `127.0.0.1` by default.
- `orin hub-serve`: HTTP(S) server bound to the address specified by `--host`.
- SSH connections: inbound only from `orin scan` on remote targets.

---

## 12. Performance

### Collection Benchmarks

| Mode | ~50-process system | ~500-process system |
|---|---|---|
| Sequential | ~8 seconds | ~45 seconds |
| Parallel (4 workers) | ~1.5 seconds | ~6 seconds |
| Parallel (8 workers) | ~0.8 seconds | ~3.5 seconds |

FIM performance scales with filesystem size and change rate. The stat-cache strategy means that on a stable system, collection time for FIM is dominated by `os.stat()` latency rather than SHA-256 computation. On a heavily active filesystem, expect proportionally more hash computation.

### Vault Size

Approximate vault growth rates (unencrypted, sequential collection, typical production system):

| Collection interval | 30 days | 90 days |
|---|---|---|
| Every 10 minutes | ~2 GB | ~6 GB |
| Every 30 minutes | ~700 MB | ~2 GB |
| Hourly | ~350 MB | ~1 GB |

eBPF streaming events (when `orin stream` is active) add approximately 50–200 MB per day depending on system activity. Plan vault storage accordingly and set a `vault prune` schedule.

---

## 13. Operations

### Initial Deployment Checklist

1. Install Orin on the target host.
2. Review and customize `orin_config.json`: set `expected_ports`, `whitelisted_processes`, `fim_paths`, and `critical_paths` for the environment.
3. If using vault encryption, set `ORIN_VAULT_PASSPHRASE` in the root environment (e.g., `/root/.bashrc` with restricted permissions, or a secrets manager).
4. Run `sudo orin init` to create the vault and record baselines. Do this on a **known-clean system state**.
5. Run `sudo orin collect` followed by `sudo orin analyze` manually and review the initial findings. Tune whitelists to eliminate expected false positives.
6. Run `sudo orin schedule --install` to automate collection.
7. Optionally start `sudo orin serve` (or configure it as a systemd service) for dashboard access.
8. Optionally start `sudo orin stream` (or configure as a systemd service) for real-time eBPF coverage.

### Responding to Alerts

1. Run `sudo orin report --format html --output /tmp/report.html` for a human-readable briefing.
2. Use `sudo orin delta --base <clean_snapshot_id> --target <current_snapshot_id>` to see exactly what changed.
3. For critical indicators (rootkit signals, deleted binaries in memory), take a signed export immediately: `sudo orin export --snapshot <id> --secret "passphrase"`.
4. Use `sudo orin stream --verbose` to observe live system activity if the threat may still be active.
5. If the system is to be taken offline, run a final `orin collect` and `orin export` before disconnection.

### Vault Backup

The vault is a single SQLite file. Back it up with:

```bash
sqlite3 /var/lib/orin/orin_vault.db ".backup /backups/orin_$(date +%Y%m%d).db"
```

This produces a clean consistent copy even if Orin is actively writing (WAL mode handles the consistency). Store the backup on a separate medium or host.

---

## 14. Troubleshooting

### eBPF streaming fails to start

**Symptom**: `orin stream` exits immediately with an error referencing `libbpf` or BTF.

**Resolution**:
1. Confirm `libbpf` is installed: `ldconfig -p | grep libbpf`
2. Confirm BTF is available: `ls /sys/kernel/btf/vmlinux`
3. Check kernel version: eBPF ring buffer requires kernel ≥ 5.8.
4. See [EBPF_TROUBLESHOOTING.md](EBPF_TROUBLESHOOTING.md) for the full error reference.

### High false positive rate after init

**Symptom**: `orin analyze` produces dozens of medium/low alerts on every run.

**Resolution**:
1. Review `whitelisted_processes` — add legitimate processes that are being flagged.
2. Review `expected_ports` — add legitimate listening services.
3. Review `fim_exclude_patterns` — add patterns for log files or cache directories inside monitored paths that change frequently.
4. Re-run `orin init` after tuning to update baselines, if the current baseline reflects a legitimate state.

### Vault grows unexpectedly fast

**Symptom**: vault file is growing faster than expected based on collection interval.

**Resolution**:
1. Check if `orin stream` is running — eBPF events are the highest-volume data source.
2. Run `orin vault stats` to see which snapshot is the largest and which collection domain is contributing the most data.
3. If FIM is monitoring a high-churn directory (e.g., `/var/log`), add it to `fim_exclude_patterns` or remove it from `fim_paths`.
4. Schedule `orin vault prune` to run weekly.

### SSH scan fails with host key error

**Symptom**: `orin scan` fails with a host key verification error on a known host.

**Resolution**:
1. If the host key has legitimately changed (e.g., OS reinstall), clear the stored key: `sudo orin scan --clear-host-key --host <ip>`
2. If the key change is unexpected, treat it as a potential security incident and investigate before proceeding.

### `orin verify` reports signature mismatch

**Symptom**: `orin verify` fails on a bundle that should be valid.

**Causes**:
1. Wrong passphrase supplied.
2. Bundle file has been modified (even whitespace changes to the JSON will invalidate the signature).
3. Bundle was produced by a different Orin installation using a different signing key.

**Resolution**: confirm the passphrase is correct, then inspect the bundle file for unexpected modifications. If the file is intact and the passphrase is correct, the bundle is genuinely tampered.

---

*Orin v1.2.0 — GNU AGPLv3*