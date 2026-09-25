<p align="center">
  <img src="assets/orin-logo.svg" alt="Orin Logo" width="200">
</p>

# Orin — Offline Linux Forensics & Integrity Engine

> Point-in-time forensic snapshot platform for Linux — built for analysts who operate where cloud connectivity is prohibited. Designed for air-gapped, offline, and forensically sensitive environments.

[![CI](https://github.com/jaradat13/orin/actions/workflows/test.yml/badge.svg)](https://github.com/jaradat13/orin/actions/workflows/test.yml)
![Version](https://img.shields.io/badge/version-v1.2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/runtime_deps-stdlib_%2B_libbpf_(optional)-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-AGPLv3-blue)
![Category](https://img.shields.io/badge/category-DFIR-blue)
![MITRE ATT&CK Mapped](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)

Orin captures point-in-time snapshots of critical OS state, compares them against trusted baselines, identifies anomalous behaviour, and produces tamper-evident evidence bundles — all without any network access, telemetry, or cloud dependencies. Built for air-gapped networks, classified environments, and forensically sensitive systems.

---

## Contents

- [Why Orin?](#why-orin)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Capabilities](#capabilities)
- [Configuration](#configuration)
- [Threat Detection](#threat-detection)
- [Testing](#testing)
- [Contributing](#contributing)
- [Security](#security)
- [Documentation](#documentation)

---

## Why Orin?

Most Linux security tools require a persistent daemon, a cloud backend, continuous network connectivity, or a large footprint of third-party packages — none of which are compatible with hardened, air-gapped, or forensically sensitive environments.

Orin requires **none of these**. It operates entirely from the Python standard library, reads directly from kernel interfaces (`/proc`, `/sys`, `/var/log`), and stores all evidence locally.

| | Orin | Falco | osquery | Wazuh |
|---|---|---|---|---|
| **Runtime dependencies** | stdlib (+ libbpf optional) | Kernel driver / eBPF | Standalone binary | Agent + manager |
| **Network required** | **Never** | Optional | Optional | **Yes** |
| **Cloud dependencies** | **Zero** | Optional | Optional | **Required** |
| **Air-gap safe** | ✅ Out-of-the-box | ⚠️ Complex setup | ⚠️ Complex setup | ❌ Requires manager |
| **Multi-tenant hub** | ✅ | ❌ | ❌ | ⚠️ Manager-only |
| **Offline threat intel** | ✅ STIX / CSV / TAXII | ❌ | ❌ | ❌ |
| **Forensic evidence signing** | ✅ HMAC-SHA256 + AES-256-GCM | ❌ | ❌ | ❌ |
| **Anti-forensics detection** | ✅ wtmp / lastlog | ❌ | ❌ | ❌ |
| **Real-time eBPF streaming** | ✅ Ring-buffer consumer | ✅ Full IDS | ⚠️ Via extensions | ❌ |

**Target use cases:** Security engineers, forensic analysts, incident responders, and system administrators operating in air-gapped environments, SCIFs, classified networks, industrial control systems, and any infrastructure where data must remain strictly on-premises.

---

## Quick Start

```bash
# One-time initialization — creates the vault and records trusted baselines
sudo orin init

# Core workflow
sudo orin collect        # Capture a system state snapshot
sudo orin analyze        # Evaluate against threat detection rules
sudo orin report         # Generate a forensic briefing

# Automate collection every 10 minutes
sudo orin schedule --install

# Launch the local web dashboard (prints a one-time access token)
sudo orin serve

# Scan a remote host over SSH (stdlib-only agent; pure-Bash fallback available)
sudo orin scan --host 192.168.1.50 --user root --init

# Real-time eBPF telemetry streaming (requires libbpf)
sudo orin stream --verbose

# Prune old snapshots
sudo orin vault prune --older-than 30

# Centralized fleet hub for multi-tenant forensic management
sudo orin hub-serve 8000 --host 0.0.0.0 --cert /path/to/cert.pem --key /path/to/key.pem
```

---

## Installation

> **Requirements:** Python ≥ 3.10 (only required for source installation). Optional: system `libbpf` for real-time eBPF streaming.

**Method A — Pre-compiled Offline Setup Bundle (Recommended)**

For air-gapped systems or targets without a Python environment, download the [orin-1.2.0-linux-x86_64.tar.gz](https://github.com/jaradat13/orin/releases/download/v1.2.0/orin-1.2.0-linux-x86_64.tar.gz) standalone release tarball and run:

```bash
tar -xzf orin-1.2.0-linux-x86_64.tar.gz
cd orin-1.2.0-linux-x86_64
chmod +x install.sh && ./install.sh
```

This securely deploys the pre-compiled `orin` binary, default configuration templates, and rules locally (under `$HOME/.local/bin` for user mode or `/usr/local/bin` for system mode) with **zero internet dependencies**.

**Method B — Automated Installer from Source**

If installing directly from the source directory:

```bash
chmod +x install.sh && ./install.sh
```

**Method C — System-wide (via pip)**

```bash
sudo pip install . --break-system-packages
```

**Method C — Development mode**

```bash
pip install -e .
PYTHONPATH=src python -m orin.main <subcommand>
```

**Optional: Enable eBPF real-time streaming**

Runtime hosts only need the system `libbpf` shared library — no compiler or kernel headers required.

```bash
# Debian / Ubuntu
sudo apt-get install libbpf1

# RHEL / Rocky / Alma
sudo dnf install libbpf
```

To modify and recompile the eBPF source itself:

```bash
sudo ./scripts/setup_ebpf.sh --build
```

See [EBPF_TROUBLESHOOTING.md](docs/EBPF_TROUBLESHOOTING.md) for kernel/BTF prerequisites and common errors.

---

## Usage

All subcommands that read privileged files (`/proc/kallsyms`, `/var/log/auth.log`, etc.) produce richer output when run as root.

```
init → collect → analyze → report
                  ↓
        delta / diff / export / verify / serve / schedule / stream
```

> **Tip:** Use `orin schedule --install` to automate the `collect → analyze` cycle. Use `orin stream` for real-time eBPF telemetry (requires `libbpf`).

### `orin init`

Create the SQLite vault and record immutable baselines for trusted kernel modules, user accounts, and SUID/SGID binaries.

```bash
sudo orin init
```

### `orin collect`

Harvest a full system state snapshot and persist it to the vault.

```bash
sudo orin collect
sudo orin collect --parallel --workers 4   # Concurrent collection (~15× faster)
```

See [PARALLEL_COLLECTION_FEATURE.md](docs/PARALLEL_COLLECTION_FEATURE.md).

### `orin analyze`

Evaluate the latest snapshot against all threat detection rules and produce a severity-tiered risk score (0–100).

```bash
sudo orin analyze
```

### `orin report`

Compile a forensic briefing from the latest snapshot and unresolved alerts.

```bash
sudo orin report --format html --output /tmp/orin_report.html
sudo orin report --format markdown --output /tmp/orin_report.md
```

### `orin stream`

Launch the eBPF real-time telemetry consumer. Streams `execve`, `connect`, and `openat` events via the kernel ring buffer into SQLite.

```bash
sudo orin stream --verbose
```

### `orin serve`

Start a local forensic web console on `127.0.0.1:8000`. A one-time session token is printed to the terminal on each start.

```bash
sudo orin serve
sudo orin serve --port 9090
sudo orin serve --no-auth   # Trusted networks only
```

### `orin scan`

Agentless remote scan over SSH. Uses a stdlib-only Python agent with a pure-Bash fallback for Python-less systems.

```bash
sudo orin scan --host 192.168.1.50 --user root --key ~/.ssh/id_ed25519
sudo orin scan --host 192.168.1.50 --user root --init   # Initialize baseline
```

See [SSH_GUIDE.md](docs/SSH_GUIDE.md).

### `orin schedule`

Install or remove the automated `collect → analyze` cron job.

```bash
sudo orin schedule --install --interval 10
sudo orin schedule --status
sudo orin schedule --remove
```

### `orin vault`

Manage snapshot lifecycle.

```bash
sudo orin vault stats
sudo orin vault prune --older-than 30 --dry-run
sudo orin vault prune --keep-last 10 --execute
sudo orin vault prune --keep-last 10 --no-preserve-critical --execute
```

### `orin delta` / `orin diff` / `orin export` / `orin verify`

```bash
sudo orin delta --base 1 --target 3
orin diff /backups/orin_day1.db /var/lib/orin/orin_vault.db
sudo orin export --snapshot 2 --secret "passphrase"
orin verify --file orin_export_snap_2.json --secret "passphrase"
```

---

## Capabilities

Orin implements 57 forensic capabilities across 8 functional domains. See [CAPABILITIES.md](docs/CAPABILITIES.md) for the full annotated reference.

**Collection modules:** Process Tree Harvester · Network Socket Auditor · Kernel Module & Symbol Auditor · User & SSH Key Inventory · File Integrity Monitor · Auth Log Parser & Sigma Engine · In-Memory Executable Recovery · Promiscuous Mode Auditor · Binary Session Auditor · Hidden Process Detector · Package Integrity Engine · Scheduled Task Harvester · eBPF & File Descriptor Auditor · DNS Forensics & Tunneling Detection · Triggered PCAP Capture · Privilege & Identity Tracker

**Analysis & detection:** Threat Detection Rules Engine · Forensic Alert Auto-Resolution · YARA Engine · Sigma Rule Evaluator · MITRE ATT&CK Mapper · Snapshot Comparator · Timeline Delta Calculator · AI Forensic Triage (Ollama)

**Evidence handling:** Cryptographic Export (HMAC-SHA256) · Encrypted Vault (AES-256-GCM) · Offline Threat Intel Importer

**Operations:** Local Web Dashboard · Fleet Hub · Agentless SSH Scanner · Automated Scheduler · Parallel Collection Engine · Vault Lifecycle Management · Agent Self-Defense Hardening · Health & Readiness Probes

**Performance notes:**
- **Stat-based FIM cache:** `os.stat()` metadata (`mtime`, `ctime`, `size`) is compared before any SHA-256 hash is computed; unchanged files are never read.
- **Lazy SHA-256 in package integrity:** MD5 is checked first; SHA-256 is computed only on confirmed mismatch, eliminating redundant hashing on clean systems.

---

## Project Structure

```
orin/
├── orin_config.json           # User configuration (optional)
├── install.sh                 # Automated installer
├── pyproject.toml             # Packaging metadata
├── src/orin/
│   ├── main.py                    # CLI entry point & subcommand router
│   ├── core/
│   │   ├── agent_signing.py       # HMAC-SHA256 remote agent signing & verification
│   │   ├── config.py              # JSON config loader with deep-copy defaults
│   │   ├── credentials.py         # Secure credential handling
│   │   ├── crypto.py              # HMAC-SHA256 signing, AES-256-GCM vault encryption
│   │   ├── database.py            # SQLite ORM, connection pool, WAL mode
│   │   ├── health.py              # /health, /ready, /api/metrics endpoints
│   │   ├── hub_server.py          # Fleet hub server (orin hub-serve)
│   │   ├── logging.py             # JSON structured logging with rotation
│   │   ├── notifier.py            # Alert forwarding: webhooks, syslog, retry
│   │   ├── rate_limiter.py        # SSH rate limiting with exponential backoff
│   │   ├── scanner.py             # SSH agentless scanner orchestrator
│   │   ├── scheduler.py           # Cron automation (orin schedule)
│   │   ├── self_defense.py        # AppArmor / SELinux / Seccomp hardening
│   │   ├── self_verify.py         # Runtime self-integrity check
│   │   ├── server.py              # HTTP server + REST API + auto-token auth
│   │   ├── validators.py          # Input validation & sanitization
│   │   └── dashboard.html         # Single-page forensic console
│   ├── collectors/
│   │   ├── connections.py         # /proc/net TCP/UDP socket parser
│   │   ├── crontabs.py            # Cron job harvester & anomaly detector
│   │   ├── deleted_binaries.py    # In-memory deleted executable recovery
│   │   ├── dns_forensics.py       # DNS tunneling & DGA detection
│   │   ├── ebpf.py                # eBPF program, pinned map & ld.so.preload auditor
│   │   ├── integrity.py           # SHA-256 FIM with stat-cache acceleration
│   │   ├── kernel.py              # LKM enumeration & kallsyms rootkit analysis
│   │   ├── logs.py                # Auth log & journald collection
│   │   ├── parallel.py            # ThreadPoolExecutor parallel collection engine
│   │   ├── persistence.py         # Persistence mechanism detection
│   │   ├── pkg_integrity.py       # dpkg md5sums verification
│   │   ├── privilege_audit.py     # PAM / eBPF privilege escalation & credential tracking
│   │   ├── processes.py           # /proc process tree harvester
│   │   ├── promisc.py             # IFF_PROMISC flag auditor
│   │   ├── remote_agent.py        # Stdlib-only remote collection agent (Python)
│   │   ├── remote_agent.sh        # Pure-Bash fallback remote agent
│   │   ├── session_audit.py       # wtmp / lastlog parser & anti-forensics detector
│   │   ├── suid.py                # SUID/SGID discovery & baselining
│   │   ├── triggered_pcap.py      # PCAP capture on forensic triggers
│   │   └── users.py               # /etc/passwd & SSH authorized_keys inventory
│   └── analysis/
│       ├── diff.py                # Snapshot comparator
│       ├── engine.py              # Threat detection rules engine
│       ├── reporter.py            # Markdown & HTML report generator
│       ├── timeline.py            # Timeline delta calculator
│       └── unhide.py              # Hidden process detector
└── tests/                         # See docs/TESTING.md
```

---

## Configuration

Orin searches for `orin_config.json` in `./` then `/etc/orin/`, falling back to built-in defaults. The keys below cover the most commonly tuned options. For a complete reference — all config keys, environment variables, and CLI credential flags — see [CONFIGURATION.md](docs/CONFIGURATION.md).

```json
{
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome", "language_server"],
  "critical_paths": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab"],
  "critical_dirs": ["/etc/cron.d", "/etc/systemd/system"]
}
```

### Encrypted Evidence Vault

```bash
export ORIN_VAULT_PASSPHRASE="your-strong-passphrase"
sudo orin init
sudo orin collect
```

All snapshot data is encrypted before SQLite storage using AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations). Without a passphrase, the vault operates in unencrypted mode with full backward compatibility.

Secure credential input alternatives:

```bash
--secret-file /path/to/pass.txt   # File with mode 0600
--secret-prompt                    # Interactive masked prompt
--secret-env-var MY_VAR            # Custom environment variable name
```

### Alert Forwarding

Push critical alerts to analysts without polling the dashboard. Supports Slack Block Kit, Microsoft Teams Adaptive Cards, generic JSON webhooks, and syslog — all via Python stdlib (`urllib.request`).

```json
{
  "notifications": {
    "enabled": true,
    "min_severity": "high",
    "syslog": { "enabled": true, "facility": "LOG_LOCAL0", "tag": "orin-alert" },
    "webhooks": [
      {
        "name": "ops-slack",
        "url": "http://192.168.1.10:8080/slack-webhook",
        "format": "slack",
        "min_severity": "critical",
        "timeout_seconds": 10,
        "enabled": true
      }
    ],
    "retry": { "max_attempts": 3, "backoff_seconds": 5 },
    "audit_log": "/var/log/orin/notification_audit.log"
  }
}
```

Forwarding runs automatically after every `orin analyze`. Failed deliveries retry with exponential backoff and are recorded in the JSONL audit log; they never abort the analysis cycle.

---

## Threat Detection

See [THREAT_DETECTION.md](docs/THREAT_DETECTION.md) for the complete rule catalogue, covering:

- Process & execution anomalies (kernel thread masquerade, reverse shells, volatile-path execution)
- Kernel & rootkit indicators (suspicious `kallsyms` entries, eBPF program anomalies)
- Persistence mechanisms (SSH key drift, unauthorized accounts, cron job changes)
- Network & communications (promiscuous mode, DNS tunneling, DGA detection, C2 beaconing)
- File integrity & tampering (FIM violations, package integrity, YARA signature matches)
- Identity & privilege escalation (PAM brute force, sudo abuse, credential access)

---

## Testing

```bash
ORIN_TEST_FAST=1 pytest --cov=orin --cov-report=term-missing
```

The CI pipeline enforces an **85% minimum coverage gate**. See [TESTING.md](docs/TESTING.md) for environment setup, test modes, and contributor guidelines.

---

## Contributing

Contributions are welcome. Before opening a pull request:

1. Run `ORIN_TEST_FAST=1 pytest` and confirm the 85% coverage gate passes.
2. New test files belong in `tests/`, prefixed `test_*.py`.
3. Review [ROADMAP.md](docs/ROADMAP.md) for current priorities to avoid duplicate effort.
4. Keep collectors stdlib-only where possible — Orin's zero-dependency posture is a core design requirement.

---

## Security

To report a vulnerability, **do not open a public issue**. Use GitHub's private security advisory workflow or contact the maintainer directly. See [SECURITY.md](docs/SECURITY.md) for the disclosure process and response timelines.

---

## Documentation

| Document | Description |
|----------|-------------|
| [DOCUMENTATION.md](docs/DOCUMENTATION.md) | Full practitioner's guide — architecture, workflows, module internals |
| [CAPABILITIES.md](docs/CAPABILITIES.md) | Complete annotated capability reference (57 modules) |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | All config keys, environment variables, and CLI flags |
| [THREAT_DETECTION.md](docs/THREAT_DETECTION.md) | Complete threat detection rule catalogue |
| [DASHBOARD_GUIDE.md](docs/DASHBOARD_GUIDE.md) | Dashboard architecture, API reference, and JavaScript function reference |
| [SSH_GUIDE.md](docs/SSH_GUIDE.md) | Remote scanning, host key verification, and rate limiting |
| [AGENT_SIGNING_GUIDE.md](docs/AGENT_SIGNING_GUIDE.md) | HMAC-SHA256 agent signing for remote deployments |
| [DATABASE_INTERNALS.md](docs/DATABASE_INTERNALS.md) | Connection pool, PRAGMAs, and encrypted storage internals |
| [PARALLEL_COLLECTION_FEATURE.md](docs/PARALLEL_COLLECTION_FEATURE.md) | Concurrent collection via ThreadPoolExecutor |
| [EBPF_TROUBLESHOOTING.md](docs/EBPF_TROUBLESHOOTING.md) | eBPF streaming setup, kernel prerequisites, error reference |
| [SCHEMA.md](docs/SCHEMA.md) | SQLite database schema reference |
| [STATUS.md](docs/STATUS.md) | Platform support matrix, deployment assumptions, known limitations |
| [ROADMAP.md](docs/ROADMAP.md) | Project direction and phased development plan |
| [TESTING.md](docs/TESTING.md) | Test setup, coverage requirements, and contributor guidelines |
| [SECURITY.md](docs/SECURITY.md) | Vulnerability reporting and security design notes |

---

## License

GNU AGPLv3 — see [LICENSE](LICENSE) for details.

> [Professional services and commercial licensing available](https://github.com/jaradat13/orin/wiki)