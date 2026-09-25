<div align="center">
  <h1>Project Spectre</h1>
  <p><b>A Behavioral Host Intrusion Detection System (HIDS)</b></p>
  
  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+"></a>
    <a href="https://github.com/Aayushbankar/spectre/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
    <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE-ATT%26CK-red.svg" alt="MITRE ATT&CK"></a>
    <a href="https://github.com/Aayushbankar/spectre/actions"><img src="https://img.shields.io/github/actions/workflow/status/Aayushbankar/spectre/ci.yml?branch=main" alt="Build Status"></a>
    <a href="https://pypi.org/project/spectre-hids/"><img src="https://img.shields.io/pypi/v/spectre-hids" alt="PyPI Version"></a>
    <a href="https://github.com/Aayushbankar/spectre/stargazers"><img src="https://img.shields.io/github/stars/Aayushbankar/spectre" alt="GitHub Stars"></a>
  </p>
  
  <p><i>Instead of asking "Is this file known?", Spectre asks "Does this sequence of actions make sense?"</i></p>
</div>

---

## Table of Contents
- [Overview](#overview)
- [Why Spectre?](#why-spectre)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage & CLI Reference](#usage--cli-reference)
- [Detection Rules & Sigma Integration](#detection-rules--sigma-integration)
- [Testing & Verification](#testing--verification)
- [Documentation & Roadmap](#documentation--roadmap)
- [Acknowledgments & External Links](#acknowledgments--external-links)

---

## Overview

**Project Spectre** is a lightweight, local-first **behavioral Host Intrusion Detection System (HIDS)**. Rather than relying heavily on static file signatures, Spectre models the grammar of host processes and resource actions to detect anomalous execution chains and behaviors. 

Currently in **v0.2.0 (Alpha PoC)**, Spectre is an experimental proof-of-concept that tracks process lineages, monitors file and network I/O, evaluates threats in real-time, provides MITRE ATT&CK context, scans payloads via YARA, and can actively quarantine malicious process trees.

**New in Phase 1:**
- **Sigma-native rule format** — Write rules in Sigma YAML, convert to Spectre automatically
- **24 built-in rules** across 4 packs: webshell, privilege escalation, credential access, lateral movement
- **Rule testing CLI** — Validate Sigma syntax, test conversion, replay traces
- **Rule pack management** — Install/uninstall community rule packs
- **Detection-as-code ready** — CI/CD integration for rule validation

---

## Why Spectre?

Traditional endpoint protection platforms (EPP) and antiviruses (AV) often rely heavily on static signatures—checking file hashes against a known database of malware. This approach completely fails against **zero-day threats**, **fileless malware**, and **"living off the land"** techniques where attackers abuse legitimate system binaries (like `powershell`, `curl`, or `bash`).

Spectre shifts the security paradigm from *static characteristics* to *dynamic relationships*. By continuously tracking process ancestry (who spawned who) and correlating it with resource access (who touched which file, who opened which socket), Spectre identifies malicious **intent** rather than malicious **files**.

**Example Attack Chain Detected:**
```text
nginx (Web Server)
└── bash (Interactive Shell)
    ├── curl (Downloads payload)
    │   └── [WRITE] -> /tmp/malware.sh
    └── sh (Executes payload)
        └── [CONNECT] -> 192.168.1.50:4444 (C2 Server)
```

---

## Architecture

The system operates across a 4-stage pipeline:

```text
+---------------------+      +---------------------+      +---------------------+
|                     |      |                     |      |                     |
|  1. OS Telemetry    |----->|  2. Graph Builder   |----->| 3. Detection Engine |
|  (psutil / eBPF)    |      |  (NetworkX Memory)  |      |  (Rules & Scoring)  |
|                     |      |                     |      |                     |
+---------------------+      +---------------------+      +---------------------+
                                                                     |
                                                                     v
                                                          +---------------------+
                                                          |                     |
                                                          |  4. Action & Alert  |
                                                          | (Containment, REST) |
                                                          |                     |
                                                          +---------------------+
```

1. **Telemetry Sensing**: Continuously polls the OS for process spawns, file descriptors, and network sockets (psutil) — eBPF sensor in development for zero-gap visibility.
2. **Graph Construction**: Events are normalized into a sliding-window, directed process-resource graph, automatically pruning stale events to prevent memory leaks.
3. **Detection Engine**: The active graph is evaluated against JSON/Sigma-configurable behavioral rules. Threat scores accumulate along process lineage chains.
4. **Action & Visualization**: Once a threshold is breached, Spectre fires an alert, maps it to MITRE ATT&CK, runs a deep-scan via YARA, and can actively freeze/kill the process tree. REST API + Lightweight Vanilla JS dashboard for real-time monitoring.

---

## Key Features

- **Process Ancestry Tracking**: Reconstructs complete execution lineages, handling PID recycling and short-lived processes safely.
- **Resource Monitoring**: Tracks I/O operations including `READ`/`WRITE` for files, and `CONNECT`/`LISTEN` for sockets.
- **Behavioral Detection Engine**: Scores chains of events dynamically using JSON-configurable rules.
- **Sigma-Native Rules**: Write rules in Sigma YAML; automatic conversion to Spectre format with MITRE ATT&CK extraction.
- **Threat Enrichment**: 
  - **MITRE ATT&CK**: Alerts mapped automatically to ATT&CK tactics (e.g., *T1059 - Command and Scripting Interpreter*).
  - **YARA Integration**: Scans suspicious files on-the-fly using the `yara-python` engine.
- **Active Containment**: Configurable actions (`--contain stop` or `kill`) to instantly freeze or terminate entire threat process trees.
- **Persistence & API**: Events and alerts stored in local SQLite database, exposed via FastAPI REST interface.
- **Live Dashboard**: Lightweight, dependency-free Vanilla HTML/JS web dashboard for monitoring graph, alerts, and system telemetry.
- **Detection Engineering Platform**: Rule testing, Sigma validation, pack management, CI/CD integration.

---

## Getting Started

### Prerequisites

- Python 3.8 or newer
- Linux Operating System (for accurate `/proc` mapping and `psutil` compatibility)
- Root privileges (required for process monitoring and containment)
- Dependencies: `psutil`, `networkx`, `fastapi`, `yara-python`, `uvicorn`, `click`, `rich`, `pyyaml`

### Installation

#### Option 1: One-line installer (recommended)
```bash
curl -sSL https://raw.githubusercontent.com/Aayushbankar/spectre/main/install.sh | sudo bash
```

#### Option 2: PyPI
```bash
pip install spectre-hids[yara]
```

#### Option 3: Docker
```bash
docker run -d --privileged --pid=host --cgroupns=host \
  -v /:/host:ro \
  -v /var/log/spectre:/var/log/spectre \
  -v /var/lib/spectre:/var/lib/spectre \
  ghcr.io/aayushbankar/spectre:latest \
  --contain kill --api
```

#### Option 4: From source
```bash
git clone https://github.com/Aayushbankar/spectre.git
cd spectre
pip install -e ".[yara]"
```

---

## Usage & CLI Reference

Spectre provides a highly configurable Command Line Interface (CLI) for tuning the engine's sensitivity and enabling specific modules.

### Basic Usage

> [!IMPORTANT]
> **Quiet Mode vs. Verbose Mode**
> By default, `spectre run` runs in **Quiet Mode**, meaning it will only log to the terminal when a critical alert threshold is breached. To see the graph updating in real-time, use the `--verbose` (`-v`) flag.

**Run with Active Containment & REST API:**
```bash
spectre run --verbose --contain kill --api
```

### Full CLI Commands

| Command | Description |
|---------|-------------|
| `spectre run` | Run HIDS monitoring |
| `spectre rules` | List loaded detection rules (table/JSON) |
| `spectre rule list` | List available rule packs (4 packs, 24 rules) |
| `spectre rule install <pack>` | Install a rule pack (webshell, privilege_escalation, credential_access, lateral_movement) |
| `spectre rule uninstall <pack>` | Uninstall a rule pack |
| `spectre rule info <pack>` | Show detailed rule pack information |
| `spectre test rule <files...>` | Validate Sigma rules and test Spectre conversion |
| `spectre test technique <Txxxx>` | Test against ATT&CK technique (Atomic Red Team) |
| `spectre stats` | Show database statistics |
| `spectre doctor` | Run system diagnostics |
| `spectre api` | Run REST API server standalone |

### `spectre run` Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--interval` | Polling interval in seconds | `0.5` |
| `--window-size`, `-w`| Sliding time window in seconds for event expiration | `60.0` |
| `--threshold`, `-t` | Threat score threshold for high-severity alerts | `15` |
| `--rules`, `-r` | Path to behavioral rules JSON file | `rules.json` |
| `--log-file` | Path to security alerts output log file | `/var/log/spectre/alerts.log` |
| `--db` | Path to SQLite database | `/var/lib/spectre/spectre.db` |
| `--yara-rules` | Directory containing YARA rule files | `/usr/share/spectre/yara_rules` |
| `--contain` | Mitigation action: `none`, `stop`, `kill` | `kill` |
| `--api` / `--no-api` | Enable/disable REST API and Dashboard | Enabled |
| `--api-port` | Port for REST API server | `8000` |
| `--verbose`, `-v` | Enable verbose mode (print all events) | `False` |

---

## Detection Rules & Sigma Integration

### Built-in Rule Packs (24 Sigma Rules)

| Pack | Rules | ATT&CK Coverage | Description |
|------|-------|-----------------|-------------|
| **webshell** | 6 | T1059.004, T1505.003, T1059, T1027.004, T1046, T1570, T1105, T1016, T1071, T1041 | Web server compromises, shell spawns, compilers, downloaders, post-exploitation |
| **privilege_escalation** | 6 | T1548.003, T1548.001, T1068, T1574.006, T1053.003, T1543.002 | Sudo abuse, SUID exploitation, kernel exploits, LD_PRELOAD, cron, systemd |
| **credential_access** | 6 | T1003.008, T1555.004, T1555.003, T1555.001, T1552.001 | Shadow files, SSH keys, browser creds, GPG keys, AWS/Docker secrets |
| **lateral_movement** | 6 | T1021.004, T1550.002, T1543.003, T1021.002, T1021.001, T1021.006 | SSH, pass-the-hash, remote services, SMB, RDP, WMI/WinRM |

### Install Rule Packs
```bash
# List available packs
spectre rule list

# Install webshell detection pack
spectre rule install webshell

# Install all packs
for p in webshell privilege_escalation credential_access lateral_movement; do
  spectre rule install "$p"
done
```

### Write Custom Sigma Rules
```yaml
title: Suspicious Python Script Execution
id: custom-suspicious-python-001
description: Detects python executing scripts from /tmp or /dev/shm
status: experimental
author: Your Name
date: 2024-01-15
logsource:
    category: process_creation
    product: linux
detection:
    selection_python:
        Image|endswith: '/python3'
    selection_tmp_script:
        CommandLine|contains:
            - '/tmp/'
            - '/dev/shm/'
    condition: selection_python and selection_tmp_script
level: high
tags:
    - attack.t1059.006
    - attack.execution
```

### Test Rules
```bash
# Validate Sigma syntax and test conversion
spectre test rule my_rule.yml

# Test all rules in a pack
spectre test rule spectre/rules/packs/webshell/*.yml
```

---

## Testing & Verification

Spectre includes an automated E2E verification test suite to simulate and assert threat escalation behaviors.

### Run E2E Test Suite
```bash
python -m pytest tests/v10/run_test.py
```

### Run Unit Tests
```bash
python -m pytest tests/unit/ -v
```

### Run Rule Tests (CI)
```bash
# Validates Sigma syntax and conversion
python -m pytest tests/ -k "sigma" -v
```

### Manual Verification
```bash
# Start Spectre in background with low threshold
spectre run --threshold 5 --contain kill --api &

# Trigger a test alert (reads /etc/hosts with python)
python -c "open('/etc/hosts').read(); import time; time.sleep(10)"

# Check dashboard at http://localhost:8000
```

---

## Documentation & Roadmap

Detailed architectural notes and version progression can be found in the `docs/` directory:

* **[Master Design Document](docs/design_doc.md)**: Vision, entity relations, and the 17-stage SDLC roadmap.
* **[Progress Tracker](docs/progress.md)**: Current completion status of the project.
* **[GTU Internship Submission](docs/gtu_submission_details.md)**: Details for project submission.

**Incremental SDLC Roadmap (Current Status):**
- [x] **v0.1**: Process Monitor, Rule Engine, Resource Tracking, Graph Memory.
- [x] **v0.2**: Active Containment (SIGSTOP), Sigma Integration, Rule Packs, Testing CLI.
- [ ] **v0.3 (Next)**: Replace `psutil` polling sensor with an event-driven `auditd`/Netlink connector.
- [ ] **v1.0 (Future)**: Rewrite sensor in Rust/C using eBPF for true zero-gap visibility and production readiness.

---

## Acknowledgments & External Links

Spectre is built on the shoulders of giants. We heavily rely on the following open-source frameworks and security standards:

- **[psutil](https://github.com/giampaolo/psutil)**: For cross-platform OS-level process and system monitoring.
- **[NetworkX](https://networkx.org/)**: For sliding-window directed graph processing and ancestry modeling.
- **[FastAPI](https://fastapi.tiangolo.com/)**: For exposing the high-performance telemetry API.
- **[YARA](https://virustotal.github.io/yara/)**: The pattern matching swiss knife for malware researchers.
- **[MITRE ATT&CK®](https://attack.mitre.org/)**: The globally-accessible knowledge base of adversary tactics and techniques.
- **[Sigma](https://github.com/SigmaHQ/sigma)**: Generic signature format for SIEM systems.
- **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)**: Atomic tests for ATT&CK techniques.

---

<div align="center">
  <i>Engineered for deep contextual visibility and zero-day resilience.</i>
  <br>
  <b>Author:</b> Aayush Bankar (<a href="mailto:aayushbankar42@gmail.com">aayushbankar42@gmail.com</a>)
</div>