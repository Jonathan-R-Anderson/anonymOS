# Project Progress Tracker

This document tracks the implementation progress of Project Spectre through the incremental SDLC roadmap.

## Summary Roadmap

| Version | Feature Goal | Status | Completed Date | Notes |
| :--- | :--- | :---: | :--- | :--- |
| **V0** | Process Monitor PoC | **Completed** | 2026-06-23 | Console tree representation of ancestry chains using `psutil`. |
| **V1** | Rule-based Detector | **Completed** | 2026-06-24 | Tree building, scoring, explanation, alert logging. |
| **V2** | Resource Tracking | **Completed** | 2026-06-24 | Files, Sockets, and READ/WRITE/CONNECT/LISTEN events. |
| **V3** | Sliding Window Graph | **Completed** | 2026-06-24 | Event expiration, cleanup, rolling memory using `networkx`. |
| **V4** | Detection Engine | **Completed** | 2026-06-24 | Weighted scoring, JSON rules, thresholding. |
| **V5** | Attack Mapping | **Completed** | 2026-06-25 | MITRE ATT&CK integration in rules, warnings, and alerts. |
| **V6** | Persistence | **Completed** | 2026-06-25 | SQLite storage for events, alerts, and session scores. |
| **V7** | REST API | **Completed** | 2026-06-25 | FastAPI endpoints for querying events, alerts, and chains. |
| **V8** | Dashboard | **Completed** | 2026-06-25 | Static HTML, CSS (glassmorphism), and JS polling interface. |
| **V9** | YARA Integration | **Completed** | 2026-06-25 | Hash lookup and string signature file scans. |
| **V10**| Active Containment | **Completed** | 2026-06-29 | Tree killing, process quarantining, SIGTERM/SIGSTOP actions. |
| **Phase 1**| Detection Engineering Platform | **Completed** | 2026-08-02 | Sigma-native rules, rule packs, testing CLI, pack management. |
| **V11**| Attack Replay | *Not Started* | - | Atomic Red Team simulation runner. |
| **V12**| Telemetry Upgrades | *Not Started* | - | eBPF, auditd, and procfs event sourcing. |
| **V13**| Machine Learning | *Not Started* | - | Isolation Forest / One-class SVM anomaly detection. |
| **V14**| Graph Embeddings | *Not Started* | - | Node2Vec / DeepWalk modeling. |
| **V15**| Multi-host Support | *Not Started* | - | Kafka / Redis streams agent-collector transport. |
| **V16**| LLM Explanations | *Not Started* | - | AI-generated alert chain summaries. |
| **V17**| Research Branch | *Not Started* | - | Temporal Graph Networks / continuous-time learning. |

---

## Current Release: v10.0.4 (2026-08-02)

**Full Feature Set:**
- Behavioral HIDS with process ancestry tracking
- File/socket monitoring (READ/WRITE/CONNECT/LISTEN)
- Sliding-window NetworkX graph with event expiration
- Behavioral detection engine with weighted scoring
- JSON + Sigma-native rules (24 rules, 4 packs)
- MITRE ATT&CK auto-mapping
- YARA file scanning + SHA256 hashing
- Active containment (SIGSTOP/SIGKILL process trees)
- SQLite persistence (events, alerts, sessions)
- FastAPI REST API + live dashboard
- Sigma-native detection engineering platform:
  - Sigma parser, field mapper, compiler
  - 4 rule packs (webshell, privilege_escalation, credential_access, lateral_movement)
  - Rule testing CLI (`spectre test rule`)
  - Rule pack management (`spectre rule install/list/info`)
- Modern packaging: PyPI, Docker (multi-arch), systemd, install.sh
- CI/CD: Ruff, mypy, pytest, Docker build, PyPI publish

---

## Phase 1: Detection Engineering Platform (Completed 2026-08-02)

| Component | Status | Description |
| :--- | :---: | :--- |
| Sigma Parser | ✅ | Parses Sigma YAML rules with validation |
| Field Mapper | ✅ | 30+ Sigma→Spectre field mappings |
| Sigma Compiler | ✅ | Converts Sigma → BehavioralRule with MITRE extraction |
| Rule Packs | ✅ | 4 packs, 24 rules (webshell, priv-esc, cred-access, lateral) |
| Rule Testing CLI | ✅ | `spectre test rule` - validates Sigma, shows conversion |
| Pack Management | ✅ | `spectre rule install/list/info/uninstall` |
| Registry | ✅ | Local JSON registry for installed packs |

---

## Detailed Milestones

### V0: Process Monitor PoC
* **Deliverable**: Console-based process tree logger.
* **Outcome**: Implemented recycled PID matching, safely handle short-lived processes, trace lineages to root, print formatted ASCII trees.
* **Artifacts**:
  * Code: [main.py](file:///mnt/work/projects/spectre/main.py)
  * Report: [v0_report.md](file:///mnt/work/projects/spectre/docs/v0_report.md)

### V1: Rule-based Detector
* **Deliverable**: Process-to-process spawn pattern matching engine with alert generation and explanation blocks.
* **Outcome**: Built decoupled modules for rules mapping, alert evaluation, and threat-focused logging. Tested and triggered alerts for web shells, curl downloads, and ncat configurations.
* **Artifacts**:
  * Code: [main.py](file:///mnt/work/projects/spectre/main.py) | [sensor/](file:///mnt/work/projects/spectre/sensor/) | [rules/](file:///mnt/work/projects/spectre/rules/) | [detectors/](file:///mnt/work/projects/spectre/detectors/) | [alerts/](file:///mnt/work/projects/spectre/alerts/)
  * Report: [v1_report.md](file:///mnt/work/projects/spectre/docs/v1_report.md)

### V2: Resource Tracking
* **Deliverable**: File and socket event tracking.
* **Outcome**: Monitors open files (READ/WRITE) and network sockets (CONNECT/LISTEN) per process.
* **Artifacts**:
  * Code: [sensor/](file:///mnt/work/projects/spectre/sensor/)
  * Report: [v2_report.md](file:///mnt/work/projects/spectre/docs/v2_report.md)

### V3: Sliding Window Graph
* **Deliverable**: In-memory process-resource graph with event expiration.
* **Outcome**: NetworkX DiGraph with sliding window, automatic cleanup of orphaned nodes.
* **Artifacts**:
  * Code: [graph/](file:///mnt/work/projects/spectre/graph/)
  * Report: [v3_report.md](file:///mnt/work/projects/spectre/docs/v3_report.md)

### V4: Detection Engine
* **Deliverable**: Weighted scoring engine with JSON rules.
* **Outcome**: Configurable rules, threshold-based alerting, session scoring.
* **Artifacts**:
  * Code: [detectors/](file:///mnt/work/projects/spectre/detectors/), [rules/](file:///mnt/work/projects/spectre/rules/)
  * Report: [v4_report.md](file:///mnt/work/projects/spectre/docs/v4_report.md)

### V5: Attack Mapping
* **Deliverable**: MITRE ATT&CK integration.
* **Outcome**: Rules map to tactics/techniques, alerts include ATT&CK context.
* **Artifacts**:
  * Code: [rules/](file:///mnt/work/projects/spectre/rules/), [alerts/](file:///mnt/work/projects/spectre/alerts/)
  * Report: [v5_report.md](file:///mnt/work/projects/spectre/docs/v5_report.md)

### V6: Persistence
* **Deliverable**: SQLite storage layer.
* **Outcome**: Events, alerts, sessions persisted with indexes.
* **Artifacts**:
  * Code: [storage/](file:///mnt/work/projects/spectre/storage/)
  * Report: [v6_report.md](file:///mnt/work/projects/spectre/docs/v6_report.md)

### V7: REST API
* **Deliverable**: FastAPI endpoints.
* **Outcome**: `/events`, `/alerts`, `/sessions`, `/stats`, `/health`.
* **Artifacts**:
  * Code: [api/](file:///mnt/work/projects/spectre/api/)
  * Report: [v7_report.md](file:///mnt/work/projects/spectre/docs/v7_report.md)

### V8: Dashboard
* **Deliverable**: Live web interface.
* **Outcome**: Glassmorphism UI, real-time polling, alert feed, session view.
* **Artifacts**:
  * Code: [dashboard/](file:///mnt/work/projects/spectre/dashboard/)
  * Report: [v8_report.md](file:///mnt/work/projects/spectre/docs/v8_report.md)

### V9: YARA Integration
* **Deliverable**: File scanning with YARA + SHA256.
* **Outcome**: Scans files on alert, adds YARA hits to alerts.
* **Artifacts**:
  * Code: [scanner/](file:///mnt/work/projects/spectre/scanner/), [yara_rules/](file:///mnt/work/projects/spectre/yara_rules/)
  * Report: [v9_report.md](file:///mnt/work/projects/spectre/docs/v9_report.md)

### V10: Active Containment
* **Deliverable**: SIGSTOP/SIGKILL process trees.
* **Outcome**: Configurable containment action, tree-wide signal delivery.
* **Artifacts**:
  * Code: [mitigation/](file:///mnt/work/projects/spectre/mitigation/), [main.py](file:///mnt/work/projects/spectre/main.py)
  * Report: [v10_report.md](file:///mnt/work/projects/spectre/docs/v10_report.md)

### Phase 1: Detection Engineering Platform
* **Deliverable**: Sigma-native detection engineering workflow.
* **Outcome**: Parse Sigma → compile → test → pack → deploy.
* **Artifacts**:
  * Code: [rules/sigma_parser.py](file:///mnt/work/projects/spectre/rules/sigma_parser.py), [rules/compiler.py](file:///mnt/work/projects/spectre/rules/compiler.py), [rules/field_mapper.py](file:///mnt/work/projects/spectre/rules/field_mapper.py)
  * CLI: [cli/rule_cli.py](file:///mnt/work/projects/spectre/cli/rule_cli.py), [cli/test_cli.py](file:///mnt/work/projects/spectre/cli/test_cli.py)
  * Packs: [rules/packs/](file:///mnt/work/projects/spectre/rules/packs/)

---

## Technical Specifications

### Architecture
```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Sensor    │────▶│    Graph    │────▶│ Detection Engine │────▶│  Action & Alert  │
│  (psutil)   │     │ (NetworkX)  │     │  (Rules + MITRE) │     │ (Containment)    │
└─────────────┘     └─────────────┘     └──────────────────┘     └──────────────────┘
       │                  │                  │                      │
       ▼                  ▼                  ▼                      ▼
  Process events    Sliding window    Sigma + JSON rules     SIGSTOP/SIGKILL
  File/socket I/O   NetworkX DiGraph  Session scoring        REST API
                    Event expiration  YARA scanning           Dashboard
```

### Key Components
| Module | File | Responsibility |
| :--- | :--- | :--- |
| Sensor | `spectre/sensor/__init__.py` | psutil-based process/file/socket polling |
| Graph | `spectre/graph/__init__.py` | NetworkX sliding-window process-resource graph |
| Rules | `spectre/rules/core.py` | BehavioralRule + MitreMapping dataclasses |
| Rules | `spectre/rules/sigma_parser.py` | Sigma YAML parser |
| Rules | `spectre/rules/compiler.py` | Sigma → BehavioralRule compiler |
| Rules | `spectre/rules/field_mapper.py` | Sigma field → Spectre field mapper |
| Detectors | `spectre/detectors/__init__.py` | Chain evaluation against rules |
| Alerts | `spectre/alerts/__init__.py` | Alert formatting, explanation engine |
| Storage | `spectre/storage/__init__.py` | SQLite persistence |
| API | `spectre/api/__init__.py` | FastAPI REST endpoints |
| Scanner | `spectre/scanner/__init__.py` | YARA scanning + SHA256 |
| Mitigation | `spectre/mitigation/__init__.py` | SIGSTOP/SIGKILL containment |
| CLI | `cli/main.py` | Click-based command interface |
| CLI | `cli/rule_cli.py` | Rule pack management |
| CLI | `cli/test_cli.py` | Rule testing framework |

### Packaging & Distribution
| Artifact | Location |
| :--- | :--- |
| PyPI Package | `spectre-hids[yara]` |
| Docker Image | `ghcr.io/aayushbankar/spectre:latest` |
| Systemd Unit | `packaging/systemd/spectre.service` |
| Install Script | `install.sh` |
| PyPI Config | `pyproject.toml` |

### CI/CD Pipeline
| Workflow | Purpose |
| :--- | :--- |
| CI | Ruff, mypy, pytest, coverage |
| Release | Build, GitHub Release, PyPI, GHCR |
| Rule Test | Sigma validation, conversion test |

---

## Quick Start

```bash
# Install
pip install spectre-hids[yara]

# Or Docker
docker run -d --privileged --pid=host ghcr.io/aayushbankar/spectre:latest

# Run
sudo spectre run --contain kill --api

# Dashboard
# http://localhost:8000

# Test rules
spectre test rule spectre/rules/packs/webshell/*.yml

# Install rule packs
spectre rule install webshell privilege_escalation credential_access lateral_movement
```

---

## Links
- **Repository**: https://github.com/Aayushbankar/spectre
- **PyPI**: https://pypi.org/project/spectre-hids/
- **Docker**: https://github.com/Aayushbankar/spectre/pkgs/container/spectre
- **Releases**: https://github.com/Aayushbankar/spectre/releases
- **Issues**: https://github.com/Aayushbankar/spectre/issues