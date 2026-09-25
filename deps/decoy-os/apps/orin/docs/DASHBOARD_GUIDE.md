# Dashboard Guide

## Overview

The Orin Forensic Investigation Console is a single-page application (SPA) dashboard providing real-time visibility into system security posture, forensic telemetry, threat detection alerts, and fleet management. All rendering is handled by vanilla JavaScript with zero external dependencies.

---

## Contents

1. [Architecture](#architecture)
2. [Navigation & Layout](#navigation--layout)
3. [Posture Pane — Alert Feed](#posture-pane--alert-feed)
4. [Telemetry Explorer](#telemetry-explorer)
5. [Timeline Delta Analysis](#timeline-delta-analysis)
6. [Settings Panel](#settings-panel)
7. [AI Triage Briefing](#ai-triage-briefing)
8. [Sidebar — Risk Gauge](#sidebar--risk-gauge)
9. [Sidebar — Snapshots & Baselines](#sidebar--snapshots--baselines)
10. [Sidebar — Fleet Overview](#sidebar--fleet-overview)
11. [Sidebar — Remote SSH Scan](#sidebar--remote-ssh-scan)
12. [API Reference](#api-reference)
13. [JavaScript Function Reference](#javascript-function-reference)
14. [Operational Workflows](#operational-workflows)
15. [Security Considerations](#security-considerations)
16. [Troubleshooting](#troubleshooting)
17. [Appendix — CSS Variables & Icon Reference](#appendix)

---

## Architecture

| Layer | Technology | Description |
|---|---|---|
| Frontend | Vanilla JS + CSS3 | Zero-dependency SPA |
| Styling | CSS custom properties | Dark theme, responsive layout |
| Backend API | Python HTTP server | RESTful JSON API |
| Storage | SQLite (`OrinStorage`) | Forensic data persistence |
| Authentication | Session token / API key | Multi-tenant isolation |

### Communication Flow

```
Browser (dashboard.html)  ←──HTTPS/JSON──►  Hub Server (port 8443)
                                                      │
                                                      ▼
                                               SQLite Vault
```

---

## Navigation & Layout

### Header Bar

| Element | Description |
|---|---|
| Logo section | Brand identity |
| `#badge-host` | Current hostname |
| `#badge-os` | Operating system details |
| `#badge-vault` | Active vault name |
| Tab navigation | Switch between main panes |
| **Capture Telemetry** button | Triggers on-demand collection |

### Two-Column Layout

- **Left column (320 px):** Risk gauge, recent snapshots, baseline controls, fleet overview, remote scan form
- **Right column (flexible):** Active pane content

### Tab System

| Tab | Pane ID | Description |
|---|---|---|
| Posture | `#pane-posture` | Security alert feed with filtering |
| Telemetry Explorer | `#pane-telemetry` | Deep-dive into system state |
| Timeline Delta | `#pane-diff` | Comparative snapshot analysis |
| Settings | `#pane-config` | Configuration management |
| AI Triage | `#pane-ai` | AI-powered executive summaries |

---

## Posture Pane — Alert Feed

The Posture pane provides a centralized, filterable view of all security events and forensic findings.

### Filter Controls

| Control | ID | Description |
|---|---|---|
| Host filter | `#filter-host` | Limit alerts to a specific host |
| Severity pills | `.sev-pills` | Filter by ALL / CRITICAL / HIGH / MEDIUM / LOW |
| Show Resolved | `#chk-resolved` | Include resolved alerts |
| Show Suppressed | `#chk-suppressed` | Include suppressed alerts |

### Severity Weight Reference

| Severity | Risk Score Impact |
|---|---|
| CRITICAL | +25 points |
| HIGH | +15 points |
| MEDIUM | +8 points |
| LOW | +2 points |

### `loadAlertsLedger()`

Fetches and renders the current alert feed from the backend.

```javascript
async function loadAlertsLedger() {
    const params = new URLSearchParams({
        host: document.getElementById('filter-host').value,
        resolved: document.getElementById('chk-resolved').checked,
        suppressed: document.getElementById('chk-suppressed').checked,
        severity: currentSeverityFilter
    });

    const response = await fetch('/api/alerts?' + params, {
        headers: { 'X-API-Key': getApiKey() }
    });

    const data = await response.json();
    renderAlertFeed(data.alerts);
}
```

**Endpoint:** `GET /api/alerts`

**Response schema:**

```json
{
  "alerts": [
    {
      "id": "evt_abc123",
      "timestamp": "2026-06-10T14:30:00Z",
      "host": "forensic-server-01",
      "severity": "CRITICAL",
      "category": "privilege_escalation",
      "title": "Sudo Abuse Detected",
      "description": "User 'john' executed sudo with suspicious arguments",
      "mitre_attack": ["T1548.003"],
      "resolved": false,
      "suppressed": false
    }
  ],
  "total_count": 42,
  "filtered_count": 15
}
```

---

## Telemetry Explorer

The Telemetry Explorer provides interactive access to captured system state snapshots across multiple forensic domains.

### Telemetry Domains

| Tab | Data Source | Collector |
|---|---|---|
| Processes | `collected_processes` | `collectors/processes.py` |
| Network Connections | `collected_ports`, `collected_outbound_connections` | `collectors/connections.py` |
| File Changes | `collected_file_hashes` | `collectors/integrity.py` |
| User Sessions | `collected_wtmp_sessions` | `collectors/session_audit.py` |
| Kernel Modules | `collected_kernel_modules` | `collectors/kernel.py` |
| Services | `collected_persistence_configs` | `collectors/persistence.py` |
| Packages | `collected_pkg_integrity` | `collectors/pkg_integrity.py` |

### `loadTelemetry(snapshotId)`

Fetches and displays telemetry data for the selected snapshot and active domain tab.

```javascript
async function loadTelemetry(snapshotId) {
    if (!snapshotId) return;
    const dataType = document.querySelector('.telemetry-menu-btn.active').dataset.tab
                           .replace('telemetry-', '');

    const response = await fetch(`/api/telemetry/${dataType}?snapshot_id=${snapshotId}`, {
        headers: { 'X-API-Key': getApiKey() }
    });
    const data = await response.json();
    renderTelemetryTable(dataType, data.records);
}
```

---

## Timeline Delta Analysis

The Timeline Delta pane enables comparative analysis between two snapshots to identify system drift and potential compromise indicators.

### Workflow

1. Select a **baseline** snapshot (known-good state)
2. Select a **comparison** snapshot (post-incident capture)
3. Click **Analyze Differences**
4. Results are displayed by category with risk colour coding:
   - 🟢 Expected / benign change
   - 🟡 Suspicious modification
   - 🔴 Critical / high-risk change

### `performDiffAnalysis()`

```javascript
async function performDiffAnalysis() {
    const baseSnapshot = document.getElementById('diff-base-snapshot').value;
    const compSnapshot = document.getElementById('diff-comp-snapshot').value;

    if (!baseSnapshot || !compSnapshot || baseSnapshot === compSnapshot) {
        showToast('Select two different snapshots to compare.', 'error');
        return;
    }

    const response = await fetch('/api/diff', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': getApiKey() },
        body: JSON.stringify({
            baseline_snapshot: baseSnapshot,
            comparison_snapshot: compSnapshot
        })
    });

    renderDiffResults(await response.json());
}
```

**Endpoint:** `POST /api/diff`

**Response schema:**

```json
{
  "summary": {
    "total_changes": 47,
    "critical_changes": 3,
    "suspicious_changes": 8,
    "benign_changes": 36
  },
  "by_category": {
    "processes": { "added": [...], "removed": [...], "modified": [...] },
    "network": { "new_connections": [...], "closed_connections": [...] },
    "files": { "created": [...], "deleted": [...], "modified": [...] }
  },
  "risk_indicators": [
    {
      "type": "new_suid_binary",
      "path": "/tmp/.hidden/backdoor",
      "severity": "CRITICAL",
      "description": "New SUID binary detected in temporary directory"
    }
  ]
}
```

---

## Settings Panel

The Settings panel configures collection intervals, alert forwarding, retention policies, and AI integration.

### Configuration Fields

| Field | ID | Default | Validation |
|---|---|---|---|
| Collection interval (seconds) | `#cfg-interval` | 300 | 60–86400 |
| Alert webhook URL | `#cfg-webhook` | — | HTTPS URL |
| Max stored snapshots | `#cfg-max-snapshots` | 50 | 1–1000 |
| Log level | `#cfg-log-level` | INFO | INFO / DEBUG / WARN / ERROR |
| Retention period (days) | `#cfg-retention` | 90 | 1–3650 |
| AI triage endpoint | `#cfg-ai-api` | — | HTTP/HTTPS URL |

**Endpoints:** `GET /api/config` (retrieve) · `PUT /api/config` (update)

---

## AI Triage Briefing

The AI Triage pane generates AI-powered executive summaries of current security findings using a local Ollama model.

### Workflow

1. Optionally select a specific snapshot (defaults to the latest)
2. Click **Generate Executive Summary**
3. The backend aggregates current alerts and telemetry anomalies
4. A structured prompt is sent to the configured local Ollama endpoint
5. A Markdown-formatted briefing is rendered inline

**Endpoint:** `POST /api/ai/triage`

**Request:**

```json
{
  "snapshot_id": "snap_abc123",
  "include_mitre_mapping": true,
  "include_remediation_steps": true
}
```

**Response:**

```json
{
  "briefing": "# Executive Security Briefing\n\n## Key Findings\n...",
  "generated_at": "2026-06-10T15:45:00Z",
  "model_used": "local-llama-3.1",
  "confidence_score": 0.87
}
```

---

## Sidebar — Risk Gauge

The risk gauge displays the current security posture as a circular progress indicator with a numeric score (0–100).

### Risk Score Formula

```
risk_score = MIN(100, SUM(alert_severity_weights))

CRITICAL alerts:  +25 points each
HIGH alerts:      +15 points each
MEDIUM alerts:    +8  points each
LOW alerts:       +2  points each
```

### Status Thresholds

| Score | Status | Colour |
|---|---|---|
| 0 | Healthy | `#10B981` (green) |
| 1–39 | Monitor | `#38BDF8` (blue) |
| 40–59 | Medium Risk | `#F59E0B` (amber) |
| 60–79 | High Risk | `#F59E0B` (amber) |
| 80–100 | Critical | `#EF4444` (red) |

---

## Sidebar — Snapshots & Baselines

### Recent Snapshots

Displays the 10 most recent forensic captures. Clicking a snapshot switches the Telemetry Explorer to that snapshot's data.

**Endpoint:** `GET /api/snapshots/recent?limit=10`

### Baseline Administration

| Action | Function | Description |
|---|---|---|
| Refresh baseline | `triggerBaselineRefresh()` | Re-compute baseline statistics |
| Add to allowlist | `addToAllowlist(type, inputId)` | Add users or kernel modules to the trusted baseline |

**Endpoint:** `POST /api/baseline/allowlist`

```json
{ "type": "user", "value": "admin" }
```

---

## Sidebar — Fleet Overview

Displays all registered hosts with live status indicators.

**Endpoint:** `GET /api/hosts`

**Response:**

```json
{
  "hosts": [
    {
      "id": "host_001",
      "hostname": "web01",
      "ip_address": "10.0.1.50",
      "status": "active",
      "last_heartbeat": "2026-06-10T15:40:00Z",
      "risk_level": "HIGH"
    }
  ]
}
```

---

## Sidebar — Remote SSH Scan

Initiates a forensic scan on a remote host via SSH from within the dashboard.

### Form Fields

| Field | ID | Example |
|---|---|---|
| Target host | `#scan-host` | 192.168.1.50 |
| SSH username | `#scan-user` | root |
| SSH port | `#scan-port` | 22 |
| Private key path | `#scan-key` | /root/.ssh/id_rsa |

**Endpoint:** `POST /api/scan/remote`

```json
{
  "target_host": "192.168.1.50",
  "ssh_username": "root",
  "ssh_port": 22,
  "private_key_path": "/root/.ssh/id_rsa",
  "operation": "scan"
}
```

---

## API Reference

### Authentication

All endpoints except `/health` and `/` require one of:
- `X-API-Key: <key>` header
- `Authorization: Bearer <token>` header

### Endpoint Summary

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness probe |
| GET | `/` | No | Serve dashboard |
| GET | `/api/status` | Yes | Hub status for current tenant |
| GET | `/api/hosts` | Yes | List registered hosts |
| GET | `/api/stats` | Yes | Tenant statistics |
| GET | `/api/snapshots` | Yes | List snapshots |
| GET | `/api/alerts` | Yes | Query security alerts |
| GET | `/api/telemetry/{type}` | Yes | Get telemetry data by type |
| GET | `/api/config` | Yes | Retrieve configuration |
| GET | `/api/risk/score` | Yes | Calculate current risk score |
| GET | `/api/vault/info` | Yes | Vault metadata |
| GET | `/api/export/{type}` | Yes | Export forensic data |
| POST | `/api/diff` | Yes | Compare two snapshots |
| POST | `/api/ai/triage` | Yes | Request AI briefing |
| POST | `/api/baseline/refresh` | Yes | Refresh baseline statistics |
| POST | `/api/baseline/allowlist` | Yes | Add item to allowlist |
| POST | `/api/scan/remote` | Yes | Initiate remote SSH scan |
| POST | `/api/register` | Yes | Register a new host |
| POST | `/api/heartbeat` | Yes | Host heartbeat |
| POST | `/api/import` | Yes | Import forensic data |
| POST | `/api/upload` | Yes | Upload snapshot archive |
| POST | `/api/tenants` | No | Create a new tenant |
| PUT | `/api/config` | Yes | Update configuration |

---

## JavaScript Function Reference

| Function | Parameters | Description |
|---|---|---|
| `switchTab(tabId)` | `tabId: string` | Switch the active pane |
| `loadAlertsLedger()` | — | Load and render the alert feed |
| `setSeverityFilter(level)` | `level: string` | Apply severity filter and reload alerts |
| `loadTelemetry(snapshotId)` | `snapshotId: string` | Load telemetry data for a snapshot |
| `switchTelemetryTab(tabId)` | `tabId: string` | Switch telemetry domain and reload |
| `performDiffAnalysis()` | — | Run snapshot comparison |
| `loadConfig()` | — | Fetch and populate configuration form |
| `saveConfig()` | — | Validate and persist configuration |
| `requestAIInsight()` | — | Request AI triage briefing |
| `updateRiskGauge(score)` | `score: number` | Update gauge SVG and status pill |
| `triggerBaselineRefresh()` | — | Refresh baseline statistics |
| `addToAllowlist(type, inputId)` | `type, inputId: string` | Add item to allowlist |
| `triggerRemoteScan(isBaseline)` | `isBaseline: boolean` | Initiate remote SSH scan |
| `triggerOnDemandCollect()` | — | Trigger immediate telemetry collection |
| `showToast(message, type)` | `message, type: string` | Display notification toast |
| `closeModal()` | — | Close alert detail modal |

---

## Operational Workflows

### Workflow 1: Initial Setup

1. Navigate to `https://<hub-ip>:8443/`
2. Enter the API key provided during tenant creation
3. Confirm that host, OS, and vault badges are populated
4. Click **Capture Telemetry** to initiate the first collection run

### Workflow 2: Incident Response

1. Review the **Posture** pane for CRITICAL / HIGH alerts
2. Apply host and severity filters as needed
3. Click an alert to open the detail modal
4. Switch to **Telemetry Explorer** and select the relevant snapshot
5. Examine **Processes** and **Network Connections** tabs
6. Use **Timeline Delta** to compare pre- and post-incident snapshots
7. Generate an **AI Triage** briefing for executive reporting
8. Mark resolved alerts as closed

### Workflow 3: Baseline Management

1. After a clean OS installation, click **Init Baseline** via the remote scan form
2. Add known-good users and kernel modules to the allowlist
3. Refresh the baseline monthly via **Refresh Baseline Ledger**
4. Monitor **Timeline Delta** for unauthorized drift

### Workflow 4: Fleet Monitoring

1. Review the **Fleet Overview** sidebar for host status indicators
2. Identify hosts with elevated risk scores
3. Click a host to switch context
4. Compare risk profiles across hosts
5. Use **Remote SSH Scan** for targeted assessments

---

## Security Considerations

**API key rotation:** Rotate keys every 90 days.

**Session timeout:** Implement a 30-minute idle timeout for dashboard sessions.

**Content Security Policy:** The dashboard enforces a strict CSP:

```
default-src 'self'
script-src 'self' 'unsafe-inline'
style-src 'self' 'unsafe-inline'
img-src 'self' data:
connect-src 'self'
frame-ancestors 'none'
base-uri 'self'
form-action 'self'
```

**Data in transit:** All API communications should use TLS 1.3. Credentials and private keys are never transmitted to the frontend.

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| Blank dashboard on load | CSP violation | Check the browser console for blocked resources |
| API calls failing with 401 | Invalid or expired API key | Re-enter the API key |
| Risk gauge stuck at 0 | `/api/risk/score` unavailable | Check hub server logs |
| Snapshot dropdown empty | No snapshots in database | Run `orin collect` and refresh |
| AI briefing does not load | Ollama endpoint unreachable | Verify `cfg-ai-api` is correctly set |

**Enable debug logging:**

```javascript
localStorage.setItem('orin_debug', 'true');
location.reload();
```

**Check hub server logs:**

```bash
journalctl -u orin-hub -f
# or
tail -f /var/log/orin/hub_server.log
```

---

## Appendix

### CSS Variable Reference

| Variable | Default | Usage |
|---|---|---|
| `--bg-primary` | `#0A0D1A` | Main background |
| `--bg-secondary` | `#0E1225` | Secondary backgrounds |
| `--bg-card` | `#121832` | Card backgrounds |
| `--text-primary` | `#F8FAFC` | Primary text |
| `--text-secondary` | `#8E9BAE` | Secondary text |
| `--primary` | `#38BDF8` | Primary accent |
| `--success` | `#10B981` | Success states |
| `--warning` | `#F59E0B` | Warning states |
| `--critical` | `#EF4444` | Critical / error states |

### Icon Reference (Lucide, via `data-icon` attribute)

| Icon | Context |
|---|---|
| `shield-alert` | Logo, security contexts |
| `alert-triangle` | Warnings and alerts |
| `database` | Telemetry and data |
| `git-compare` | Diff analysis |
| `settings` | Configuration |
| `bot` | AI features |
| `refresh-cw` | Refresh actions |
| `check-circle` | Success notifications |
| `alert-circle` | Error notifications |
| `loader` | Loading spinners |
| `x` | Close actions |