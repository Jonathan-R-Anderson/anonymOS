# Project Spectre V4: Detection Engine Upgrades

We have successfully completed **V4 (Detection Engine Upgrades)**. This version implements dynamic rule loading, process-resource rule criteria, and weighted threat score accumulation for process sessions.

---

## 1. Dynamic JSON Rules

EDR detection rules can now be configured dynamically in `rules.json`. The JSON format supports process-resource properties:

```json
{
  "id": "python_hosts_read",
  "name": "Python Accessing Hosts Configuration",
  "score": 12,
  "description": "...",
  "process_names": ["python", "python3"],
  "file_paths": ["/etc/hosts"],
  "file_events": ["READ"]
}
```

This supports matching actions on target files (READ/WRITE) and sockets (CONNECT/LISTEN) in addition to ancestral process spawns.

---

## 2. Weighted Threat Accumulation & Thresholds

Instead of alerting on isolated, static rule violations, Spectre V4 groups related actions by their **Session Leader** (the oldest monitored ancestor process in the chain):
1. **Threat Accumulation**: When any child or descendant in the tree triggers a rule, its score weight is added to the session's cumulative threat score.
2. **Threshold Escalation**: When the session's cumulative score crosses the configurable alerting threshold (`--threshold`, default: `15`), a **High Severity Alert** is raised.
3. **Spam Mitigation**: The session alert is only re-triggered if the cumulative score increases (new threats detected), preventing repeated logging of the same threat during polling cycles.

---

## 3. Reproducible E2E Verification Tests

Following the user's directive, we created a reproducible E2E test suite under `tests/v4/`:
* **`tests/v4/trigger_simulation.py`**: Spawns host actions that read `/etc/hosts` (triggers `python_hosts_read` = 12 points) and connect a socket to `8.8.8.8:53` (triggers `python_outbound_dns` = 14 points).
* **`tests/v4/run_test.py`**: Automatically spawns the Spectre monitor in the background, triggers the simulation, terminates the monitor, and asserts the logs.

### Executing Verification
Run the verification test suite directly:
```bash
python3 tests/v4/run_test.py
```

### Test Output
```text
[*] Running V4 E2E Test Suite...
[*] Spawning Spectre monitor process...
[*] Spawning trigger simulation...
[*] Starting V4 validation trigger simulation...
[*] Simulating Event 1: Reading /etc/hosts...
[*] Simulating Event 2: Outbound network connection to 8.8.8.8:53...
[*] Simulation complete.
[*] Stopping Spectre monitor process...
[*] Validating logs in test_v4_alerts.log...

========================================
V4 VERIFICATION REPORT:
  - Event 1 (Hosts read warning):   [PASS]
  - Event 2 (Outbound DNS warning): [PASS]
  - Threshold Breach Escalation:    [PASS]
========================================

[SUCCESS] V4 E2E Test Suite Passed successfully.
```
This confirms that the cumulative scoring logic correctly escalates sub-threshold threat events (12 points + 14 points = 26 points) to high-severity warnings when crossing the alert threshold (20 points).
