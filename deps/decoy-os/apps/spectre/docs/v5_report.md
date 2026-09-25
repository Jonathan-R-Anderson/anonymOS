# Project Spectre V5: Attack Mapping (MITRE ATT&CK)

We have successfully completed **V5 (Attack Mapping)**. This version maps all behavioral detection rules to the MITRE ATT&CK framework, enriching alerts and logs with standardized threat intelligence metadata.

---

## 1. MITRE ATT&CK Rule Mappings

Every rule in `rules.json` now carries a `mitre_attack` array containing one or more technique objects:

```json
{
  "tactic": "Execution",
  "technique_id": "T1059.004",
  "technique_name": "Command and Scripting Interpreter: Unix Shell"
}
```

### Current Mappings

| Rule | MITRE Techniques |
|:-----|:-----------------|
| Web Server Spawning Shell | T1059.004 (Execution), T1505.003 (Persistence) |
| Shell Spawning Network Tool | T1046 (Discovery), T1570 (Lateral Movement) |
| Shell Spawning Downloader | T1105 (C2), T1059.004 (Execution) |
| Web Server Spawning Compiler | T1059 (Execution), T1027.004 (Defense Evasion) |
| Python Accessing Hosts Config | T1016 (Discovery) |
| Python Outbound Socket | T1071 (C2), T1041 (Exfiltration) |

---

## 2. Enriched Alerts

MITRE metadata is now surfaced in three places:
1. **Startup Banner**: Rule listing shows technique IDs alongside scores.
2. **Warning Logs**: Each warning log line includes `MITRE: T1016 (Discovery)` style annotations.
3. **High-Severity Alerts**: Threshold breach explanations list MITRE mappings for every triggered behavior.

---

## 3. Verification

```bash
python3 tests/v5/run_test.py
```

All three assertions pass:
- Hosts read warning includes MITRE T1016.
- Outbound connection warning includes MITRE T1071.
- Threshold breach escalation triggered with enriched explanation.
