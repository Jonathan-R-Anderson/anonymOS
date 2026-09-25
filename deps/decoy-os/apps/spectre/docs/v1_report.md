# Project Spectre - V1 Progress Report

## Overview
This report details the implementation, architecture, and verification of **V1 (Rule-Based Behavioral Detector)** for Project Spectre. V1 moves the telemetry framework into a modular system capable of matching process lineage trees against security rules, calculating threat scores, logging alerts, and generating human-readable explanations.

---

## 1. What We Did (The Goal)
The objective of V1 was to build a fully functional local HIDS that:
* Defines a declarative rule structure for process spawns.
* Parses and matches process parent-child relationships (and general ancestor relationships).
* Assigns risk/threat scores to matched process chains.
* Generates clear, human-understandable explanations of why the alert triggered.
* Logs warnings to a persistent log file (`spectre_alerts.log`) and highlights security warnings on the console.

---

## 2. How It Works (Technical Details)
The project structure was transitioned into a clean modular layout:

* **`rules/`**: Defines the `BehavioralRule` dataclass and loads default security rules (e.g. web server spawning shell, shell spawning network/download tools, etc.).
* **`detectors/`**: The `DetectionEngine` matches child-parent process pairs or ancestor-descendant processes using lists of matching executable names.
* **`alerts/`**: The `ExplanationEngine` constructs semantic descriptions of the alert (e.g., describing why a web server spawning `bash` is dangerous). The `AlertLogger` writes formatted entries to `spectre_alerts.log` and outputs colored console warnings.
* **`sensor/`**: The `ProcessSensor` runs the background polling thread/process and emits spawn chains.
* **`main.py`**: Orchestrates all modules and provides options like `--log-file` and `--verbose` (to fall back to V0 logging behavior).

---

## 3. Verification & Live Trace Results
We validated the rule matches using deliberate host-injection tests:

### Trigger: Shell Spawning Downloader (Score: 10)
Running `curl --version` from a standard shell triggered the downloader rule:
```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
⚠️  SECURITY ALERT: SHELL SPAWNING DOWNLOADER
Severity Score: 10/20
Explanation:    Shell 'bash' (PID: 10693) spawned transfer utility 'curl' (PID: 10712) [Cmd: curl --version]. This is a common behavior when downloading secondary payloads, scripts, or post-exploitation toolkits.

Execution Chain:
  systemd (PID: 1) [Cmd: /usr/lib/systemd/systemd --switched-root --system --deserialize=57 rhgb splash]
  └── systemd (PID: 2571) [Cmd: /usr/lib/systemd/systemd --user]
        └── gnome-shell (PID: 2804) [Cmd: /usr/bin/gnome-shell --mode=user]
              └── antigravity (PID: 4516) [Cmd: /usr/share/antigravity/antigravity]
                    └── language_server_linux_x64 (PID: 5185) [Cmd: /usr/share/antigravity/resources/app/extensions/antigravity/bin/language_serv...]
                          └── bash (PID: 10693) [Cmd: bash -c trap 'declare -p > "/home/legion/.gemini/antigravity/brain/41f8b7f1-e...]
                                └── curl (PID: 10712) [Cmd: curl --version]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Trigger: Shell Spawning Network Tool (Score: 15)
Running `nc -l 9999` from a shell triggered the network tool rule:
```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
⚠️  SECURITY ALERT: SHELL SPAWNING NETWORK TOOL
Severity Score: 15/20
Explanation:    Shell 'bash' (PID: 10762) spawned network tool 'nc' (PID: 10780) [Cmd: nc -l 9999]. This may indicate active host reconnaissance, port scanning, or the establishment of outbound traffic redirection.

Execution Chain:
  systemd (PID: 1) [Cmd: /usr/lib/systemd/systemd --switched-root --system --deserialize=57 rhgb splash]
  └── systemd (PID: 2571) [Cmd: /usr/lib/systemd/systemd --user]
        └── gnome-shell (PID: 2804) [Cmd: /usr/bin/gnome-shell --mode=user]
              └── antigravity (PID: 4516) [Cmd: /usr/share/antigravity/antigravity]
                    └── language_server_linux_x64 (PID: 5185) [Cmd: /usr/share/antigravity/resources/app/extensions/antigravity/bin/language_serv...]
                          └── bash (PID: 10762) [Cmd: bash -c trap 'declare -p > "/home/legion/.gemini/antigravity/brain/41f8b7f1-e...]
                                └── nc (PID: 10780) [Cmd: nc -l 9999]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Trigger: Web Server Spawning Shell (Score: 20)
To simulate a web-shell RCE exploit:
1. We copied the python executable to `./nginx` (so it maintains its process name as `nginx` instead of overriding it via `prctl` as `bash` does).
2. Spawned a background sub-shell command using `subprocess.Popen` from Python.
3. Used sequential commands (`sleep 5; echo done`) to prevent Linux/bash from optimizing the fork with an `exec` call.

This correctly simulated the exploit and triggered the web server alert:
```text
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
⚠️  SECURITY ALERT: WEB SERVER SPAWNING SHELL
Severity Score: 20/20
Explanation:    Web server 'nginx' (PID: 11043) spawned an interactive shell 'bash' (PID: 11044) [Cmd: /usr/bin/bash -c sleep 5; echo done]. This process pattern is highly suspicious and typical of web shell access or remote code execution (RCE) attempts.

Execution Chain:
  systemd (PID: 1) [Cmd: /usr/lib/systemd/systemd --switched-root --system --deserialize=57 rhgb splash]
  └── systemd (PID: 2571) [Cmd: /usr/lib/systemd/systemd --user]
        └── gnome-shell (PID: 2804) [Cmd: /usr/bin/gnome-shell --mode=user]
              └── antigravity (PID: 4516) [Cmd: /usr/share/antigravity/antigravity]
                    └── language_server_linux_x64 (PID: 5185) [Cmd: /usr/share/antigravity/resources/app/extensions/antigravity/bin/language_serv...]
                          └── bash (PID: 11022) [Cmd: bash -c trap 'declare -p > "/home/legion/.gemini/antigravity/brain/41f8b7f1-e...]
                                └── bash (PID: 11040) [Cmd: bash -c trap 'declare -p > "/home/legion/.gemini/antigravity/brain/41f8b7f1-e...]
                                      └── nginx (PID: 11043) [Cmd: ./nginx -c import subprocess, time; subprocess.Popen(['/usr/bin/bash', '-c', ...]
                                            └── bash (PID: 11044) [Cmd: /usr/bin/bash -c sleep 5; echo done]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 4. Evaluation & Next Steps
* **Alert Logging**: Alerts are successfully written with standard log levels and timestamps to `spectre_alerts.log`.
* **Architecture Validation**: The separation of telemetry collection (`sensor`), rules configuration (`rules`), rule checking (`detectors`), and representation/formatting (`alerts`) is highly clean and decoupled.
* **Next Stage**: We will proceed to **V2 (Resource Tracking)**. In V2, we will expand our entity definitions to include Sockets and Files, and capture events like `READ`, `WRITE`, and `CONNECT` in addition to process spawns.
