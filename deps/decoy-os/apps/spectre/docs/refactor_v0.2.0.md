# Spectre v0.2.0-alpha: Architecture Corrections & True PoC

This document outlines the architectural corrections made to transition Spectre from a heavily-oversold experimental prototype into a mathematically sound, credible Proof-of-Concept (PoC).

## 1. Documentation & Marketing Corrections
* **Version Re-alignment**: Reverted the claimed "V10" down to `v0.2.0-alpha`. Claiming V10 on an untested, polling-based sensor creates an immediate loss of credibility in the cybersecurity space.
* **Dashboard Transparency**: Removed false claims of a "Next.js dashboard." The UI is now accurately documented as a "Lightweight, dependency-free Vanilla HTML/JS Dashboard" (which is often preferred by sysadmins anyway).
* **Roadmap Reality**: Clearly stated that `psutil` is an interim solution and that eBPF is required for a V1.0 release.

## 2. Dynamic Configuration (Removing Hardcoded Hacks)
* **The Problem**: The sensor previously hardcoded specific ignore logic for `antigravity` and `language_server` directly into the `ProcessSensor` class. Hardcoding local IDE tools into a published security tool is a massive red flag.
* **The Fix**: Introduced `ignores.yaml`. The sensor now accepts an `ignores_config` dictionary injected at runtime.
* **How it works**: `main.py` parses a new `--ignores` argument, loads the YAML file, and passes it to the sensor. Users can now define their own noise-reduction rules.

## 3. Mitigation Safety (`SIGSTOP` over `SIGKILL`)
* **The Problem**: Because the sensor relies on polling `psutil` every 0.5s, there is a 500ms blind spot. If an attacker's process exits and the OS recycles that Process ID (PID) to a legitimate system service, issuing a `SIGKILL` would corrupt the host machine.
* **The Fix**: 
  * Changed the default `--contain` action in the CLI to `stop` (which issues `SIGSTOP`).
  * Added a prominent `logger.warning` in the mitigation engine whenever `kill` is used, alerting the user to the race condition danger of PID recycling. Freezing a process is safe and reversible; blinding killing based on a 500ms old PID is not.

## 4. Integration Testing
* **The Problem**: The test suite had 35 passing tests, but overall coverage was ~53%, and the sensor had 23% coverage. The tests only validated that the Sigma YAML parser worked, not that the sensor could actually detect anything.
* **The Fix**: Added `tests/integration/test_sensor_integration.py`. This test actually spawns a malicious subprocess (`python3 -c "open('/etc/hosts')"`), binds to the sensor, and mathematically proves that the `psutil` engine can detect the execution (while documenting the inherent race condition flaws of missing the file read).

## Next Steps (v0.3.0)
The absolute highest priority is completely removing `psutil` from `sensor/__init__.py`. We will replace it with an event-driven `auditd` tailer or a Python Netlink Connector. Only then can we guarantee 100% visibility into short-lived process executions.
