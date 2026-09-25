#!/usr/bin/env python3
import os
import subprocess
import sys
import time


def main():
    print("[*] Running V5 E2E Test Suite...")
    test_log = "test_v5_alerts.log"
    if os.path.exists(test_log):
        os.remove(test_log)

    # 1. Start Spectre monitor in the background
    print("[*] Spawning Spectre monitor process...")
    spectre_proc = subprocess.Popen(
        [
            sys.executable,
            "main.py",
            "--interval",
            "0.1",
            "--log-file",
            test_log,
            "--threshold",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    # 2. Trigger the simulation
    print("[*] Spawning trigger simulation...")
    sim_proc = subprocess.Popen(
        [sys.executable, "tests/v5/trigger_simulation.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sim_stdout, _ = sim_proc.communicate(timeout=15)
    print(sim_stdout.decode())

    # 3. Wait for sensor polling to capture events
    time.sleep(3)

    # 4. Stop Spectre monitor
    print("[*] Stopping Spectre monitor process...")
    spectre_proc.terminate()
    try:
        spectre_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        spectre_proc.kill()

    # 5. Validate log output
    print(f"[*] Validating logs in {test_log}...")
    if not os.path.exists(test_log):
        print("[FAIL] Log file not created!")
        sys.exit(1)

    with open(test_log) as f:
        log_content = f.read()

    # Check for MITRE ATT&CK metadata in warnings
    has_hosts_warn = "triggered rule 'Python Accessing Hosts Configuration'" in log_content and (
        "T1016" in log_content
    )
    has_conn_warn = "triggered rule 'Python Outbound Socket Connection'" in log_content and (
        "T1071" in log_content or "T1041" in log_content
    )
    has_threshold = "Exceeded Threat Threshold" in log_content or "ALERT" in log_content

    # Report
    print()
    print("=" * 40)
    print("V5 VERIFICATION REPORT:")
    print(f"  - Hosts read + MITRE T1016:        {'[PASS]' if has_hosts_warn else '[FAIL]'}")
    print(f"  - Outbound conn + MITRE T1071:     {'[PASS]' if has_conn_warn else '[FAIL]'}")
    print(f"  - Threshold Breach Escalation:     {'[PASS]' if has_threshold else '[FAIL]'}")
    print("=" * 40)

    if not has_hosts_warn or not has_conn_warn:
        print()
        print("[DEBUG] Log file contents:")
        print(log_content)

    if has_hosts_warn and has_conn_warn and has_threshold:
        print("\n[SUCCESS] V5 E2E Test Suite Passed successfully.")
        # Cleanup
        if os.path.exists(test_log):
            os.remove(test_log)
        sys.exit(0)
    else:
        print("\n[FAIL] V5 E2E Test Suite Failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
