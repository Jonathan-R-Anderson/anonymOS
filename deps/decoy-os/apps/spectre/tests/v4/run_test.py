#!/usr/bin/env python3
import os
import subprocess
import sys
import time


def main():
    print("[*] Running V4 E2E Test Suite...")
    test_log = "test_v4_alerts.log"
    if os.path.exists(test_log):
        os.remove(test_log)

    # 1. Start the Spectre monitor in the background
    monitor_cmd = [
        "./venv/bin/python",
        "main.py",
        "--interval",
        "0.1",
        "--threshold",
        "20",
        "--log-file",
        test_log,
    ]
    print("[*] Spawning Spectre monitor process...")
    monitor_proc = subprocess.Popen(
        monitor_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Wait for the monitor to initialize
    time.sleep(2)

    # 2. Run the simulation script to trigger behaviors
    print("[*] Spawning trigger simulation...")
    sys.stdout.flush()
    try:
        subprocess.run(
            ["./venv/bin/python", "tests/v4/trigger_simulation.py"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] Simulation script failed: {e}")
        monitor_proc.terminate()
        sys.exit(1)

    # Allow time for telemetry to process
    time.sleep(2)

    # 3. Stop the monitor process cleanly (SIGINT/SIGTERM)
    print("[*] Stopping Spectre monitor process...")
    monitor_proc.terminate()
    try:
        monitor_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        monitor_proc.kill()

    # 4. Assert and parse the log file
    print("[*] Validating logs in test_v4_alerts.log...")
    if not os.path.exists(test_log):
        print(f"[FAIL] Alert log file {test_log} was not created.")
        sys.exit(1)

    with open(test_log) as f:
        log_content = f.read()

    # We expect warning entries for both actions
    has_hosts_warn = "triggered rule 'Python Accessing Hosts Configuration'" in log_content and (
        "[WARNING] Process 'python3'" in log_content or "[WARNING] Process 'python'" in log_content
    )
    has_conn_warn = "triggered rule 'Python Outbound Socket Connection'" in log_content and (
        "[WARNING] Process 'python3'" in log_content or "[WARNING] Process 'python'" in log_content
    )

    # We expect a high severity threshold breach alert
    has_high_severity_alert = (
        "Process Session Exceeded Threat Threshold" in log_content and "Score: 26" in log_content
    )

    print("\n" + "=" * 40)
    print("V4 VERIFICATION REPORT:")
    print(f"  - Event 1 (Hosts read warning):   {'[PASS]' if has_hosts_warn else '[FAIL]'}")
    print(f"  - Event 2 (Outbound DNS warning): {'[PASS]' if has_conn_warn else '[FAIL]'}")
    print(
        f"  - Threshold Breach Escalation:    {'[PASS]' if has_high_severity_alert else '[FAIL]'}",
    )
    print("=" * 40)

    if has_hosts_warn and has_conn_warn and has_high_severity_alert:
        print("\n[SUCCESS] V4 E2E Test Suite Passed successfully.")
        if os.path.exists(test_log):
            os.remove(test_log)
        sys.exit(0)
    else:
        print("\n[FAIL] V4 E2E Test Suite Failed. Log content:")
        print(log_content)
        if os.path.exists(test_log):
            os.remove(test_log)
        sys.exit(1)


if __name__ == "__main__":
    main()
