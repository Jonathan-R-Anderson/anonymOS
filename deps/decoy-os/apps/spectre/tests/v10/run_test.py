#!/usr/bin/env python3
import os
import subprocess
import sys
import time

import psutil


def main():
    print("[*] Running V10 E2E Test Suite...")
    test_log = "test_v10_alerts.log"
    test_db = "test_v10.db"
    for f in [test_log, test_db]:
        if os.path.exists(f):
            os.remove(f)

    # 1. Start Spectre monitor with --contain kill
    # Threshold 10, so a single /etc/hosts read (Score 15) triggers an alert + kill
    print("[*] Spawning Spectre monitor process with Active Containment (kill)...")
    spectre_proc = subprocess.Popen(
        [
            sys.executable,
            "main.py",
            "--interval",
            "0.1",
            "--log-file",
            test_log,
            "--db",
            test_db,
            "--contain",
            "kill",
            "--threshold",
            "10",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    # 2. Trigger simulation
    print("[*] Spawning trigger simulation...")
    sim_proc = subprocess.Popen(
        [sys.executable, "tests/v10/trigger_simulation.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sim_pid = sim_proc.pid

    # Wait for sensor to detect and contain
    time.sleep(4)

    # 3. Verify containment
    print(f"[*] Verifying containment of PID {sim_pid}...")
    try:
        proc = psutil.Process(sim_pid)
        is_running = proc.is_running()
        status = proc.status()
    except psutil.NoSuchProcess:
        is_running = False
        status = "terminated"

    print(f"    Simulation Process Running: {is_running}")
    if is_running:
        print(f"    Simulation Process Status: {status}")

    # 4. Stop monitor
    print("[*] Stopping Spectre monitor process...")
    spectre_proc.terminate()
    try:
        spectre_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        spectre_proc.kill()

    # Report
    print()
    print("=" * 40)
    print("V10 VERIFICATION REPORT:")
    print(
        f"  - Active Containment (Process Killed): {'[PASS]' if not is_running or status == 'zombie' else '[FAIL]'}",
    )
    print("=" * 40)

    if not is_running or status == "zombie":
        print("\n[SUCCESS] V10 E2E Test Suite Passed successfully.")
        for f in [test_log, test_db]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)
    else:
        print("\n[FAIL] V10 E2E Test Suite Failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
