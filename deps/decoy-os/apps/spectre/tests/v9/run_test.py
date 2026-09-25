#!/usr/bin/env python3
import os
import subprocess
import sys
import time


def main():
    print("[*] Running V9 E2E Test Suite...")
    test_log = "test_v9_alerts.log"
    test_db = "test_v9.db"
    for f in [test_log, test_db]:
        if os.path.exists(f):
            os.remove(f)

    # 1. Start Spectre monitor with --yara-rules
    print("[*] Spawning Spectre monitor process with YARA scanning...")
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
            "--yara-rules",
            "yara_rules",
            "--threshold",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    # 2. Trigger simulation
    print("[*] Spawning trigger simulation...")
    sim_proc = subprocess.Popen(
        [sys.executable, "tests/v9/trigger_simulation.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sim_stdout, _ = sim_proc.communicate(timeout=15)
    print(sim_stdout.decode())
    time.sleep(3)

    # 3. Stop monitor
    print("[*] Stopping Spectre monitor process...")
    spectre_proc.terminate()
    try:
        spectre_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        spectre_proc.kill()

    # 4. Validate logs for YARA match
    print(f"[*] Validating logs in {test_log}...")
    if not os.path.exists(test_log):
        print("[FAIL] Log file not created!")
        sys.exit(1)

    with open(test_log) as f:
        log_content = f.read()

    has_yara_match = "matched YARA ['SuspiciousShellScript']" in log_content
    has_sha256 = "SHA256" in log_content

    # Report
    print()
    print("=" * 40)
    print("V9 VERIFICATION REPORT:")
    print(f"  - YARA rule matched:         {'[PASS]' if has_yara_match else '[FAIL]'}")
    print(f"  - SHA256 hash in alert:      {'[PASS]' if has_sha256 else '[FAIL]'}")
    print("=" * 40)

    if not has_yara_match:
        print()
        print("[DEBUG] Log file contents:")
        print(log_content)

    all_pass = has_yara_match and has_sha256

    if all_pass:
        print("\n[SUCCESS] V9 E2E Test Suite Passed successfully.")
        for f in [test_log, test_db]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)
    else:
        print("\n[FAIL] V9 E2E Test Suite Failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
