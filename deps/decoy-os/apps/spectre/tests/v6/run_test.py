#!/usr/bin/env python3
import os
import sqlite3
import subprocess
import sys
import time


def main():
    print("[*] Running V6 E2E Test Suite...")
    test_log = "test_v6_alerts.log"
    test_db = "test_v6.db"
    for f in [test_log, test_db]:
        if os.path.exists(f):
            os.remove(f)

    # 1. Start Spectre monitor
    print("[*] Spawning Spectre monitor process...")
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
            "--threshold",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    # 2. Trigger simulation (reuse V5 trigger)
    print("[*] Spawning trigger simulation...")
    sim_proc = subprocess.Popen(
        [sys.executable, "tests/v5/trigger_simulation.py"],
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

    # 4. Validate SQLite database
    print(f"[*] Validating SQLite database {test_db}...")
    if not os.path.exists(test_db):
        print("[FAIL] Database file not created!")
        sys.exit(1)

    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    event_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    alert_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM sessions")
    session_count = cursor.fetchone()[0]

    # Check MITRE metadata in events
    cursor.execute("SELECT mitre FROM events WHERE mitre != '' LIMIT 1")
    mitre_row = cursor.fetchone()
    has_mitre_in_db = mitre_row is not None and "T10" in mitre_row[0]

    conn.close()

    has_events = event_count >= 2
    has_alerts = alert_count >= 1
    has_sessions = session_count >= 1

    print()
    print("=" * 40)
    print("V6 VERIFICATION REPORT:")
    print(f"  - Events in DB ({event_count}):           {'[PASS]' if has_events else '[FAIL]'}")
    print(f"  - Alerts in DB ({alert_count}):            {'[PASS]' if has_alerts else '[FAIL]'}")
    print(f"  - Sessions in DB ({session_count}):         {'[PASS]' if has_sessions else '[FAIL]'}")
    print(f"  - MITRE metadata in events:     {'[PASS]' if has_mitre_in_db else '[FAIL]'}")
    print("=" * 40)

    all_pass = has_events and has_alerts and has_sessions and has_mitre_in_db

    if all_pass:
        print("\n[SUCCESS] V6 E2E Test Suite Passed successfully.")
        for f in [test_log, test_db]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)
    else:
        print("\n[FAIL] V6 E2E Test Suite Failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
