#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import urllib.request


def main():
    print("[*] Running V7 E2E Test Suite...")
    test_log = "test_v7_alerts.log"
    test_db = "test_v7.db"
    for f in [test_log, test_db]:
        if os.path.exists(f):
            os.remove(f)

    # 1. Start Spectre monitor with --api
    print("[*] Spawning Spectre monitor process with REST API...")
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
            "--api",
            "--api-port",
            "8001",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(3)  # Wait for uvicorn to start

    # 2. Check health endpoint
    print("[*] Checking API /api/health...")
    try:
        req = urllib.request.urlopen("http://localhost:8001/api/health")
        health_data = json.loads(req.read().decode())
        print(f"    Health: {health_data['status']} (v{health_data['version']})")
        api_healthy = health_data["status"] == "ok"
    except Exception as e:
        print(f"[FAIL] Failed to contact health API: {e}")
        api_healthy = False

    # 3. Trigger simulation to generate events
    print("[*] Spawning trigger simulation to generate events...")
    sim_proc = subprocess.Popen(
        [sys.executable, "tests/v5/trigger_simulation.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sim_proc.communicate(timeout=15)
    time.sleep(3)

    # 4. Check API endpoints for data
    print("[*] Checking API endpoints for data...")
    try:
        req = urllib.request.urlopen("http://localhost:8001/api/events")
        events_data = json.loads(req.read().decode())
        has_events = events_data["count"] > 0
        print(f"    Events count: {events_data['count']}")

        req = urllib.request.urlopen("http://localhost:8001/api/stats")
        stats_data = json.loads(req.read().decode())
        stats_valid = stats_data["total_events"] > 0
        print(f"    Stats: {stats_data}")

    except Exception as e:
        print(f"[FAIL] Failed to fetch data from API: {e}")
        has_events = False
        stats_valid = False

    # 5. Stop monitor
    print("[*] Stopping Spectre monitor process...")
    spectre_proc.terminate()
    try:
        spectre_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        spectre_proc.kill()

    # Report
    print()
    print("=" * 40)
    print("V7 VERIFICATION REPORT:")
    print(f"  - API Health Check:        {'[PASS]' if api_healthy else '[FAIL]'}")
    print(f"  - API Events Fetch:        {'[PASS]' if has_events else '[FAIL]'}")
    print(f"  - API Stats Fetch:         {'[PASS]' if stats_valid else '[FAIL]'}")
    print("=" * 40)

    all_pass = api_healthy and has_events and stats_valid

    if all_pass:
        print("\n[SUCCESS] V7 E2E Test Suite Passed successfully.")
        for f in [test_log, test_db]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)
    else:
        print("\n[FAIL] V7 E2E Test Suite Failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
