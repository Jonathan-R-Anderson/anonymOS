#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import urllib.request


def main():
    print("[*] Running V8 E2E Test Suite...")
    test_log = "test_v8_alerts.log"
    test_db = "test_v8.db"
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
            "8002",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(3)  # Wait for uvicorn to start

    # 2. Check dashboard root endpoint
    print("[*] Checking Dashboard at http://localhost:8002/ ...")
    try:
        req = urllib.request.urlopen("http://localhost:8002/")
        html_content = req.read().decode()

        has_title = "<title>Spectre HIDS Dashboard</title>" in html_content
        has_js_api = "const API_BASE = '/api';" in html_content
        is_html = req.headers.get_content_type() == "text/html"

    except Exception as e:
        print(f"[FAIL] Failed to fetch dashboard: {e}")
        has_title = False
        has_js_api = False
        is_html = False

    # 3. Stop monitor
    print("[*] Stopping Spectre monitor process...")
    spectre_proc.terminate()
    try:
        spectre_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        spectre_proc.kill()

    # Report
    print()
    print("=" * 40)
    print("V8 VERIFICATION REPORT:")
    print(f"  - Content-Type is HTML:    {'[PASS]' if is_html else '[FAIL]'}")
    print(f"  - Contains correct Title:  {'[PASS]' if has_title else '[FAIL]'}")
    print(f"  - Contains API JS logic:   {'[PASS]' if has_js_api else '[FAIL]'}")
    print("=" * 40)

    all_pass = is_html and has_title and has_js_api

    if all_pass:
        print("\n[SUCCESS] V8 E2E Test Suite Passed successfully.")
        for f in [test_log, test_db]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)
    else:
        print("\n[FAIL] V8 E2E Test Suite Failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
