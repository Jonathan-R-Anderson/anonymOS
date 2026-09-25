import socket
import sys
import time


def main():
    print("[*] Starting V4 validation trigger simulation...")
    sys.stdout.flush()

    # 1. Read /etc/hosts (Expected rule match: python_hosts_read, Score: 12)
    print("[*] Simulating Event 1: Reading /etc/hosts...")
    sys.stdout.flush()
    try:
        f = open("/etc/hosts")
        f.read()
        time.sleep(2)
        f.close()
    except Exception as e:
        print(f"[!] Failed to read /etc/hosts: {e}")

    # 2. Open socket connection (Expected rule match: python_outbound_dns, Score: 14)
    # Total accumulated score will be 12 + 14 = 26, crossing threshold 20!
    print("[*] Simulating Event 2: Outbound network connection to 8.8.8.8:53...")
    sys.stdout.flush()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 53))
        time.sleep(2)
        s.close()
    except Exception as e:
        print(f"[*] Connect attempt complete: {e}")
        sys.stdout.flush()

    print("[*] Simulation complete.")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
