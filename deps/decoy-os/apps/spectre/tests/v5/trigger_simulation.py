import socket
import sys
import time


def main():
    print("[*] Starting V5 validation trigger simulation...")
    sys.stdout.flush()

    # 1. Read /etc/hosts (Expected rule match: python_hosts_read, Score: 12)
    # MITRE: T1016 (Discovery)
    print("[*] Simulating Event 1: Reading /etc/hosts...")
    sys.stdout.flush()
    try:
        f = open("/etc/hosts")
        f.read()
        time.sleep(2)
        f.close()
    except Exception as e:
        print(f"[!] Failed to read /etc/hosts: {e}")

    # 2. Outbound network connection (Expected rule match: python_outbound_dns, Score: 14)
    # MITRE: T1071 (Command and Control), T1041 (Exfiltration)
    print("[*] Simulating Event 2: Outbound network connection to 8.8.8.8:53...")
    sys.stdout.flush()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("8.8.8.8", 53))
        time.sleep(2)
        s.close()
    except Exception as e:
        print(f"[!] Failed outbound connect: {e}")

    print("[*] Simulation complete.")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
