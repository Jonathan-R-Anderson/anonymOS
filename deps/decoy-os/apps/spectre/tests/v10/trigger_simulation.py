import sys
import time


def main():
    print("[*] Starting V10 validation trigger simulation...")
    sys.stdout.flush()

    try:
        f1 = open("/etc/hosts")
        f1.read()
        print("[*] Sleeping to keep file open so sensor can catch it...")
        sys.stdout.flush()
        time.sleep(2)
        f1.close()
    except:
        pass

    print("[*] Sleeping to keep process alive so it can be contained...")
    sys.stdout.flush()

    try:
        # Loop to wait for SIGSTOP/SIGKILL
        for _ in range(30):
            time.sleep(1)
            print("    [sim] Still alive...")
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
