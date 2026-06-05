#!/usr/bin/env python3
"""GUI roadmap G4 helper: type a command into the guest over QMP.

Waits for the terminal to spawn its shell, then types a command via QEMU
input-send-event (PS/2 keyboard) and checks the terminal's serial mirror for the
command output.  Used by scripts/qemu-g4-verify.sh.
"""
import json
import socket
import sys
import time

# char -> QEMU qcode (US layout, unshifted only — keep the test command lowercase)
QCODE = {
    'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd', 'e': 'e', 'f': 'f', 'g': 'g',
    'h': 'h', 'i': 'i', 'j': 'j', 'k': 'k', 'l': 'l', 'm': 'm', 'n': 'n',
    'o': 'o', 'p': 'p', 'q': 'q', 'r': 'r', 's': 's', 't': 't', 'u': 'u',
    'v': 'v', 'w': 'w', 'x': 'x', 'y': 'y', 'z': 'z',
    '0': '0', '1': '1', '2': '2', '3': '3', '4': '4', '5': '5',
    '6': '6', '7': '7', '8': '8', '9': '9',
    ' ': 'spc', '\n': 'ret', '-': 'minus', '.': 'dot', '/': 'slash',
}


def connect_qmp(path, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            return s
        except OSError:
            time.sleep(1)
    raise SystemExit(f"could not connect to QMP at {path}")


class QMP:
    def __init__(self, path):
        self.s = connect_qmp(path)
        self.f = self.s.makefile("rw")
        self._read()
        self.cmd("qmp_capabilities")

    def _read(self):
        return json.loads(self.f.readline())

    def cmd(self, execute, **args):
        msg = {"execute": execute}
        if args:
            msg["arguments"] = args
        self.f.write(json.dumps(msg) + "\n")
        self.f.flush()
        while True:
            r = self._read()
            if "error" in r:
                print(f"[g4] QMP error: {r['error']}", flush=True)
                return r
            if "return" in r:
                return r

    def rel(self, axis, value):
        self.cmd("input-send-event",
                 events=[{"type": "rel", "data": {"axis": axis, "value": value}}])

    def btn(self, button, down):
        self.cmd("input-send-event",
                 events=[{"type": "btn", "data": {"button": button, "down": down}}])

    def focus_window(self):
        # Pin the cursor to the top-left corner, then walk into the terminal
        # window (mapped near 20,20) and click to give it keyboard focus.
        for _ in range(40):
            self.rel("x", -40); self.rel("y", -40); time.sleep(0.02)
        time.sleep(0.2)
        for _ in range(15):
            self.rel("x", 9); self.rel("y", 9); time.sleep(0.04)
        time.sleep(0.3)
        self.btn("left", True); time.sleep(0.15); self.btn("left", False)
        time.sleep(0.5)

    def key(self, qcode, down):
        self.cmd("input-send-event",
                 events=[{"type": "key",
                          "data": {"down": down,
                                   "key": {"type": "qcode", "data": qcode}}}])

    def type_str(self, s):
        for ch in s:
            qc = QCODE.get(ch)
            if not qc:
                continue
            self.key(qc, True)
            time.sleep(0.03)
            self.key(qc, False)
            time.sleep(0.05)


def wait_for(serial_path, marker, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(serial_path, "rb") as fh:
                if marker.encode() in fh.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(2)
    return False


def main():
    qmp_path, serial_path = sys.argv[1], sys.argv[2]
    qmp = QMP(qmp_path)
    print("[g4] QMP connected, waiting for shell spawn...", flush=True)

    if not wait_for(serial_path, "G4 SHELL", timeout=420):
        print("[g4] terminal never spawned its shell", flush=True)
        return 2
    print("[g4] shell spawned; waiting for terminal window to map...", flush=True)
    if not wait_for(serial_path, "G4 COMMIT", timeout=300):
        print("[g4] terminal window never mapped", flush=True)
        return 2
    # let the shell's banner/prompt drain into the terminal
    time.sleep(5)

    print("[g4] clicking terminal to focus it", flush=True)
    qmp.focus_window()
    if wait_for(serial_path, "G4 FOCUS", timeout=10):
        print("[g4] terminal has keyboard focus", flush=True)

    print("[g4] typing: echo g4pass", flush=True)
    qmp.type_str("echo g4pass\n")

    ok = wait_for(serial_path, "G4OUT: g4pass", timeout=40)
    print(f"[g4] typed command output observed: {ok}", flush=True)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
