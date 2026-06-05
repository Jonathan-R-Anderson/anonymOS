#!/usr/bin/env python3
"""GUI roadmap G3 helper: drive the guest PS/2 mouse over QMP.

Waits for the G2 client window to map (serial marker), then injects relative
pointer motion to walk the cursor into the window and a left-button click, using
QEMU's input-send-event.  Used by scripts/qemu-g3-verify.sh.
"""
import json
import os
import socket
import sys
import time


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
        self._read()                       # greeting
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
                print(f"[g3] QMP error for {execute}: {r['error']}", flush=True)
                return r
            if "return" in r:
                return r

    def send_events(self, events):
        self.cmd("input-send-event", events=events)


def rel(axis, value):
    return {"type": "rel", "data": {"axis": axis, "value": value}}


def btn(button, down):
    return {"type": "btn", "data": {"button": button, "down": down}}


def wait_for_marker(serial_path, marker, timeout):
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
    print("[g3] QMP connected, waiting for window map...", flush=True)

    if not wait_for_marker(serial_path, "Map request", timeout=400):
        print("[g3] window never mapped within timeout", flush=True)
        # still try injecting; the pointer device should exist regardless

    print("[g3] injecting pointer motion + click", flush=True)
    # Hyprland clamps the pointer to the monitor, so first pin it to the
    # top-left corner with a large negative sweep, then walk into the window
    # interior (mapped at [20,20], size 600x360 -> aim for ~300,200).
    for _ in range(40):
        qmp.send_events([rel("x", -40), rel("y", -40)])
        time.sleep(0.03)

    time.sleep(0.3)
    for _ in range(30):
        qmp.send_events([rel("x", 10), rel("y", 7)])
        time.sleep(0.05)

    time.sleep(0.5)
    qmp.send_events([btn("left", True)])
    time.sleep(0.2)
    qmp.send_events([btn("left", False)])
    print("[g3] click injected; waiting for delivery...", flush=True)

    ok = wait_for_marker(serial_path, "G3 CLICK", timeout=30)
    print(f"[g3] click delivered to surface: {ok}", flush=True)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
