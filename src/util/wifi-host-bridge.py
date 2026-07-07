#!/usr/bin/env python3
# wifi-host-bridge.py <unix-socket-path>
#
# HOST side of the EpinAnonymOS WiFi bridge.  QEMU (launched by qemu-run.sh WIFI=1)
# exposes the guest's COM2 as a listening UNIX socket; this process connects to it
# and shuttles REAL WiFi state between the host's NetworkManager and the guest:
#
#   host  -> guest : the live `nmcli dev wifi list` formatted as the guest's
#                    /run/wifi/networks file, terminated by a form-feed (0x0C).
#   guest -> host  : "CONNECT\t<SSID>\t<PSK>\n" lines (the desktop Wi-Fi menu's
#                    selection) -> a real `nmcli dev wifi connect`.
#
# So the guest desktop shows the real nearby networks with real signal strengths,
# and picking one actually connects the host's WiFi card (which the guest then
# reaches the internet through via QEMU slirp when run with NET=1).

import os
import socket
import subprocess
import sys
import threading
import time

SOCK = sys.argv[1] if len(sys.argv) > 1 else "wifibr.sock"


def split_nmcli(line):
    """nmcli -t escapes field-internal ':' as '\\:' — split on the unescaped ones."""
    out, cur, i = [], "", 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur += line[i + 1]; i += 2; continue
        if c == ":":
            out.append(cur); cur = ""; i += 1; continue
        cur += c; i += 1
    out.append(cur)
    return out


def sec_label(sec):
    s = sec.lower()
    if "wpa3" in s or "wpa2" in s or "rsn" in s:
        return "wpa2"
    if "wpa" in s:
        return "wpa"
    if "wep" in s:
        return "wep"
    return "open"


def scan_body():
    """Return the guest /run/wifi/networks content from the host's cached scan.

    `--rescan no` returns the current scan list instantly; forcing a rescan on every
    call queues multi-second rescans that time out.  A separate low-rate rescanner
    (rescan_loop) keeps the cache fresh."""
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no"],
            text=True, timeout=8)
    except Exception as e:
        sys.stderr.write("[wifi-bridge] nmcli list failed: %s\n" % e)
        out = ""

    best = {}          # ssid -> (signal, security, active)
    any_active = 0
    for ln in out.splitlines():
        p = split_nmcli(ln)
        if len(p) < 4:
            continue
        inuse, ssid, signal, sec = p[0], p[1], p[2], p[3]
        if not ssid:
            continue   # hidden network
        active = 1 if inuse.strip() == "*" else 0
        any_active |= active
        try:
            sig = int(signal)
        except ValueError:
            sig = 0
        secl = sec_label(sec)
        prev = best.get(ssid)
        if prev is None or sig > prev[0] or active:
            keep_active = active or (prev[2] if prev else 0)
            best[ssid] = (max(sig, prev[0]) if prev else sig, secl, keep_active)

    # Stable ordering so rows don't jump under the cursor as signal levels jitter:
    # the connected network is pinned first, then by signal bucketed to the nearest
    # 25% (the 4-bar glyph the guest draws) and finally alphabetically as a tiebreak.
    def sort_key(kv):
        ssid, (sig, secl, active) = kv
        bars = min(4, sig // 25)          # 0..4, matches the guest's bar glyph
        return (0 if active else 1, -bars, ssid.lower())

    rows = []
    for ssid, (sig, secl, active) in sorted(best.items(), key=sort_key):
        s = ssid.replace("\t", " ").replace("\n", " ")
        rows.append("%s\t%d\t%s\t%d\t/host/%s" % (s, sig, secl, active, s))

    state = 100 if any_active else 30
    body = "#dev\t/host\twlan0\t%d\n" % state
    if rows:
        body += "\n".join(rows) + "\n"
    return body


def do_connect(ssid, psk):
    cmd = ["nmcli", "dev", "wifi", "connect", ssid]
    if psk:
        cmd += ["password", psk]
    sys.stderr.write("[wifi-bridge] connecting to '%s'%s\n" % (ssid, " (with psk)" if psk else ""))
    if os.environ.get("HOS_WIFI_DRYRUN"):
        sys.stderr.write("[wifi-bridge] DRYRUN — would run: %s\n" % " ".join(cmd))
        return
    try:
        r = subprocess.run(cmd, timeout=45, capture_output=True, text=True)
        sys.stderr.write("[wifi-bridge] nmcli connect rc=%d %s%s\n"
                         % (r.returncode, r.stdout.strip(), r.stderr.strip()))
    except Exception as e:
        sys.stderr.write("[wifi-bridge] connect failed: %s\n" % e)


def rescan_loop(stop):
    """Ask NM to refresh its scan cache every ~20s (best-effort, non-blocking)."""
    while not stop.is_set():
        try:
            subprocess.run(["nmcli", "dev", "wifi", "rescan"], timeout=20,
                           capture_output=True)
        except Exception:
            pass
        stop.wait(20.0)


def sender(conn, stop):
    while not stop.is_set():
        body = scan_body()
        try:
            conn.sendall(body.encode() + b"\x0c")   # form-feed frames the file
        except Exception:
            return
        stop.wait(3.0)


def receiver(conn, stop):
    buf = b""
    conn.settimeout(1.0)
    while not stop.is_set():
        try:
            data = conn.recv(4096)
        except socket.timeout:
            continue
        except Exception:
            return
        if data == b"":
            return
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            s = line.decode(errors="replace")
            if s.startswith("CONNECT\t"):
                f = s.split("\t")
                ssid = f[1] if len(f) > 1 else ""
                psk = f[2] if len(f) > 2 else ""
                if ssid:
                    threading.Thread(target=do_connect, args=(ssid, psk), daemon=True).start()


def serve(conn):
    stop = threading.Event()
    t1 = threading.Thread(target=sender, args=(conn, stop), daemon=True)
    t2 = threading.Thread(target=receiver, args=(conn, stop), daemon=True)
    t3 = threading.Thread(target=rescan_loop, args=(stop,), daemon=True)
    t1.start(); t2.start(); t3.start()
    t2.join()          # receiver returns on disconnect
    stop.set()
    t1.join(timeout=2)


def main():
    sys.stderr.write("[wifi-bridge] waiting for guest COM2 socket %s\n" % SOCK)
    while True:
        try:
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(SOCK)
        except Exception:
            time.sleep(0.5); continue
        sys.stderr.write("[wifi-bridge] connected to guest\n")
        try:
            serve(c)
        except Exception as e:
            sys.stderr.write("[wifi-bridge] session error: %s\n" % e)
        finally:
            try: c.close()
            except Exception: pass
        time.sleep(1.0)


if __name__ == "__main__":
    main()
