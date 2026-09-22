#!/usr/bin/env python3
"""Boot an INSTALLED encrypted disk under real UEFI firmware (OVMF), type a password at the
pre-boot prompt (QMP keystrokes, exactly as a person would), and assert what boots.

This is the end-to-end proof for INSTALLER.md §E6: the disk image is one the in-OS installer
wrote (Full disk or Hidden OS), booted through the disk's OWN ESP (the production preboot.efi,
no proof markers), so a passing run means the shipped chain works: firmware -> preboot prompt
-> password -> VeraCrypt header -> XTS decrypt off the raw disk -> Limine -> EpinAnonymOS
(or the Alpine decoy, or nothing).

  usage: scripts/encrypted-boot-test.py <disk.img> <password> <EPIN|DECOY|REJECT> [timeout-s]

  EPIN    expect EpinAnonymOS to boot: "[dkernel] EpinAnonymOS D kernel starting" and the
          "[fde] key module accepted" line (the object store is encrypted), then a present.
  DECOY   expect the Alpine decoy: a Linux banner + "DECOY-INIT-OK" / a getty on ttyS0.
  REJECT  expect "Incorrect passphrase." and NO kernel of either kind.

The production loader prints "Enter passphrase: " to COM1 as well as the screen, so the prompt
is waited for on serial.  Exit 0 = all assertions held, 1 = an assertion failed, 2 = setup.
"""
import json, os, signal, socket, subprocess, sys, time

if len(sys.argv) < 4:
    print(__doc__); sys.exit(2)
disk, pw, want = sys.argv[1], sys.argv[2], sys.argv[3].upper()
timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 240
if want not in ("EPIN", "DECOY", "REJECT"):
    print("want must be EPIN | DECOY | REJECT"); sys.exit(2)
if not os.path.exists(disk):
    print("no such disk image:", disk); sys.exit(2)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
OUT = os.path.join(ROOT, "build")
os.makedirs(OUT, exist_ok=True)
varsfd = os.path.join(OUT, "OVMF_VARS_encboot.fd")
sock_path = os.path.join(OUT, "qmp-encboot.sock")
log = os.path.join(OUT, "serial-encboot-%s.log" % want.lower())
for p in (sock_path, log):
    try: os.remove(p)
    except FileNotFoundError: pass
subprocess.run(["cp", OVMF_VARS, varsfd], check=True)

QEMU = os.environ.get("QEMU_BIN", os.path.expanduser("~/.local/qemu-virgl/bin/qemu-system-x86_64"))
if not os.access(QEMU, os.X_OK):
    QEMU = "qemu-system-x86_64"
MEM = os.environ.get("MEM", "4096")
# Same machine shape as qemu-run.sh: AHCI data disk (the kernel's disk driver), std VGA for the
# framebuffer, qemu64 without SMAP/SMEP.  The installed system needs ~4 GiB: the loader decrypts
# the 512 MiB boot volume into RAM and Limine then loads kernel + modules from it.
argv = [QEMU, "-enable-kvm", "-cpu", "qemu64,-smap,-smep", "-m", MEM, "-smp", "1",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + OVMF_CODE,
        "-drive", "if=pflash,format=raw,file=" + varsfd,
        "-drive", "file=%s,if=none,id=hosdisk,format=raw" % disk,
        "-device", "ahci,id=ahci0", "-device", "ide-hd,drive=hosdisk,bus=ahci0.0",
        "-vga", "std", "-display", "none", "-no-reboot",
        "-serial", "file:" + log,
        "-qmp", "unix:%s,server,nowait" % sock_path]
qemu = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

import re
def readlog():
    try: return open(log, 'rb').read().replace(b'\0', b'').decode('latin1')
    except FileNotFoundError: return ""
# The production loader echoes its prompt to the screen (ConOut) as well as COM1, and OVMF routes
# ConOut to the serial port too, so loader text arrives with every character doubled
# ("EEnntteerr  ppaasssspphhrraassee::").  Kernel klog lines go straight to the UART and are single.
# Match loader strings with each character allowed once or twice.
def loader_pat(text):
    return re.compile("".join(re.escape(c) + "{1,2}" for c in text))
def seen(text, lg):
    return text in lg or loader_pat(text).search(lg) is not None
def wait_for(text, t):
    t0 = time.time()
    while time.time() - t0 < t:
        if seen(text, readlog()): return True
        if qemu.poll() is not None: return seen(text, readlog())
        time.sleep(0.5)
    return False

rc = 1
try:
    # Connect + greeting + capabilities as one retried unit: a connect that lands while QEMU is
    # still binding the listener (server=on,nowait) can succeed and then fail the first read with
    # EINVAL, which used to abort the whole test.
    f = None
    for _ in range(120):
        try:
            s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sock_path)
            f = s.makefile('rwb', buffering=0)
            if not f.readline(): raise OSError("empty greeting")
            f.write(b'{"execute":"qmp_capabilities"}\n')
            if not f.readline(): raise OSError("no capabilities reply")
            s.settimeout(None)
            break
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            f = None
            try: s.close()
            except Exception: pass
            time.sleep(0.5)
    if f is None:
        print("FAIL: QMP never came up"); sys.exit(2)
    if not wait_for("Enter passphrase:", 60):
        print("FAIL: never saw the pre-boot prompt on serial (is this an encrypted install?)")
        print(readlog()[-2000:]); sys.exit(1)
    time.sleep(1)
    def key(q):
        f.write(json.dumps({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": q}]}}).encode() + b'\n')
        f.readline(); time.sleep(0.12)
    qmap = {'-': 'minus', '.': 'dot', '_': 'shift_underscore', ' ': 'spc'}
    for ch in pw:
        key(qmap.get(ch, ch))
    key("ret")

    checks = []
    if want == "EPIN":
        checks.append(("EpinAnonymOS kernel started off the decrypted volume",
                       wait_for("[dkernel] EpinAnonymOS D kernel starting", timeout)))
        checks.append(("kernel accepted the FDE key module ([fde] key module accepted)",
                       wait_for("[fde] key module accepted", 60)))
        checks.append(("installed-system boot (no install payload present)",
                       wait_for("[live] installed system:", 60)))
        checks.append(("desktop presented on the encrypted install",
                       wait_for("[present] total=", timeout)))
        lg = readlog()
        checks.append(("no plaintext-store fallback ([objstore] must not use the free tail)",
                       "store in the free tail" not in lg))
        checks.append(("no OBJECT TABLE EXHAUSTED", "[objmgr] OBJECT TABLE EXHAUSTED" not in lg))
    elif want == "DECOY":
        checks.append(("Alpine decoy kernel booted", wait_for("Linux version", timeout)))
        ok_init = wait_for("DECOY-INIT-OK", timeout) or wait_for("login:", 30) or wait_for("Welcome to Alpine", 30)
        checks.append(("decoy reached userspace", ok_init))
        lg = readlog()
        checks.append(("EpinAnonymOS did NOT boot on the decoy password",
                       "[dkernel] EpinAnonymOS D kernel starting" not in lg))
    else:
        checks.append(("wrong password was refused", wait_for("Incorrect passphrase.", 90)))
        time.sleep(5)
        lg = readlog()
        checks.append(("nothing booted on REJECT",
                       "[dkernel]" not in lg and "Linux version" not in lg))
    for name, c in checks:
        print("  [%s] %s" % ("PASS" if c else "FAIL", name))
    ok = all(c for _, c in checks)
    print("encrypted-boot-test (pw=%r want=%s): %s  (serial: %s)" % (pw, want, "PASS" if ok else "FAIL", log))
    rc = 0 if ok else 1
finally:
    try: qemu.send_signal(signal.SIGKILL)
    except Exception: pass
sys.exit(rc)
