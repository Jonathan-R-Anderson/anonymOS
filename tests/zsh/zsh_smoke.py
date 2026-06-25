#!/usr/bin/env python3
# Z12.2 — headless zsh smoke + regression harness for EpinAnonymOS.
#
# Boots hos.iso under qemu (headless, QMP-driven), opens a terminal via the Domain Manager,
# runs golden shell checks (version / builtin+pipe / completion / plugin / history / prompt),
# then switches the domain to the NATIVE shell and confirms the in-process object builtin works.
# Each check echoes a value-bearing marker (SMK...<value>) captured on the serial console; the
# harness strips ANSI escapes and asserts the marker is present. Exit 0 iff every check passes.
#
# Self-contained (vendors the minimal QMP key/mouse logic) so it has no scratch-file dependency.
# Usage:  python3 tests/zsh/zsh_smoke.py [path/to/hos.iso]
import socket, json, sys, time, os, re, subprocess, signal

ROOT   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ISO    = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "hos.iso")
DISK   = os.path.join(ROOT, "hos-disk-z.img")
SERIAL = os.path.join(ROOT, "serial-smoke.log")
SOCK   = os.path.join(ROOT, "qmp-smoke.sock")

# ---- QMP transport (vendored from scratch-qmp.py) -------------------------------------------
CH = {'[':'bracket_left',']':'bracket_right',' ':'spc','\n':'ret','-':'minus','/':'slash',
      '.':'dot',':':('shift','semicolon'),'_':('shift','minus'),'=':'equal','$':('shift','4'),
      ';':'semicolon',',':'comma','|':('shift','backslash'),'(':('shift','9'),')':('shift','0'),
      '<':('shift','comma'),'>':('shift','dot')}
for c in "abcdefghijklmnopqrstuvwxyz": CH[c] = c
for d in "0123456789": CH[d] = d
for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ": CH[c] = ('shift', c.lower())

def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK)
    f = s.makefile("rw"); f.readline()
    f.write(json.dumps({"execute":"qmp_capabilities"})+"\n"); f.flush(); f.readline()
    return s, f
def qmp(f, e, **a):
    m = {"execute": e}
    if a: m["arguments"] = a
    f.write(json.dumps(m)+"\n"); f.flush()
    while True:
        l = f.readline()
        if not l: return None
        o = json.loads(l)
        if "return" in o or "error" in o: return o
def keyev(f, q, d): qmp(f, "input-send-event", events=[{"type":"key","data":{"down":d,"key":{"type":"qcode","data":q}}}])
def keys(f, ks):
    for k in ks: keyev(f, k, True)
    time.sleep(0.03)
    for k in reversed(ks): keyev(f, k, False)
    time.sleep(0.02)
def rel(f, dx, dy):
    e = []
    if dx: e.append({"type":"rel","data":{"axis":"x","value":int(dx)}})
    if dy: e.append({"type":"rel","data":{"axis":"y","value":int(dy)}})
    if e: qmp(f, "input-send-event", events=e)
def click(f, x, y):
    for _ in range(80): rel(f, -12, -12)
    time.sleep(0.15); ax, ay = int(x), int(y)
    while ax > 0 or ay > 0:
        dx = min(ax,12); dy = min(ay,12); rel(f, dx, dy); time.sleep(0.012); ax -= dx; ay -= dy
    time.sleep(0.2)
    qmp(f, "input-send-event", events=[{"type":"btn","data":{"button":"left","down":True}}]); time.sleep(0.05)
    qmp(f, "input-send-event", events=[{"type":"btn","data":{"button":"left","down":False}}])
def typ(f, s):
    for ch in s:
        k = CH.get(ch)
        if k is None: continue
        keys(f, list(k) if isinstance(k, tuple) else [k]); time.sleep(0.05)
def run(f, line):           # type a command line + Enter
    typ(f, line); time.sleep(0.2); keys(f, ['ret']); time.sleep(1.2)

# ---- serial-log helpers ---------------------------------------------------------------------
def serial_text():
    try:
        raw = open(SERIAL, "rb").read().decode("latin-1")
    except FileNotFoundError:
        return ""
    t = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', raw)   # ESC-prefixed CSI escapes
    t = re.sub(r'\[[0-9;]*m', '', t)                    # bare SGR colour codes (the console log drops ESC)
    return t
def wait_for(token, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if token in serial_text(): return True
        time.sleep(2)
    return False

# ---- the checks: (name, command, regex the OUTPUT marker must match) ------------------------
LINUX_CHECKS = [
    ("version",    "echo SMKVER$ZSH_VERSION",                                  r"SMKVER5\.\d"),
    ("builtin+pipe","echo SMKPIPE$(echo a b c | wc -w)",                       r"SMKPIPE3"),
    ("completion", "echo SMKCOMP$(whence -w compdef | grep -c function)",      r"SMKCOMP1"),
    ("plugin",     "echo SMKPLUG$(whence -w _zsh_highlight | grep -c function)",r"SMKPLUG1"),
    ("history",    "echo SMKHIST$(fc -l | wc -l)",                             r"SMKHIST[1-9]"),
    ("aliases",    "echo SMKALIAS$(alias | wc -l)",                            r"SMKALIAS[1-9]"),
]
NATIVE_CHECKS = [
    ("native-obj", "echo SMKOBJ$(builtin obj | wc -l)",                        r"SMKOBJ[1-9]"),
]

def main():
    if not os.path.exists(ISO):
        print("FAIL: iso not found:", ISO); return 2
    for p in (SERIAL, SOCK):
        try: os.remove(p)
        except FileNotFoundError: pass

    qemu = subprocess.Popen(
        ["qemu-system-x86_64","-boot","d","-cdrom",ISO,"-serial","file:"+SERIAL,"-m","512",
         "-no-reboot","-no-shutdown","-enable-kvm","-cpu","qemu64,-smap,-smep",
         "-drive","file=%s,if=none,id=hosdisk,format=raw"%DISK,
         "-device","ahci,id=ahci0","-device","ide-hd,drive=hosdisk,bus=ahci0.0",
         "-display","none","-qmp","unix:%s,server,nowait"%SOCK],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    try:
        if not wait_for("launching '/wl-domain-manager'", 90):
            print("FAIL: desktop did not come up"); return 3
        time.sleep(3)
        for _ in range(20):
            if os.path.exists(SOCK): break
            time.sleep(0.5)
        s, f = conn()

        # Phase 1 — Linux-personality zsh (default System domain).
        click(f, 432, 590)                       # Launch Terminal
        time.sleep(6)
        for name, cmd, pat in LINUX_CHECKS:
            run(f, cmd)
        # golden prompt: the four-field prompt must have rendered on the console.
        prompt_ok = re.search(r"\[user@System\].*fs:rw", serial_text()) is not None
        results.append(("prompt", prompt_ok))

        # Phase 2 — switch the System domain to the NATIVE shell + confirm the object builtin.
        click(f, 169, 175); time.sleep(1)        # raise the Domain Manager
        click(f, 627, 502); time.sleep(0.6)      # Shell: Linux -> Windows
        click(f, 627, 502); time.sleep(0.6)      # Windows -> Native
        click(f, 432, 590)                       # Launch Terminal (native)
        wait_for("G4TERM: domain=System", 20); time.sleep(5)
        for name, cmd, pat in NATIVE_CHECKS:
            run(f, cmd)
        s.close()

        text = serial_text()
        for name, cmd, pat in LINUX_CHECKS + NATIVE_CHECKS:
            results.append((name, re.search(pat, text) is not None))
    finally:
        qemu.send_signal(signal.SIGKILL); qemu.wait()

    npass = sum(1 for _, ok in results if ok)
    print("\n=== zsh smoke results ===")
    for name, ok in results:
        print("  %-14s %s" % (name, "PASS" if ok else "FAIL"))
    print("=== %d/%d passed ===" % (npass, len(results)))
    return 0 if npass == len(results) else 1

if __name__ == "__main__":
    sys.exit(main())
