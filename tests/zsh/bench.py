#!/usr/bin/env python3
# Z12.3 — zsh benchmarks for EpinAnonymOS (Deliverable 19).
#
# Boots hos.iso headless, opens a terminal, and measures (via serial-console markers):
#   - peak RSS of the fully-loaded interactive zsh (vs busybox ash, vs the /hos-sh footprint),
#   - bare-zsh startup latency (zsh -fc exit) and full-rc startup (zsh -ic exit),
# using the zsh/datetime EPOCHREALTIME clock.  Also reports the host-side on-disk footprint and
# the headroom against the 512 MiB boot ceiling.  Honest about the dev kernel's timing limits.
#
# Usage:  python3 tests/zsh/bench.py [path/to/hos.iso]
import socket, json, sys, time, os, re, subprocess, signal

ROOT   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ISO    = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "hos.iso")
DISK   = os.path.join(ROOT, "hos-disk-z.img")
SERIAL = os.path.join(ROOT, "serial-bench.log")
SOCK   = os.path.join(ROOT, "qmp-bench.sock")
CEILING_MIB = 512

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
def run(f, line, settle=1.5):
    typ(f, line); time.sleep(0.2); keys(f, ['ret']); time.sleep(settle)
def serial_text():
    try: raw = open(SERIAL, "rb").read().decode("latin-1")
    except FileNotFoundError: return ""
    t = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', raw)
    return re.sub(r'\[[0-9;]*m', '', t)
def wait_for(token, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if token in serial_text(): return True
        time.sleep(2)
    return False
def grab(pat):
    m = re.search(pat, serial_text())
    return m.group(1) if m else None

def host_footprint():
    def sz(p):
        try: return os.path.getsize(os.path.join(ROOT, p))
        except OSError: return 0
    comps = {"zsh bin": sz("deps/zsh/zsh"), "musl libc.so": sz("deps/musl/install/lib/libc.so"),
             "busybox": sz("cd/busybox"), "hos-sh": sz("cd/hos-sh")}
    mods = sum(os.path.getsize(p) for p in __import__("glob").glob(os.path.join(ROOT,"deps/zsh/modules/*.so")))
    blobs = sum(sz(b) for b in ("cd/zshfns.blob","cd/zshplugins.blob","cd/omz.blob"))
    comps["zmodules (37)"] = mods; comps["fn/plugin/omz blobs"] = blobs
    return comps

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
    try:
        if not wait_for("launching '/wl-domain-manager'", 90):
            print("FAIL: desktop did not come up"); return 3
        time.sleep(3)
        for _ in range(20):
            if os.path.exists(SOCK): break
            time.sleep(0.5)
        s, f = conn()
        click(f, 432, 590); time.sleep(6)                 # Launch Terminal (Linux zsh)
        run(f, "zmodload zsh/datetime")
        run(f, "print BNCHrss$(grep VmRSS /proc/self/status | tr -dc 0-9)")
        # startup latency, 10x each: bare zsh (no rc) vs busybox vs the native /hos-sh ...
        run(f, "t0=$EPOCHREALTIME")
        run(f, "for i in 1 2 3 4 5; do zsh -fc exit; done", settle=26)
        run(f, "print BNCHbare$((EPOCHREALTIME-t0))")
        run(f, "t0=$EPOCHREALTIME")
        run(f, "for i in 1 2 3 4 5; do busybox true; done", settle=26)
        run(f, "print BNCHbb$((EPOCHREALTIME-t0))")
        run(f, "t0=$EPOCHREALTIME")
        run(f, "for i in 1 2 3 4 5; do /hos-sh sys; done", settle=26)
        run(f, "print BNCHhos$((EPOCHREALTIME-t0))")
        # ... and the full interactive login startup (sources /etc/zshrc: compinit, plugins, omz) x2
        run(f, "t0=$EPOCHREALTIME")
        run(f, "for i in 1 2; do zsh -ic exit; done", settle=32)
        run(f, "print BNCHrc$((EPOCHREALTIME-t0))")
        s.close()
    finally:
        qemu.send_signal(signal.SIGKILL); qemu.wait()

    rss   = grab(r"BNCHrss(\d+)")
    bare  = grab(r"BNCHbare([\d.]+)")
    bb    = grab(r"BNCHbb([\d.]+)")
    hos   = grab(r"BNCHhos([\d.]+)")
    rc    = grab(r"BNCHrc([\d.]+)")
    print("\n=== zsh benchmarks ===")
    fp = host_footprint(); total = sum(fp.values())
    print("on-disk footprint (boot modules + ramfs blobs):")
    for k, v in fp.items(): print("    %-22s %8.2f MB" % (k, v/1048576))
    print("    %-22s %8.2f MB  (%.1f%% of the %d MiB ceiling)" %
          ("TOTAL", total/1048576, 100.0*total/(CEILING_MIB*1048576), CEILING_MIB))
    print("runtime / latency (in-VM, zsh/datetime EPOCHREALTIME clock):")
    if rss: print("    %-22s %8.2f MB  (%.2f%% of %d MiB)  loaded interactive zsh" %
                  ("peak RSS (zsh)", int(rss)/1024, 100.0*int(rss)/1024/CEILING_MIB, CEILING_MIB))
    else:   print("    peak RSS (zsh)         n/a")
    def lat(label, val, n, note):
        if val and float(val) > 0: print("    %-22s %8.1f ms  %s" % (label, float(val)*1000/n, note))
        else: print("    %-22s %8s    %s" % (label, "n/a", note))
    print("startup latency (mean per exec, in-VM; dominated by the kernel fork/exec/load path):")
    lat("zsh -fc exit (bare)", bare, 5, "5x, no rc")
    lat("busybox true",        bb,   5, "5x, baseline exec cost")
    lat("/hos-sh sys (native)",hos,  5, "5x, the 56 KB native shell")
    lat("zsh -ic exit (login)",rc,   2, "2x, sources /etc/zshrc: compinit + plugins + omz")
    return 0

if __name__ == "__main__":
    sys.exit(main())
