#!/usr/bin/env python3
# §E5c — boot the pre-boot loader in OVMF and drive the interactive password prompt with
# real keystrokes injected via QMP, then check the routing verdict.
#   usage: qmp-interactive-test.py <install-disk.img> [password] [expected:DECOY|HIDDEN|REJECT]
import socket, json, subprocess, time, os, sys, signal

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BLD  = os.path.join(ROOT, "deps", "veracrypt", "build")
disk = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target.img")
pw   = sys.argv[2] if len(sys.argv) > 2 else "decoy-password"
want = sys.argv[3] if len(sys.argv) > 3 else "DECOY"
expect = {"DECOY":"BOOTING DECOY OS","HIDDEN":"BOOTING HIDDEN OS","REJECT":"access denied"}[want]
sock_path, log = BLD + "/qmp-efi.sock", BLD + "/serial-efi-int.log"
for p in (sock_path, log):
    try: os.remove(p)
    except FileNotFoundError: pass

qemu = subprocess.Popen([
  "qemu-system-x86_64","-enable-kvm","-m","256",
  "-drive","if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
  "-drive","if=pflash,format=raw,file=%s/OVMF_VARS.fd"%BLD,
  "-drive","file=%s/esp.img,format=raw,if=ide"%BLD,
  "-drive","file=%s,format=raw,if=ide"%disk,
  "-serial","file:%s"%log,"-display","none",
  "-qmp","unix:%s,server,nowait"%sock_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_for(text, timeout):
    t0=time.time()
    while time.time()-t0 < timeout:
        try:
            if text in open(log,'rb').read().replace(b'\0',b'').decode('latin1'): return True
        except FileNotFoundError: pass
        time.sleep(0.5)
    return False
try:
    for _ in range(60):
        try: s=socket.socket(socket.AF_UNIX); s.connect(sock_path); break
        except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.5)
    f=s.makefile('rwb', buffering=0); f.readline()
    f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline()
    if not wait_for("Enter password:", 40):
        print("FAIL: never saw the prompt"); sys.exit(1)
    time.sleep(1)
    def key(q):
        f.write(json.dumps({"execute":"send-key","arguments":{"keys":[{"type":"qcode","data":q}]}}).encode()+b'\n')
        f.readline(); time.sleep(0.12)
    qmap={'-':'minus','.':'dot','_':'shift_underscore'}
    for ch in pw: key(qmap.get(ch, ch))
    key("ret")
    ok = wait_for(expect, 15)
    print("RESULT:", "PASS" if ok else "FAIL", "(pw=%r want=%s)"%(pw, want))
    sys.exit(0 if ok else 1)
finally:
    qemu.send_signal(signal.SIGKILL)
