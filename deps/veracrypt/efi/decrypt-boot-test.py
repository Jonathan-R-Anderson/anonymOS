#!/usr/bin/env python3
# §E5d — prove the pre-boot loader DECRYPTS the matched OS's bootloader off the raw install
# disk and starts it. The ESP carries ONLY preboot.efi (no plaintext stage2.efi anywhere), so
# a "STAGE2 RUNNING" marker can ONLY have come from XTS-decrypting the on-disk payload with the
# master key the entered password unlocked — that is the whole point of this test.
#   usage: decrypt-boot-test.py <install-disk.img> <password> <DECOY|HIDDEN|REJECT>
import socket, json, subprocess, time, os, sys, signal

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BLD  = os.path.join(ROOT, "deps", "veracrypt", "build")
disk = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BLD, "install.img")
pw   = sys.argv[2] if len(sys.argv) > 2 else "decoy-password"
want = sys.argv[3] if len(sys.argv) > 3 else "DECOY"
verdict = {"DECOY":"BOOTING DECOY OS","HIDDEN":"BOOTING HIDDEN OS","REJECT":"access denied"}[want]
booted  = want in ("DECOY","HIDDEN")

OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
esp, varsfd = BLD + "/esp-e5d.img", BLD + "/OVMF_VARS_e5d.fd"
sock_path, log = BLD + "/qmp-e5d.sock", BLD + "/serial-e5d.log"
for p in (sock_path, log):
    try: os.remove(p)
    except FileNotFoundError: pass

# ESP with preboot.efi ONLY — deliberately NO stage2.efi, so a running payload proves decryption.
subprocess.run(["dd","if=/dev/zero","of="+esp,"bs=1M","count=48","status=none"], check=True)
subprocess.run(["mformat","-i",esp,"-F","::"], check=True)
subprocess.run(["mmd","-i",esp,"::/EFI","::/EFI/BOOT"], check=True)
subprocess.run(["mcopy","-i",esp,BLD+"/preboot.efi","::/EFI/BOOT/BOOTX64.EFI"], check=True)
subprocess.run(["cp",OVMF_VARS,varsfd], check=True)

qemu = subprocess.Popen([
  "qemu-system-x86_64","-enable-kvm","-m","256",
  "-drive","if=pflash,format=raw,readonly=on,file="+OVMF_CODE,
  "-drive","if=pflash,format=raw,file="+varsfd,
  "-drive","file=%s,format=raw,if=ide"%esp,
  "-drive","file=%s,format=raw,if=ide"%disk,
  "-serial","file:%s"%log,"-display","none",
  "-qmp","unix:%s,server,nowait"%sock_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def readlog():
    try: return open(log,'rb').read().replace(b'\0',b'').decode('latin1')
    except FileNotFoundError: return ""
def wait_for(text, timeout):
    t0=time.time()
    while time.time()-t0 < timeout:
        if text in readlog(): return True
        time.sleep(0.5)
    return False

rc = 1
try:
    for _ in range(60):
        try: s=socket.socket(socket.AF_UNIX); s.connect(sock_path); break
        except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.5)
    f=s.makefile('rwb', buffering=0); f.readline()
    f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline()
    if not wait_for("Enter password:", 40):
        print("FAIL: never saw the prompt"); raise SystemExit(1)
    time.sleep(1)
    def key(q):
        f.write(json.dumps({"execute":"send-key","arguments":{"keys":[{"type":"qcode","data":q}]}}).encode()+b'\n')
        f.readline(); time.sleep(0.12)
    qmap={'-':'minus','.':'dot','_':'shift_underscore'}
    for ch in pw: key(qmap.get(ch, ch))
    key("ret")

    ok = wait_for(verdict, 15)
    checks = [("routing verdict %r"%verdict, ok)]
    # The marker proving the decrypted payload actually RAN. Default is the stage2 test stub;
    # BOOT_MARKER overrides it for a real payload (e.g. "DECOY-INIT-OK" from the Alpine UKI),
    # which can take longer to reach userspace, so BOOT_TIMEOUT is generous.
    marker = os.environ.get("BOOT_MARKER", "STAGE2 RUNNING")
    btmo = int(os.environ.get("BOOT_TIMEOUT", "12"))
    if booted:
        dec = wait_for("decrypted the OS bootloader", btmo)
        run = wait_for(marker, btmo)
        checks += [("decrypted payload off raw disk", dec),
                   ("decrypted bootloader actually ran (%s)"%marker, run)]
    else:
        # a rejected password must NOT decrypt or start anything
        time.sleep(3)
        lg = readlog()
        checks += [("no bootloader decrypted on REJECT", "decrypted the OS bootloader" not in lg),
                   ("no payload ran on REJECT", marker not in lg)]
    allok = all(c for _,c in checks)
    for name,c in checks: print("  [%s] %s"%("PASS" if c else "FAIL", name))
    print("E5d decrypt-and-boot (pw=%r want=%s): %s"%(pw, want, "PASS" if allok else "FAIL"))
    rc = 0 if allok else 1
finally:
    qemu.send_signal(signal.SIGKILL)
sys.exit(rc)
