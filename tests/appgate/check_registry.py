#!/usr/bin/env python3
"""check_registry.py -- host-side proof that the appgate registry covers everything that can run.

The kernel refuses to exec an image core/appreg.d does not classify (outside the System domain), so a
program that ships without a registry row fails silently at runtime -- in a domain, or when an
infrastructure launcher starts it.  This catches that at build time:

  1. every EXECUTABLE boot module any build branch can stage has a registry row
     (sources: src/boot/limine.conf, every `module_path: boot():/X` literal in the top-level Makefile
     across all conditional branches, scripts/mk-install-iso.sh -- NOT the generated limine.conf,
     which only reflects the last build's optional deps);
  2. every Domain Manager application (DMAPPS in src/util/wl-domain-manager.c) is a registry APP whose
     appId is its exec basename (the key the port/unport verbs and /config/apps.json use);
  3. every launch target -- .desktop Exec=, Hyprland hl.dsp.exec_cmd(), kernel spawn literals,
     userland execve/execv/execvp/execl literals -- resolves to a registry row, a busybox applet, or a
     known not-shipped program (EXPECTED_ENOENT).

Exit 0 = all checks pass; 1 = a gap (the report says which row to add).  Stdlib only.
"""
import glob
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def rd(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        return f.read()

# ── 1. the registry ──────────────────────────────────────────────────────────────────────────
ROW = re.compile(r'AppRegEntry\(\s*"([^"]+)",\s*(?:"([^"]*)"|null),\s*(APP|SYS|RUN|INF|NOX),\s*(SES|SYH),'
                 r'\s*(DNO|DSE|DNM),\s*(?:"([^"]*)"|null),\s*([^)]*)\)')
src = rd("src/kernel/d/core/appreg.d")
tbl = src[src.index("g_appReg = ["):]
tbl = tbl[:tbl.index("];")]
REG = {}
for m in ROW.finditer(tbl):
    image, appid, cls, host, dflt, ddom, flags = m.groups()
    if image in REG:
        print(f"FAIL duplicate registry row: {image}"); sys.exit(1)
    REG[image] = dict(appId=appid, cls=cls, host=host, flags=flags.replace(" ", ""))
if len(REG) < 20:
    print(f"FAIL parsed only {len(REG)} registry rows -- the row format changed?"); sys.exit(1)

# busybox applets (every /bin/<applet> resolves to the busybox module)
psx = rd("src/kernel/d/core/syscalls/posix.d")
a = psx.index("g_busyboxApplets =")
b = psx.index(";", a)
APPLETS = set(" ".join(re.findall(r'"([^"]*)"', psx[a:b])).split())

# programs that are referenced (host Hyprland config, Hyprland internals, optional tools) but never
# shipped as modules: exec of them is ENOENT before the gate runs.
EXPECTED_ENOENT = {
    "hyprctl", "qs", "kitty", "hyprpicker", "wpctl", "playerctl", "grim", "slurp", "notify-send",
    "loginctl", "systemctl", "gnome-keyring-daemon", "hypridle", "hyprlock", "wl-paste", "wl-copy",
    "dbus-update-activation-environment", "easyeffects", "hyprland-dialog", "hyprland-welcome",
    "hyprland-update-screen", "hyprland-donate-screen", "Xwayland", "xdg-open", "wl-installer",
    "brightnessctl", "pavucontrol", "nautilus", "dolphin", "fuzzel", "wofi", "rofi", "cliphist",
    "swww", "foot", "alacritty", "wezterm", "konsole", "kgx", "uxterm", "xterm", "sh",
    "nmcli", "wpa_cli", "sudo", "pkexec", "env", "true", "false", "sleep", "killall", "mkdir",
    "bash", "firefox", "cloud-hypervisor-test", "udhcpc",
}

def classify_target(tok):
    """Resolve a launch target's first token to how the kernel will treat it."""
    base = os.path.basename(tok)
    if base in REG:           return "registry"
    if base in APPLETS:       return "applet"
    if base in EXPECTED_ENOENT: return "enoent-expected"
    return None

# ── 2. the stageable module universe ─────────────────────────────────────────────────────────
MOD = re.compile(r'module_path:\s*boot\(\):/([A-Za-z0-9._+\-]+)')
modules = set()
for rel in ("src/boot/limine.conf", "Makefile", "scripts/mk-install-iso.sh"):
    try:
        modules.update(MOD.findall(rd(rel)))
    except FileNotFoundError:
        pass

DATA_SUFFIX = (".blob", ".conf", ".bin", ".json", ".png", ".iso", ".ext4", ".pem", ".key", ".sh",
               ".img", ".hosupd", ".txt", ".cfg", ".sig", ".pub", ".tar", ".gz", ".xz", ".zst")
DATA_NAMES = {"hiddeninstall-test", "epin-debug-ssh-key", "test.hosupd", "install.json", "anos.key",
              "manifest.blob", "guest-vmlinuz", "guest-initrd",
              "vm-alpine.vmlinuz", "vm-alpine.initrd", "vm-firmware.fd"}
DATA_PATTERN = re.compile(r'^esp-[a-z-]*image$')      # ESP / hidden-volume disk images

def is_library(name):
    return name.endswith(".so") or ".so." in name

def elf_kind(path):
    """'exec' for an ELF executable, 'lib' for a shared object without an entry, 'data' otherwise."""
    try:
        with open(path, "rb") as f:
            h = f.read(64)
    except OSError:
        return None
    if len(h) < 64 or h[:4] != b"\x7fELF":
        return "data"
    e_type = int.from_bytes(h[16:18], "little")
    if e_type == 2:
        return "exec"
    if e_type == 3:
        entry = int.from_bytes(h[24:32], "little")
        return "exec" if entry != 0 else "lib"
    return "data"

executables, data, unbuilt = [], [], []
for m in sorted(modules):
    if (is_library(m) or m.endswith(DATA_SUFFIX) or m in DATA_NAMES or DATA_PATTERN.match(m)
            or m.startswith("autoinstall")):
        data.append(m); continue
    kind = None
    for d in ("cd", "build"):
        p = os.path.join(ROOT, d, m)
        if os.path.exists(p):
            kind = elf_kind(p); break
    if kind is None:
        unbuilt.append(m); kind = "exec"          # not built here: assume it runs
    (executables if kind == "exec" else data).append(m)

fails = []
for m in executables:
    if m not in REG:
        fails.append(f"module '{m}' is an executable with no registry row "
                     f"(add an AppRegEntry to src/kernel/d/core/appreg.d)")

# ── 3. the Domain Manager's applications ─────────────────────────────────────────────────────
dm = rd("src/util/wl-domain-manager.c")
blk = dm[dm.index("static const struct dmapp DMAPPS[] = {"):]
blk = blk[:blk.index("};")]
dmapps = re.findall(r'\{\s*"([^"]+)",\s*"(/[^"]+)",\s*"[^"]*"', blk)
for label, ex in dmapps:
    base = ex.lstrip("/")
    r = REG.get(base)
    if r is None or r["cls"] != "APP" or r["appId"] != base:
        fails.append(f"Domain Manager app '{label}' ({ex}) must be a registry APP whose appId is '{base}'")

# ── 4. launch targets ───────────────────────────────────────────────────────────────────────
targets = []   # (where, token)
for p in sorted(glob.glob(os.path.join(ROOT, "system/applications/*.desktop"))):
    for line in open(p, encoding="utf-8", errors="replace"):
        if line.startswith("Exec="):
            tok = line[5:].strip().split()[0] if line[5:].strip() else ""
            if tok: targets.append((os.path.relpath(p, ROOT), tok))
for p in sorted(glob.glob(os.path.join(ROOT, "system/hypr/**/*.lua"), recursive=True)):
    for m in re.finditer(r'hl\.dsp\.exec_cmd\(\s*"([^"]+)"', open(p, encoding="utf-8", errors="replace").read()):
        tok = m.group(1).split()[0]
        if tok.startswith(("~", "$")): continue
        targets.append((os.path.relpath(p, ROOT), tok))
km = rd("src/kernel/d/core/kernel_main.d")
# spawn CALLS whose program argument is a literal: spawnWaylandProgram(<prog>, <tag>) and
# domainSpawnInto(<dom>, <prog>).  A program taken from a variable (desktop.conf autostart) is
# covered by the module check instead.
for m in re.finditer(r'(spawnWaylandProgram|domainSpawnInto)\(([^()]*)\)', km):
    args = [a.strip() for a in m.group(2).split(",")]
    idx = 0 if m.group(1) == "spawnWaylandProgram" else 1
    if len(args) > idx:
        lit = re.match(r'"([^"\\]+)(?:\\0)?"', args[idx])
        if lit: targets.append(("kernel_main.d spawn", lit.group(1)))
for m in re.finditer(r'execveTask\([^;]*?"(/[^"\\]+)(?:\\0)?"', km):
    targets.append(("kernel_main.d execveTask", m.group(1)))
EXEC_CALL = re.compile(r'\b(?:execve|execv|execvp|execl|execlp)\s*\(\s*"([^"]+)"')
for p in sorted(glob.glob(os.path.join(ROOT, "src/util/*.c")) + glob.glob(os.path.join(ROOT, "src/util/*.rs"))):
    for m in EXEC_CALL.finditer(open(p, encoding="utf-8", errors="replace").read()):
        targets.append((os.path.relpath(p, ROOT), m.group(1)))

unresolved = []
kinds = {}
for where, tok in targets:
    k = classify_target(tok)
    if k is None:
        unresolved.append(f"{where}: launches '{tok}' -- not a registry row, busybox applet, or expected-ENOENT")
    else:
        kinds[k] = kinds.get(k, 0) + 1
fails.extend(unresolved)

# ── report ───────────────────────────────────────────────────────────────────────────────────
print(f"registry rows:          {len(REG)}")
print(f"stageable modules:      {len(modules)}  ({len(executables)} executable, {len(data)} data/library"
      f"{', ' + str(len(unbuilt)) + ' not built here (assumed executable)' if unbuilt else ''})")
print(f"Domain Manager apps:    {len(dmapps)}")
print(f"launch targets checked: {len(targets)}  " + ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())))
if fails:
    print(f"\nFAIL: {len(fails)} gap(s)")
    for f in fails: print("  - " + f)
    sys.exit(1)
print("\nPASS: every executable module, Domain Manager app and launch target is classified")
