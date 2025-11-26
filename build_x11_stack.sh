#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$PWD}"
OUT_DIR="${OUT_DIR:-build}"
# This matches DESKTOP_STAGING_DIR in buildscript.sh
STAGING_DIR="$OUT_DIR/desktop-stack"

echo "[*] Preparing desktop stack in $STAGING_DIR..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/bin" "$STAGING_DIR/lib" "$STAGING_DIR/etc" "$STAGING_DIR/share"

# Python script to find and copy dependencies
cat <<EOF > "$OUT_DIR/copy_deps.py"
import subprocess
import sys
import shutil
import os
import re

staging_lib = sys.argv[1]
binaries = sys.argv[2:]

copied_libs = set()

def get_libs(binary):
    try:
        output = subprocess.check_output(["ldd", binary], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        return []
    
    libs = []
    for line in output.splitlines():
        # Match: libname.so => /path/to/libname.so (0x...)
        # Or: /lib64/ld-linux... (0x...)
        m = re.search(r'(\S+)\s+=>\s+(\S+)', line)
        if m:
            libs.append(m.group(2))
        else:
            # Handle ld-linux line which looks like: /lib64/ld-linux-x86-64.so.2 (0x...)
            m2 = re.search(r'^\s*(\/\S+)', line)
            if m2:
                libs.append(m2.group(1))
    return libs

for binary in binaries:
    if not os.path.exists(binary):
        print(f"Warning: Binary {binary} not found")
        continue
        
    print(f"Processing {binary}...")
    libs = get_libs(binary)
    for lib in libs:
        if lib in copied_libs:
            continue
        if not os.path.exists(lib):
            continue
            
        dest = os.path.join(staging_lib, os.path.basename(lib))
        if not os.path.exists(dest):
            shutil.copy2(lib, dest)
        copied_libs.add(lib)

print(f"Copied {len(copied_libs)} libraries.")
EOF

# List of binaries to copy
BINARIES=(
    "i3"
    "i3-msg"
    "i3-nagbar"
    "i3-config-wizard"
    "Xorg"
    "xinit"
    "xauth"
    "xrdb"
    "setxkbmap"
    "sh"
    "bash"
    "ls"
    "cat"
    "mkdir"
    "rm"
    "cp"
    "mv"
    "sleep"
    "id"
    "uname"
    "whoami"
)

# Find absolute paths
HOST_BINARIES=()
for bin in "${BINARIES[@]}"; do
    path="$(which "$bin" || true)"
    if [ -n "$path" ]; then
        HOST_BINARIES+=("$path")
        cp "$path" "$STAGING_DIR/bin/"
    else
        echo "Warning: $bin not found on host"
    fi
done

# Include locally built st terminal if present
if [ -f "$ROOT/st/st" ]; then
  echo "[*] Including local st terminal"
  HOST_BINARIES+=("$ROOT/st/st")
  cp "$ROOT/st/st" "$STAGING_DIR/bin/"
else
  echo "Warning: st binary not found at $ROOT/st/st"
fi

# Copy dependencies
python3 "$OUT_DIR/copy_deps.py" "$STAGING_DIR/lib" "${HOST_BINARIES[@]}"

# Copy config files
echo "[*] Copying configurations..."

# X11 configs
if [ -d "/usr/share/X11" ]; then
    mkdir -p "$STAGING_DIR/share/X11"
    # Copy xkb, locale, etc.
    cp -r /usr/share/X11/xkb "$STAGING_DIR/share/X11/" 2>/dev/null || true
    cp -r /usr/share/X11/locale "$STAGING_DIR/share/X11/" 2>/dev/null || true
fi

# i3 config (minimal, with launcher shortcut for st)
mkdir -p "$STAGING_DIR/etc/i3"
cat <<'I3CONF' > "$STAGING_DIR/etc/i3/config"
set $mod Mod4
font pango:monospace 10

floating_modifier $mod

# launch terminal
bindsym $mod+Return exec --no-startup-id /bin/st

# basic navigation
bindsym $mod+h focus left
bindsym $mod+j focus down
bindsym $mod+k focus up
bindsym $mod+l focus right

bindsym $mod+Shift+h move left
bindsym $mod+Shift+j move down
bindsym $mod+Shift+k move up
bindsym $mod+Shift+l move right

bindsym $mod+f fullscreen toggle
bindsym $mod+Shift+q kill

# exit i3 (logs out of the session)
bindsym $mod+Shift+e exec "i3-nagbar -t warning -m 'Exit i3?' -B 'Yes' 'i3-msg exit'"
I3CONF

# Create a basic xinitrc
mkdir -p "$STAGING_DIR/etc/X11/xinit"
cat <<'XINITRC' > "$STAGING_DIR/etc/X11/xinit/xinitrc"
#!/bin/sh
exec i3
XINITRC
chmod +x "$STAGING_DIR/etc/X11/xinit/xinitrc"

echo "[✓] Desktop stack prepared in $STAGING_DIR"
