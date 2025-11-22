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
    "xterm"
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

# i3 config
if [ -d "/etc/i3" ]; then
    mkdir -p "$STAGING_DIR/etc/i3"
    cp -r /etc/i3/* "$STAGING_DIR/etc/i3/"
fi

# Create a basic xinitrc
mkdir -p "$STAGING_DIR/etc/X11/xinit"
cat <<XINITRC > "$STAGING_DIR/etc/X11/xinit/xinitrc"
#!/bin/sh
exec i3
XINITRC
chmod +x "$STAGING_DIR/etc/X11/xinit/xinitrc"

echo "[✓] Desktop stack prepared in $STAGING_DIR"
