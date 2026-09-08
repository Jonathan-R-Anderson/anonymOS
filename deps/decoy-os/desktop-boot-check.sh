#!/bin/bash
# deps/decoy-os/desktop-boot-check.sh — boot the decoy XFCE desktop image in QEMU and assert a
# real desktop RENDERED. A failed session leaves a flat solid colour (near-zero variance); a
# painted XFCE desktop (wallpaper + panel + icons) has high variance. -vga virtio so QMP
# screendump captures the DRM scanout, not just the legacy VGA plane. (roadmap/INSTALLER.md §H1)
#   usage: desktop-boot-check.sh <build-dir>
set -u
B="${1:?usage: desktop-boot-check.sh <build-dir>}"
cd "$B"
rm -f serial-decoy.log qmp-decoy.sock shot-decoy.ppm shot-decoy.png
qemu-system-x86_64 -enable-kvm -cpu host -m 2560 -smp 2 \
  -kernel vmlinuz-decoy -initrd initramfs-decoy.gz \
  -append "console=tty0 console=ttyS0,115200 rw" \
  -drive file=decoy-desktop.ext4,format=raw,if=virtio \
  -vga virtio -serial file:serial-decoy.log -display none \
  -qmp unix:qmp-decoy.sock,server,nowait >/dev/null 2>&1 &
QPID=$!
# wait for the QMP socket, then give the desktop time to autologin -> startx -> XFCE
for _ in $(seq 1 30); do [ -S qmp-decoy.sock ] && break; sleep 1; done
sleep 90
printf '{"execute":"qmp_capabilities"}\n{"execute":"screendump","arguments":{"filename":"%s/shot-decoy.ppm"}}\n' "$B" \
  | nc -U -q4 qmp-decoy.sock >/dev/null 2>&1 || true
sleep 2
kill -9 "$QPID" 2>/dev/null || true

if [ ! -f shot-decoy.ppm ]; then echo "  [FAIL] no screendump captured"; exit 1; fi
convert shot-decoy.ppm shot-decoy.png
SD=$(convert shot-decoy.png -colorspace Gray -format '%[fx:standard_deviation]' info:)
if awk "BEGIN{exit !($SD > 0.05)}"; then
  echo "  [PASS] XFCE desktop rendered (screen variance $SD) -> shot-decoy.png"
  exit 0
else
  echo "  [FAIL] blank/flat screen (variance $SD) -- desktop did not paint"
  exit 1
fi
