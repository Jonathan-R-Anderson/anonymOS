#!/usr/bin/env bash
# macOS / Apple Silicon runner for HanonymOS.
#
# This is the cross-architecture counterpart to qemu-run.sh (which targets
# Linux + KVM). On this arm64 Mac there is no way to hardware-accelerate an
# x86_64 guest:
#   - /dev/kvm does not exist on macOS.
#   - macOS HVF (Hypervisor.framework) can only accelerate a guest that shares
#     the host's CPU architecture, and we're emulating x86_64 on arm64.
# So we run under TCG (pure software CPU translation). That works correctly but
# the software-rendered guest desktop will be sluggish; the serial console is
# the fast, reliable channel during bring-up.
#
# Usage:
#   ./qemu-run-mac.sh            # native macOS window (cocoa) + serial.log
#   ./qemu-run-mac.sh --serial   # serial console attached to the terminal, no GUI
#   ./qemu-run-mac.sh --vnc      # headless + VNC on :0 (connect via Finder → vnc://localhost:5900)
set -euo pipefail

cd "$(dirname "$0")"

MODE="cocoa"
case "${1:-}" in
  --serial)  MODE="serial" ;;
  --vnc)     MODE="vnc" ;;
  --cocoa|"") MODE="cocoa" ;;
  *) echo "usage: $0 [--serial|--vnc|--cocoa]"; exit 1 ;;
esac

# The guest requires SMAP/SMEP disabled; keep the constrained qemu64 model
# (SSE2 present, no AVX whose xstate the kernel does not enable).
ACCEL=(-cpu qemu64,-smap,-smep)
echo "[qemu-run-mac] TCG software emulation (cross-arch x86_64 on arm64) — expect a sluggish GUI"

# Persistent 32 MiB object-store disk (AHCI/SATA), created on first run.
DISK_IMG="hos-disk.img"
if [ ! -f "$DISK_IMG" ]; then
  qemu-img create -f raw "$DISK_IMG" 32M >/dev/null 2>&1 || dd if=/dev/zero of="$DISK_IMG" bs=1M count=32 status=none
  echo "[qemu-run-mac] created $DISK_IMG (32M) for persistent object store"
fi

# Per-mode display + serial wiring.
case "$MODE" in
  cocoa)
    DISPLAY=(-display cocoa -serial file:serial.log)
    echo "[qemu-run-mac] cocoa window + serial → serial.log (tail -f serial.log)"
    ;;
  serial)
    # Attach the guest's primary serial port to this terminal for live I/O.
    DISPLAY=(-display none -serial stdio)
    echo "[qemu-run-mac] headless, serial → this terminal (Ctrl-A X to quit QEMU)"
    ;;
  vnc)
    DISPLAY=(-display none -serial file:serial.log -vnc :0)
    echo "[qemu-run-mac] headless + VNC :0 → vnc://localhost:5900"
    ;;
esac

exec qemu-system-x86_64 \
  -boot d \
  -cdrom hos.iso \
  -m 512 \
  -no-reboot \
  -no-shutdown \
  -d int,cpu_reset,guest_errors \
  -D qemu-debug.log \
  "${ACCEL[@]}" \
  -drive file="$DISK_IMG",if=none,id=hosdisk,format=raw \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=hosdisk,bus=ahci0.0 \
  "${DISPLAY[@]}"
