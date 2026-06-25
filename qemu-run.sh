#!/usr/bin/env bash
# Use KVM hardware acceleration when the host exposes /dev/kvm. Without it QEMU
# falls back to TCG pure software emulation, which runs the (already software-
# rendered) desktop ~10-100x slower — the dominant cause of a sluggish cursor and
# UI. The OS requires SMAP/SMEP disabled, so strip them from whichever CPU model
# we use.
# Keep the qemu64 CPU model in both cases: it exposes SSE2 (which the kernel sets
# up) but not AVX/AVX-512, whose extended state the kernel does not enable — using
# -cpu host under KVM exposed those and faulted Hyprland immediately. KVM still
# accelerates execution; only the advertised feature set is constrained.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-enable-kvm -cpu qemu64,-smap,-smep)
  echo "[qemu-run] KVM acceleration enabled"
else
  ACCEL=(-cpu qemu64,-smap,-smep)
  echo "[qemu-run] /dev/kvm unavailable — using slow TCG emulation (expect a sluggish desktop)"
fi

# A5/F4 persistence: a 32 MiB raw SATA disk on an AHCI controller backs the object
# store across reboots (created on first run; kept out of git via .gitignore).
DISK_IMG="hos-disk.img"
if [ ! -f "$DISK_IMG" ]; then
  qemu-img create -f raw "$DISK_IMG" 32M >/dev/null 2>&1 || dd if=/dev/zero of="$DISK_IMG" bs=1M count=32 status=none
  echo "[qemu-run] created $DISK_IMG (32M) for persistent object store"
fi

exec qemu-system-x86_64 \
  -boot d \
  -cdrom hos.iso \
  -serial file:serial.log \
  -m 512 \
  -no-reboot \
  -no-shutdown \
  -d int,cpu_reset,guest_errors \
  -D qemu-debug.log \
  "${ACCEL[@]}" \
  -drive file="$DISK_IMG",if=none,id=hosdisk,format=raw \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=hosdisk,bus=ahci0.0 \
  -display gtk
# R2 (GPU stack) is OFF by default: `gtk,gl=on` + a virtio-gpu-gl device gives a BLACK SCREEN on
# many hosts (the GL display path doesn't present the firmware-VGA framebuffer the desktop renders
# to).  To exercise the kernel's virgl path, run HEADLESS instead and read serial.log:
#   ... -vga std -device virtio-gpu-gl-pci -display egl-headless -serial file:serial.log ...
# then look for "[virtio-gpu] R2..." (R2.1 detect, R2.2 transport).  See roadmap R2.
# NOTE: the guest exposes only a RELATIVE PS/2 mouse (no USB/virtio tablet), so
# QEMU must *grab* the host pointer to deliver motion + keystrokes. `show-cursor=on`
# was suppressing that grab — you saw the host cursor float over a frozen guest
# cursor. With it removed: CLICK inside the window to grab input (the host cursor
# hides and the guest cursor starts tracking + the keyboard reaches the guest);
# press Ctrl+Alt+G to release the grab.
