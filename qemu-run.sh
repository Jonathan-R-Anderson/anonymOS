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

# QEMU binary: prefer the locally-built virgl-capable QEMU >= 9.1 (~/.local/qemu-virgl), which is
# REQUIRED for the GPU/blob path — the Ubuntu repo only ships 8.2.2, which refuses virgl+blob
# ("blobs and virgl are not compatible (yet)").  Built from source, no sudo.  Falls back to system.
QEMU_BIN="${QEMU_BIN:-$HOME/.local/qemu-virgl/bin/qemu-system-x86_64}"
[ -x "$QEMU_BIN" ] || QEMU_BIN="qemu-system-x86_64"
echo "[qemu-run] using $("$QEMU_BIN" --version | head -1)"

# GPU=1 selects the HEADLESS virgl path with host-visible blob memory enabled (the GPU desktop +
# GPU clients); GPU unset = the interactive gtk software desktop.  egl-headless has no window, so
# observe the GPU desktop via serial.log + QMP screendumps (qmp.sock).
if [ "${GPU:-0}" = "1" ]; then
  MEM="${MEM:-1024}"
  GFX=(-vga std -device virtio-gpu-gl-pci,blob=true,hostmem=256M
       -display egl-headless,rendernode=/dev/dri/renderD128
       -qmp unix:qmp.sock,server,nowait)
  echo "[qemu-run] GPU=1: headless virgl + host-visible blob (read serial.log; QMP at qmp.sock)"
else
  MEM="${MEM:-512}"
  GFX=(-display gtk)
fi

# A5/F4 persistence: a 32 MiB raw SATA disk on an AHCI controller backs the object
# store across reboots (created on first run; kept out of git via .gitignore).
DISK_IMG="hos-disk.img"
if [ ! -f "$DISK_IMG" ]; then
  qemu-img create -f raw "$DISK_IMG" 32M >/dev/null 2>&1 || dd if=/dev/zero of="$DISK_IMG" bs=1M count=32 status=none
  echo "[qemu-run] created $DISK_IMG (32M) for persistent object store"
fi

# L3b LKL bring-up: a conflict-free NVMe device for LKL to drive (EpinAnonymOS uses AHCI and
# ignores NVMe).  Opt-in via LKL_NVME=1 so the normal desktop boot is unchanged.
NVME=()
if [ "${LKL_NVME:-0}" = "1" ]; then
  NVME_IMG="${NVME_IMG:-$HOME/lkl-build/lkl-nvme.img}"
  [ -f "$NVME_IMG" ] || truncate -s 16M "$NVME_IMG"
  NVME=( -drive file="$NVME_IMG",if=none,id=lklnvme,format=raw
         -device nvme,drive=lklnvme,serial=lkl-nvme-0 )
  echo "[qemu-run] LKL_NVME=1: attaching NVMe $NVME_IMG for the LKL driver"
fi

# L5 LKL bring-up: an xHCI USB controller + a USB keyboard/mouse for LKL's xhci+usbhid to drive.
# Opt-in via LKL_USB=1 so the normal desktop boot is unchanged.
USBDEV=()
if [ "${LKL_USB:-0}" = "1" ]; then
  USBDEV=( -device qemu-xhci,id=xhci
           -device usb-kbd,bus=xhci.0
           -device usb-mouse,bus=xhci.0 )
  echo "[qemu-run] LKL_USB=1: attaching xHCI + usb-kbd + usb-mouse for the LKL driver"
fi

exec "$QEMU_BIN" \
  -boot d \
  -cdrom hos.iso \
  -serial file:serial.log \
  -m "$MEM" \
  -no-reboot \
  -no-shutdown \
  -d int,cpu_reset,guest_errors \
  -D qemu-debug.log \
  "${ACCEL[@]}" \
  -drive file="$DISK_IMG",if=none,id=hosdisk,format=raw \
  -device ahci,id=ahci0 \
  -device ide-hd,drive=hosdisk,bus=ahci0.0 \
  "${NVME[@]}" \
  "${USBDEV[@]}" \
  "${GFX[@]}"
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
