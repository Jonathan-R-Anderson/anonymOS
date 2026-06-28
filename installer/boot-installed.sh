#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Boot the INSTALLED EpinAnonymOS disk (produced by install-to-disk.sh) in QEMU
# via UEFI/OVMF — proving the OS boots from a hard disk, with no ISO/CD attached.
#
# The installed image is attached as a virtio-blk disk: the UEFI firmware boots it
# (runs /EFI/BOOT/BOOTX64.EFI → limine → kernel), while the kernel ignores it — it is
# neither AHCI (the object-store driver) nor one of the classes that trigger the LKL
# launch (0x0380 display / 0x0c03 xHCI / 0x0108 NVMe).  A separate AHCI disk
# (hos-disk.img) is the persistent object store, exactly as on the ISO boot.
#
# Usage:  installer/boot-installed.sh
#   HEADLESS=1   windowless (egl-headless + QMP) for automated testing
#   GPU=1        virgl GPU desktop (needs the local virgl QEMU)
#   IMG=path     installed image (default: hos-installed.img)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMG="${IMG:-hos-installed.img}"
[ -f "$IMG" ] || { echo "[boot] $IMG not found — run installer/install-to-disk.sh first"; exit 1; }

# OVMF UEFI firmware (code is read-only; vars are a writable per-run copy).
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_SRC="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
[ -f "$OVMF_CODE" ] || { echo "[boot] OVMF firmware missing: $OVMF_CODE (apt install ovmf)"; exit 1; }
VARS="ovmf-vars-installed.fd"
cp -f "$OVMF_VARS_SRC" "$VARS"

# Persistent object store (AHCI SATA), same as the ISO boot.
DISK_IMG="hos-disk.img"
[ -f "$DISK_IMG" ] || qemu-img create -f raw "$DISK_IMG" 32M >/dev/null 2>&1

if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-enable-kvm -cpu qemu64,-smap,-smep)
else
  ACCEL=(-cpu qemu64,-smap,-smep)
fi

QEMU_BIN="${QEMU_BIN:-$HOME/.local/qemu-virgl/bin/qemu-system-x86_64}"
[ -x "$QEMU_BIN" ] || QEMU_BIN="qemu-system-x86_64"

if [ "${GPU:-0}" = "1" ]; then
  MEM="${MEM:-1024}"
  if [ "${HEADLESS:-0}" = "1" ]; then
    GFX=(-vga std -device virtio-gpu-gl-pci,blob=true,hostmem=256M
         -display egl-headless,rendernode=/dev/dri/renderD128 -qmp unix:qmp.sock,server,nowait)
  else
    GFX=(-vga std -device virtio-gpu-gl-pci,blob=true,hostmem=256M
         -display gtk,gl=on -qmp unix:qmp.sock,server,nowait)
  fi
else
  MEM="${MEM:-512}"
  # -vga std gives OVMF a GOP framebuffer for limine/the kernel even when headless.
  if [ "${HEADLESS:-0}" = "1" ]; then GFX=(-vga std -display none -qmp unix:qmp.sock,server,nowait)
  else GFX=(-vga std -display gtk); fi
fi

echo "[boot] booting INSTALLED disk $IMG via UEFI (OVMF), no ISO"
exec "$QEMU_BIN" \
  -machine q35 \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,unit=1,file="$VARS" \
  -drive file="$IMG",if=none,id=osboot,format=raw \
  -device virtio-blk-pci,drive=osboot \
  -drive file="$DISK_IMG",if=none,id=hosdisk,format=raw \
  -device ahci,id=ahci0 -device ide-hd,drive=hosdisk,bus=ahci0.0 \
  -serial file:serial.log \
  -m "$MEM" \
  -smp "${SMP:-1}" \
  -no-reboot -no-shutdown \
  -d guest_errors -D qemu-debug.log \
  "${ACCEL[@]}" \
  "${GFX[@]}"
