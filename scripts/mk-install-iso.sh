#!/usr/bin/env bash
# Build the INSTALLER ISO (hos-install.iso): a normal EpinAnonymOS boot tree PLUS a prebuilt
# FAT32 "esp-image" boot module (limine BOOTX64.EFI + kernel + modules + limine.conf).  The
# in-OS installer (desktop "Install to Disk") writes that image, with a single-ESP GPT, onto
# a target disk, so UEFI firmware boots the installed OS — no install medium needed.
#
# Prereq: `make hos.iso` has populated cd/ (the boot tree).  This script is idempotent.
#
# Usage:  scripts/mk-install-iso.sh [ESP_MiB]      (default 240; must exceed du(cd) + slack)
set -euo pipefail
cd "$(dirname "$0")/.."

ESP_MB="${1:-240}"
BOOTX64="deps/bdepend/boot/limine-bin/BOOTX64.EFI"
LIMCONF="cd/boot/limine/limine.conf"

[ -d cd ] || { echo "cd/ not found — run 'make hos.iso' first" >&2; exit 1; }
[ -f "$BOOTX64" ] || { echo "$BOOTX64 not found" >&2; exit 1; }

echo "==== mk-install-iso: building the installed-OS ESP image (${ESP_MB} MiB) ===="

# 1. idempotency: drop any prior payload + its module line so the image we build is the
#    pristine installed OS (NOT itself carrying the installer payload).
rm -f cd/esp-image esp.img
sed -i '\#module_path: boot():/esp-image#d' "$LIMCONF"

USED_MB=$(du -sm cd | cut -f1)
if [ "$USED_MB" -ge "$ESP_MB" ]; then
    echo "  boot tree is ${USED_MB} MiB but ESP is ${ESP_MB} MiB — bump the ESP_MiB arg" >&2; exit 1
fi

# 2. build the FAT32 ESP image: the whole boot tree at root + limine's UEFI app.
dd if=/dev/zero of=esp.img bs=1M count="$ESP_MB" status=none
mkfs.fat -F 32 -n EPINESP esp.img >/dev/null
mcopy -s -i esp.img cd/* ::
mmd -i esp.img ::/EFI ::/EFI/BOOT
mcopy -i esp.img "$BOOTX64" ::/EFI/BOOT/BOOTX64.EFI
echo "  esp.img: $(du -h esp.img | cut -f1) (boot tree ${USED_MB} MiB + BOOTX64.EFI)"

# 3. stage it as the "esp-image" boot module + advertise it to limine.
cp esp.img cd/esp-image
printf '\n    module_path: boot():/esp-image\n' >> "$LIMCONF"

# 4. repackage the ISO (same options as the Makefile hos.iso target).
xorriso -as mkisofs \
    -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image \
    --protective-msdos-label \
    cd -o hos-install.iso 2>/dev/null

echo "==== built hos-install.iso ($(du -h hos-install.iso | cut -f1)) ===="
echo "  Boot it (UEFI) with a blank target disk; the installer writes the OS to that disk."
