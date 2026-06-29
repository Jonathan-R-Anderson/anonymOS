#!/usr/bin/env bash
# Build the INSTALLER ISO (hos-install.iso): a normal EpinAnonymOS boot tree PLUS a prebuilt
# FAT32 "esp-image" boot module (limine BOOTX64.EFI + kernel + modules + limine.conf).  The
# in-OS installer (desktop "Install to Disk") writes that image, with a single-ESP GPT, onto
# a target disk, so UEFI firmware boots the installed OS — no install medium needed.
#
# Prereq: `make stage-iso-tree` has populated cd/ (the boot tree). This script is idempotent.
#
# Usage:  scripts/mk-install-iso.sh [ESP_MiB]      (default 240; must exceed du(cd) + slack)
set -euo pipefail
cd "$(dirname "$0")/.."

ESP_MB="${1:-240}"
BOOTX64="deps/bdepend/boot/limine-bin/BOOTX64.EFI"
PREBOOT_EFI="deps/veracrypt/build/preboot.efi"
STAGE2_EFI="deps/veracrypt/build/stage2.efi"
LIMCONF="cd/boot/limine/limine.conf"

[ -d cd ] || { echo "cd/ not found — run 'make stage-iso-tree' first (or just use 'make iso')" >&2; exit 1; }
[ -f "$BOOTX64" ] || { echo "$BOOTX64 not found" >&2; exit 1; }
[ -f "$PREBOOT_EFI" ] || { echo "$PREBOOT_EFI not found — run 'make veracrypt-efi'" >&2; exit 1; }
[ -f "$STAGE2_EFI" ] || { echo "$STAGE2_EFI not found — run 'make veracrypt-efi'" >&2; exit 1; }

echo "==== mk-install-iso: building installed-OS ESP images (${ESP_MB} MiB) ===="

# 1. idempotency: drop any prior payload + its module line so the image we build is the
#    pristine installed OS (NOT itself carrying the installer payload).
rm -f cd/esp-image cd/esp-hidden-image esp.img hidden-esp.img
sed -i '\#module_path: boot():/esp-image#d' "$LIMCONF"
sed -i '\#module_path: boot():/esp-hidden-image#d' "$LIMCONF"

ESP_ROOT="$(mktemp -d)"
INSTALL_PLACEHOLDER="$(mktemp)"
INSTALL_LIMCONF="$(mktemp)"
cleanup_install_tmp() { rm -rf "$ESP_ROOT"; rm -f "$INSTALL_PLACEHOLDER" "$INSTALL_LIMCONF" esp.img hidden-esp.img; }
trap cleanup_install_tmp EXIT

cp -a cd/. "$ESP_ROOT"/
rm -f "$ESP_ROOT/esp-image" "$ESP_ROOT/esp-hidden-image" "$ESP_ROOT/decoy-linux.ext4"
sed -i '\#module_path: boot():/esp-image#d' "$ESP_ROOT/boot/limine/limine.conf"
sed -i '\#module_path: boot():/esp-hidden-image#d' "$ESP_ROOT/boot/limine/limine.conf"
sed -i '\#module_path: boot():/decoy-linux.ext4#d' "$ESP_ROOT/boot/limine/limine.conf"

USED_MB=$(du -sm "$ESP_ROOT" | cut -f1)
if [ "$USED_MB" -ge "$ESP_MB" ]; then
    echo "  boot tree is ${USED_MB} MiB but ESP is ${ESP_MB} MiB — bump the ESP_MiB arg" >&2; exit 1
fi

# The installed system loads /install.json as a first-boot module. The live
# installer patches this placeholder in-place after streaming esp-image to disk,
# so keep it large enough for the wizard JSON without needing FAT allocation.
dd if=/dev/zero of="$INSTALL_PLACEHOLDER" bs=32768 count=1 status=none

add_install_placeholder() {
    local img="$1"
    mcopy -i "$img" "$INSTALL_PLACEHOLDER" ::/install.json
    rm -f "$INSTALL_LIMCONF"
    mcopy -i "$img" ::/boot/limine/limine.conf "$INSTALL_LIMCONF"
    if ! grep -q 'boot():/install.json' "$INSTALL_LIMCONF"; then
        printf '\n    module_path: boot():/install.json\n' >> "$INSTALL_LIMCONF"
    fi
    mcopy -o -i "$img" "$INSTALL_LIMCONF" ::/boot/limine/limine.conf
}

# 2. build the normal FAT32 ESP image: scrubbed boot tree + limine's UEFI app.
dd if=/dev/zero of=esp.img bs=1M count="$ESP_MB" status=none
mkfs.fat -F 32 -n EPINESP esp.img >/dev/null
mcopy -s -i esp.img "$ESP_ROOT"/* ::
mmd -i esp.img ::/EFI ::/EFI/BOOT
mcopy -i esp.img "$BOOTX64" ::/EFI/BOOT/BOOTX64.EFI
add_install_placeholder esp.img

echo "  esp.img: $(du -h esp.img | cut -f1) (boot tree ${USED_MB} MiB + BOOTX64.EFI + install.json placeholder)"

# 3. build the Hidden OS ESP image: same scrubbed boot tree, but the UEFI entrypoint
#    is the VeraCrypt-style preboot authenticator, with its chain-loaded stage2 present.
dd if=/dev/zero of=hidden-esp.img bs=1M count="$ESP_MB" status=none
mkfs.fat -F 32 -n EPINHIDE hidden-esp.img >/dev/null
mcopy -s -i hidden-esp.img "$ESP_ROOT"/* ::
mmd -i hidden-esp.img ::/EFI ::/EFI/BOOT ::/EFI/anonymos
mcopy -i hidden-esp.img "$PREBOOT_EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i hidden-esp.img "$STAGE2_EFI" ::/EFI/anonymos/stage2.efi
add_install_placeholder hidden-esp.img

echo "  hidden-esp.img: $(du -h hidden-esp.img | cut -f1) (preboot.efi + stage2.efi + install.json placeholder)"

# 4. stage them as installer boot modules + advertise them to limine.
cp esp.img cd/esp-image
cp hidden-esp.img cd/esp-hidden-image
printf '\n    module_path: boot():/esp-image\n' >> "$LIMCONF"
printf '\n    module_path: boot():/esp-hidden-image\n' >> "$LIMCONF"

# 5. package the installer ISO using the same Limine/xorriso options as the staged boot tree expects.
xorriso -as mkisofs \
    -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image \
    --protective-msdos-label \
    cd -o hos-install.iso 2>/dev/null

echo "==== built hos-install.iso ($(du -h hos-install.iso | cut -f1)) ===="
echo "  Boot it (UEFI) with a blank target disk; the installer writes the OS to that disk."
