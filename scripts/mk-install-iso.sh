#!/usr/bin/env bash
# Build the INSTALLER ISO (hos-install.iso): a normal EpinAnonymOS boot tree PLUS a prebuilt
# FAT32 "esp-image" boot module (limine BOOTX64.EFI + kernel + modules + limine.conf).  The
# in-OS installer (desktop "Install to Disk") writes that image, with a single-ESP GPT, onto
# a target disk, so UEFI firmware boots the installed OS — no install medium needed.
#
# Prereq: `make stage-iso-tree` has populated cd/ (the boot tree). This script is idempotent.
#
# Usage:  scripts/mk-install-iso.sh [ESP_MiB]      (default 512; must exceed du(cd) + slack)
set -euo pipefail
cd "$(dirname "$0")/.."

# Default raised 320 -> 512 when llvmpipe landed: JIT-compiling shaders means Mesa statically
# links LLVM, which took the boot tree from ~335 MiB to 380 MiB and no longer fit.  The check
# below is what caught it -- it refuses to build a too-small ESP rather than producing an image
# that fails at install time.
ESP_MB="${1:-512}"
BOOTX64="deps/bdepend/boot/limine-bin/BOOTX64.EFI"
PREBOOT_EFI="deps/veracrypt/build/preboot.efi"
STAGE2_EFI="deps/veracrypt/build/stage2.efi"
ARBITER_EFI="build/arbiter.efi"   # UPDATE U1-C slot-arbiter (make -C boot/arbiter)
LIMCONF="cd/boot/limine/limine.conf"

[ -d cd ] || { echo "cd/ not found — run 'make stage-iso-tree' first (or just use 'make iso')" >&2; exit 1; }
[ -f "$BOOTX64" ] || { echo "$BOOTX64 not found" >&2; exit 1; }
[ -f "$PREBOOT_EFI" ] || { echo "$PREBOOT_EFI not found — run 'make veracrypt-efi'" >&2; exit 1; }
[ -f "$ARBITER_EFI" ] || { echo "$ARBITER_EFI not found — run 'make arbiter-efi'" >&2; exit 1; }

echo "==== mk-install-iso: building installed-OS ESP images (${ESP_MB} MiB) ===="

# 1. idempotency: drop any prior payload + its module line so the image we build is the
#    pristine installed OS (NOT itself carrying the installer payload).
rm -f cd/esp-image cd/esp-hidden-image cd/esp-boot-image cd/esp-preboot-image esp.img hidden-esp.img esp-boot.img esp-preboot.img
sed -i '\#module_path: boot():/esp-image#d' "$LIMCONF"
sed -i '\#module_path: boot():/esp-hidden-image#d' "$LIMCONF"
sed -i '\#module_path: boot():/esp-boot-image#d' "$LIMCONF"
sed -i '\#module_path: boot():/esp-preboot-image#d' "$LIMCONF"

ESP_ROOT="$(mktemp -d)"
INSTALL_PLACEHOLDER="$(mktemp)"
INSTALL_LIMCONF="$(mktemp)"
cleanup_install_tmp() { rm -rf "$ESP_ROOT"; rm -f "$INSTALL_PLACEHOLDER" "$INSTALL_LIMCONF" "${ANOS_KEY_PLACEHOLDER:-}" esp.img hidden-esp.img esp-boot.img esp-preboot.img; }
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

# INSTALLER §C(i)/§D (FDE): the runtime key placeholder.  On an ENCRYPTED install the pre-boot
# loader, after decrypting the EpinAnonymOS boot volume into RAM, scans the decrypted FAT image
# for this 512-byte record and overwrites it (in RAM only) with the ANOSKEY1 master-key record
# before StartImage; Limine then loads /anos.key as an ordinary boot module and the kernel picks
# up the key (core/fde.d).  On a PLAIN install the record is never patched, so the kernel sees the
# bare marker (no "ANOSKEY1" magic) and ignores it — harmless.  The file MUST be exactly one 512-
# byte sector so its record is contiguous and the loader's marker scan is safe.
#
# LOADER↔KERNEL CONTRACT: the first bytes are the ASCII marker "ANOSKEY-PLACEHOLDER-v1-" that the
# loader scans for; efi_main.c must scan for the identical string.  The rest is zero-filled.
ANOS_KEY_PLACEHOLDER="$(mktemp)"
printf 'ANOSKEY-PLACEHOLDER-v1-' > "$ANOS_KEY_PLACEHOLDER"
truncate -s 512 "$ANOS_KEY_PLACEHOLDER"

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

# INSTALLER §C(i): drop the /anos.key placeholder into a boot-volume image and advertise it to the
# image's own limine.conf, so a boot from that volume hands the kernel an "anos.key" module.
add_anos_key_placeholder() {
    local img="$1"
    mcopy -o -i "$img" "$ANOS_KEY_PLACEHOLDER" ::/anos.key
    rm -f "$INSTALL_LIMCONF"
    mcopy -i "$img" ::/boot/limine/limine.conf "$INSTALL_LIMCONF"
    if ! grep -q 'boot():/anos.key' "$INSTALL_LIMCONF"; then
        printf '\n    module_path: boot():/anos.key\n' >> "$INSTALL_LIMCONF"
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
add_anos_key_placeholder esp.img   # §C(i)/§D: runtime FDE key placeholder (harmless on plain installs)

echo "  esp.img: $(du -h esp.img | cut -f1) (boot tree ${USED_MB} MiB + BOOTX64.EFI + install.json + anos.key placeholder)"

# 2b. UPDATE U1: the ESP-boot image — a tiny FAT32 ESP holding ONLY the slot-arbiter as
#     \EFI\BOOT\BOOTX64.EFI. The installer streams this to GPT partition 0 (the only ESP-
#     typed partition → the one firmware boots); the arbiter then chainloads slot A or B.
# FAT16, NOT FAT32: an 8 MiB "FAT32" has ~16k clusters, and edk2-derived firmware (OVMF,
# VirtualBox, most vendors) derives the FAT type from the CLUSTER COUNT (< 65525 => FAT16) and then
# rejects a BPB whose root-entry count is FAT32-style zero -- the ESP mounts nowhere and the boot
# option fails with "Not Found".  Seen in OVMF with the preboot ESP; the same construction here.
dd if=/dev/zero of=esp-boot.img bs=1M count=8 status=none
mkfs.fat -F 16 -s 1 -n EPINBOOT esp-boot.img >/dev/null
mmd -i esp-boot.img ::/EFI ::/EFI/BOOT
mcopy -i esp-boot.img "$ARBITER_EFI" ::/EFI/BOOT/BOOTX64.EFI
echo "  esp-boot.img: $(du -h esp-boot.img | cut -f1) (arbiter.efi as \\EFI\\BOOT\\BOOTX64.EFI)"

# 2c. INSTALLER §C(ii)/§D (FDE + Hidden): the PREBOOT ESP — an 8 MiB FAT32 ESP holding ONLY the
#     VeraCrypt-style pre-boot authenticator as \EFI\BOOT\BOOTX64.EFI.  Both the Full-disk and the
#     Hidden-OS installs use this as GPT partition 0: it is the ONLY plaintext on an encrypted disk.
#     It carries NO boot tree, NO stage2, NO install.json (§D: "the preboot ESP has no install.json")
#     and NO anos.key — the real boot tree + key placeholder live inside the ENCRYPTED esp-image
#     payload that the preboot decrypts into RAM.  This replaces the 512 MiB esp-hidden-image, which
#     bundled the whole plaintext boot tree (a deniability hole).
dd if=/dev/zero of=esp-preboot.img bs=1M count=8 status=none
mkfs.fat -F 16 -s 1 -n EPINPRE esp-preboot.img >/dev/null    # FAT16: see esp-boot.img above
mmd -i esp-preboot.img ::/EFI ::/EFI/BOOT
mcopy -i esp-preboot.img "$PREBOOT_EFI" ::/EFI/BOOT/BOOTX64.EFI
echo "  esp-preboot.img: $(du -h esp-preboot.img | cut -f1) (preboot.efi as \\EFI\\BOOT\\BOOTX64.EFI; no boot tree, no install.json)"

# 3. (REMOVED) the 512 MiB "hidden-esp.img" -- preboot.efi + stage2.efi + the WHOLE PLAINTEXT boot
#    tree -- is no longer built or staged.  Encrypted installs (Full disk and Hidden OS) boot through
#    esp-preboot.img (2c above), and the boot tree exists on disk only inside the XTS-encrypted
#    esp-image payload the pre-boot loader decrypts into RAM.  Dropping it also takes 512 MiB off
#    the live installer's RAM footprint (Limine loads every boot module into memory).  The kernel
#    still accepts an esp-hidden-image from an older ISO, with a warning.

# 4. stage them as installer boot modules + advertise them to limine.
cp esp.img cd/esp-image
cp esp-boot.img cd/esp-boot-image
cp esp-preboot.img cd/esp-preboot-image   # §C(ii)/§D: preboot-only ESP for encrypted installs
printf '\n    module_path: boot():/esp-image\n' >> "$LIMCONF"
printf '\n    module_path: boot():/esp-boot-image\n' >> "$LIMCONF"
printf '\n    module_path: boot():/esp-preboot-image\n' >> "$LIMCONF"

# 5. package the installer ISO using the same Limine/xorriso options as the staged boot tree expects.
xorriso -as mkisofs \
    -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image \
    --protective-msdos-label \
    cd -o hos-install.iso 2>/dev/null

echo "==== built hos-install.iso ($(du -h hos-install.iso | cut -f1)) ===="
echo "  Boot it (UEFI) with a blank target disk; the installer writes the OS to that disk."
