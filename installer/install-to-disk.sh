#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# EpinAnonymOS — disk installer
#
# Installs the live boot payload (kernel + modules + limine config, i.e. the `cd/`
# tree produced by `make hos.iso`) onto a bootable UEFI/GPT hard-disk image.
# The disk gets a GPT label with a single EFI System Partition (FAT32) holding the
# limine UEFI bootloader (BOOTX64.EFI) and the whole boot payload, so the firmware
# boots straight into EpinAnonymOS from the disk — no ISO/CD.
#
# No root required: the ESP is formatted + populated in place with mtools
# (mformat/mcopy via the `image@@offset` syntax), never a loopback mount.
#
# Usage:
#   make hos.iso                 # produce the boot payload (cd/) first
#   installer/install-to-disk.sh [OUT_IMAGE]
#     OUT_IMAGE   target disk image (default: hos-installed.img)
#     SIZE_MB=N   disk size override (default: payload size + headroom)
#
# Then boot it:   installer/boot-installed.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-hos-installed.img}"
CD="cd"
LIMINE_DIR="deps/bdepend/boot/limine-bin"
LIMINE_X64="$LIMINE_DIR/BOOTX64.EFI"
LIMINE_IA32="$LIMINE_DIR/BOOTIA32.EFI"

say() { printf '\033[1;36m[installer]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[installer] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0. preconditions ─────────────────────────────────────────────────────────
[ -d "$CD" ] && [ -f "$CD/boot/kernel.elf" ] \
  || die "boot payload missing — run 'make hos.iso' first (no $CD/boot/kernel.elf)"
[ -f "$CD/boot/limine/limine.conf" ] || die "$CD/boot/limine/limine.conf missing"
[ -f "$LIMINE_X64" ] || die "limine UEFI app missing: $LIMINE_X64"
for t in sgdisk mformat mcopy mmd truncate du; do
  command -v "$t" >/dev/null 2>&1 || die "missing host tool: $t  (apt install gdisk mtools)"
done

# ── 1. size the disk to the payload ──────────────────────────────────────────
NEED_MB=$(du -sm "$CD" | awk '{print $1}')
SIZE_MB="${SIZE_MB:-$(( NEED_MB + 96 ))}"          # FAT + GPT overhead headroom
[ "$SIZE_MB" -gt $(( NEED_MB + 48 )) ] || SIZE_MB=$(( NEED_MB + 96 ))
say "payload ${NEED_MB} MB  →  disk image ${SIZE_MB} MB  ($OUT)"

# ── 2. raw disk + GPT (one ESP spanning the disk) ────────────────────────────
rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
sgdisk --clear \
       --new=1:2048:0 \
       --typecode=1:EF00 \
       --change-name=1:"EPINANONYMOS" \
       "$OUT" >/dev/null
say "GPT written: partition 1 = EFI System Partition (type EF00)"

PART_OFFSET=$(( 2048 * 512 ))                       # 1 MiB, sector 2048

# ── 3. format the ESP as FAT32 in place (no loopback) ────────────────────────
# -F = FAT32, -v = volume label.  mtools addresses the partition via image@@offset.
mformat -i "$OUT@@$PART_OFFSET" -F -v EPINANONOS ::
say "ESP formatted FAT32 (label EPINANONOS)"

mtools() { local sub="$1"; shift; "m$sub" -i "$OUT@@$PART_OFFSET" "$@"; }

# ── 4. limine UEFI bootloader → /EFI/BOOT/ ───────────────────────────────────
mtools md ::/EFI ::/EFI/BOOT
mtools copy "$LIMINE_X64" ::/EFI/BOOT/BOOTX64.EFI
[ -f "$LIMINE_IA32" ] && mtools copy "$LIMINE_IA32" ::/EFI/BOOT/BOOTIA32.EFI
say "installed limine UEFI app → /EFI/BOOT/BOOTX64.EFI"

# ── 5. the boot payload (kernel + modules + limine.conf), preserving cd/ layout ─
#   limine.conf references boot():/boot/kernel.elf and boot():/<module>, and the
#   loader searches /boot/limine/limine.conf — so the ESP is just a copy of cd/.
say "copying boot payload (${NEED_MB} MB) onto the ESP…"
mtools copy -s "$CD"/* ::/
say "payload installed"

# ── 6. done ──────────────────────────────────────────────────────────────────
cat <<EOF

$(printf '\033[1;32m✓ EpinAnonymOS installed to %s\033[0m' "$OUT")
  layout : GPT / 1× EFI System Partition (FAT32) / limine UEFI
  boot   : installer/boot-installed.sh        (QEMU + OVMF, boots from the disk)
  real HW: write it to a USB stick / disk, e.g.  sudo dd if=$OUT of=/dev/sdX bs=4M conv=fsync
EOF
