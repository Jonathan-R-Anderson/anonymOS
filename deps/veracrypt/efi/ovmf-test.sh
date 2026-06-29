#!/usr/bin/env bash
# §E5b — boot the pre-boot loader .efi in real UEFI firmware (OVMF) against an install
# disk and capture the decoy/hidden/reject routing self-test over serial.
#   usage: ovmf-test.sh <install-disk.img>   (a disk with the §E4b/E5 install layout)
set -euo pipefail
DISK="${1:?usage: ovmf-test.sh <install-disk.img>}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BLD="$ROOT/deps/veracrypt/build"
OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd

make -C "$ROOT/deps/veracrypt" efi

ESP="$BLD/esp.img"; dd if=/dev/zero of="$ESP" bs=1M count=48 status=none
mformat -i "$ESP" -F ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$BLD/preboot.efi" ::/EFI/BOOT/BOOTX64.EFI
cp "$OVMF_VARS" "$BLD/OVMF_VARS.fd"

LOG="$BLD/serial-efi.log"; rm -f "$LOG"
qemu-system-x86_64 -enable-kvm -m 256 \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$BLD/OVMF_VARS.fd" \
  -drive file="$ESP",format=raw,if=ide \
  -drive file="$DISK",format=raw,if=ide \
  -serial file:"$LOG" -display none -no-reboot &
QPID=$!
for _ in $(seq 1 30); do grep -qE "SELFTEST DONE|not found" "$LOG" 2>/dev/null && break; sleep 1; done
sleep 1; kill -9 $QPID 2>/dev/null || true
echo "=== pre-boot loader routing (OVMF serial) ==="
grep -aE "preboot-efi|-> (DECOY|HIDDEN|REJECT)" "$LOG" | tr -d '\000'
