#!/bin/bash
# Run anonymOS ISO with virtualization support (KVM if available).
set -e
DRY_RUN=no
while [[ "$1" == --* ]]; do
  case "$1" in
    --dry-run) DRY_RUN=yes ; shift ;;
    *) break ;;
  esac
done
ISO="build/anonymOS.iso"
if [ "$DRY_RUN" = no ] && [ ! -f "$ISO" ]; then
  echo "ISO image $ISO not found. Build it first (make iso)." >&2
  exit 1
fi
QEMU="qemu-system-x86_64"
CMD="$QEMU -cdrom $ISO -m 128M -display curses -vga std \
    -d int,guest_errors -D qemu.log -debugcon file:qemu.log -serial file:qemu.log"
if grep -q -E '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then
  CMD="$CMD --enable-kvm"
fi
if [ "$DRY_RUN" = yes ]; then
  echo "$CMD $*"
else
  eval "$CMD $*"
fi
