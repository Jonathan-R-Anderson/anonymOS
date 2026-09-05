#!/usr/bin/env bash
# GUI roadmap G5 verification: boot the ISO and confirm the kernel draws trusted
# identity-coloured window borders in the present blit.  The autostarted terminal
# maps a window; Hyprland reports its rect+pid (DRM ioctl 0xF1); the kernel paints
# a border in drmPresentToFramebuffer and logs it once.
#
# Success marker (serial.log):
#   "[g5] drew identity borders for ... -- G5 BORDER"
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SERIAL="$ROOT/serial.log"
rm -f "$SERIAL"

qemu-system-x86_64 \
  -boot d -cdrom hos-install.iso -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null' EXIT

deadline=$(( $(date +%s) + 600 ))
rc=2
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "G5 BORDER" "$SERIAL" 2>/dev/null; then rc=0; break; fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then break; fi
    sleep 5
done

echo "==== G5 serial markers ===="
grep -aE "G5 BORDER|G4 COMMIT|Map request dispatched" "$SERIAL" | head -10 || true
exit $rc
