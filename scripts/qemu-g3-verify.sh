#!/usr/bin/env bash
# GUI roadmap G3 verification: boot the ISO headless with a QMP socket, wait for
# the G2 client window to map, then inject PS/2 mouse motion + a left click via
# QEMU input-send-event and capture the serial markers proving the cursor moved
# and the click was routed to the focused surface.
#
# Success markers (in serial.log):
#   "New mouse created, pointer AQ:"      -> aquamarine pointer enumerated
#   "G3PTR: pointer enter"                -> client received pointer focus
#   "G3PTR: button 0x110 state 1 -- G3 CLICK" -> left click delivered to surface
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SERIAL="$ROOT/serial.log"
QMP="/tmp/g3-qmp.sock"
rm -f "$SERIAL" "$QMP"

qemu-system-x86_64 \
  -boot d -cdrom hos-install.iso -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" \
  -qmp "unix:$QMP,server,nowait" &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null' EXIT

python3 "$ROOT/scripts/qemu-mouse-inject.py" "$QMP" "$SERIAL"
RC=$?

echo "==== G3 serial markers ===="
grep -aE "New mouse created, pointer AQ|G3PTR:|bridging kernel evdev|Map request" "$SERIAL" || true
exit $RC
