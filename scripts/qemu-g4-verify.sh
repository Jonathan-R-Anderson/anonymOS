#!/usr/bin/env bash
# GUI roadmap G4 verification: boot the ISO headless with a QMP socket, wait for
# the software terminal to spawn its shell on a kernel PTY, then type a command
# over the PS/2 keyboard and confirm the shell ran it.
#
# Success markers (serial.log):
#   "New keyboard created"               -> Hyprland enumerated the bridged kbd
#   "G4TERM: ... G4 COMMIT"              -> terminal window mapped
#   "G4TERM: spawned shell ... G4 SHELL" -> busybox running on the PTY
#   "G4KEY: keyboard enter ... G4 FOCUS" -> terminal got keyboard focus
#   "G4OUT: g4pass"                      -> typed `echo g4pass` ran in the shell
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G4_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=term hos.iso
fi

SERIAL="$ROOT/serial.log"
QMP="/tmp/g4-qmp.sock"
rm -f "$SERIAL" "$QMP"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" \
  -qmp "unix:$QMP,server,nowait" &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null' EXIT

python3 "$ROOT/scripts/qemu-key-inject.py" "$QMP" "$SERIAL"
RC=$?

echo "==== G4 serial markers ===="
grep -aE "New keyboard created|G4TERM:|G4KEY:|G4OUT:|bridging kernel evdev keyboard" "$SERIAL" | head -40 || true
exit $RC
