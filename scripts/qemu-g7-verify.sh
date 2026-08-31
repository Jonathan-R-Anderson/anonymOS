#!/usr/bin/env bash
# GUI roadmap G7 verification: boot the ISO, capture a QEMU screendump, and
# require the image dimensions to match the selected display target.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

EXPECT_W="${1:-1280}"
EXPECT_H="${2:-800}"
EXPECT_SCALE="${DISPLAY_SCALE:-1}"
EXPECT_REFRESH="${DISPLAY_REFRESH:-60}"
EXPECT_FORCE="${DISPLAY_FORCE_MODE:-0}"

if [ "${G7_REBUILD:-0}" = "1" ]; then
    make -j1 DISPLAY_WIDTH="$EXPECT_W" DISPLAY_HEIGHT="$EXPECT_H" \
        DISPLAY_SCALE="$EXPECT_SCALE" DISPLAY_REFRESH="$EXPECT_REFRESH" \
        DISPLAY_FORCE_MODE="$EXPECT_FORCE" hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g7-hmp.sock"
SHOT="/tmp/epin-g7-${EXPECT_W}x${EXPECT_H}.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" \
  -monitor "unix:$MON,server,nowait" &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$(( $(date +%s) + 360 ))
display_ready=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "Framebuffer:" "$SERIAL" 2>/dev/null && grep -aq "headless: display mode" "$SERIAL" 2>/dev/null; then
        display_ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ "$display_ready" -eq 0 ]; then
    sleep "${G7_SETTLE_SECONDS:-20}"
fi

if [ -S "$MON" ]; then
    printf 'screendump %s\nquit\n' "$SHOT" | nc -U "$MON" >/tmp/g7-hmp.out 2>/tmp/g7-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G7 serial display markers ===="
grep -aE "Framebuffer:|\\[display\\]|headless: display mode|G4TERM:|Map request dispatched" "$SERIAL" | tail -80 || true
echo "==== G7 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$display_ready" -ne 0 ]; then
    echo "G7 FAIL: display did not initialize before timeout"
    exit 2
fi

python3 - "$SHOT" "$EXPECT_W" "$EXPECT_H" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
expect_w = int(sys.argv[2])
expect_h = int(sys.argv[3])
if not path.exists():
    print("G7 FAIL: missing screendump")
    sys.exit(3)

data = path.read_bytes()
idx = 0

def read_token():
    global idx
    while idx < len(data) and data[idx] in b" \t\r\n":
        idx += 1
    if idx < len(data) and data[idx:idx + 1] == b"#":
        while idx < len(data) and data[idx] not in b"\r\n":
            idx += 1
        return read_token()
    start = idx
    while idx < len(data) and data[idx] not in b" \t\r\n":
        idx += 1
    return data[start:idx]

magic = read_token()
width = int(read_token())
height = int(read_token())
max_value = int(read_token())
if magic != b"P6" or max_value != 255:
    print("G7 FAIL: unsupported PPM screendump")
    sys.exit(4)

print(f"G7 screenshot size: {width}x{height}")
if width != expect_w or height != expect_h:
    print(f"G7 FAIL: expected {expect_w}x{expect_h}, got {width}x{height}")
    sys.exit(5)

print(f"G7 PASS: screendump resolution is {width}x{height}")
PY
