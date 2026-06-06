#!/usr/bin/env bash
# GUI roadmap G6 verification: boot the ISO, wait for the wl_shm terminal window
# to map, capture a QEMU screendump, and require visible glyph pixels in the
# terminal region. This is intentionally screenshot-based; serial-only mapping
# is not enough for G6.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G6_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=term hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g6-hmp.sock"
SHOT="/tmp/epin-g6.ppm"
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
mapped=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "G4 COMMIT" "$SERIAL" 2>/dev/null && grep -aq "Map request dispatched" "$SERIAL" 2>/dev/null; then
        mapped=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ -S "$MON" ]; then
    printf 'screendump %s\nquit\n' "$SHOT" | nc -U "$MON" >/tmp/g6-hmp.out 2>/tmp/g6-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G6 serial markers ===="
grep -aE "G4TERM:|Map request dispatched|G5 BORDER|HOS G6|Invalid rectangle" "$SERIAL" | tail -40 || true
echo "==== G6 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$mapped" -ne 0 ]; then
    echo "G6 FAIL: terminal did not map before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("G6 FAIL: missing screendump")
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
while idx < len(data) and data[idx] in b" \t\r\n":
    idx += 1

pixels = data[idx:]
if magic != b"P6" or max_value != 255 or len(pixels) < width * height * 3:
    print("G6 FAIL: unsupported or truncated PPM")
    sys.exit(4)

# The terminal maps near the top of the 1280x800 output.  Count bright glyph
# pixels in that band; a black interior or border-only frame will not pass this.
bright = 0
dark = 0
band_h = min(height, 140)
for y in range(band_h):
    row = y * width * 3
    for x in range(width):
        off = row + x * 3
        r, g, b = pixels[off], pixels[off + 1], pixels[off + 2]
        if r > 180 and g > 180 and b > 180:
            bright += 1
        if r < 20 and g < 20 and b < 20:
            dark += 1

print(f"G6 screenshot stats: bright_top_pixels={bright} dark_top_pixels={dark}")
if bright < 1000 or dark < 1000:
    print("G6 FAIL: screendump lacks visible terminal text")
    sys.exit(5)

print("G6 PASS: wl_shm terminal contents are visible in QEMU screendump")
PY
