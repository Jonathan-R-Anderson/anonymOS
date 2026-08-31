#!/usr/bin/env bash
# GUI roadmap G14 verification: boot the toolkit demo and require the CPU
# present path to draw a polished bottom dock (rounded translucent shelf with
# coloured launcher tiles and an identity-accent running indicator) below the
# desktop, without overlapping the application window.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G14_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=cairo hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g14-hmp.sock"
SHOT="/tmp/epin-g14.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m "${G14_MEM:-512}" \
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

deadline=$(( $(date +%s) + 300 ))
ready=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "G11FONT: loaded" "$SERIAL" 2>/dev/null &&
       grep -aq "G11 REDRAW" "$SERIAL" 2>/dev/null &&
       grep -aq "HOS G14 dock rendered" "$SERIAL" 2>/dev/null &&
       grep -aq "renderer: HOS G6 wl_shm software compositor blitted 1 surface(s)" "$SERIAL" 2>/dev/null; then
        ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ -S "$MON" ]; then
    sleep "${G14_SETTLE_SECONDS:-3}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G14_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g14-hmp.out 2>/tmp/g14-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G14 serial markers ===="
grep -aE "G11|G14 dock|wl_shm software compositor blitted|\\[assets\\]|OOM" "$SERIAL" | tail -120 || true
echo "==== G14 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G14 FAIL: toolkit window and dock frame were not ready before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("G14 FAIL: missing screendump")
    sys.exit(3)

data = path.read_bytes()
idx = 0

def token():
    global idx
    while idx < len(data) and data[idx] in b" \t\r\n":
        idx += 1
    if idx < len(data) and data[idx:idx + 1] == b"#":
        while idx < len(data) and data[idx] not in b"\r\n":
            idx += 1
        return token()
    start = idx
    while idx < len(data) and data[idx] not in b" \t\r\n":
        idx += 1
    return data[start:idx]

magic = token()
width = int(token())
height = int(token())
max_value = int(token())
while idx < len(data) and data[idx] in b" \t\r\n":
    idx += 1
pixels = data[idx:]
if magic != b"P6" or max_value != 255 or len(pixels) < width * height * 3:
    print("G14 FAIL: unsupported or truncated PPM")
    sys.exit(4)

# Dock geometry (must track GLRenderer hosDrawDock): the shelf sits in the
# bottom HOS_DOCK_REGION_H band, centred horizontally, with a tile row.
cx_lo = width // 2 - 200       # comfortably wider than the centred pill
cx_hi = width // 2 + 200
tile_y0 = height - 74          # launcher tile row
tile_y1 = height - 26
shelf_y0 = height - 88         # whole shelf pill
shelf_y1 = height - 12
gap_y0 = height - 103          # reserved gap strip above the dock region
gap_y1 = height - 96

stats = {
    "shelf_dark": 0,     # translucent dark shelf over the wallpaper
    "amber_tile": 0,     # Files launcher
    "blue_tile": 0,      # Editor launcher
    "green_tile": 0,     # Monitor launcher
    "accent_dot": 0,     # identity-accent running indicator (cyan)
    "tile_aa": 0,        # antialiased / partial edge pixels on the tiles
    "gap_window_white": 0,  # window must be shrunk clear of the dock region
}

for y in range(height - 104, height):
    row = y * width * 3
    for x in range(width):
        if not (cx_lo <= x <= cx_hi):
            continue
        off = row + x * 3
        r, g, b = pixels[off], pixels[off + 1], pixels[off + 2]
        if shelf_y0 <= y <= shelf_y1 and r < 60 and g < 60 and b < 78:
            stats["shelf_dark"] += 1
        if tile_y0 <= y <= tile_y1:
            if r > 180 and g > 120 and b < 110:
                stats["amber_tile"] += 1
            if b > 180 and r < 150 and g < 190:
                stats["blue_tile"] += 1
            if g > 150 and r < 120 and 90 < b < 200:
                stats["green_tile"] += 1
            if 70 <= r <= 150 and 70 <= g <= 150 and 70 <= b <= 165:
                stats["tile_aa"] += 1
        if tile_y0 <= y <= shelf_y1 and r < 130 and g > 150 and b > 205:
            stats["accent_dot"] += 1
        if gap_y0 <= y <= gap_y1 and r > 215 and g > 225 and b > 230:
            stats["gap_window_white"] += 1

print("G14 screenshot stats: " + " ".join(f"{k}={v}" for k, v in stats.items()))

thresholds = {
    "shelf_dark": 3000,
    "amber_tile": 600,
    "blue_tile": 600,
    "green_tile": 600,
    "accent_dot": 10,
    "tile_aa": 200,
}
for key, minimum in thresholds.items():
    if stats[key] < minimum:
        print(f"G14 FAIL: {key} below threshold: {stats[key]} < {minimum}")
        sys.exit(5)
if stats["gap_window_white"] > 200:
    print(f"G14 FAIL: window not reserved clear of the dock region: {stats['gap_window_white']}")
    sys.exit(6)

print("G14 PASS: bottom dock renders launcher tiles and a running indicator below the desktop")
PY
