#!/usr/bin/env bash
# GUI roadmap G13 verification: boot the toolkit demo and require the CPU
# present path to draw a persistent top panel above the window.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G13_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=cairo hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g13-hmp.sock"
SHOT="/tmp/epin-g13.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m "${G13_MEM:-512}" \
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
    sleep "${G13_SETTLE_SECONDS:-3}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G13_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g13-hmp.out 2>/tmp/g13-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G13 serial markers ===="
grep -aE "G11|Map request dispatched|wl_shm software compositor blitted|\\[assets\\]|OOM" "$SERIAL" | tail -120 || true
echo "==== G13 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G13 FAIL: toolkit window and panel frame were not ready before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("G13 FAIL: missing screendump")
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
    print("G13 FAIL: unsupported or truncated PPM")
    sys.exit(4)

stats = {
    "panel_dark": 0,
    "panel_text": 0,
    "status_text": 0,
    "clock_text": 0,
    "teal_logo": 0,
    "gold_logo": 0,
    "divider": 0,
    "top_white_intrusion": 0,
    "window_white": 0,
}
for y in range(height):
    row = y * width * 3
    for x in range(width):
        off = row + x * 3
        r, g, b = pixels[off], pixels[off + 1], pixels[off + 2]
        if y < 35 and r < 35 and g < 45 and b < 65:
            stats["panel_dark"] += 1
        if 6 <= y <= 29 and 45 <= x <= 330 and r > 205 and g > 215 and b > 225:
            stats["panel_text"] += 1
        if 6 <= y <= 29 and width - 290 <= x <= width - 150 and r > 180 and g > 190 and b > 200:
            stats["status_text"] += 1
        if 6 <= y <= 29 and width - 100 <= x <= width - 15 and r > 215 and g > 220 and b > 225:
            stats["clock_text"] += 1
        if y < 35 and 10 <= x <= 42 and g > 90 and r < 45 and b < 140:
            stats["teal_logo"] += 1
        if y < 35 and 10 <= x <= 42 and r > 180 and g > 125 and b < 95:
            stats["gold_logo"] += 1
        if 34 <= y <= 36 and b > 120 and g > 90 and r < 100:
            stats["divider"] += 1
        if 36 <= y < 44 and r > 210 and g > 220 and b > 225:
            stats["top_white_intrusion"] += 1
        if y > 70 and r > 215 and g > 225 and b > 230:
            stats["window_white"] += 1

print("G13 screenshot stats: " + " ".join(f"{k}={v}" for k, v in stats.items()))
thresholds = {
    "panel_dark": width * 18,
    "panel_text": 250,
    "status_text": 80,
    "clock_text": 80,
    "teal_logo": 40,
    "gold_logo": 40,
    "divider": 500,
    "window_white": 80000,
}
for key, minimum in thresholds.items():
    if stats[key] < minimum:
        print(f"G13 FAIL: {key} below threshold: {stats[key]} < {minimum}")
        sys.exit(5)
if stats["top_white_intrusion"] > 50:
    print(f"G13 FAIL: window appears to overlap the reserved panel area: {stats['top_white_intrusion']}")
    sys.exit(6)

print("G13 PASS: top panel renders above the desktop window")
PY
