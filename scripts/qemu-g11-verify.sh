#!/usr/bin/env bash
# GUI roadmap G11 verification: boot the toolkit rendering demo, require the
# bundled font-backed Cairo/FreeType wl_shm client to map, then check pixels.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G11_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=cairo hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g11-hmp.sock"
SHOT="/tmp/epin-g11.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m "${G11_MEM:-512}" \
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
       grep -aq "G11 COMMIT" "$SERIAL" 2>/dev/null &&
       grep -aq "G11 REDRAW" "$SERIAL" 2>/dev/null &&
       grep -aq "Map request dispatched" "$SERIAL" 2>/dev/null; then
        ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ -S "$MON" ]; then
    sleep "${G11_SETTLE_SECONDS:-3}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G11_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g11-hmp.out 2>/tmp/g11-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G11 serial markers ===="
grep -aE "G11|Map request dispatched|wl_shm software compositor blitted|\\[assets\\]|OOM" "$SERIAL" | tail -120 || true
echo "==== G11 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G11 FAIL: toolkit demo did not load its font, map, and redraw before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("G11 FAIL: missing screendump")
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
    print("G11 FAIL: unsupported or truncated PPM")
    sys.exit(4)

stats = {
    "whitecard": 0,
    "teal": 0,
    "purple": 0,
    "blue": 0,
    "gold": 0,
    "text_dark": 0,
    "aa_text": 0,
}
for y in range(height):
    row = y * width * 3
    for x in range(width):
        off = row + x * 3
        r, g, b = pixels[off], pixels[off + 1], pixels[off + 2]
        mx, mn = max(r, g, b), min(r, g, b)
        if r > 215 and g > 225 and b > 230:
            stats["whitecard"] += 1
        if g > 110 and b > 90 and r < 80:
            stats["teal"] += 1
        if r > 100 and b > 130 and g < 100:
            stats["purple"] += 1
        if b > 150 and g > 100 and r < 100:
            stats["blue"] += 1
        if r > 190 and g > 130 and b < 80:
            stats["gold"] += 1
        if 340 <= x <= 950 and 210 <= y <= 610:
            if r < 95 and g < 110 and b < 135:
                stats["text_dark"] += 1
            if 80 <= mx <= 210 and mx - mn <= 45:
                stats["aa_text"] += 1

print("G11 screenshot stats: " + " ".join(f"{k}={v}" for k, v in stats.items()))
thresholds = {
    "whitecard": 80000,
    "teal": 4000,
    "purple": 500,
    "blue": 150,
    "gold": 3000,
    "text_dark": 2500,
    "aa_text": 500,
}
for key, minimum in thresholds.items():
    if stats[key] < minimum:
        print(f"G11 FAIL: {key} below threshold: {stats[key]} < {minimum}")
        sys.exit(5)

print("G11 PASS: Cairo/FreeType toolkit demo renders controls and antialiased text")
PY
