#!/usr/bin/env bash
# GUI roadmap G12 verification: boot without clients and require the compositor
# present path to draw a non-flat default wallpaper into the framebuffer.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G12_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=none hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g12-hmp.sock"
SHOT="/tmp/epin-g12.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m "${G12_MEM:-512}" \
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

deadline=$(( $(date +%s) + 240 ))
ready=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "renderer: using HOS CPU-readback clear frame path" "$SERIAL" 2>/dev/null &&
       grep -aq "renderer: HOS G6 wl_shm software compositor blitted 0 surface(s)" "$SERIAL" 2>/dev/null; then
        ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ -S "$MON" ]; then
    sleep "${G12_SETTLE_SECONDS:-3}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G12_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g12-hmp.out 2>/tmp/g12-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G12 serial markers ===="
grep -aE "renderer: using HOS|wl_shm software compositor blitted|\\[assets\\]|OOM|G11" "$SERIAL" | tail -100 || true
echo "==== G12 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G12 FAIL: compositor wallpaper frame was not presented before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("G12 FAIL: missing screendump")
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
    print("G12 FAIL: unsupported or truncated PPM")
    sys.exit(4)

stats = {
    "blackish": 0,
    "old_clear": 0,
    "teal": 0,
    "purple": 0,
    "warm": 0,
    "mist": 0,
}
samples = set()
for y in range(height):
    row = y * width * 3
    for x in range(width):
        off = row + x * 3
        r, g, b = pixels[off], pixels[off + 1], pixels[off + 2]
        if r < 25 and g < 25 and b < 30:
            stats["blackish"] += 1
        if 10 <= r <= 22 and 18 <= g <= 32 and 24 <= b <= 40:
            stats["old_clear"] += 1
        if g > 85 and b > 60 and r < 95:
            stats["teal"] += 1
        if r > 70 and b > 115 and g < 125:
            stats["purple"] += 1
        if r > 120 and g > 85 and b < 100:
            stats["warm"] += 1
        if r > 120 and g > 130 and b > 135:
            stats["mist"] += 1
        if (x & 7) == 0 and (y & 7) == 0:
            samples.add((r, g, b))

print("G12 screenshot stats: " + " ".join(f"{k}={v}" for k, v in stats.items()) + f" unique8={len(samples)}")
thresholds = {
    "teal": 40000,
    "purple": 10000,
    "warm": 40000,
}
for key, minimum in thresholds.items():
    if stats[key] < minimum:
        print(f"G12 FAIL: {key} below threshold: {stats[key]} < {minimum}")
        sys.exit(5)
if stats["old_clear"] > width * height // 8:
    print(f"G12 FAIL: old flat clear color still dominates: {stats['old_clear']}")
    sys.exit(6)
if len(samples) < 256:
    print(f"G12 FAIL: wallpaper is too flat: unique8={len(samples)}")
    sys.exit(7)

print("G12 PASS: default wallpaper fills the boot desktop")
PY
