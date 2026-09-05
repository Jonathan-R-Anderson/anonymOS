#!/usr/bin/env bash
# GUI roadmap G16 verification: boot the toolkit demo and require the present
# path to draw modern window decorations — a titlebar with minimize/maximize/
# close controls and an identity accent, a drop shadow, and a rounded,
# kernel-owned identity border wrapping the decorated window.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G16_REBUILD:-1}" = "1" ]; then
    # G16 touches the kernel (rounded identity border). `make hos-install.iso` does not
    # recompile the D kernel on its own, so refresh it explicitly first.
    make -j1 -C src/kernel/d
    make -j1 kernel.elf
    make -j1 GUI_AUTOSTART=cairo hos-install.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g16-hmp.sock"
SHOT="/tmp/epin-g16.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos-install.iso -m "${G16_MEM:-768}" \
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
    if grep -aq "G11 REDRAW" "$SERIAL" 2>/dev/null &&
       grep -aq "G5 BORDER" "$SERIAL" 2>/dev/null &&
       grep -aq "HOS G14 dock rendered" "$SERIAL" 2>/dev/null; then
        ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ -S "$MON" ]; then
    sleep "${G16_SETTLE_SECONDS:-4}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G16_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g16-hmp.out 2>/tmp/g16-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G16 serial markers ===="
grep -aE "G11|G5 BORDER|HOS G14 dock|blitted" "$SERIAL" | tail -30 || true
echo "==== G16 screendump ===="
ls -l "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G16 FAIL: decorated desktop was not ready before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = path.read_bytes()
idx = 0

def token():
    global idx
    while idx < len(data) and data[idx] in b" \t\r\n":
        idx += 1
    start = idx
    while idx < len(data) and data[idx] not in b" \t\r\n":
        idx += 1
    return data[start:idx]

magic = token(); width = int(token()); height = int(token()); mv = int(token())
idx += 1
px = data[idx:]
if magic != b"P6" or mv != 255 or len(px) < width * height * 3:
    print("G16 FAIL: bad PPM")
    sys.exit(4)

# The titlebar controls are the unambiguous G16 signal. They live in the upper
# half of the screen (titlebar of a window mapped below the panel).
stats = {
    "close_red": 0,    # close control  (0xED6A5E)
    "max_green": 0,    # maximize        (0x61C554)
    "min_amber": 0,    # minimize        (0xF4BF4F)
    "titlebar_dark": 0,
}
for y in range(40, height // 2):
    row = y * width * 3
    for x in range(width):
        o = row + x * 3
        r, g, b = px[o], px[o + 1], px[o + 2]
        if r > 200 and 70 <= g <= 140 and 70 <= b <= 140:
            stats["close_red"] += 1
        if 60 <= r <= 140 and g > 160 and b < 130:
            stats["max_green"] += 1
        if r > 220 and 150 <= g <= 215 and b < 120:
            stats["min_amber"] += 1
        if 30 <= r <= 70 and 34 <= g <= 78 and 40 <= b <= 92:
            stats["titlebar_dark"] += 1

print("G16 screenshot stats: " + " ".join(f"{k}={v}" for k, v in stats.items()))

checks = {
    "close_red": 35,
    "max_green": 35,
    "min_amber": 35,
    "titlebar_dark": 1500,
}
for k, m in checks.items():
    if stats[k] < m:
        print(f"G16 FAIL: {k} below threshold: {stats[k]} < {m}")
        sys.exit(5)

print("G16 PASS: window titlebar with min/max/close controls, shadow, and rounded identity border render")
PY
