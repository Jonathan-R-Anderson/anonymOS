#!/usr/bin/env bash
# GUI roadmap G9 verification: boot the ISO, require the terminal to load the
# bundled FreeType font, then check the screendump for antialiased text pixels.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G9_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=term hos.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g9-hmp.sock"
SHOT="/tmp/epin-g9.ppm"
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

deadline=$(( $(date +%s) + 420 ))
ready=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "G9FONT: loaded" "$SERIAL" 2>/dev/null &&
       grep -aq "G4 COMMIT" "$SERIAL" 2>/dev/null &&
       grep -aq "Map request dispatched" "$SERIAL" 2>/dev/null &&
       grep -aq "G9 REDRAW" "$SERIAL" 2>/dev/null; then
        ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [ -S "$MON" ]; then
    sleep "${G9_SETTLE_SECONDS:-3}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G9_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g9-hmp.out 2>/tmp/g9-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G9 serial markers ===="
grep -aE "G9FONT:|G9FRAME:|G4TERM:|G4OUT:|\\[assets\\]|Map request dispatched|wl_shm software compositor blitted" "$SERIAL" | tail -120 || true
echo "==== G9 screendump ===="
ls -l "$SHOT" 2>/dev/null || true
file "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G9 FAIL: terminal did not load bundled FreeType font and redraw after map before timeout"
    exit 2
fi

python3 - "$SHOT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("G9 FAIL: missing screendump")
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
    print("G9 FAIL: unsupported or truncated PPM")
    sys.exit(4)

band_w = min(width, 920)
band_h = min(height, 520)
bright = 0
dark = 0
aa = 0
aa_colors = set()
for y in range(band_h):
    row = y * width * 3
    for x in range(band_w):
        off = row + x * 3
        r, g, b = pixels[off], pixels[off + 1], pixels[off + 2]
        mx = max(r, g, b)
        mn = min(r, g, b)
        if r > 180 and g > 180 and b > 180:
            bright += 1
        if r < 25 and g < 25 and b < 25:
            dark += 1
        if 35 <= mx <= 190 and mx - mn <= 16:
            aa += 1
            if len(aa_colors) < 64:
                aa_colors.add((r, g, b))

print(
    "G9 screenshot stats: "
    f"bright={bright} dark={dark} antialias_mid_pixels={aa} "
    f"antialias_color_samples={len(aa_colors)}"
)
if bright < 1000 or dark < 1000:
    print("G9 FAIL: screendump lacks visible terminal text")
    sys.exit(5)
if aa < 150 or len(aa_colors) < 6:
    print("G9 FAIL: terminal text does not show enough antialiased edge pixels")
    sys.exit(6)

print("G9 PASS: bundled FreeType terminal text is antialiased in QEMU screendump")
PY
