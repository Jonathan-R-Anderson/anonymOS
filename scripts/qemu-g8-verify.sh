#!/usr/bin/env bash
# GUI roadmap G8 verification: boot the ISO, capture the mapped terminal,
# inject keyboard input, then require a post-input screendump to differ in the
# terminal band. This catches "client committed but no new present happened"
# regressions that serial-only tests miss.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G8_REBUILD:-1}" = "1" ]; then
    make -j1 GUI_AUTOSTART=term hos-install.iso
fi

SERIAL="$ROOT/serial.log"
QMP="/tmp/g8-qmp.sock"
MON="/tmp/g8-hmp.sock"
BEFORE="/tmp/epin-g8-before.ppm"
AFTER="/tmp/epin-g8-after.ppm"
rm -f "$SERIAL" "$QMP" "$MON" "$BEFORE" "$AFTER"

qemu-system-x86_64 \
  -boot d -cdrom hos-install.iso -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" \
  -qmp "unix:$QMP,server,nowait" \
  -monitor "unix:$MON,server,nowait" &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$(( $(date +%s) + 420 ))
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

if [ "$mapped" -eq 0 ]; then
    G4_FOCUS_ONLY=1 python3 "$ROOT/scripts/qemu-key-inject.py" "$QMP" "$SERIAL"
    FOCUS_RC=$?
    if [ "$FOCUS_RC" -eq 0 ]; then
        sleep "${G8_BASELINE_SETTLE_SECONDS:-3}"
    fi
    printf 'screendump %s\n' "$BEFORE" | timeout "${G8_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g8-hmp-before.out 2>/tmp/g8-hmp-before.err || true
    sleep 1
fi

G4_SKIP_FOCUS=1 G4_PRE_ENTER_DELAY="${G8_PRE_ENTER_DELAY:-0.5}" G4_KEY_UP_DELAY="${G8_KEY_UP_DELAY:-0.10}" \
    python3 "$ROOT/scripts/qemu-key-inject.py" "$QMP" "$SERIAL"
KEY_RC=$?

if [ -S "$MON" ]; then
    sleep "${G8_AFTER_SETTLE_SECONDS:-3}"
    printf 'screendump %s\nquit\n' "$AFTER" | timeout "${G8_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g8-hmp-after.out 2>/tmp/g8-hmp-after.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G8 serial markers ===="
grep -aE "G4TERM:|G4KEY:|G4OUT:|G8 frame|G8 watchdog|G8 surface|Map request dispatched" "$SERIAL" | tail -120 || true
echo "==== G8 screendumps ===="
ls -l "$BEFORE" "$AFTER" 2>/dev/null || true
file "$BEFORE" "$AFTER" 2>/dev/null || true

if [ "$mapped" -ne 0 ]; then
    echo "G8 FAIL: terminal did not map before timeout"
    exit 2
fi

if [ "$KEY_RC" -ne 0 ]; then
    if ! grep -aq "G4KEY: code=" "$SERIAL" 2>/dev/null; then
        echo "G8 FAIL: no post-focus keyboard input reached the terminal"
        exit "$KEY_RC"
    fi
    echo "G8 WARN: shell output was not observed under HMP screendump timing; continuing with redraw validation"
fi

if ! grep -aq "G8 frame" "$SERIAL" 2>/dev/null || ! grep -aq "present .*damage_rects=" "$SERIAL" 2>/dev/null; then
    echo "G8 FAIL: missing frame/present pacing logs"
    exit 3
fi

python3 - "$BEFORE" "$AFTER" <<'PY'
import sys
from pathlib import Path

def read_ppm(path):
    data = Path(path).read_bytes()
    idx = 0

    def token():
        nonlocal idx
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
        raise SystemExit(f"G8 FAIL: unsupported or truncated PPM: {path}")
    return width, height, pixels

before_w, before_h, before = read_ppm(sys.argv[1])
after_w, after_h, after = read_ppm(sys.argv[2])
if (before_w, before_h) != (after_w, after_h):
    print(f"G8 FAIL: screendump size changed {before_w}x{before_h} -> {after_w}x{after_h}")
    sys.exit(4)

# wl-term maps near the top-left. Restrict the comparison to the terminal band
# so blinking cursor/input text changes dominate over unrelated boot noise.
band_w = min(before_w, 760)
band_h = min(before_h, 260)
changed = 0
bright_after = 0
dark_after = 0
for y in range(band_h):
    row = y * before_w * 3
    for x in range(band_w):
        off = row + x * 3
        if before[off:off + 3] != after[off:off + 3]:
            changed += 1
        r, g, b = after[off], after[off + 1], after[off + 2]
        if r > 180 and g > 180 and b > 180:
            bright_after += 1
        if r < 25 and g < 25 and b < 25:
            dark_after += 1

print(f"G8 screenshot stats: changed_terminal_band_pixels={changed} bright_after={bright_after} dark_after={dark_after}")
if changed < 50:
    print("G8 FAIL: post-input screendump did not visibly change")
    sys.exit(5)
if bright_after < 1000 or dark_after < 1000:
    print("G8 FAIL: post-input screendump lacks visible terminal content")
    sys.exit(6)

print("G8 PASS: post-client-commit screendump visibly updated")
PY
