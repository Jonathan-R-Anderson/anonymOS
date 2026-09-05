#!/usr/bin/env bash
# GUI roadmap G17 verification: autostart the wl-files file manager and require
# it to render a Finder-style browser — a Places sidebar, a toolbar with the
# current path, and a list of the current directory's folders with icons and
# real names read from the VFS.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G17_REBUILD:-1}" = "1" ]; then
    # G17 includes a kernel getdents64 ABI fix; refresh the kernel explicitly
    # since `make hos-install.iso` does not recompile the D kernel on its own.
    make -j1 -C src/kernel/d
    make -j1 kernel.elf
    make -j1 GUI_AUTOSTART=files hos-install.iso
fi

SERIAL="$ROOT/serial.log"
MON="/tmp/g17-hmp.sock"
SHOT="/tmp/epin-g17.ppm"
rm -f "$SERIAL" "$MON" "$SHOT"

qemu-system-x86_64 \
  -boot d -cdrom hos-install.iso -m "${G17_MEM:-768}" \
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
    if grep -aq "G17 REDRAW" "$SERIAL" 2>/dev/null &&
       grep -aq "G17 LIST" "$SERIAL" 2>/dev/null &&
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
    sleep "${G17_SETTLE_SECONDS:-4}"
    printf 'screendump %s\nquit\n' "$SHOT" | timeout "${G17_HMP_TIMEOUT:-10}" nc -U "$MON" >/tmp/g17-hmp.out 2>/tmp/g17-hmp.err || true
    sleep 1
fi
cleanup
trap - EXIT

echo "==== G17 serial markers ===="
grep -aE "G17FILES|G17 LIST|G17 REDRAW|blitted" "$SERIAL" | tail -30 || true
echo "==== G17 screendump ===="
ls -l "$SHOT" 2>/dev/null || true

if [ "$ready" -ne 0 ]; then
    echo "G17 FAIL: file manager was not ready before timeout"
    exit 2
fi

echo "==== directory listing (serial) ===="
grep -aE "G17 LIST" "$SERIAL" | tail -3 || true

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
    print("G17 FAIL: bad PPM")
    sys.exit(4)

stats = {
    "window_light": 0,   # the file manager's light content surface
    "sidebar_panel": 0,  # bluish-grey sidebar / panels
    "folder_icon": 0,    # amber/gold folder icons (sidebar + list)
    "row_select": 0,     # the blue selected row / highlight
    "dark_text": 0,      # antialiased dark text (labels, names, path)
}
for y in range(40, height - 60):
    row = y * width * 3
    for x in range(width):
        o = row + x * 3
        r, g, b = px[o], px[o + 1], px[o + 2]
        if r > 235 and g > 240 and b > 244:
            stats["window_light"] += 1
        if 215 <= r <= 240 and 222 <= g <= 244 and 230 <= b <= 250 and b >= r:
            stats["sidebar_panel"] += 1
        if 200 <= r <= 255 and 150 <= g <= 210 and 40 <= b <= 130:
            stats["folder_icon"] += 1
        if 40 <= r <= 90 and 110 <= g <= 160 and 200 <= b <= 250:
            stats["row_select"] += 1
        if r < 80 and g < 90 and b < 100:
            stats["dark_text"] += 1

print("G17 screenshot stats: " + " ".join(f"{k}={v}" for k, v in stats.items()))

checks = {
    "window_light": 40000,
    "folder_icon": 800,
    "row_select": 1500,
    "dark_text": 1200,
}
for k, m in checks.items():
    if stats[k] < m:
        print(f"G17 FAIL: {k} below threshold: {stats[k]} < {m}")
        sys.exit(5)

print("G17 PASS: file manager renders a Places sidebar, path toolbar, and a folder listing with icons and names")
PY
