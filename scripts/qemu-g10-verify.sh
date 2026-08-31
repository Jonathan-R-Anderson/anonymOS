#!/usr/bin/env bash
# GUI roadmap G10 verification: validate category asset blobs and confirm the
# kernel unpacks them into the guest rtfs overlay during boot.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "${G10_REBUILD:-0}" = "1" ]; then
    make -j1 hos.iso
fi

python3 - "$ROOT" <<'PY'
import json
import re
import struct
import sys
from pathlib import Path

root = Path(sys.argv[1])
blob_dir = root / "build" / "asset-blobs"
required = {
    "fonts.blob": {
        "usr/share/fonts/noto/NotoSans-Regular.ttf",
        "usr/share/fonts/noto/NotoSansMono-Regular.ttf",
    },
    "icons.blob": {
        "usr/share/icons/Epin/index.theme",
        "usr/share/icons/Epin/scalable/apps/terminal.svg",
        "usr/share/icons/default/index.theme",
    },
    "cursors.blob": {
        "usr/share/icons/Epin/cursors/left_ptr",
        "usr/share/cursors/Epin/cursor.theme",
    },
    "wallpapers.blob": {
        "usr/share/backgrounds/epin/wall0.png",
        "usr/share/backgrounds/epin/wall0.svg",
        "usr/share/hypr/wall0.png",
    },
    "themes.blob": {
        "usr/share/themes/Epin/index.theme",
        "usr/share/themes/Epin/gtk-3.0/settings.ini",
        "usr/share/hos/assets/manifest.json",
    },
}
forbidden = re.compile(
    r"\b(apple|macos|mac\s+os|san\s+francisco|sf\s+pro|sf\s+compact|cupertino|proprietary)\b",
    re.I,
)


def read_blob(path):
    data = path.read_bytes()
    off = 0
    out = {}
    while off + 8 <= len(data):
        path_len = struct.unpack_from("<I", data, off)[0]
        off += 4
        if path_len == 0 or path_len > 4096 or off + path_len + 4 > len(data):
            raise SystemExit(f"G10 FAIL: malformed entry in {path}")
        guest_path = data[off:off + path_len].decode("utf-8")
        off += path_len
        size = struct.unpack_from("<I", data, off)[0]
        off += 4
        if off + size > len(data):
            raise SystemExit(f"G10 FAIL: truncated entry in {path}")
        out[guest_path] = data[off:off + size]
        off += size
    if off != len(data):
        raise SystemExit(f"G10 FAIL: trailing bytes in {path}")
    return out


all_entries = {}
for blob, paths in required.items():
    path = blob_dir / blob
    if not path.exists():
        raise SystemExit(f"G10 FAIL: missing {path}")
    entries = read_blob(path)
    missing = sorted(paths - set(entries))
    if missing:
        raise SystemExit(f"G10 FAIL: {blob} missing {missing}")
    all_entries.update(entries)
    print(f"G10 blob stats: {blob} files={len(entries)} bytes={sum(len(v) for v in entries.values())}")

manifest_data = all_entries.get("usr/share/hos/assets/manifest.json")
if not manifest_data:
    raise SystemExit("G10 FAIL: missing asset manifest")
manifest = json.loads(manifest_data.decode("utf-8"))
defaults = manifest.get("defaults", {})
expected_defaults = {
    "ui_font": "Noto Sans 10",
    "monospace_font": "Noto Sans Mono 11",
    "icon_theme": "Epin",
    "cursor_theme": "Epin",
    "gtk_theme": "Epin",
    "wallpaper": "/usr/share/backgrounds/epin/wall0.png",
}
for key, value in expected_defaults.items():
    if defaults.get(key) != value:
        raise SystemExit(f"G10 FAIL: manifest default {key}={defaults.get(key)!r}, expected {value!r}")

assets = manifest.get("assets", [])
if len(assets) < 20:
    raise SystemExit(f"G10 FAIL: manifest too small: {len(assets)} assets")
if any(item.get("license") in {"", "unknown", None} for item in assets):
    bad = [item.get("path") for item in assets if item.get("license") in {"", "unknown", None}][:5]
    raise SystemExit(f"G10 FAIL: manifest has missing license metadata: {bad}")
manifest_text = manifest_data.decode("utf-8", errors="ignore")
if forbidden.search(manifest_text):
    raise SystemExit("G10 FAIL: manifest contains a forbidden proprietary asset marker")

print("G10 host asset manifest OK")
PY

SERIAL="$ROOT/serial.log"
rm -f "$SERIAL"

qemu-system-x86_64 \
  -boot d -cdrom hos.iso -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$(( $(date +%s) + 180 ))
ready=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "\\[assets\\] /fonts.blob unpacked" "$SERIAL" 2>/dev/null &&
       grep -aq "\\[assets\\] /icons.blob unpacked" "$SERIAL" 2>/dev/null &&
       grep -aq "\\[assets\\] /cursors.blob unpacked" "$SERIAL" 2>/dev/null &&
       grep -aq "\\[assets\\] /wallpapers.blob unpacked" "$SERIAL" 2>/dev/null &&
       grep -aq "\\[assets\\] /themes.blob unpacked" "$SERIAL" 2>/dev/null; then
        ready=0
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 2
done

cleanup
trap - EXIT

echo "==== G10 serial markers ===="
grep -aE "\\[assets\\]|G9FONT:|G4TERM:" "$SERIAL" | tail -80 || true

if [ "$ready" -ne 0 ]; then
    echo "G10 FAIL: kernel did not unpack all GUI asset category blobs before timeout"
    exit 2
fi

echo "G10 PASS: GUI asset category blobs and manifest are mounted in the guest"
