#!/usr/bin/env bash
# Boot the install ISO headless, wait for the installer to map, then walk its pages with
# injected keystrokes and screendump each one -- so "what does the installer look like" and
# "does it still respond after N pages" are answered by PNGs and timings, not by prose.
#
#   scripts/installer-walkthrough.sh [out-dir]        (default build/walkthrough)
#   PAGES=8 MEM=4096 scripts/installer-walkthrough.sh
#
# It drives ./qemu-run.sh (HEADLESS=1) exactly like boot-test.sh does, uses the HMP monitor's
# `sendkey` + `screendump`, and prints, per page, how long the guest took to change the screen
# after the key -- a coarse but real responsiveness number for the software-rendered desktop.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${1:-$ROOT/build/walkthrough}"
PAGES="${PAGES:-9}"
MON="$ROOT/mon.sock"
SERIAL="$ROOT/serial.log"
mkdir -p "$OUT"
rm -f "$OUT"/*.ppm "$OUT"/*.png "$SERIAL"

command -v nc >/dev/null || { echo "nc required"; exit 2; }
command -v convert >/dev/null || { echo "ImageMagick required"; exit 2; }

hmp() { printf '%s\n' "$1" | nc -N -U "$MON" >/dev/null 2>&1; }
shot() {   # shot <name>  -> $OUT/<name>.png ; echoes the md5 of the PPM
    local ppm="$OUT/$1.ppm"
    rm -f "$ppm"
    hmp "screendump $ppm"
    for _ in $(seq 1 40); do [ -s "$ppm" ] && break; sleep 0.25; done
    [ -s "$ppm" ] || { echo "none"; return; }
    convert "$ppm" "$OUT/$1.png" 2>/dev/null
    md5sum "$ppm" | cut -c1-32
}
clean_serial() { tr -d '\000' < "$SERIAL" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'; }

setsid env HEADLESS=1 MEM="${MEM:-4096}" WIFI=0 ISO_CHECK=0 ./qemu-run.sh >"$OUT/qemu.out" 2>&1 &
QPID=$!
trap 'pkill -P $QPID 2>/dev/null; kill $QPID 2>/dev/null' EXIT

# 1. wait for the installer to map (kernel launches it as /calamares) and the desktop to present
deadline=$((SECONDS + 240))
while [ $SECONDS -lt $deadline ]; do
    if clean_serial | grep -q "\[inst\] calamares launched" && [ "$(clean_serial | grep -c '\[present\] total=')" -ge 2 ]; then break; fi
    sleep 2
done
clean_serial | grep -q "\[inst\] calamares launched" || { echo "walkthrough: installer never launched"; exit 1; }
sleep 20    # first frame of the wizard on a software-rendered desktop
base="$(shot 00_welcome)"
echo "page 0 (Welcome): captured"

# 2. Enter advances every page up to Encryption (list pages accept Enter; Welcome's Enter = Install)
names=(01_language 02_keyboard 03_timezone 04_network 05_drivers 06_disk 07_filesystem 08_encryption 09_bootintegrity 10_account)
for i in $(seq 1 "$PAGES"); do
    idx=$((i - 1))
    [ $idx -lt ${#names[@]} ] || break
    t0=$(date +%s.%N)
    hmp "sendkey ret"
    # poll until the screen differs from the previous page (or 20 s pass)
    changed=""
    for _ in $(seq 1 80); do
        sleep 0.25
        cur="$(shot "${names[$idx]}")"
        if [ -n "$cur" ] && [ "$cur" != "$base" ] && [ "$cur" != "none" ]; then changed=1; break; fi
    done
    t1=$(date +%s.%N)
    dt=$(echo "$t1 - $t0" | bc)
    if [ -n "$changed" ]; then
        echo "page $i (${names[$idx]}): screen changed ${dt}s after Enter"
        base="$cur"
    else
        echo "page $i (${names[$idx]}): NO screen change within 20 s"
    fi
done
sleep 1
# a last capture after all the key presses, to show the final state
shot zz_final >/dev/null
echo "walkthrough: screenshots in $OUT"
clean_serial | grep -c "\[present\] total=" | sed 's/^/present heartbeats seen: /'
