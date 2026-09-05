#!/usr/bin/env bash
# Capture the guest's framebuffer and assert it is not a blank screen.
#
# Why this exists.  Every visual symptom in this project has been reported in PROSE -- "the
# desktop is black", "the windows disappear", "the borders load but nothing else" -- because
# nothing could see the screen.  Days went into reasoning about a 5,000-line serial log when a
# single screenshot would have said "the top-left is a black rectangle" immediately.  The
# serial log cannot answer "what is actually on screen"; this can.
#
# It deliberately checks the CHEAPEST useful property rather than pixel-diffing a baseline:
# a rendered desktop contains thousands of distinct colours, whereas every failure this project
# has actually hit -- black screen, cleared framebuffer, one solid fill -- collapses to a
# handful.  A colour count needs no golden image, never goes stale, and cannot fail spuriously
# because a clock digit changed.
#
# Usage:
#   scripts/screen-check.sh                       # capture + check, default thresholds
#   MIN_COLORS=64 scripts/screen-check.sh
#   OUT=/tmp/desktop.png scripts/screen-check.sh
#   MON=mon.sock scripts/screen-check.sh
#
# Requires a RUNNING guest with qemu-run.sh's HMP monitor socket (it always creates one).
# Exit 0 = the screen has content.  1 = blank/uniform.  2 = could not capture.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MON="${MON:-$ROOT/mon.sock}"
OUT="${OUT:-$ROOT/screenshot.png}"
PPM="${TMPDIR:-/tmp}/screen-check.$$.ppm"
MIN_COLORS="${MIN_COLORS:-32}"
# A desktop whose single most common colour covers essentially everything is a blank fill even
# if a cursor or a HUD row adds a few stray colours.
MAX_DOMINANT_PCT="${MAX_DOMINANT_PCT:-97}"

[ -S "$MON" ] || { echo "screen-check: no monitor socket at $MON (is the guest running?)" >&2; exit 2; }
command -v nc >/dev/null 2>&1 || { echo "screen-check: nc not found" >&2; exit 2; }

# -N is load-bearing: OpenBSD nc does not shutdown(SHUT_WR) on stdin EOF, so without it the
# monitor never sees the end of the command and this hangs forever.
rm -f "$PPM"
printf 'screendump %s\n' "$PPM" | nc -N -U "$MON" >/dev/null 2>&1
for _ in $(seq 1 20); do [ -s "$PPM" ] && break; sleep 0.5; done

if [ ! -s "$PPM" ]; then
    echo "screen-check: screendump produced nothing at $PPM" >&2
    exit 2
fi

read -r W H < <(identify -format '%w %h' "$PPM" 2>/dev/null || echo "0 0")
if [ "${W:-0}" -eq 0 ]; then
    echo "screen-check: could not read the captured image" >&2
    exit 2
fi

# Distinct colours, and how much of the frame the single most common one covers.
STATS="$(python3 - "$PPM" <<'PY'
import sys
from PIL import Image
im = Image.open(sys.argv[1]).convert("RGB")
total = im.width * im.height
cols = im.getcolors(maxcolors=total) or []
n = len(cols)
top = max((c for c, _ in cols), default=0)
print(n, round(100.0 * top / total, 1))
PY
)" || { echo "screen-check: colour analysis failed" >&2; exit 2; }

NCOLORS="$(printf '%s' "$STATS" | cut -d' ' -f1)"
DOMPCT="$(printf '%s' "$STATS" | cut -d' ' -f2)"

convert "$PPM" "$OUT" 2>/dev/null && SAVED="$OUT" || SAVED="$PPM"
rm -f "$PPM" 2>/dev/null || true

echo "screen-check: ${W}x${H}  colours=$NCOLORS  dominant=${DOMPCT}%  -> $SAVED"

fail=0
if [ "$NCOLORS" -lt "$MIN_COLORS" ]; then
    echo "screen-check: FAIL — only $NCOLORS distinct colours (need >= $MIN_COLORS); the screen looks blank" >&2
    fail=1
fi
# `${DOMPCT%.*}` drops the decimal so [ ] can compare it as an integer.
if [ "${DOMPCT%.*}" -ge "$MAX_DOMINANT_PCT" ]; then
    echo "screen-check: FAIL — one colour covers ${DOMPCT}% of the frame (limit ${MAX_DOMINANT_PCT}%); the screen looks like a solid fill" >&2
    fail=1
fi

[ "$fail" -eq 0 ] && echo "screen-check: PASS — the desktop is rendering content"
exit "$fail"
