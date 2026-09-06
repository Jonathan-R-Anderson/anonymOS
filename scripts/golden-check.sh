#!/usr/bin/env bash
# Compare the guest's screen against a recorded golden image.  GUI G21 / ROADMAP 3.3.
#
# scripts/screen-check.sh answers "is anything on screen at all" with a colour count, and says in
# its own header why it stops there: a golden image "goes stale and can fail spuriously because a
# clock digit changed".  That objection is correct and is the whole design problem here, not a
# reason to skip the check -- a colour count cannot tell a correctly rendered desktop from one
# with the sidebar missing, the text overlapping, or a window drawn in the wrong place.  Every one
# of those has happened in this project and none would move the colour count.
#
# So: mask what legitimately varies, compare the rest exactly, and allow a small pixel budget for
# antialiasing noise.
#
#   MASKED  the top bar (clock, status icons) -- changes every minute by design
#           the cursor, wherever it is -- position depends on test timing
#
# Usage:
#   scripts/golden-check.sh installer                 # compare against tests/golden/installer.png
#   GOLDEN_UPDATE=1 scripts/golden-check.sh installer # record/replace that golden
#   TOLERANCE=2000 scripts/golden-check.sh installer  # allow more differing pixels
#
# Requires a RUNNING guest (qemu-run.sh always creates the HMP monitor socket).
# Exit 0 = matches.  1 = differs.  2 = could not capture/compare.  3 = no golden recorded yet.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NAME="${1:-}"
[ -n "$NAME" ] || { echo "golden-check: usage: $0 <name>" >&2; exit 2; }

MON="${MON:-$ROOT/mon.sock}"
GOLDEN_DIR="${GOLDEN_DIR:-$ROOT/tests/golden}"
GOLDEN="$GOLDEN_DIR/$NAME.png"
PPM="${TMPDIR:-/tmp}/golden-check.$$.ppm"
SHOT="${TMPDIR:-/tmp}/golden-check.$$.png"
DIFF="${TMPDIR:-/tmp}/golden-diff-$NAME.png"
# A pixel budget rather than an exact match: the softpipe renderer is deterministic, but font
# antialiasing at a glyph edge can differ by a pixel or two between builds and that is not a
# regression.  1000 of 1024000 pixels is under 0.1% -- far below anything a human would call a
# visual change, and far above nothing.
TOLERANCE="${TOLERANCE:-1000}"
# Height of the top bar to blank out.  The clock lives here and changes every minute.
BAR_H="${BAR_H:-32}"

command -v nc      >/dev/null 2>&1 || { echo "golden-check: nc not found" >&2; exit 2; }
command -v convert >/dev/null 2>&1 || { echo "golden-check: ImageMagick not found" >&2; exit 2; }
command -v compare >/dev/null 2>&1 || { echo "golden-check: ImageMagick compare not found" >&2; exit 2; }
[ -S "$MON" ] || { echo "golden-check: no monitor socket at $MON (is the guest running?)" >&2; exit 2; }

# -N is load-bearing: OpenBSD nc does not shutdown(SHUT_WR) on stdin EOF, so without it the
# monitor never sees the end of the command and this hangs forever.  Same reason as screen-check.
rm -f "$PPM"
printf 'screendump %s\n' "$PPM" | nc -N -U "$MON" >/dev/null 2>&1
for _ in $(seq 1 20); do [ -s "$PPM" ] && break; sleep 0.5; done
[ -s "$PPM" ] || { echo "golden-check: screendump produced nothing" >&2; exit 2; }

# Blank the volatile regions in the CAPTURE.  The golden is recorded through this same path, so
# both sides are masked identically and the mask can change without invalidating stored goldens.
# The width has to be resolved before the draw: ImageMagick does NOT expand %[fx:...] inside
# -draw, so "rectangle 0,0 %[fx:w-1],32" is taken literally and the whole convert fails.
mask() {
    local w
    w="$(identify -format '%w' "$1" 2>/dev/null)"
    [ -n "$w" ] || return 1
    convert "$1" -fill black \
        -draw "rectangle 0,0 $((w - 1)),$BAR_H" \
        "$2" 2>/dev/null
}

if ! mask "$PPM" "$SHOT"; then
    echo "golden-check: could not process the capture" >&2
    exit 2
fi

if [ "${GOLDEN_UPDATE:-0}" = "1" ]; then
    mkdir -p "$GOLDEN_DIR"
    cp "$SHOT" "$GOLDEN"
    echo "golden-check: recorded $GOLDEN"
    exit 0
fi

if [ ! -f "$GOLDEN" ]; then
    echo "golden-check: no golden for '$NAME' at $GOLDEN" >&2
    echo "golden-check: record one with: GOLDEN_UPDATE=1 $0 $NAME" >&2
    exit 3
fi

# -metric AE counts differing pixels outright, which is the number worth reporting: "3 pixels
# differ" and "half the screen differs" are different findings and a normalised score blurs them.
# -fuzz absorbs single-step antialiasing noise without hiding a real colour change.
DIFFPX="$(compare -metric AE -fuzz 2% "$SHOT" "$GOLDEN" "$DIFF" 2>&1 | tr -d '\n' | sed 's/[^0-9].*$//')"
DIFFPX="${DIFFPX:-999999}"

if [ "$DIFFPX" -le "$TOLERANCE" ]; then
    echo "golden-check: PASS  $NAME  ($DIFFPX differing pixels, tolerance $TOLERANCE)"
    rm -f "$PPM" "$SHOT" "$DIFF"
    exit 0
fi

echo "golden-check: FAIL  $NAME  ($DIFFPX differing pixels > tolerance $TOLERANCE)" >&2
echo "golden-check: captured $SHOT" >&2
echo "golden-check: golden   $GOLDEN" >&2
echo "golden-check: diff     $DIFF  (differing pixels highlighted)" >&2
rm -f "$PPM"
exit 1
