#!/bin/sh
# Reassemble the pfSense/Netgate installer ISO from the committed <95 MiB parts.
#
# GitHub rejects any single file over 100 MiB, and the installer image is ~327 MB gzipped, so it is
# committed SPLIT into deps/pfsense/*.part (byte-exact `split -b 95m`).  This script concatenates
# them back into the original gzip, verifies it against the recorded SHA-256 (so a corrupt or
# partial checkout fails loudly rather than producing a broken installer), and — with --gunzip —
# also expands the raw .iso the VMM boots.  Output is git-ignored; it is a build artifact.
#
# Usage:  scripts/pfsense-assemble.sh [--gunzip]
set -eu

DO_GUNZIP=0
for arg in "$@"; do
    [ "$arg" = "--gunzip" ] && DO_GUNZIP=1
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PARTS_DIR="$ROOT/deps/pfsense"
BASENAME="netgate-installer-v1.2-RELEASE-amd64.iso.gz"
OUT_GZ="$ROOT/deps/$BASENAME"
SHA_FILE="$PARTS_DIR/netgate-installer.iso.gz.sha256"

# Parts are named .00.part, .01.part, … so a plain glob sorts them in order.
first_part=$(ls "$PARTS_DIR/$BASENAME".*.part 2>/dev/null | head -1 || true)
if [ -z "$first_part" ]; then
    echo "pfsense-assemble: no parts found in $PARTS_DIR (expected $BASENAME.NN.part)" >&2
    exit 1
fi
cat "$PARTS_DIR/$BASENAME".*.part > "$OUT_GZ"

if [ -f "$SHA_FILE" ] && command -v sha256sum >/dev/null 2>&1; then
    want="$(awk '{print $1}' "$SHA_FILE")"
    got="$(sha256sum "$OUT_GZ" | awk '{print $1}')"
    if [ "$want" != "$got" ]; then
        echo "pfsense-assemble: CHECKSUM MISMATCH — want $want, got $got" >&2
        rm -f "$OUT_GZ"
        exit 1
    fi
    echo "pfsense-assemble: reassembled + verified $OUT_GZ"
else
    echo "pfsense-assemble: reassembled $OUT_GZ (sha256 not verified — no checksum file or sha256sum)"
fi

if [ "$DO_GUNZIP" = "1" ]; then
    gunzip -kf "$OUT_GZ"
    echo "pfsense-assemble: expanded ${OUT_GZ%.gz}"
fi
