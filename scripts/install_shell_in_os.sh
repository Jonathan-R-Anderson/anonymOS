#!/bin/sh
# Build the third-party -sh shell inside anonymOS using the bundled D compiler.
# This script is expected to run from within the installed system.
set -e

SRC_DIR="/third_party/sh"
DMD="/bin/dmd"
OUT="/bin/sh"

if [ ! -x "$DMD" ]; then
    echo "dmd compiler not found at $DMD" >&2
    exit 1
fi

if [ ! -d "$SRC_DIR" ]; then
    echo "Shell sources not found at $SRC_DIR" >&2
    exit 1
fi

echo "Compiling shell sources..."
"$DMD" -I"$SRC_DIR" -I"$SRC_DIR/src" "$SRC_DIR"/src/*.d -of="$OUT"

echo "Shell installed to $OUT"
