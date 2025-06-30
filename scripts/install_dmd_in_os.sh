#!/bin/sh
# Build the DMD compiler inside anonymOS using the bundled D compiler.
set -e
SRC_DIR="/third_party/dmd"
DMD="/bin/dmd"
OUT="/bin/dmd"

if [ ! -x "$DMD" ]; then
    echo "dmd compiler not found at $DMD" >&2
    exit 1
fi

if [ ! -d "$SRC_DIR" ]; then
    echo "DMD sources not found at $SRC_DIR" >&2
    exit 1
fi

cd "$SRC_DIR"
echo "Compiling DMD..."
make -f posix.mak AUTO_BOOTSTRAP=1 MODEL=64 > /tmp/dmd_build.log 2>&1
cp generated/linux/release/64/dmd "$OUT"
echo "DMD installed to $OUT"
