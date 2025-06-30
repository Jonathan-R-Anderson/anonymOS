#!/bin/sh
# Build POSIX wrapper library inside anonymOS.
set -e
SRC_DIR="/third_party/posix"
DMD="/bin/dmd"
OUT="/lib/posix.o"

[ ! -d "/lib" ] && mkdir -p "/lib"

if [ ! -x "$DMD" ]; then
    echo "dmd compiler not found at $DMD" >&2
    exit 1
fi
if [ ! -d "$SRC_DIR" ]; then
    echo "POSIX sources not found at $SRC_DIR" >&2
    exit 1
fi

echo "Compiling POSIX wrappers..."
"$DMD" -betterC -c -I"$SRC_DIR/src" "$SRC_DIR"/src/posix.d -of="$OUT"

echo "POSIX library installed to $OUT"
