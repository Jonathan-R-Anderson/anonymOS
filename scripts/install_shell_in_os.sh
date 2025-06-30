#!/bin/sh
# Build the third-party -sh shell inside anonymOS using the bundled D compiler.
# This script is expected to run from within the installed system.
set -e

SRC_DIR="/third_party/sh"
POSIX_DIR="/third_party/posix"
DMD="/bin/dmd"
POSIX_OBJ="/tmp/posix.o"
OUT="/bin/sh"

[ ! -d "/bin" ] && mkdir -p "/bin"

if [ ! -x "$DMD" ]; then
    echo "dmd compiler not found at $DMD" >&2
    exit 1
fi

if [ ! -d "$SRC_DIR" ]; then
    echo "Shell sources not found at $SRC_DIR" >&2
    exit 1
fi
if [ ! -d "$POSIX_DIR" ]; then
    echo "POSIX wrappers not found at $POSIX_DIR" >&2
    exit 1
fi

echo "Compiling POSIX wrappers..."
"$DMD" -betterC -c -I"$POSIX_DIR/src" "$POSIX_DIR"/src/posix.d -of="$POSIX_OBJ"

echo "Compiling shell sources..."
"$DMD" -I"$SRC_DIR" -I"$SRC_DIR/src" -I"$POSIX_DIR/src" "$POSIX_OBJ" "$SRC_DIR"/src/*.d -of="$OUT"

echo "Shell installed to $OUT"
