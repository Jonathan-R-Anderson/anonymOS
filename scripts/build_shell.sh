#!/bin/sh
# Build the -sh shell for anonymOS using the cross compiler.
# This compiles the shell sources from third_party/sh into a
# static binary placed under build/bin/sh so it can be copied
# to the ISO at /bin/sh.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SH_DIR="$PROJECT_ROOT/third_party/sh"
STUB="$PROJECT_ROOT/third_party/stub_shell.d"
OUT_DIR="$PROJECT_ROOT/build/bin"
OUT="$OUT_DIR/sh"
DC=${DC:-ldc2}
CC=${CC:-gcc}
export CC

# Ensure sources are present
if [ ! -d "$SH_DIR" ]; then
    echo "Shell sources not found in $SH_DIR" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Try building the full shell. If compilation fails, fall back to a simple stub
# so the overall OS build can proceed.
if ! $DC -I"$SH_DIR" -I"$SH_DIR/src" \
    $SH_DIR/src/*.d -of="$OUT" 2>/tmp/sh_build_err.log; then
    echo "Full shell build failed, falling back to stub." >&2
    $DC "$STUB" -of="$OUT"
fi

echo "Shell built at $OUT"
