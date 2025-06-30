#!/bin/sh
# Build the -sh shell for anonymOS using the cross compiler.
# This compiles the shell sources from third_party/sh into a
# static binary placed under build/bin/sh so it can be copied
# to the ISO at /bin/sh.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SH_DIR="$PROJECT_ROOT/third_party/sh"
POSIX_DIR="$PROJECT_ROOT/third_party/posix"
STUB="$PROJECT_ROOT/third_party/stub_shell.d"
OUT_DIR="$PROJECT_ROOT/build/bin"
OUT="$OUT_DIR/sh"
DC=${DC:-ldc2}
CC=${CC:-gcc}
export CC

# Ensure the ldc2 compiler is available
if ! command -v "$DC" >/dev/null 2>&1; then
    echo "D compiler '$DC' not found. Install ldc2 or set DC to your compiler." >&2
    exit 1
fi

# Ensure sources are present
if [ ! -d "$SH_DIR" ]; then
    echo "Shell sources not found in $SH_DIR, fetching..." >&2
    "$SCRIPT_DIR/fetch_shell.sh"
fi

mkdir -p "$OUT_DIR"

# Try building the full shell. If compilation fails, fall back to a simple stub
# so the overall OS build can proceed.
POSIX_OBJ="$OUT_DIR/posix.o"

# Build POSIX wrappers used by the shell
if [ -d "$POSIX_DIR" ]; then
    $DC -betterC -c -I"$POSIX_DIR/src" "$POSIX_DIR/src/posix.d" -of="$POSIX_OBJ"
else
    echo "POSIX sources not found in $POSIX_DIR" >&2
    exit 1
fi

# Try building the full shell. If compilation fails, fall back to a simple stub
if ! $DC -I"$SH_DIR" -I"$SH_DIR/src" -I"$POSIX_DIR/src" \
    "$POSIX_OBJ" $SH_DIR/src/*.d -of="$OUT" 2>/tmp/sh_build_err.log; then
    echo "Full shell build failed, falling back to stub." >&2
    head -n 20 /tmp/sh_build_err.log >&2 || true
    $DC "$STUB" -of="$OUT"
fi

echo "Shell built at $OUT"
