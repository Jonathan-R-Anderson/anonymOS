#!/bin/sh
# Build the -sh shell for anonymOS using the cross compiler.
# This compiles the shell sources from third_party/sh into a
# static binary placed under build/bin/sh so it can be copied
# to the ISO at /bin/sh.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SH_DIR="$PROJECT_ROOT/third_party/sh"
OUT_DIR="$PROJECT_ROOT/build/bin"
OUT="$OUT_DIR/sh"
DC=${DC:-ldc2}
TRIPLE=${TRIPLE:-x86_64-linux-gnu}
CPU=${CPU:-x86-64}
CC=${CC:-x86_64-linux-gnu-gcc}
LD=${LD:-x86_64-linux-gnu-gcc}
export CC

# Ensure sources are present
if [ ! -d "$SH_DIR" ]; then
    echo "Shell sources not found in $SH_DIR" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

$DC --gcc="$CC" --linker="$LD" \
    -I"$SH_DIR" -I"$SH_DIR/src" \
    -mtriple=$TRIPLE -mcpu=$CPU \
    $SH_DIR/src/*.d -of="$OUT"
echo "Shell built at $OUT"
