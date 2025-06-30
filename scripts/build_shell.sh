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
TRIPLE=${TRIPLE:-x86_64-unknown-elf}
CPU=${CPU:-x86-64}

# Ensure sources are present
if [ ! -d "$SH_DIR" ]; then
    echo "Shell sources not found in $SH_DIR" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Determine modules that avoid unsupported features (mirrors build_betterc.sh)
unsupported=$(grep -lE '\b(Exception|import std|try|catch|throw)\b' "$SH_DIR"/src/*.d | tr '\n' ' ')
modules=""
for f in "$SH_DIR"/src/*.d; do
    base=$(basename "$f")
    if echo "$unsupported" | grep -q "$f"; then
        continue
    fi
    [ "$base" = "example.d" ] && continue
    modules="$modules $f"
done
modules="$modules $SH_DIR/src/interpreter.d"

$DC -betterC --nodefaultlib -I"$SH_DIR" -I"$SH_DIR/src" -mtriple=$TRIPLE -mcpu=$CPU $modules -of="$OUT"
echo "Shell built at $OUT"
