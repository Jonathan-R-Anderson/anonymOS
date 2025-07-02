#!/bin/sh
# Build the DMD compiler for anonymOS using the cross-compiler.
# Sources are fetched and patched via fetch_dmd.sh. The resulting
# binary is copied to build/bin/dmd for inclusion in the ISO.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DMD_DIR="$PROJECT_ROOT/third_party/dmd"
BIN_DIR="$PROJECT_ROOT/build/bin"
HOST_DMD=${HOST_DMD:-ldmd2}
JOBS=${JOBS:-$(nproc)}

# Ensure sources and patches are up to date
"$SCRIPT_DIR/fetch_dmd.sh"

mkdir -p "$BIN_DIR"
make -C "$DMD_DIR" -f powernex.mak -j$JOBS HOST_DMD="$HOST_DMD" ENABLE_RELEASE=1
cp "$DMD_DIR/generated/powernex/release/64/dmd" "$BIN_DIR/dmd"

echo "DMD built and copied to $BIN_DIR/dmd"
