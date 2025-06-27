#!/bin/sh
# Build the DMD compiler for anonymOS using the cross-compiler.
# This expects the dmd sources under third_party/dmd.
# The resulting binary is copied to build/bin/dmd so it is included
# in the anonymOS ISO image.

set -e

SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DMD_DIR="$PROJECT_ROOT/third_party/dmd"
BIN_DIR="$PROJECT_ROOT/build/bin"
HOST_DMD=${HOST_DMD:-ldmd2}
JOBS=${JOBS:-$(nproc)}

mkdir -p "$BIN_DIR"

make -C "$DMD_DIR" -f Makefile -j$JOBS HOST_DMD="$HOST_DMD" ENABLE_RELEASE=1
cp "$DMD_DIR/generated/linux/release/64/dmd" "$BIN_DIR/dmd"

echo "DMD built and copied to $BIN_DIR/dmd"
