#!/bin/bash
# Build fs.img with file payloads for anonymOS simple FS format
set -e
BUILD_DIR="$(dirname "$0")/../build"
IMG="$BUILD_DIR/fs.img"
INTERP="$BUILD_DIR/bin/sh"

mkdir -p "$BUILD_DIR"

# create fs.img
{
  # root directories we care about
  echo "D /" 
  echo "D /bin" 
  # write interpreter if exists
  if [ -f "$INTERP" ]; then
    size=$(stat -c%s "$INTERP")
    echo "F /bin/sh $size"
    cat "$INTERP"
  fi
} > "$IMG"

echo "filesystem image written to $IMG" 