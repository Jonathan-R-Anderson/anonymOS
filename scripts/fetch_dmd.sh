#!/bin/sh
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DMD_DIR="$PROJECT_ROOT/third_party/dmd"
PATCH_DIR="$PROJECT_ROOT/toolchain/dmd_patches"
REPO_URL="https://github.com/dlang/dmd.git"

VERSION=""
[ -f "$PATCH_DIR/DMD_VERSION" ] && VERSION=$(cat "$PATCH_DIR/DMD_VERSION")

if [ ! -d "$DMD_DIR/.git" ]; then
    mkdir -p "$PROJECT_ROOT/third_party"
    if [ -n "$VERSION" ]; then
        git clone --depth 1 --branch "$VERSION" "$REPO_URL" "$DMD_DIR"
    else
        git clone --depth 1 "$REPO_URL" "$DMD_DIR"
    fi
else
    echo "Updating DMD repository..."
    git -C "$DMD_DIR" fetch origin
    git -C "$DMD_DIR" fetch --tags
    git -C "$DMD_DIR" reset --hard origin/master
fi

if [ -n "$VERSION" ]; then
    git -C "$DMD_DIR" checkout "$VERSION"
fi

if [ -d "$PATCH_DIR" ]; then
    for patch in "$PATCH_DIR"/*.patch; do
        echo "Applying $(basename "$patch")"
        git -C "$DMD_DIR" am "$patch"
    done
fi
