#!/bin/sh
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DMD_DIR="$PROJECT_ROOT/third_party/dmd"
REPO_URL="https://github.com/dlang/dmd.git"

if [ ! -d "$DMD_DIR/.git" ]; then
    mkdir -p "$PROJECT_ROOT/third_party"
    git clone --depth 1 "$REPO_URL" "$DMD_DIR"
else
    git -C "$DMD_DIR" pull --ff-only
fi
