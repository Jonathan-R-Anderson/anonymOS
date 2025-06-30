#!/bin/sh
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POSIX_DIR="$PROJECT_ROOT/third_party/posix"
REPO_URL="https://github.com/Jonathan-R-Anderson/anonymos-posix.git"
if [ ! -d "$POSIX_DIR/.git" ]; then
    mkdir -p "$PROJECT_ROOT/third_party"
    if [ -d "$POSIX_DIR" ] && [ "$(ls -A "$POSIX_DIR" 2>/dev/null)" ]; then
        echo "Removing existing non-git directory $POSIX_DIR"
        rm -rf "$POSIX_DIR"
    fi
    git clone --depth 1 "$REPO_URL" "$POSIX_DIR"
else
    git -C "$POSIX_DIR" pull --ff-only
fi
