#!/bin/sh
# Setup development environment: fetch POSIX wrappers, build D compiler, and build shell.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Fetch POSIX wrappers
"$SCRIPT_DIR/fetch_posix.sh"

# Build D compiler using bundled cross compiler
"$SCRIPT_DIR/build_dmd.sh"

# Fetch shell sources and build shell
"$SCRIPT_DIR/fetch_shell.sh"
"$SCRIPT_DIR/build_shell.sh"
