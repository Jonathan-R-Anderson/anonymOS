#!/bin/sh
# Setup development environment: fetch sources for POSIX wrappers, the D compiler
# and the -sh shell.  Actual compilation happens inside anonymOS after boot.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Fetch POSIX wrappers
"$SCRIPT_DIR/fetch_posix.sh"

# Fetch D compiler and shell sources
"$SCRIPT_DIR/fetch_dmd.sh"
"$SCRIPT_DIR/fetch_shell.sh"
