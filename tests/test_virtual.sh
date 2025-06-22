#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
cmd=$("$ROOT_DIR"/scripts/virtual_run.sh --dry-run)
[[ $cmd == qemu-system-x86_64* ]]
echo "virtual_run dry-run passed"
