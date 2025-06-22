#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
cmd=$("$ROOT_DIR"/scripts/kernel_isolate.sh --dry-run)
if command -v docker >/dev/null 2>&1; then
  [[ $cmd == docker\ run* ]]
else
  [[ $cmd == *virtual_run.sh* ]]
fi
echo "kernel isolation script dry-run passed"
