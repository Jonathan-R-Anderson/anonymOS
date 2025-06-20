#!/bin/bash
set -e
cmd=$(scripts/kernel_isolate.sh --dry-run)
if command -v docker >/dev/null 2>&1; then
  [[ $cmd == docker\ run* ]]
else
  [[ $cmd == *virtual_run.sh* ]]
fi
echo "kernel isolation script dry-run passed"
