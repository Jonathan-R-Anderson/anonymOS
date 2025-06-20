#!/bin/bash
set -e
cmd=$(scripts/virtual_run.sh --dry-run)
[[ $cmd == qemu-system-x86_64* ]]
echo "virtual_run dry-run passed"
