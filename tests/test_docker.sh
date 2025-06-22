#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
cmd=$("$ROOT_DIR"/scripts/docker_run.sh --build --dry-run)
[[ $cmd == docker\ build* ]]
cmd2=$("$ROOT_DIR"/scripts/docker_run.sh --dry-run echo hello)
[[ $cmd2 == docker\ run* ]] && [[ $cmd2 == *"echo hello"* ]]
cmd3=$("$ROOT_DIR"/scripts/docker_service.sh --dry-run /bin/true)
[[ $cmd3 == docker\ run* ]] && [[ $cmd3 == */bin/true* ]]
echo "docker scripts dry-run checks passed"
