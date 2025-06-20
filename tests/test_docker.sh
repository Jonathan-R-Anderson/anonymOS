#!/bin/bash
set -e
cmd=$(scripts/docker_run.sh --build --dry-run)
[[ $cmd == docker\ build* ]]
cmd2=$(scripts/docker_run.sh --dry-run echo hello)
[[ $cmd2 == docker\ run* ]] && [[ $cmd2 == *"echo hello"* ]]
cmd3=$(scripts/docker_service.sh --dry-run /bin/true)
[[ $cmd3 == docker\ run* ]] && [[ $cmd3 == */bin/true* ]]
echo "docker scripts dry-run checks passed"
