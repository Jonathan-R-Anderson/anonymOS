#!/bin/sh
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

fetch_repo() {
    DIR="$1"
    REPO="$2"
    if [ ! -d "$PROJECT_ROOT/$DIR/.git" ]; then
        echo "Cloning $REPO into $DIR"
        rm -rf "$PROJECT_ROOT/$DIR"
        git clone --depth 1 "$REPO" "$PROJECT_ROOT/$DIR"
    else
        echo "Updating $DIR"
        git -C "$PROJECT_ROOT/$DIR" pull --ff-only
    fi
}

fetch_repo modules/microkernel https://github.com/Jonathan-R-Anderson/anonymos-microkernel.git
fetch_repo modules/user-services https://github.com/Jonathan-R-Anderson/anonymos-user-services.git
fetch_repo modules/hypervisor https://github.com/Jonathan-R-Anderson/anonymos-hypervisor.git
fetch_repo modules/containers https://github.com/Jonathan-R-Anderson/anonymos-containers.git
fetch_repo modules/object-tree https://github.com/Jonathan-R-Anderson/anonymos-object-tree.git
fetch_repo modules/distributed-fs https://github.com/Jonathan-R-Anderson/distributedFS.git
