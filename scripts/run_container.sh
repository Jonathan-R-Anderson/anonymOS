#!/bin/bash
# Launch a container using Docker if available or fall back to QEMU.
set -e
IMAGE=""
CMD=""
DRY_RUN=no

usage() {
    echo "Usage: $0 [--dry-run] --image IMAGE --cmd COMMAND" >&2
}

while [[ "$1" == --* ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2;;
        --cmd) CMD="$2"; shift 2;;
        --dry-run) DRY_RUN=yes; shift;;
        *) usage; exit 1;;
    esac
done

if [ -z "$IMAGE" ] || [ -z "$CMD" ]; then
    usage
    exit 1
fi

if command -v docker >/dev/null 2>&1; then
    RUN_CMD="docker run --rm -it $IMAGE $CMD"
elif command -v qemu-system-x86_64 >/dev/null 2>&1; then
    RUN_CMD="qemu-system-x86_64 -m 512M -drive file=$IMAGE,format=raw -nographic -kernel $CMD"
else
    echo "No container runtime available" >&2
    exit 1
fi

if [ "$DRY_RUN" = yes ]; then
    echo "$RUN_CMD"
else
    eval $RUN_CMD
fi
