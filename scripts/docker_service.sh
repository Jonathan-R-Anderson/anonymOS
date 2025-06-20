#!/bin/bash
# Run a system service inside the anonymOS Docker container with shared namespaces.
set -e
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
IMAGE_NAME=anonymos-userland
DRY_RUN=no
function usage {
    echo "Usage: $0 [--dry-run] <service> [args...]"
}
while [[ "$1" == --* ]]; do
    case "$1" in
        --dry-run) DRY_RUN=yes ;;
        *) usage; exit 1 ;;
    esac
    shift
done
if [ -z "$1" ]; then
    usage
    exit 1
fi
SERVICE=$1
shift
RUN_CMD="docker run --rm -it --net=host --pid=host --ipc=host \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --cap-drop ALL -v \"$ROOT_DIR\":/mnt -w /mnt $IMAGE_NAME $SERVICE $*"
if [ "$DRY_RUN" = yes ]; then
    echo "$RUN_CMD"
else
    eval "$RUN_CMD"
fi
