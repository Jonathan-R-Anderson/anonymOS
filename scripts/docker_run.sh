#!/bin/bash
# Helper to build and run anonymOS userland in a Docker container.
set -e
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
IMAGE_NAME=anonymos-userland
BUILD=no
DRY_RUN=no
function usage {
    echo "Usage: $0 [--build] [--dry-run] [COMMAND...]"
}
while [[ "$1" == --* ]]; do
    case "$1" in
        --build) BUILD=yes ;;
        --dry-run) DRY_RUN=yes ;;
        *) usage; exit 1 ;;
    esac
    shift
done
if [ "$BUILD" = yes ]; then
    CMD="docker build -t $IMAGE_NAME -f \"$ROOT_DIR/Dockerfile\" \"$ROOT_DIR\""
    if [ "$DRY_RUN" = yes ]; then
        echo "$CMD"
    else
        eval "$CMD"
    fi
    exit 0
fi
if [ "$#" -gt 0 ]; then
    RUN_ARGS="$@"
else
    RUN_ARGS="/bin/bash"
fi
RUN_CMD="docker run --rm -it --cap-drop ALL $IMAGE_NAME $RUN_ARGS"
if [ "$DRY_RUN" = yes ]; then
    echo "$RUN_CMD"
else
    eval "$RUN_CMD"
fi
