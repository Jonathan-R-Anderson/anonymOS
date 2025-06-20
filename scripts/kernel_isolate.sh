#!/bin/bash
# Boot the anonymOS kernel in an isolated Docker container, falling back to a VM.
set -e
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
IMAGE_NAME=anonymos-kernel
BUILD=no
DRY_RUN=no

usage() {
    echo "Usage: $0 [--build] [--dry-run]" >&2
}

while [[ "$1" == --* ]]; do
    case "$1" in
        --build) BUILD=yes ; shift ;;
        --dry-run) DRY_RUN=yes ; shift ;;
        *) usage; exit 1 ;;
    esac
done

ISO="$ROOT_DIR/build/anonymOS.iso"
QEMU_CMD="qemu-system-x86_64 -cdrom $ISO -m 128M -display curses -vga std"

if [ "$BUILD" = yes ]; then
    CMD="docker build -t $IMAGE_NAME -f \"$ROOT_DIR/Dockerfile.kernel\" \"$ROOT_DIR\""
    if [ "$DRY_RUN" = yes ]; then
        echo "$CMD"
    else
        eval "$CMD"
    fi
    exit 0
fi

if [ "$DRY_RUN" = no ] && [ ! -f "$ISO" ]; then
    echo "ISO image $ISO not found. Build it first (make iso)." >&2
    exit 1
fi

if command -v docker >/dev/null 2>&1; then
    RUN_CMD="docker run --rm -it"
    [ -e /dev/kvm ] && RUN_CMD="$RUN_CMD --device /dev/kvm"
    RUN_CMD="$RUN_CMD -v \"$ROOT_DIR\":/mnt -w /mnt $IMAGE_NAME $QEMU_CMD"
else
    RUN_CMD="$SCRIPT_DIR/virtual_run.sh"
fi

if [ "$DRY_RUN" = yes ]; then
    echo "$RUN_CMD"
else
    eval $RUN_CMD
fi
