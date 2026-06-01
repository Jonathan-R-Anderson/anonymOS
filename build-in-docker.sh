#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="haskellos-builder"

# Build the Docker image
echo "Building Docker image..."
docker build -t "$IMAGE_NAME" .

# Run the build
echo "Running build in Docker..."
# We mount the current directory to /src_mount
# We do the work in /build_work to avoid overwriting build.opts on the host
docker run --rm -v "$(pwd):/src_mount" "$IMAGE_NAME" bash -c '
    set -euo pipefail

    copy_build_dir() {
        [ -d build ] || return 0
        mkdir -p /src_mount/build
        cp -r build/. /src_mount/build/
    }

    copy_file_if_present() {
        [ -f "$1" ] || return 0
        cp "$1" /src_mount/
    }

    mkdir -p /build_work
    cp -r /src_mount/. /build_work/
    cd /build_work

    if make clean && make; then
        copy_build_dir
        copy_file_if_present hos.iso
        copy_file_if_present kernel.bin
        copy_file_if_present kernel.elf
        copy_file_if_present kernel.symbols
    else
        copy_build_dir
        exit 1
    fi
'

echo "Build complete. hos.iso should be in the current directory."
