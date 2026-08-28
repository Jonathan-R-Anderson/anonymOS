#!/usr/bin/env bash
# Build anonymOS in Docker and drop the installer ISO on the host.
#
#   ./build-in-docker.sh              # -> dist/hos-install.iso (+ dist/kernel.elf)
#   ./build-in-docker.sh shell        # build everything, then drop into the tree
#
# Docker is the only host requirement — the whole make (musl, libc++, the GTK
# stack, weston, mutter, zsh, the D kernel, the boot tree, the ISO) happens inside
# the image.  See Dockerfile for the stages.
#
# Env:
#   BUILD_JOBS=N   parallelism for the dependency builds (default 1; the dep
#                  builds are memory-heavy, so raise it only on a big machine)
#   OUT_DIR=dir    where the artifacts land (default ./dist)
#   IMAGE_NAME=n   tag used by the non-buildx fallback path (default anonymos-builder)
#   LKL_BUILD_DIR=p  path INSIDE the build context to a prebuilt LKL tree; without
#                  one the ISO is staged without the lkl-boot WiFi module
set -euo pipefail
cd "$(dirname "$0")"

BUILD_JOBS="${BUILD_JOBS:-1}"
OUT_DIR="${OUT_DIR:-dist}"
IMAGE_NAME="${IMAGE_NAME:-anonymos-builder}"
MODE="${1:-iso}"

BUILD_ARGS=(--build-arg "BUILD_JOBS=$BUILD_JOBS")
[ -n "${LKL_BUILD_DIR:-}" ] && BUILD_ARGS+=(--build-arg "LKL_BUILD_DIR=$LKL_BUILD_DIR")

command -v docker >/dev/null 2>&1 || {
    echo "docker not found — this script is the no-make path, so Docker is required." >&2
    exit 1
}

# The first build is measured in hours: it compiles musl, libc++ (from the
# vendored llvm-project), the whole GTK3 stack, weston and mutter before it ever
# reaches the kernel.  Re-runs reuse the cached deps layer unless deps/ changed.
echo "==== anonymOS: building in Docker (BUILD_JOBS=$BUILD_JOBS) ===="

if [ "$MODE" = "shell" ]; then
    docker build --target build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" .
    exec docker run --rm -it -w /build "$IMAGE_NAME" bash
fi

mkdir -p "$OUT_DIR"

if docker buildx version >/dev/null 2>&1; then
    # BuildKit writes the `artifacts` stage (a scratch image holding just the
    # outputs) straight into $OUT_DIR — no container, no docker cp.
    docker buildx build \
        --target artifacts \
        "${BUILD_ARGS[@]}" \
        --output "type=local,dest=$OUT_DIR" \
        .
else
    # Older Docker without buildx: build the same default stage, then copy the
    # files out of a (never started) container.
    docker build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" .
    cid="$(docker create "$IMAGE_NAME" /bin/true)"
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
    docker cp "$cid:/hos-install.iso" "$OUT_DIR/"
    docker cp "$cid:/kernel.elf" "$OUT_DIR/"
fi

echo ""
echo "✅ Build complete: $OUT_DIR/hos-install.iso"
ls -lh "$OUT_DIR"
