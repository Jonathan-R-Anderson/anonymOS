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
# Every run is also written to logs/build-<timestamp>.log, with logs/latest.log
# pointing at the most recent one — the build prints tens of thousands of lines and
# a terminal scrollback will not hold them.  On failure, the interesting part is the
# end of the file: scripts/docker-build-step.sh repeats the failing step's last 150
# lines and the newest meson log there.
#
#   tail -200 logs/latest.log         # what actually broke
#   grep -n "^=\+ FAILED" logs/latest.log
#
# Env:
#   BUILD_JOBS=N   parallelism for the dependency builds (default 1; the dep
#                  builds are memory-heavy, so raise it only on a big machine)
#   OUT_DIR=dir    where the artifacts land (default ./dist)
#   LOG_DIR=dir    where the build logs land (default ./logs)
#   LOG_FILE=path  exact log file to write (default $LOG_DIR/build-<timestamp>.log)
#   IMAGE_NAME=n   tag used by the non-buildx fallback path (default anonymos-builder)
#   LKL_BUILD_DIR=p  path INSIDE the build context to a prebuilt LKL tree; without
#                  one the ISO is staged without the lkl-boot WiFi module
set -euo pipefail
cd "$(dirname "$0")"

BUILD_JOBS="${BUILD_JOBS:-1}"
OUT_DIR="${OUT_DIR:-dist}"
LOG_DIR="${LOG_DIR:-logs}"
IMAGE_NAME="${IMAGE_NAME:-anonymos-builder}"
MODE="${1:-iso}"

BUILD_ARGS=(--build-arg "BUILD_JOBS=$BUILD_JOBS")
[ -n "${LKL_BUILD_DIR:-}" ] && BUILD_ARGS+=(--build-arg "LKL_BUILD_DIR=$LKL_BUILD_DIR")

command -v docker >/dev/null 2>&1 || {
    echo "docker not found — this script is the no-make path, so Docker is required." >&2
    exit 1
}

if [ "$MODE" = "shell" ]; then
    # Interactive: no logging, the point is the shell at the end.
    docker build --target build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" .
    exec docker run --rm -it -w /build "$IMAGE_NAME" bash
fi

mkdir -p "$OUT_DIR" "$LOG_DIR"
LOG_FILE="${LOG_FILE:-$LOG_DIR/build-$(date +%Y%m%d-%H%M%S).log}"
mkdir -p "$(dirname "$LOG_FILE")"
# logs/latest.log always points at the newest run — but only when the log actually
# lives in LOG_DIR (an explicit LOG_FILE elsewhere would make it a dangling link).
case "$LOG_FILE" in
    "$LOG_DIR"/*) ln -sfn "$(basename "$LOG_FILE")" "$LOG_DIR/latest.log" 2>/dev/null || true ;;
esac

# Say where the log is on the way out, whichever way we leave — a failure exits
# through `set -e` from inside a pipeline, so this cannot be a trailing echo.
on_exit() {
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        echo ""
        echo "✅ Build complete: $OUT_DIR/hos-install.iso"
        ls -lh "$OUT_DIR"
    else
        echo "" >&2
        echo "❌ Build failed (exit $rc). Full log: $LOG_FILE" >&2
        echo "   tail -200 $LOG_FILE" >&2
    fi
    echo "Log: $LOG_FILE"
    return "$rc"
}
trap on_exit EXIT

# The first build is measured in hours: it compiles musl, libc++ (from the
# vendored llvm-project), the whole GTK3 stack and weston before it ever reaches
# the kernel.  Re-runs reuse the cached dep layers unless deps/ changed.
echo "==== anonymOS: building in Docker (BUILD_JOBS=$BUILD_JOBS) ====" | tee "$LOG_FILE"
echo "Logging to $LOG_FILE"

if docker buildx version >/dev/null 2>&1; then
    # BuildKit writes the `artifacts` stage (a scratch image holding just the
    # outputs) straight into $OUT_DIR — no container, no docker cp.
    # --progress=plain: the default `auto` renders a live TTY dashboard that
    # collapses finished steps, so a log captured from it is unreadable.
    docker buildx build \
        --target artifacts \
        --progress=plain \
        "${BUILD_ARGS[@]}" \
        --output "type=local,dest=$OUT_DIR" \
        . 2>&1 | tee -a "$LOG_FILE"
else
    # Older Docker without buildx: build the same default stage, then copy the
    # files out of a (never started) container.
    docker build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" . 2>&1 | tee -a "$LOG_FILE"
    cid="$(docker create "$IMAGE_NAME" /bin/true)"
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true; on_exit' EXIT
    docker cp "$cid:/hos-install.iso" "$OUT_DIR/" 2>&1 | tee -a "$LOG_FILE"
    docker cp "$cid:/kernel.elf" "$OUT_DIR/" 2>&1 | tee -a "$LOG_FILE"
fi
