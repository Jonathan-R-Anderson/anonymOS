#!/usr/bin/env bash
# Build anonymOS in Docker and drop the installer ISO on the host.
#
#   ./build-in-docker.sh              # -> dist/hos-install.iso (+ dist/kernel.elf)
#   ./build-in-docker.sh shell        # build everything, then drop into the tree
#
# Docker is the only host requirement — the whole make (musl, libc++, the GTK
# stack, weston, the D kernel, the boot tree, the ISO) happens inside the image.
#
# Every run is logged to logs/build-<timestamp>.log (logs/latest.log points at the
# newest); on failure the tail of that log is printed automatically.
#
# Env:
#   BUILD_JOBS=N   parallelism for the dependency builds (default 1; they are
#                  memory-heavy, so raise it only on a big machine)
#   OUT_DIR=dir    where the artifacts land (default ./dist)
#   LOG_DIR=dir    where the build logs land (default ./logs)
#   LOG_FILE=path  exact log file to write
#   IMAGE_NAME=n   image tag (default anonymos-builder)
#   USE_BUILDX=1   export artifacts with `buildx --output` instead of docker cp
#   LKL_BUILD_DIR=p  path INSIDE the build context to a prebuilt LKL tree; without
#                  one the ISO is staged without the lkl-boot WiFi module
set -uo pipefail
cd "$(dirname "$0")"

BUILD_JOBS="${BUILD_JOBS:-1}"
OUT_DIR="${OUT_DIR:-dist}"
LOG_DIR="${LOG_DIR:-logs}"
IMAGE_NAME="${IMAGE_NAME:-anonymos-builder}"
MODE="${1:-iso}"

BUILD_ARGS=(--build-arg "BUILD_JOBS=$BUILD_JOBS")
[ -n "${LKL_BUILD_DIR:-}" ] && BUILD_ARGS+=(--build-arg "LKL_BUILD_DIR=$LKL_BUILD_DIR")

# Plain, line-by-line build output instead of the live TTY dashboard, which
# collapses finished steps and is unreadable once captured to a file.  Honoured by
# both `docker build` and `docker buildx build`, and ignored by versions that
# predate it — unlike --progress=plain, which older CLIs reject outright.
export BUILDKIT_PROGRESS=plain

command -v docker >/dev/null 2>&1 || {
    echo "docker not found — this script is the no-make path, so Docker is required." >&2
    exit 1
}

if [ "$MODE" = "shell" ]; then
    docker build --target build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" . || exit $?
    exec docker run --rm -it -w /build "$IMAGE_NAME" bash
fi

mkdir -p "$OUT_DIR" "$LOG_DIR"
LOG_FILE="${LOG_FILE:-$LOG_DIR/build-$(date +%Y%m%d-%H%M%S).log}"
mkdir -p "$(dirname "$LOG_FILE")"
case "$LOG_FILE" in
    "$LOG_DIR"/*) ln -sfn "$(basename "$LOG_FILE")" "$LOG_DIR/latest.log" 2>/dev/null || true ;;
esac

# log_run <label> <command...> — run it with its output going STRAIGHT to the log
# file, never through a pipe, and stream the file to the terminal meanwhile.
#
# This is not a style choice.  Go kills a process outright on SIGPIPE when the
# broken pipe is stdout or stderr, so `docker build ... | tee` means any hiccup in
# the pipe kills the build: exit 141, no error message, and the daemon logging
# `request cancelled by client / unexpected EOF`.  A plain file redirect cannot
# SIGPIPE, so docker lives long enough to report its own failures.
log_run() {
    local label="$1"; shift
    echo "---- $label ----" >> "$LOG_FILE"
    tail -n0 -F "$LOG_FILE" 2>/dev/null &
    local tail_pid=$!
    "$@" >> "$LOG_FILE" 2>&1
    local rc=$?
    sleep 1
    kill "$tail_pid" 2>/dev/null
    wait "$tail_pid" 2>/dev/null
    return "$rc"
}

# Everything a "it just died" needs answering, printed on the spot: docker said
# nothing useful in this failure mode, so ask the machine instead.  A build killed
# by the OOM killer or a full docker root disk looks exactly like a silent crash.
diagnose() {
    echo "" >&2
    echo "---- last 40 lines of $LOG_FILE ----" >&2
    tail -40 "$LOG_FILE" >&2
    echo "---- diagnostics ----" >&2
    docker version --format "client {{.Client.Version}} / server {{.Server.Version}}" 2>&1 | sed "s/^/  /" >&2
    local root
    root="$(docker info --format "{{.DockerRootDir}}" 2>/dev/null || echo /var/lib/docker)"
    echo "  docker root: $root" >&2
    df -h "$root" 2>/dev/null | tail -1 | sed "s/^/  disk: /" >&2
    free -m 2>/dev/null | sed -n "2p" | sed "s/^/  mem(MB): /" >&2
    echo "  repo tree (before .dockerignore): $(du -sh . 2>/dev/null | cut -f1), $(find . -type f 2>/dev/null | wc -l) files" >&2
    if dmesg 2>/dev/null | tail -50 | grep -qiE "out of memory|killed process"; then
        echo "  !! the kernel log shows a recent OOM kill:" >&2
        dmesg 2>/dev/null | grep -iE "out of memory|killed process" | tail -3 | sed "s/^/    /" >&2
    fi
    # An exit of 141 is SIGPIPE: the CLI was killed because the daemon hung up on it.
    # Nothing the CLI prints explains that — the reason is in the daemon's own log.
    if command -v journalctl >/dev/null 2>&1; then
        echo "---- docker daemon log (last 30 lines) ----" >&2
        journalctl -u docker -n 30 --no-pager 2>&1 | sed "s/^/  /" >&2
    fi
    echo "---- full log: $LOG_FILE ----" >&2
}

echo "==== anonymOS: building in Docker (BUILD_JOBS=$BUILD_JOBS) ====" | tee "$LOG_FILE"
echo "Logging to $LOG_FILE"

if [ "${USE_BUILDX:-0}" = 1 ]; then
    # Opt-in: BuildKit writes the `artifacts` stage straight into $OUT_DIR.
    log_run "docker buildx build (artifacts -> $OUT_DIR)" \
        docker buildx build --target artifacts "${BUILD_ARGS[@]}" \
            --output "type=local,dest=$OUT_DIR" . \
        || { echo "❌ buildx build failed (exit $?)" >&2; diagnose; exit 1; }
else
    # Default: build the image (its last stage is `artifacts`, a scratch image
    # holding just the ISO and kernel.elf), then copy the files out of a container
    # that is created but never started.  No buildx-only flags anywhere.
    log_run "docker build (BuildKit)" docker build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" .
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "" >&2
        echo "⚠  BuildKit build failed (exit $rc) — retrying with the classic builder." >&2
        echo "   (DOCKER_BUILDKIT=0: different context handling and error reporting," >&2
        echo "    and it works on setups where the BuildKit session dies silently.)" >&2
        DOCKER_BUILDKIT=0 log_run "docker build (classic builder)" \
            docker build "${BUILD_ARGS[@]}" -t "$IMAGE_NAME" .
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "" >&2
            echo "❌ both builders failed (exit $rc)" >&2
            diagnose
            exit "$rc"
        fi
    fi

    cid="$(docker create "$IMAGE_NAME" /bin/true 2>>"$LOG_FILE")" || {
        echo "❌ docker create failed" >&2; diagnose; exit 1; }
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
    log_run "extract hos-install.iso" docker cp "$cid:/hos-install.iso" "$OUT_DIR/" \
        || { echo "❌ could not extract the ISO" >&2; diagnose; exit 1; }
    log_run "extract kernel.elf" docker cp "$cid:/kernel.elf" "$OUT_DIR/" \
        || { echo "❌ could not extract kernel.elf" >&2; diagnose; exit 1; }
fi

echo ""
echo "✅ Build complete: $OUT_DIR/hos-install.iso"
ls -lh "$OUT_DIR"
echo "Log: $LOG_FILE"
