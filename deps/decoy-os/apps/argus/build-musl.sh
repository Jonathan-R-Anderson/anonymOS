#!/bin/sh
# apps/argus/build-musl.sh — build argus as a musl binary for the decoy, in an Alpine container.
#
# VERIFIED recipe: this exact build was run and produces
#   dist/argus         : ELF x86-64, interpreter /lib/ld-musl-x86_64.so.1 (the decoy's musl)
#   dist/argus-server  : (fleet aggregator; not used by the decoy, produced anyway)
#
# argus is libbpf CO-RE, so the build-time vmlinux.h can come from ANY BTF (host's here); at RUN
# time the DECOY kernel must expose /sys/kernel/btf/vmlinux — enabled via CONFIG_DEBUG_INFO_BTF=y
# in deps/decoy-os/kernel/decoy-kernel.config (+ dwarves in the Dockerfile).
#
# Requires: docker, and host BTF at /sys/kernel/btf/vmlinux (present on any BTF-enabled host).
# Run this before `make` so apps/argus/install.sh has dist/argus to stage. Musl-portability
# header patches are already applied to src/ (sys/select.h, sys/time.h in metrics/forward/store/
# syscallanom).
set -e
HERE="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
IMG="${ARGUS_BUILDER_IMG:-argus-builder}"

[ -e /sys/kernel/btf/vmlinux ] || { echo "[argus] FATAL: /sys/kernel/btf/vmlinux absent — need a BTF-enabled build host" >&2; exit 1; }

docker build -t "$IMG" - >/dev/null <<'EOF'
FROM alpine:3.19
RUN apk add --no-cache build-base clang llvm bpftool libbpf-dev elfutils-dev zlib-dev pkgconf linux-headers
EOF

mkdir -p "$HERE/dist"
docker run --rm \
  -v "$HERE":/src:ro -v /sys/kernel/btf:/sys/kernel/btf:ro -v "$HERE/dist":/out \
  "$IMG" sh -e -c '
    cp -r /src /b && cd /b
    rm -f src/bpf/vmlinux.h src/bpf/*.o src/bpf/*.skel.h argus argus-server
    make
    cp argus /out/argus
    [ -f argus-server ] && cp argus-server /out/argus-server || true
    chmod 0755 /out/argus* 2>/dev/null || true
  '
echo "[argus] built -> $HERE/dist/argus"
file "$HERE/dist/argus" 2>/dev/null || true
