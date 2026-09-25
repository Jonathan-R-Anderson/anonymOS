#!/bin/sh
# apps/prx-sd/build-musl.sh — build prx-sd's `sd` binary as a musl binary for the decoy.
#
# Alpine 3.19 (the decoy) ships Rust 1.76, but prx-sd requires edition 2024 (Rust >= 1.85), so we
# build in an alpine:edge container (Rust 1.98, musl-native) with STATIC OpenSSL so the result runs
# on the 3.19 decoy regardless of its libssl version. LMDB is bundled (lmdb-master-sys). Produces
# dist/sd.
#
# crt-static is deliberately NOT set: `-C target-feature=+crt-static` breaks proc-macro crates on a
# musl-native host (asn1-rs-derive et al. can't be built as static proc-macros). Without it the
# binary dynamically links only musl libc, whose ABI is stable across Alpine versions.
#
# Requires: docker. First run pulls Rust + crates (large); a named cargo volume caches them.
set -e
HERE="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
IMG="${PRXSD_BUILDER_IMG:-prxsd-edge}"

docker build -t "$IMG" - >/dev/null <<'EOF'
FROM alpine:edge
RUN apk add --no-cache build-base rust cargo pkgconf openssl-dev openssl-libs-static lmdb-dev linux-headers
EOF

mkdir -p "$HERE/dist"
docker run --rm \
  -v "$HERE":/src:ro -v prxsd-cargo:/root/.cargo -v prxsd-target:/target -v "$HERE/dist":/out \
  "$IMG" sh -e -c '
    cp -r /src /b && cd /b
    export OPENSSL_STATIC=1 OPENSSL_DIR=/usr CARGO_TARGET_DIR=/target
    cargo build --release
    cp /target/release/sd /out/sd
    chmod 0755 /out/sd
  '
echo "[prx-sd] built -> $HERE/dist/sd"
file "$HERE/dist/sd" 2>/dev/null || true
