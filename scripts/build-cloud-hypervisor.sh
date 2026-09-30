#!/usr/bin/env bash
# Build Cloud Hypervisor as a static-musl binary for the anonymOS VMM tier.
#
# Cloud Hypervisor is the first userspace VMM target: it is the only researched
# VMM that boots x86_64 with SPLIT irqchip (it never calls KVM_CREATE_IRQCHIP,
# which anonymOS rejects) — see docs/hw-bringup/CLOUD_HYPERVISOR.md.  Its KVM
# ABI needs (Phase-0 caps IRQ_ROUTING/IRQFD/IOEVENTFD, the Phase-5 ioctls, and
# guest entry) are implemented in src/kernel/d/core/virt/.
#
# The source is NOT vendored (it is large and Apache-2.0/BSD-3 — license-clean
# to depend on).  This clones the pinned commit into deps/cloud-hypervisor/
# (gitignored), applies patches/cloud-hypervisor/*.patch, and builds the binary;
# the OS image build copies the result into cd/ (see the Makefile).
#
# Requires: a Rust toolchain (rustc/cargo) and the musl cross gcc used elsewhere
# in this tree (deps use ~/lkl-build/x86_64-linux-musl-cross for cc-rs crates
# such as zstd-sys).  Both are the same tools the LKL/ethsign deps already use.
set -euo pipefail

# Pinned to the exact commit traced in docs/hw-bringup/CLOUD_HYPERVISOR.md.
CH_COMMIT="${CH_COMMIT:-48e9deba50e7a61250ef7b855b34c45b5eaa9a88}"
CH_REPO="${CH_REPO:-https://github.com/cloud-hypervisor/cloud-hypervisor.git}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CH_DIR="$ROOT/deps/cloud-hypervisor"
TARGET="x86_64-unknown-linux-musl"

CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"
MUSL_CROSS="${MUSL_CROSS:-$HOME/lkl-build/x86_64-linux-musl-cross/bin}"
MUSL_GCC="$MUSL_CROSS/x86_64-linux-musl-gcc"

[ -x "$CARGO_BIN" ] || { echo "cargo not found at $CARGO_BIN (set CARGO=...)"; exit 1; }
[ -x "$MUSL_GCC" ]  || { echo "musl cross gcc not found at $MUSL_GCC (set MUSL_CROSS=...)"; exit 1; }

# Fetch just the pinned commit (depth 1) into deps/cloud-hypervisor/.
if [ ! -e "$CH_DIR/.git" ]; then
    mkdir -p "$CH_DIR"
    git -C "$CH_DIR" init -q
    git -C "$CH_DIR" remote add origin "$CH_REPO"
fi
if ! git -C "$CH_DIR" cat-file -e "$CH_COMMIT^{commit}" 2>/dev/null; then
    echo "Fetching Cloud Hypervisor $CH_COMMIT (depth 1)..."
    git -C "$CH_DIR" fetch --depth 1 origin "$CH_COMMIT"
fi
git -C "$CH_DIR" checkout -q "$CH_COMMIT"

# anonymOS patches (patches/cloud-hypervisor/*.patch, in order): what FreeBSD guests (OPNsense) need
# from the devices, and later ones.  Idempotent: a patch already in the tree is skipped; one that
# neither applies nor is present stops the build.
for p in "$ROOT"/patches/cloud-hypervisor/*.patch; do
    [ -f "$p" ] || continue
    if git -C "$CH_DIR" apply --check "$p" 2>/dev/null; then
        git -C "$CH_DIR" apply "$p"
        echo "applied $(basename "$p")"
    elif git -C "$CH_DIR" apply --check -R "$p" 2>/dev/null; then
        echo "already applied $(basename "$p")"
    else
        echo "patch $(basename "$p") does not apply to $CH_COMMIT" >&2
        exit 1
    fi
done

# The musl target uses the Rust-provided musl for its own std, but some C build
# scripts (zstd-sys) need a musl gcc for cc-rs; point the target's CC/AR/linker
# at the cross toolchain the rest of the tree already uses.
export PATH="$MUSL_CROSS:$(dirname "$CARGO_BIN"):$PATH"
export CC_x86_64_unknown_linux_musl="x86_64-linux-musl-gcc"
export AR_x86_64_unknown_linux_musl="x86_64-linux-musl-ar"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="x86_64-linux-musl-gcc"

echo "Building cloud-hypervisor ($TARGET, release)..."
( cd "$CH_DIR" && "$CARGO_BIN" build --release --target "$TARGET" --bin cloud-hypervisor )

BIN="$CH_DIR/target/$TARGET/release/cloud-hypervisor"
[ -x "$BIN" ] || { echo "build produced no binary at $BIN"; exit 1; }
echo "OK: $BIN"
file "$BIN" || true
