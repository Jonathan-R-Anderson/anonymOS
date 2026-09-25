#!/bin/sh
# apps/argus/install.sh — STAGE the musl argus binary into a decoy rootfs. Run by stage-apps.sh
# as: install.sh <ROOTFS>.
#
# The musl cross-build is done by build-musl.sh (a verified Alpine-container build) into dist/,
# because the build needs a full C/eBPF/libbpf toolchain and host BTF that don't belong in the
# rootfs staging step. Run  apps/argus/build-musl.sh  once before `make`; this script just copies
# the result in. Runtime libs (libbpf, libelf, zlib, zstd-libs) come from RECLAIM_DEP_PKGS in the
# decoy Makefile, and argus needs the decoy kernel's BTF (CONFIG_DEBUG_INFO_BTF=y, enabled).
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
log() { echo "[argus] $*"; }

if [ ! -f "$APP/dist/argus" ]; then
	log "no prebuilt binary at dist/argus — run apps/argus/build-musl.sh first (needs docker + host BTF). Skipping; the launcher will skip argus until it is present."
	exit 0
fi

mkdir -p "$R/usr/local/bin" "$R/var/log/argus"
install -m 755 "$APP/dist/argus" "$R/usr/local/bin/argus"
[ -f "$APP/dist/argus-server" ] && install -m 755 "$APP/dist/argus-server" "$R/usr/local/bin/argus-server" || true
log "staged /usr/local/bin/argus (musl). Enable its detectors.json entry after verifying alerts."
