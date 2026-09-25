#!/bin/sh
# apps/prx-sd/install.sh — STAGE the musl `sd` binary into a decoy rootfs. Run by stage-apps.sh
# as: install.sh <ROOTFS>.
#
# The musl cross-build is done by build-musl.sh (an alpine:edge container build — the decoy's own
# Rust 1.76 is too old for prx-sd's edition-2024 crates) into dist/sd. Run
#   apps/prx-sd/build-musl.sh
# once before `make`; this script just copies the result in. The binary links OpenSSL/LMDB
# statically and only musl libc dynamically, so no extra runtime packages are needed.
#
# NB prx-sd is OFF-TARGET for snoop detection (it finds malware, not forensic examiners); it is
# enabled per request but consider leaving it out — argus + orin cover snoop detection better.
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
log() { echo "[prx-sd] $*"; }

if [ ! -f "$APP/dist/sd" ]; then
	log "no prebuilt binary at dist/sd — run apps/prx-sd/build-musl.sh first (needs docker). Skipping; the launcher will skip prx-sd until it is present."
	exit 0
fi

mkdir -p "$R/usr/local/bin" "$R/var/log/prx-sd"
install -m 755 "$APP/dist/sd" "$R/usr/local/bin/sd"
# prx-sd ships a minimal embedded signature set; run `sd update` (or stage a signature DB) for
# comprehensive detection. Enable its detectors.json entry after verifying its alert output.
log "staged /usr/local/bin/sd (musl)."
