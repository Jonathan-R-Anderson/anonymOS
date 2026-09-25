#!/bin/sh
# apps/prx-sd/install.sh — STAGE PRX-SD (antivirus engine, Rust) from the vendored source in THIS
# directory into a decoy rootfs. Run by stage-apps.sh as: install.sh <ROOTFS>.
#
# The upstream HOST installer (curl|bash) is preserved as install.upstream.sh (upstream's
# uninstall.sh also remains); neither is used here.
#
# !! stage-apps.sh only runs install.sh if EXECUTABLE:  chmod +x apps/*/install.sh
# !! OFF-TARGET (finds malware, not forensic examiners) + HEAVY. OFF by default in the launcher
# !!   (RUN_PRXSD=no) and disabled in detectors.json. Recommend leaving it off; argus+orin cover
# !!   snoop detection far better.
# !! CROSS-BUILD PORT: build for x86_64-unknown-linux-musl (static), then stage the YARA/signature
# !!   DB it expects at runtime. The host build below is a starting point, not a finished port.
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
log() { echo "[prx-sd] $*"; }

mkdir -p "$R/var/log/prx-sd"
# A cargo build here is slow, fetches crates from the network, and is off-target — so it is
# opt-in and off by default (matches RUN_PRXSD=no in the launcher):
if [ "${STAGE_PRXSD:-0}" != 1 ]; then
	log "skip build (off-target AV, off by default; set STAGE_PRXSD=1 to build). Cross-build port required."
	exit 0
fi
# PORT: cargo build --release --target x86_64-unknown-linux-musl (static).
if ( cd "$APP" && cargo build --release ); then
	if [ -f "$APP/target/release/sd" ]; then
		install -m 755 "$APP/target/release/sd" "$R/usr/local/bin/sd"
		log "installed /usr/local/bin/sd  (also stage its signature/YARA DB — VERIFY paths)"
	else
		log "WARN no target/release/sd produced — check the cargo build"
	fi
else
	log "WARN prx-sd build failed — musl cross-build port required. Detector stays skipped."
fi
