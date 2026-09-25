#!/bin/sh
# apps/argus/install.sh — STAGE Argus (eBPF kernel telemetry, C) from the vendored source in
# THIS directory into a decoy rootfs, as a snoop-detector feeding snoop-monitor. Run by
# stage-apps.sh as: install.sh <ROOTFS>.
#
# !! stage-apps.sh only runs install.sh if it is EXECUTABLE:  chmod +x apps/*/install.sh
#
# !! CROSS-BUILD PORT REQUIRED — will NOT work as-is:
# !!   1. argus's `make` generates vmlinux.h from the *running* kernel's BTF via bpftool. In an
# !!      image build that is the BUILD HOST kernel, not the decoy kernel. Generate vmlinux.h
# !!      from the DECOY kernel's BTF (deps/decoy-os builds vmlinuz-decoy), built with
# !!      CONFIG_DEBUG_INFO_BTF=y, or argus won't load at boot.
# !!   2. Link the loader for the decoy's musl/static environment (clang/libbpf/libelf/zlib),
# !!      per the deps/<name> cross-build convention (installer/ARCHITECTURE.md).
# !! Treat this as a starting point to port, not a finished build.
#
# Launched at boot by synthetic-logs-run:  argus --json  (stdout -> /var/log/argus/service.log,
# tailed by snoop-monitor; see /etc/disk-reclaim/detectors.json). VERIFY argus's JSON event-type
# strings match that detector's pattern.
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"     # the vendored argus source lives here
log() { echo "[argus] $*"; }

mkdir -p "$R/var/log/argus"
# A plain host `make` here runs on every image build and produces glibc/host-BTF binaries that
# will NOT run on the musl decoy kernel (see header). So it is opt-in until the port is done:
if [ "${STAGE_ARGUS:-0}" != 1 ]; then
	log "skip build (set STAGE_ARGUS=1 to attempt a host build; a real decoy build needs the"
	log "BTF/musl cross-build port). Launcher will skip argus until its binary is installed."
	exit 0
fi
# PORT: build against the DECOY kernel's BTF, cross-linked for musl. Placeholder host build:
if ( cd "$APP" && make ); then
	if [ -f "$APP/argus" ]; then
		install -m 755 "$APP/argus" "$R/usr/local/bin/argus"
		log "installed /usr/local/bin/argus  (VERIFY it loads on the decoy kernel + emits JSON)"
	else
		log "WARN build produced no ./argus binary — check the make output"
	fi
else
	log "WARN argus build failed — cross-build/BTF port required (see header). Detector stays skipped."
fi
