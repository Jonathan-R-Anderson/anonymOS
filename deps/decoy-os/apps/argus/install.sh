#!/bin/sh
# apps/argus/install.sh — vendor + build Argus (eBPF kernel telemetry, C) into a decoy rootfs
# as a snoop-detector feeding snoop-monitor. Run by stage-apps.sh: install.sh <ROOTFS>.
#
# !! stage-apps.sh only runs install.sh if it is EXECUTABLE:  chmod +x apps/*/install.sh
#
# !! CROSS-BUILD PORT REQUIRED — this will NOT work as-is. Two hard problems:
# !!   1. argus's `make` generates vmlinux.h from the *running* kernel's BTF via bpftool. In an
# !!      image build that is the BUILD HOST kernel, not the decoy kernel. You must generate
# !!      vmlinux.h from the DECOY kernel's BTF (deps/decoy-os builds vmlinuz-decoy) and the
# !!      decoy kernel must be built with CONFIG_DEBUG_INFO_BTF=y, or argus won't load at boot.
# !!   2. The userspace loader must link for the decoy's musl/static environment (clang, libbpf,
# !!      libelf, zlib), matching the deps/<name> cross-build convention (see installer/ARCHITECTURE.md).
# !! Treat the steps below as a starting point to be ported, not a finished build.
#
# Launched at boot by synthetic-logs-run:  argus --json  (stdout -> /var/log/argus/service.log,
# tailed by snoop-monitor; see /etc/disk-reclaim/detectors.json). VERIFY argus's JSON event-type
# strings match that detector's pattern (ptrace/kernel_module/namespace_escape/mem_exec).
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REF="${ARGUS_REF:-main}"            # PIN to an audited commit before shipping
log() { echo "[argus] $*"; }

if [ ! -d "$APP/upstream/.git" ]; then
	log "cloning upstream @ $REF"
	git clone https://github.com/DennisPrudlik/argus "$APP/upstream"
fi
git -C "$APP/upstream" fetch origin "$REF" 2>/dev/null || true
git -C "$APP/upstream" checkout -q "$REF" 2>/dev/null || true

mkdir -p "$R/var/log/argus"
# PORT: build against the DECOY kernel's BTF, cross-linked for musl. Placeholder host build:
if ( cd "$APP/upstream" && make ); then
	if [ -f "$APP/upstream/argus" ]; then
		install -m 755 "$APP/upstream/argus" "$R/usr/local/bin/argus"
		log "installed /usr/local/bin/argus  (VERIFY it loads on the decoy kernel + emits JSON)"
	else
		log "WARN build produced no ./argus binary — check upstream make output"
	fi
else
	log "WARN argus build failed — cross-build/BTF port required (see header). Detector will stay skipped."
fi
