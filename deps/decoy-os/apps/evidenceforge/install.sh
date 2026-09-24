#!/bin/sh
# apps/evidenceforge/install.sh — stage the evidenceforge generator (Python) into a
# decoy rootfs. Run by ../../stage-apps.sh as: install.sh <ROOTFS>.
#
# Installs into /opt/evidenceforge, where the shared OpenRC service (apps/synthetic-logs)
# expects the source tree + the branch-office scenario at boot. Runtime is python3, from
# SYNTH_PKGS in the Makefile.
#
# INSTALLED ONCE: a stamp (/opt/evidenceforge/.installed) makes a second run a no-op.
set -e

R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
DEST="$R/opt/evidenceforge"
MANIFEST="$R/etc/synthetic-logs.stage"

log()  { echo "[evidenceforge] $*"; }
warn() { echo "[evidenceforge] WARN: $*" >&2; }
note() { mkdir -p "$R/etc"; printf '%s\n' "$*" >> "$MANIFEST"; }   # sourced by the service at boot

if [ -f "$DEST/.installed" ]; then
	log "already installed in this rootfs — skipping"
	exit 0
fi

mkdir -p "$DEST"

# copy the parts the service uses (src, scenarios, project metadata); skip VCS/build cruft
for item in src scenarios pyproject.toml uv.lock README.md; do
	if [ -e "$APP/$item" ]; then
		cp -r "$APP/$item" "$DEST/"
		log "$item"
	fi
done

# the exact scenario the service runs by default
if [ -f "$DEST/scenarios/branch-office-example/scenario.yaml" ]; then
	note "STAGE_EFORGE_SCENARIO=ok"
else
	warn "branch-office-example/scenario.yaml missing — the service's default scenario is absent"
	note "STAGE_EFORGE_SCENARIO=missing"
fi

# Optional: pip-install into the rootfs so `python3 -m evidenceforge` resolves. Needs pip
# INSIDE the rootfs (py3-pip); if absent, the service can still run it from /opt via
# PYTHONPATH. Non-fatal either way.
if [ -x "$R/usr/bin/pip3" ] || [ -x "$R/usr/bin/pip" ]; then
	if mountpoint -q "$R/proc" 2>/dev/null || mount -t proc proc "$R/proc" 2>/dev/null; then
		if chroot "$R" /usr/bin/env pip3 install --no-index --no-build-isolation /opt/evidenceforge >/dev/null 2>&1; then
			log "pip installed into rootfs"
			note "STAGE_EFORGE_PIP=ok"
		else
			warn "pip install failed (offline/deps) — service will run from /opt via PYTHONPATH"
			note "STAGE_EFORGE_PIP=skipped"
		fi
		umount "$R/proc" 2>/dev/null || true
	else
		note "STAGE_EFORGE_PIP=skipped"
	fi
else
	log "no pip in rootfs — service runs evidenceforge from /opt via PYTHONPATH"
	note "STAGE_EFORGE_PIP=no-pip"
fi

note "STAGE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
touch "$DEST/.installed"
log "done -> /opt/evidenceforge"
