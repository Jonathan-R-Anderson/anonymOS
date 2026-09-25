#!/bin/sh
# apps/spectre/install.sh — STAGE Project Spectre (behavioral HIDS, Python) from the vendored
# source in THIS directory into a decoy rootfs. Run by stage-apps.sh as: install.sh <ROOTFS>.
#
# The upstream HOST installer (curl|bash, installs onto the BUILD MACHINE) is preserved as
# install.upstream.sh and is deliberately NOT used here.
#
# !! stage-apps.sh only runs install.sh if EXECUTABLE:  chmod +x apps/*/install.sh
#
# Spectre needs 3rd-party deps (fastapi/networkx/yara/psutil/…), so we pip-install the vendored
# source INTO the rootfs (needs py3-pip in $R). VERIFY they resolve on your Alpine (yara may need
# py3-yara or a compiler). Launched by synthetic-logs-run:
#   spectre run --no-api --contain none --log-file /var/log/spectre/alerts.log
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
DEST="$R/opt/spectre"
log() { echo "[spectre] $*"; }
[ -f "$DEST/.installed" ] && { log "already staged in this rootfs"; exit 0; }

mkdir -p "$DEST" "$R/var/log/spectre"
# copy the vendored source, minus VCS + the install scripts themselves
cp -r "$APP/." "$DEST/"
rm -rf "$DEST/.git" "$DEST/install.sh" "$DEST/install.upstream.sh" "$DEST/.installed"

if [ -x "$R/usr/bin/pip3" ] && { mountpoint -q "$R/proc" 2>/dev/null || mount -t proc proc "$R/proc" 2>/dev/null; }; then
	if chroot "$R" /usr/bin/env sh -c 'cd /opt/spectre && pip3 install --break-system-packages ".[yara]"'; then
		log "pip installed spectre into rootfs"
	else
		log "WARN pip install failed (offline/deps) — provide offline wheels or a PYTHONPATH launcher (VERIFY)"
	fi
	umount "$R/proc" 2>/dev/null || true
else
	log "WARN no pip in rootfs — wire /usr/local/bin/spectre to /opt/spectre's entrypoint (VERIFY)"
fi
touch "$DEST/.installed"
log "done -> /opt/spectre. Enable its detectors.json entry after verifying alerts."
