#!/bin/sh
# apps/orin/install.sh — STAGE Orin (offline forensics/integrity, Python) from the vendored
# source in THIS directory into a decoy rootfs. Run by stage-apps.sh as: install.sh <ROOTFS>.
#
# The upstream HOST installer (apt/pipx, installs onto the BUILD MACHINE, ignores <ROOTFS>) is
# preserved as install.upstream.sh and is deliberately NOT used here.
#
# !! stage-apps.sh only runs install.sh if EXECUTABLE:  chmod +x apps/*/install.sh
#
# Orin is Python-stdlib, so we stage the source + a PYTHONPATH launcher (no pip needed) and
# replicate the parts upstream deploys (rules -> /var/lib/orin/rules, config -> /etc/orin).
# Launched at boot by synthetic-logs-run:  orin stream --verbose  (needs libbpf; else switch the
# launcher to a collect/analyze loop). Feeds snoop-monitor via /etc/disk-reclaim/detectors.json.
set -e
R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
DEST="$R/opt/orin"
log() { echo "[orin] $*"; }
[ -f "$DEST/.installed" ] && { log "already staged in this rootfs"; exit 0; }

mkdir -p "$DEST" "$R/var/log/orin" "$R/etc/orin" "$R/var/lib/orin/rules" "$R/usr/local/bin"

[ -d "$APP/src" ] && cp -r "$APP/src" "$DEST/" || log "WARN no src/ in vendored orin (VERIFY layout)"
[ -d "$APP/rules" ] && cp -r "$APP/rules/." "$R/var/lib/orin/rules/" 2>/dev/null || true
if [ ! -f "$R/etc/orin/orin_config.json" ]; then
	if   [ -f "$APP/orin_config.json.example" ]; then cp "$APP/orin_config.json.example" "$R/etc/orin/orin_config.json"
	elif [ -f "$APP/orin_config.json" ];         then cp "$APP/orin_config.json"         "$R/etc/orin/orin_config.json"; fi
	[ -f "$R/etc/orin/orin_config.json" ] && chmod 600 "$R/etc/orin/orin_config.json"
fi

# launcher: run from source, no pip. VERIFY the module path (README: PYTHONPATH=src python -m orin.main).
cat > "$R/usr/local/bin/orin" <<'EOF'
#!/bin/sh
exec env PYTHONPATH=/opt/orin/src python3 -m orin.main "$@"
EOF
chmod 755 "$R/usr/local/bin/orin"

touch "$DEST/.installed"
log "done -> /opt/orin (+ launcher, rules, config). Enable its detectors.json entry after verifying."
