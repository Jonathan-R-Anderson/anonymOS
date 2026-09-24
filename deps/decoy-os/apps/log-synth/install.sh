#!/bin/sh
# apps/log-synth/install.sh — stage the log-synth generator (Apache Mahout synthetic
# data, Java) into a decoy rootfs. Run by ../../stage-apps.sh as: install.sh <ROOTFS>.
#
# Installs into /opt/log-synth, where the shared OpenRC service (apps/synthetic-logs)
# expects the jar + schema at boot. Runtime is java, from SYNTH_PKGS in the Makefile.
#
# INSTALLED ONCE: a stamp (/opt/log-synth/.installed) makes a second run a no-op, so
# the payload is never copied twice into the same rootfs.
set -e

R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
APP="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
DEST="$R/opt/log-synth"
MANIFEST="$R/etc/synthetic-logs.stage"

log()  { echo "[log-synth] $*"; }
warn() { echo "[log-synth] WARN: $*" >&2; }
note() { mkdir -p "$R/etc"; printf '%s\n' "$*" >> "$MANIFEST"; }   # sourced by the service at boot

if [ -f "$DEST/.installed" ]; then
	log "already installed in this rootfs — skipping"
	exit 0
fi

mkdir -p "$DEST"

# The jar is not vendored prebuilt; it comes from a maven build (target/). Copy whatever
# jar is present; if none, warn and continue — a missing generator must never wedge the
# build, and the service guards against it at boot.
JAR="$(find "$APP" -name 'log-synth-*-jar-with-dependencies.jar' 2>/dev/null | head -1)"
[ -n "$JAR" ] || JAR="$(find "$APP/target" -name '*.jar' 2>/dev/null | head -1)"
if [ -n "$JAR" ] && [ -f "$JAR" ]; then
	cp "$JAR" "$DEST/"
	log "jar -> /opt/log-synth/$(basename "$JAR")"
	note "STAGE_LOGSYNTH_JAR=ok"
else
	warn "no jar found under apps/log-synth (build it: cd apps/log-synth && mvn -q package)"
	note "STAGE_LOGSYNTH_JAR=missing"
fi

# schema + examples the service references
if [ -f "$APP/examples/names-and-cities.json" ]; then
	cp "$APP/examples/names-and-cities.json" "$DEST/schema.json"
	log "schema.json"
fi
if [ -d "$APP/examples" ]; then
	cp -r "$APP/examples" "$DEST/examples"
	log "examples/"
fi

note "STAGE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
touch "$DEST/.installed"
log "done -> /opt/log-synth"
