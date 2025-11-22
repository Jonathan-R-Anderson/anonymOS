#!/bin/sh
set -eu
SESSION_NAME="i3-desktop"
log() {
  printf '[session:%s] %s\n' "$SESSION_NAME" "$1"
}

log "Preparing session helpers"
PANEL_HELPER="/bin/i3status"
BACKGROUND_HELPER="/bin/xsetroot"
if [ -x "$BACKGROUND_HELPER" ]; then
  "$BACKGROUND_HELPER" -solid '#202020' || true
else
  log "No background helper present; skipping root window styling"
fi

if [ -x "$PANEL_HELPER" ]; then
  "$PANEL_HELPER" &
  log "Started panel helper ($PANEL_HELPER)"
else
  log "Panel helper not available; continuing without status bar"
fi

if [ -x /bin/i3 ]; then
  log "Launching window manager (/bin/i3)"
  exec /bin/i3
else
  log "i3 binary missing; ending session"
fi
