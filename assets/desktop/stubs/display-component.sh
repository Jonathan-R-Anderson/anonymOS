#!/bin/sh
set -eu
COMPONENT="$(basename "$0")"
SESSION_SCRIPT="/etc/X11/xinit/minimal-i3-session"
log() {
  printf '[%s] %s\n' "$COMPONENT" "$1"
}

case "$COMPONENT" in
  Xorg)
    log "Xorg placeholder available; skipping real server bring-up."
    ;;
  xinit)
    log "Running xinit handoff to session script: $SESSION_SCRIPT"
    if [ -x "$SESSION_SCRIPT" ]; then
      exec "$SESSION_SCRIPT"
    fi
    ;;
  xdm|lightdm|gdm)
    log "Display manager shim launching session script: $SESSION_SCRIPT"
    if [ -x "$SESSION_SCRIPT" ]; then
      exec "$SESSION_SCRIPT"
    fi
    ;;
  i3)
    log "Starting i3 window manager placeholder"
    sleep 1
    ;;
  *)
    log "Unhandled display component"
    ;;
esac

exit 0
