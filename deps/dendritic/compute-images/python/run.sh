#!/bin/sh
# Runs the submitted entrypoint. Nothing else.
#
# `exec` rather than a wrapper process: the program's exit code IS the job's
# result, and a shell in between would report its own.
set -eu
: "${ENTRYPOINT:?no entrypoint supplied}"
[ -f "/work/$ENTRYPOINT" ] || { echo "entrypoint not found: $ENTRYPOINT" >&2; exit 2; }
exec python3 "/work/$ENTRYPOINT"
