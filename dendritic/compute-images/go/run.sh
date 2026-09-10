#!/bin/sh
set -eu
: "${ENTRYPOINT:?no entrypoint supplied}"
[ -f "/work/$ENTRYPOINT" ] || { echo "entrypoint not found: $ENTRYPOINT" >&2; exit 2; }
exec go run "/work/$ENTRYPOINT"
