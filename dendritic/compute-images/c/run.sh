#!/bin/sh
set -eu
: "${ENTRYPOINT:?no entrypoint supplied}"
[ -f "/work/$ENTRYPOINT" ] || { echo "entrypoint not found: $ENTRYPOINT" >&2; exit 2; }
# Built into /tmp because the root filesystem is read-only, deliberately.
gcc -O2 -frandom-seed=0 -o /tmp/prog "/work/$ENTRYPOINT" 2>&1
exec /tmp/prog
