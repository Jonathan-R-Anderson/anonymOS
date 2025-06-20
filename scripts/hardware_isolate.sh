#!/bin/bash
# Run a hardware driver in an isolated container or LXC VM.
set -e
DRY_RUN=no
DEVICE=""
while [[ "$1" == --* ]]; do
  case "$1" in
    --dry-run) DRY_RUN=yes ; shift ;;
    --device) DEVICE=$2 ; shift 2 ;;
    *) break ;;
  esac
done
if [ -z "$1" ]; then
  echo "Usage: $0 [--dry-run] [--device DEVICE] <driver> [args...]" >&2
  exit 1
fi
DRIVER=$1
shift
if command -v docker >/dev/null 2>&1; then
  RUN_CMD="docker run --rm -it"
  if [ -n "$DEVICE" ]; then
    RUN_CMD="$RUN_CMD --device $DEVICE"
  fi
  RUN_CMD="$RUN_CMD --cap-drop ALL anonymos-hw $DRIVER $*"
else
  NAME=${DEVICE:-hw}
  RUN_CMD="lxc-execute -n $NAME -- $DRIVER $*"
fi
if [ "$DRY_RUN" = yes ]; then
  echo "$RUN_CMD"
else
  eval "$RUN_CMD"
fi
