#!/bin/sh
# syndichan-node installer -- entry point.
#
# THIS FILE IS STRICTLY POSIX sh, and deliberately tiny, because on Alpine it is
# the only part that can run: Alpine ships busybox ash and no bash at all, so
# `#!/usr/bin/env bash` fails with "bash: command not found" before a single
# check happens.
#
# The real installer is install-main.sh, which requires bash and stays that way
# on purpose. Its most important test is a SAM v3 handshake against
# 127.0.0.1:7656 using bash's /dev/tcp, which busybox does NOT provide; rewriting
# it in POSIX sh would mean probing the I2P bridge with nc (not guaranteed to
# exist) or not at all. So this file does one job: make sure bash exists, then
# hand over.
#
# No arrays, no [[ ]], no /dev/tcp, no local, no $'...' -- nothing that busybox
# ash cannot parse. Verified with `busybox ash -n` and `dash -n`.

set -eu

PROGRAM="$(basename "$0")"
DIR="$(cd "$(dirname "$0")" && pwd)"
MAIN="$DIR/install-main.sh"

if [ ! -f "$MAIN" ]; then
  echo "$PROGRAM: cannot find $MAIN -- this script must stay next to it" >&2
  exit 2
fi

# Only the three flags that change what THIS file does are inspected. Every
# argument is forwarded to install-main.sh untouched, including these.
DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --check|--dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) DRY_RUN=1 ;;   # --help must never install anything
  esac
done

# Already have bash: nothing to do. This is the path every non-Alpine machine
# takes, so the common case costs one command -v.
if command -v bash >/dev/null 2>&1; then
  exec bash "$MAIN" "$@"
fi

# --- no bash ---------------------------------------------------------------

PKG=""
CMD=""
if command -v apk >/dev/null 2>&1; then
  PKG="apk"; CMD="apk add --no-cache bash"
elif command -v apt-get >/dev/null 2>&1; then
  PKG="apt"; CMD="apt-get install -y bash"
elif command -v dnf >/dev/null 2>&1; then
  PKG="dnf"; CMD="dnf install -y bash"
elif command -v pacman >/dev/null 2>&1; then
  PKG="pacman"; CMD="pacman -S --needed --noconfirm bash"
elif command -v zypper >/dev/null 2>&1; then
  PKG="zypper"; CMD="zypper --non-interactive install bash"
elif command -v yum >/dev/null 2>&1; then
  PKG="yum"; CMD="yum install -y bash"
fi

printf 'syndichan-node installer\n\n'
printf '  %-8s %-22s %s\n' "STATUS" "DEPENDENCY" "DETAIL"
printf '  %-8s %-22s %s\n' "------" "----------" "------"
if [ -n "$CMD" ]; then
  printf '  %-8s %-22s %s\n' "install" "bash" "missing; will install it with: $CMD"
else
  printf '  %-8s %-22s %s\n' "cannot" "bash" "missing, and no known package manager here"
fi
printf '  %-8s %-22s %s\n' "skip" "everything else" "cannot be checked until bash exists"
printf '\n'

# --check must not install, and must not pretend it checked the rest.
if [ "$DRY_RUN" = "1" ]; then
  echo "bash is missing, so only this much could be checked."
  if [ -n "$CMD" ]; then
    echo "Install it and re-run to see the full dependency report:"
    echo "    sudo $CMD"
    echo "    sudo $0 --check"
  else
    echo "Install bash with whatever this system uses, then re-run: $0 --check"
  fi
  exit 1
fi

if [ -z "$CMD" ]; then
  echo "$PROGRAM: bash is required and no known package manager was found." >&2
  echo "Install bash by hand, then re-run: $0 $*" >&2
  exit 1
fi

if [ "$(id -u)" != "0" ]; then
  echo "$PROGRAM: bash is missing and installing it needs root." >&2
  echo "Run:  sudo $CMD" >&2
  echo "Then: sudo $0 $*" >&2
  exit 1
fi

if [ "$ASSUME_YES" != "1" ]; then
  printf 'Install bash now? [y/N] '
  read -r answer || answer=""
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Nothing was changed."; exit 0 ;;
  esac
fi

echo "==> $CMD"
if [ "$PKG" = "apt" ]; then
  apt-get update
fi
# Unquoted on purpose: CMD is built from the fixed table above, never from user
# input, and must be split into words.
# shellcheck disable=SC2086
if ! $CMD; then
  echo "$PROGRAM: could not install bash. Install it by hand and re-run." >&2
  exit 1
fi

if ! command -v bash >/dev/null 2>&1; then
  echo "$PROGRAM: bash still not found after '$CMD'." >&2
  exit 1
fi

exec bash "$MAIN" "$@"
