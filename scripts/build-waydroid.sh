#!/usr/bin/env bash
# Waydroid -- run Android (.apk) apps inside a domain (docs/COMPAT.md).
#
# Waydroid runs a full Android system in a container and shows its apps on Wayland.  The tooling
# (waydroid/waydroid) is small Python; this clones the pinned commit into deps/waydroid/ (gitignored).
# The Android system image is large and fetched at init time by waydroid itself, not vendored here.
#
# PORTING STATUS (honest): Waydroid needs Linux kernel features anonymOS does not provide -- binder
# and ashmem (the Android IPC/mem drivers) and the LXC/namespace stack it containers Android with.
# Those are a kernel bring-up task (docs/COMPAT.md); until they exist Waydroid cannot start a
# session here, and hos-waydroid reports Waydroid-not-installed rather than faking it.  The tooling
# is fetched so the integration (Domain Manager delegation, hos-waydroid) is in place for when it can.
. "$(dirname "$0")/compat-common.sh"
WAYDROID_REPO="${WAYDROID_REPO:-https://github.com/waydroid/waydroid.git}"
WAYDROID_COMMIT="${WAYDROID_COMMIT:-HEAD}"   # pin to a release commit once a baseline is chosen
DIR="$ROOT/deps/waydroid"
compat_fetch "$DIR" "$WAYDROID_REPO" "$WAYDROID_COMMIT"
echo "Fetched Waydroid tooling into $DIR."
echo "It installs with 'make install' (Python); it needs binder/ashmem + LXC at runtime -- see"
echo "docs/COMPAT.md for the anonymOS kernel bring-up this is gated on."
