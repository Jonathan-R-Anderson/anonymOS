#!/usr/bin/env bash
# Darling -- run macOS (Mach-O, .app) software inside a domain (docs/COMPAT.md).
#
# Darling is a Darwin/macOS translation layer.  It is NOT in Alpine, so there is no Software Center
# package; this script is the way to get it.  Source is NOT vendored (it is large and has many
# submodules); this clones the pinned commit with submodules into deps/darling/ (gitignored) and
# builds it, installing under deps/darling/install.  hos-darling then runs `darling shell <program>`.
#
# PORTING STATUS (honest): historically Darling needed its own Linux kernel module (darling-mach);
# the project is moving its Mach/BSD emulation into usermode.  anonymOS is a custom kernel with a
# musl Linux PERSONALITY, not stock Linux, so the usermode build is the only viable target here and
# the Darwin syscalls it leans on (Mach traps, commpage, dyld behaviour) are a bring-up task tracked
# in docs/COMPAT.md.  Until that lands, hos-darling reports Darling-not-installed rather than faking it.
. "$(dirname "$0")/compat-common.sh"
DARLING_REPO="${DARLING_REPO:-https://github.com/VibeDarling/darling.git}"
DARLING_COMMIT="${DARLING_COMMIT:-HEAD}"     # pin to a commit once a bring-up baseline is chosen
DIR="$ROOT/deps/darling"
compat_fetch "$DIR" "$DARLING_REPO" "$DARLING_COMMIT" --recurse
echo "Fetched Darling into $DIR (submodules included)."
echo "Build (usermode) per the project's instructions into $DIR/build, 'make install' into"
echo "$DIR/install (darling at .../bin/darling). See docs/COMPAT.md for the anonymOS bring-up gaps."
