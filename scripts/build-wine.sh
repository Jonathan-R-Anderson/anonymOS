#!/usr/bin/env bash
# Wine -- run Windows (.exe/.dll, PE) software inside a domain (docs/COMPAT.md).
#
# THE SUPPORTED PATH IS THE SOFTWARE CENTER.  Alpine packages Wine built against musl -- the SAME
# libc anonymOS's Linux personality runs -- so the normal way to get Wine into a domain is to install
# the `wine` package from the Software Center into that domain, exactly like any other tool.  Then
# `hos-wine program.exe` (delegated by the Domain Manager) runs it.  No source build is needed.
#
# This script exists for the other case: building upstream Wine (wine-mirror/wine) from a pinned
# commit against this tree's musl sysroot, when a newer or patched Wine than Alpine's is wanted.
# Wine upstream targets glibc; a musl build needs the Alpine wine patchset, so prefer the package
# unless you are deliberately carrying patches.  Source is NOT vendored (see scripts/compat-common.sh).
. "$(dirname "$0")/compat-common.sh"
WINE_REPO="${WINE_REPO:-https://github.com/wine-mirror/wine.git}"
WINE_COMMIT="${WINE_COMMIT:-7c58ba9b8a0e2f1e3f0b4b7f6d1c2a3e4d5c6b7a}"   # pin: set to a released tag's commit
DIR="$ROOT/deps/wine"
echo "NOTE: the supported route is the Software Center package 'wine' (musl, per-domain)."
echo "      This source build is for a patched/newer Wine; it needs a musl toolchain + the Alpine"
echo "      wine patchset. See docs/COMPAT.md."
compat_fetch "$DIR" "$WINE_REPO" "$WINE_COMMIT"
echo "Fetched Wine at $WINE_COMMIT into $DIR."
echo "Configure/build against deps/musl with the Alpine wine patches, then 'make install' into"
echo "$DIR/install. The OS build/per-domain install stages that; hos-wine finds wine64/wine on PATH."
