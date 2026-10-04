#!/usr/bin/env bash
# Package a Darling install for anonymOS: deps/darling/install (DESTDIR of `ninja install`) with its
# Linux-side programs replaced by the static musl builds from scripts/darling-musl-host.py, as one
# tarball (deps/darling/stage/darling.tar.gz) holding usr/local/... -- unpack it anywhere and run
#   DARLING_INSTALL_PREFIX=<dir>/usr/local DPREFIX=<prefix> DARLING_NONROOT=1 \
#       <dir>/usr/local/bin/darling shell <program>
# Non-root mode needs no namespaces or mounts: darlingserver copies the system root into the prefix
# (docs/hw-bringup/DARWIN.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="$ROOT/deps/darling"
INSTALL="$D/install"
MUSL="$D/build-musl"
STAGE="$D/stage"
[ -x "$INSTALL/usr/local/bin/darling" ] || { echo "no Darling install in $INSTALL (ninja install first)"; exit 1; }
for b in src/startup/darling src/external/darlingserver/darlingserver src/startup/mldr/mldr; do
    [ -x "$MUSL/$b" ] || { echo "missing musl build $MUSL/$b (run scripts/darling-musl-host.py)"; exit 1; }
done
rm -rf "$STAGE/tree" && mkdir -p "$STAGE/tree"
cp -a "$INSTALL/usr" "$STAGE/tree/"
L="$STAGE/tree/usr/local"
install -m 0755 "$MUSL/src/startup/darling" "$L/bin/darling"            # not setuid: non-root mode
install -m 0755 "$MUSL/src/external/darlingserver/darlingserver" "$L/bin/darlingserver"
install -m 0755 "$MUSL/src/startup/mldr/mldr" "$L/libexec/darling/usr/libexec/darling/mldr"
install -m 0755 "$MUSL/src/startup/mldr/mldr" "$L/libexec/darling/bin/mldr"
rm -f "$L/bin/darling-coredump"                                          # glibc-only diagnostic
if find "$STAGE/tree" -type f -exec file {} + | grep 'ELF' | grep -v 'statically linked'; then
    echo "a dynamically linked ELF is left in the stage (above)"; exit 1
fi
tar -C "$STAGE/tree" -czf "$STAGE/darling.tar.gz" usr
echo "staged $(du -sh "$STAGE/tree" | cut -f1) -> $STAGE/darling.tar.gz ($(du -h "$STAGE/darling.tar.gz" | cut -f1))"
