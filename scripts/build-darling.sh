#!/usr/bin/env bash
# Darling -- run macOS (Mach-O, .app) software inside a domain (docs/COMPAT.md, docs/hw-bringup/DARWIN.md).
#
# Darling is a Darwin/macOS translation layer.  It is NOT in Alpine, so there is no Software Center
# package; this script is the way to get it.  Source is NOT vendored (it is large and has many
# submodules): this fetches VibeDarling (latest master unless DARLING_COMMIT pins a SHA) with its
# submodules into deps/darling/ (gitignored), applies scripts/darling-patches/, and builds it.
#
# anonymOS runs Darling's USERMODE architecture: `mldr` loads Mach-O in userspace and `darlingserver`
# implements Mach IPC and the Darwin syscalls, both as ordinary programs on the kernel's Linux
# personality.  Its non-root mode needs no namespaces or mounts.  Those programs (and the `darling`
# launcher) are the only ELF files Darling installs; they are rebuilt as static musl executables
# (scripts/darling-musl-host.py) and staged with the Mach-O tree (scripts/darling-stage.sh) as
# deps/darling/stage/darling.tar.gz.
#
# Steps: fetch -> patch -> host tools (bison, flex, libucontext; no root needed) -> cmake/ninja
# (COMPONENTS, default cli) -> DESTDIR install -> musl host programs -> stage.
. "$(dirname "$0")/compat-common.sh"
DARLING_REPO="${DARLING_REPO:-https://github.com/VibeDarling/darling.git}"
DARLING_COMMIT="${DARLING_COMMIT:-HEAD}"     # a moving ref fetches the latest; a 40-hex SHA pins
COMPONENTS="${DARLING_COMPONENTS:-cli}"
DIR="$ROOT/deps/darling"
TOOLS="$DIR/build-tools"
JOBS="${JOBS:-$(nproc)}"

compat_fetch "$DIR" "$DARLING_REPO" "$DARLING_COMMIT" --recurse

# Local fixes, one patch per file named <submodule>-NNNN-*.patch (or superproject-NNNN-*.patch);
# idempotent: a patch that is already applied is skipped.
for p in "$ROOT"/scripts/darling-patches/*.patch; do
    [ -e "$p" ] || continue
    sub="${p##*/}"; sub="${sub%%-[0-9][0-9][0-9][0-9]-*}"
    where="$DIR"; [ "$sub" = superproject ] || where="$DIR/src/external/$sub"
    if git -C "$where" apply --check -R "$p" 2>/dev/null; then
        echo "patch already applied: ${p##*/}"
    else
        git -C "$where" apply "$p" && echo "applied: ${p##*/}"
    fi
done

# Host tools Darling's build needs that a stock host may lack, built into $TOOLS (no root).
fetch_tool() {   # <url> <sha256> <file>
    [ -f "$TOOLS/src/$3" ] || curl -sSL -o "$TOOLS/src/$3" "$1"
    echo "$2  $TOOLS/src/$3" | sha256sum -c --quiet
}
mkdir -p "$TOOLS/src"
if ! command -v bison >/dev/null && [ ! -x "$TOOLS/bin/bison" ]; then
    fetch_tool https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz \
        9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2 bison-3.8.2.tar.xz
    (cd "$TOOLS/src" && tar xf bison-3.8.2.tar.xz && cd bison-3.8.2 && ./configure --prefix="$TOOLS" -q \
        && make -j"$JOBS" -s && make install -s)
fi
if ! command -v flex >/dev/null && [ ! -x "$TOOLS/bin/flex" ]; then
    fetch_tool https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz \
        e87aae032bf07c26f85ac0ed3250998c37621d95f8bd748b31f15b33c45ee995 flex-2.6.4.tar.gz
    (cd "$TOOLS/src" && tar xf flex-2.6.4.tar.gz && cd flex-2.6.4 && ./configure --prefix="$TOOLS" -q \
        && make -j"$JOBS" -s && make install -s)
fi
UCTX="$TOOLS/src/libucontext-libucontext-1.3.2"   # musl has no getcontext/makecontext/setcontext
if [ ! -f "$UCTX/libucontext.a" ]; then
    fetch_tool https://github.com/kaniini/libucontext/archive/refs/tags/libucontext-1.3.2.tar.gz \
        4faf1838a15d61efe27ddac24fded2c290929eb3a1fefc72f952ae96d5bda006 libucontext-1.3.2.tar.gz
    (cd "$TOOLS/src" && tar xf libucontext-1.3.2.tar.gz && cd "$UCTX" && make ARCH=x86_64 \
        CC="$ROOT/deps/musl/install/bin/musl-clang" EXPORT_UNPREFIXED=yes libucontext.a libucontext_posix.a)
fi
export PATH="$TOOLS/bin:$PATH"

# Darling itself.  x86-64 only (no i386 slices).  A clean ninja exit can leave work pending when the
# graph regenerates (Darling's CLAUDE.md), so it runs until `ninja -n` has nothing to do.
mkdir -p "$DIR/build"
cmake -S "$DIR" -B "$DIR/build" -G Ninja -DCOMPONENTS="$COMPONENTS" -DTARGET_i386=OFF \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local >/dev/null
for pass in 1 2 3; do
    ninja -C "$DIR/build" -j"$JOBS"
    ninja -C "$DIR/build" -n | grep -q 'no work to do' && break
done
rm -rf "$DIR/install"
DESTDIR="$DIR/install" ninja -C "$DIR/build" install >/dev/null

python3 "$ROOT/scripts/darling-musl-host.py" "$DIR/build"
bash "$ROOT/scripts/darling-stage.sh"
echo "Darling $(git -C "$DIR" rev-parse --short HEAD) ($COMPONENTS) staged for anonymOS."
