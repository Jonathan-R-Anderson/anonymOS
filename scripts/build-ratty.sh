#!/usr/bin/env bash
# Build ratty (https://github.com/orhun/ratty) -- the GPU-rendered terminal emulator with inline
# 3D graphics (Bevy + wgpu + Ratatui + Parley) -- for anonymOS.
#
# How it runs on the OS (see patches/ratty/*.patch for the why of each change):
#   * DYNAMIC musl (x86_64-unknown-linux-musl with -crt-static): a static binary cannot dlopen,
#     and everything graphical is dlopen'd -- libEGL.so.1 (wgpu's khronos-egl), libwayland-client
#     and -egl, libxkbcommon (winit), and Mesa's DRI driver (by libEGL).  libfontconfig.so.1
#     is linked (Parley/fontique system fonts).  Interpreter: /lib/ld-musl-x86_64.so.1.
#   * wgpu's OpenGL ES backend over Mesa EGL on Wayland: there is no Vulkan driver on the OS, and
#     the guest's Mesa is llvmpipe (GLES 3.2 / GL 4.5).  Bevy creates the wgpu instance without a
#     display handle, which on GLES means a surfaceless EGL display that cannot present to a Wayland
#     window -- patches/ratty/crates/bevy_render-*/ adds the display handle (RenderDisplayHandle).
#   * libEGL.so.1 does not exist in the sysroot (Mesa is built static: libEGL.a + libgbm.a); this
#     script links one from those archives -- exactly the objects gl-term links statically -- with
#     libglapi.so / libwayland-*.so as DT_NEEDED so the process has ONE libwayland-client.
#
# The source is NOT vendored: the pinned commit is cloned into deps/ratty/ (git-ignored); the one
# patched crates.io dependency is unpacked from its checksum-verified .crate into
# deps/ratty/anonymos-crates/ and wired in with [patch.crates-io].  Outputs (staged into the ISO by
# the Makefile's ratty block when present):
#     build/ratty          the terminal (boot module /ratty)
#     build/libEGL.so.1    the EGL library it dlopens (boot module /libEGL.so.1)
#
# Requires: a recent stable cargo/rustc (tested: 1.96) with the x86_64-unknown-linux-musl target, the musl
# cross gcc (~/lkl-build/x86_64-linux-musl-cross, as cloud-hypervisor / hos-ethsign-dyn use), the
# in-tree musl-clang (deps/musl/install) and the gtk-stack sysroot with Mesa built
# (make -C deps/gtk-stack).  Network access on the first run (git + crates.io).
#
#   scripts/build-ratty.sh                 # release (fat LTO, as upstream ships)
#   RATTY_PROFILE=release-fast scripts/build-ratty.sh   # no LTO: ~5 min instead of ~15
set -euo pipefail

# Pinned: upstream main after v0.5.0 (fux-vt 0.2.0 from crates.io, PR #159).
RATTY_COMMIT="${RATTY_COMMIT:-e3b8f93906f453123f544779b6712e128c3d3fb4}"
RATTY_REPO="${RATTY_REPO:-https://github.com/orhun/ratty.git}"
RATTY_PROFILE="${RATTY_PROFILE:-release}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RATTY_DIR="${RATTY_DIR:-$ROOT/deps/ratty}"
OUT="${RATTY_OUT:-$ROOT/build}"
TARGET="x86_64-unknown-linux-musl"
SYSROOT="$ROOT/deps/gtk-stack/sysroot"
MUSL_CC="$ROOT/deps/musl/install/bin/musl-clang"

CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"
MUSL_CROSS="${MUSL_CROSS:-$HOME/lkl-build/x86_64-linux-musl-cross/bin}"
MUSL_GCC="$MUSL_CROSS/x86_64-linux-musl-gcc"

die() { echo "build-ratty: $*" >&2; exit 1; }
[ -x "$CARGO_BIN" ] || die "cargo not found at $CARGO_BIN (set CARGO=...)"
[ -x "$MUSL_GCC" ]  || die "musl cross gcc not found at $MUSL_GCC (set MUSL_CROSS=...)"
[ -x "$MUSL_CC" ]   || die "musl-clang not found at $MUSL_CC (build deps/musl first)"
grep -qa eglGetDisplay "$SYSROOT/lib/libEGL.a" 2>/dev/null \
    || die "no Mesa in $SYSROOT/lib (libEGL.a); run: make -C deps/gtk-stack"
for so in libfontconfig.so libglapi.so libwayland-client.so.0 libwayland-egl.so.1 libxkbcommon.so.0; do
    [ -e "$SYSROOT/lib/$so" ] || die "missing $SYSROOT/lib/$so (gtk-stack sysroot incomplete)"
done
[ -f "$SYSROOT/lib/dri/swrast_dri.so" ] || die "missing $SYSROOT/lib/dri/swrast_dri.so (Mesa DRI driver)"

# ── 1. the pinned upstream source ─────────────────────────────────────────────────────────────
if [ ! -e "$RATTY_DIR/.git" ]; then
    mkdir -p "$RATTY_DIR"
    git -C "$RATTY_DIR" init -q
    git -C "$RATTY_DIR" remote add origin "$RATTY_REPO"
fi
if ! git -C "$RATTY_DIR" cat-file -e "$RATTY_COMMIT^{commit}" 2>/dev/null; then
    echo "Fetching ratty $RATTY_COMMIT (depth 1)..."
    git -C "$RATTY_DIR" fetch --depth 1 origin "$RATTY_COMMIT"
fi
git -C "$RATTY_DIR" checkout -q "$RATTY_COMMIT"

# A tree patched with an older patch set (or by hand) cannot take the current one on top: unless
# the stamp in .git/ says this exact patch set was applied, put a modified tree back to the
# pristine commit first.  target/ stays, so cargo only rebuilds what the patches touch.
PATCH_SUM="$(cat "$ROOT"/patches/ratty/*.patch "$ROOT"/patches/ratty/crates/*/*.patch 2>/dev/null | sha256sum | cut -d' ' -f1)"
STAMP="$RATTY_DIR/.git/anonymos-patches"
if [ "$(cat "$STAMP" 2>/dev/null)" != "$PATCH_SUM" ] \
   && [ -n "$(git -C "$RATTY_DIR" status --porcelain --untracked-files=all -- . ':!target' | head -n1)" ]; then
    echo "resetting $RATTY_DIR to $RATTY_COMMIT (patched with a different patch set)"
    git -C "$RATTY_DIR" checkout -q -f "$RATTY_COMMIT"
    git -C "$RATTY_DIR" clean -fdq -e /target
fi

# apply_patch <dir-relative-to-RATTY_DIR or ""> <patch>: idempotent -- a patch already in the tree
# is skipped; one that neither applies nor is present stops the build.
apply_patch() {
    local dir="$1" p="$2" opt=()
    [ -n "$dir" ] && opt=(--directory="$dir")
    if git -C "$RATTY_DIR" apply "${opt[@]}" --check "$p" 2>/dev/null; then
        git -C "$RATTY_DIR" apply "${opt[@]}" "$p"
        echo "applied ${dir:+$dir: }$(basename "$p")"
    elif git -C "$RATTY_DIR" apply "${opt[@]}" --check -R "$p" 2>/dev/null; then
        echo "already applied ${dir:+$dir: }$(basename "$p")"
    else
        die "patch ${dir:+$dir/}$(basename "$p") does not apply to $RATTY_COMMIT"
    fi
}

# ── 2. patched crates.io dependencies (patches/ratty/crates/<name>-<version>/*.patch) ─────────
# Unpacked from the .crate whose SHA-256 the pinned Cargo.lock records, so the patched source is
# exactly the published one plus our diff.
for cdir in "$ROOT"/patches/ratty/crates/*/; do
    [ -d "$cdir" ] || continue
    crate="$(basename "$cdir")"; name="${crate%-*}"; ver="${crate##*-}"
    rel="anonymos-crates/$crate"
    if [ ! -f "$RATTY_DIR/$rel/Cargo.toml" ]; then
        sum="$(git -C "$RATTY_DIR" show "$RATTY_COMMIT:Cargo.lock" | awk -v n="$name" -v v="$ver" '
            /^\[\[package\]\]/ { f = 0; g = 0 }
            $0 == "name = \"" n "\"" { f = 1 }
            f && $0 == "version = \"" v "\"" { g = 1 }
            g && !done && /^checksum = / { gsub(/checksum = |"/, ""); print; done = 1 }')"
        [ -n "$sum" ] || die "$crate is not in ratty's Cargo.lock"
        tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
        cached="$(ls "${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/"$crate.crate" 2>/dev/null | head -n1 || true)"
        if [ -n "$cached" ]; then cp "$cached" "$tmp/c.crate"
        else curl -fsSL "https://static.crates.io/crates/$name/$crate.crate" -o "$tmp/c.crate"; fi
        echo "$sum  $tmp/c.crate" | sha256sum -c --quiet - || die "$crate.crate: SHA-256 mismatch"
        mkdir -p "$RATTY_DIR/anonymos-crates"
        tar -xzf "$tmp/c.crate" -C "$RATTY_DIR/anonymos-crates"
        rm -rf "$tmp"; trap - EXIT
        echo "unpacked $crate (sha256 $sum)"
    fi
    for p in "$cdir"*.patch; do [ -f "$p" ] && apply_patch "$rel" "$p"; done
done

# ── 3. anonymOS patches to ratty itself (patches/ratty/*.patch, in order) ─────────────────────
for p in "$ROOT"/patches/ratty/*.patch; do
    [ -f "$p" ] && apply_patch "" "$p"
done
echo "$PATCH_SUM" > "$STAMP"

# ── 4. cargo build: dynamic musl ──────────────────────────────────────────────────────────────
# -crt-static + link-self-contained=no: link against the cross toolchain's libc.so (the guest's
# /ld-musl-x86_64.so.1 provides it) instead of the self-contained static musl.  pkg-config finds
# fontconfig in the gtk-stack sysroot; -rpath-link lets ld resolve that library's own DT_NEEDED.
export PATH="$MUSL_CROSS:$(dirname "$CARGO_BIN"):$PATH"
export CC_x86_64_unknown_linux_musl="x86_64-linux-musl-gcc"
export AR_x86_64_unknown_linux_musl="x86_64-linux-musl-ar"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="x86_64-linux-musl-gcc"
export RUSTFLAGS="-C target-feature=-crt-static -C link-self-contained=no -C link-arg=-Wl,-rpath-link,$SYSROOT/lib"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_LIBDIR="$SYSROOT/lib/pkgconfig:$SYSROOT/share/pkgconfig"
export PKG_CONFIG_PATH="" PKG_CONFIG_SYSROOT_DIR=""

echo "Building ratty ($TARGET, profile $RATTY_PROFILE)..."
( cd "$RATTY_DIR" && "$CARGO_BIN" build --locked --profile "$RATTY_PROFILE" --target "$TARGET" --bin ratty )

pdir="$RATTY_PROFILE"; [ "$pdir" = dev ] && pdir=debug
BIN="$RATTY_DIR/target/$TARGET/$pdir/ratty"
[ -x "$BIN" ] || die "build produced no binary at $BIN"

# ── 5. libEGL.so.1 from the sysroot's static Mesa ─────────────────────────────────────────────
# -u every public egl* entry point so the archive members gl-term pulls statically are pulled
# here too (and nothing else: --whole-archive would drag in Mesa's C++ ASTC decoder).  The
# Wayland/glapi libraries stay shared (DT_NEEDED) so winit, wgpu and Mesa share one
# libwayland-client and one GL dispatch table.
mkdir -p "$OUT"
EGL_SYMS="$(nm "$SYSROOT/lib/libEGL.a" 2>/dev/null | awk '$2 == "T" && $3 ~ /^egl[A-Z]/ { printf "-Wl,-u,%s ", $3 }')"
[ -n "$EGL_SYMS" ] || die "no egl* entry points in $SYSROOT/lib/libEGL.a"
# shellcheck disable=SC2086
"$MUSL_CC" -shared -o "$OUT/libEGL.so.1.tmp" -Wl,-soname,libEGL.so.1 $EGL_SYMS \
    "$SYSROOT/lib/libEGL.a" "$SYSROOT/lib/libgbm.a" "$SYSROOT/lib/libdrm.a" \
    -L"$SYSROOT/lib" -Wl,--as-needed -l:libglapi.so -l:libwayland-client.so.0 \
    -l:libwayland-server.so.0 -l:libexpat.so.1 -l:libz.so.1 -lpthread -lm -Wl,--no-undefined
mv "$OUT/libEGL.so.1.tmp" "$OUT/libEGL.so.1"

cp "$BIN" "$OUT/ratty.tmp" && mv "$OUT/ratty.tmp" "$OUT/ratty"

# ── 6. verify: dynamic musl, and every DT_NEEDED is something the image stages ────────────────
readelf -l "$OUT/ratty" | grep -q 'interpreter: /lib/ld-musl-x86_64.so.1' \
    || die "$OUT/ratty is not dynamic musl (interpreter is not ld-musl) -- refusing"
bad=""
for f in "$OUT/ratty" "$OUT/libEGL.so.1"; do
    for n in $(readelf -d "$f" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p'); do
        case "$n" in
            libc.so|libgcc_s.so.1) ;;
            *) [ -e "$SYSROOT/lib/$n" ] || bad="$bad $(basename "$f"):$n" ;;
        esac
    done
done
[ -z "$bad" ] || die "unexpected DT_NEEDED (not in the gtk-stack sysroot):$bad"
for s in libEGL.so.1 libwayland-client.so.0 libwayland-egl.so.1 libxkbcommon.so.0; do
    grep -qa "$s" "$OUT/ratty" || die "$OUT/ratty does not reference $s (feature set changed?)"
done

echo "OK: $OUT/ratty ($(du -h "$OUT/ratty" | cut -f1)), $OUT/libEGL.so.1"
echo "    ratty NEEDED:       $(readelf -d "$OUT/ratty" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p' | tr '\n' ' ')"
echo "    libEGL.so.1 NEEDED: $(readelf -d "$OUT/libEGL.so.1" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p' | tr '\n' ' ')"
echo "    dlopen'd at runtime: libEGL.so.1 libwayland-client.so.0 libwayland-egl.so.1 libxkbcommon.so.0,"
echo "                         and via libEGL: swrast_dri.so (+ libglapi.so); libvulkan.so.1 is probed and absent"
