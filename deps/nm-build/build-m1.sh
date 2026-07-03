#!/bin/bash
# M1: build libnl-3 (core + genl + route) and libndp for the EpinAnonymOS musl target.
# These are NetworkManager's only mandatory external libs once crypto=null (no gnutls/nss).
# Installs into the gtk-stack sysroot so NM's meson cross setup finds headers/libs/.pc there.
set -e
ROOT=/home/bruns/Documents/EpinAnonymOS
MUSL=$ROOT/deps/musl/install
SYSROOT=$ROOT/deps/gtk-stack/sysroot
CC=$MUSL/bin/musl-clang
CLANG_RES=$(clang -print-resource-dir)

export CC
export CFLAGS="-O2 -fPIC -isystem $CLANG_RES/include -I$SYSROOT/include -I$MUSL/include"
export LDFLAGS="-Wl,--allow-multiple-definition -no-pie -L$SYSROOT/lib -L$MUSL/lib"
export PKG_CONFIG_LIBDIR="$SYSROOT/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"

# ---- libnl 3.7.0 ---------------------------------------------------------
cd "$ROOT/deps/nm-build"
[ -d libnl-3.7.0 ] || tar xf libnl-3.7.0.tar.gz
cd libnl-3.7.0
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true
echo "=== configuring libnl-3.7.0 ==="
./configure \
  --host=x86_64-pc-linux-musl \
  --build="$(gcc -dumpmachine)" \
  --prefix="$SYSROOT" \
  --disable-cli \
  --disable-static \
  --enable-shared \
  2>&1 | tail -8
echo "=== building libnl ==="
make -j"$(nproc)" 2>&1 | tail -6
make install 2>&1 | tail -3
echo "--- libnl installed:"
ls -la "$SYSROOT"/lib/libnl-3.so* "$SYSROOT"/lib/libnl-genl-3.so* "$SYSROOT"/lib/libnl-route-3.so* 2>/dev/null
ls "$SYSROOT"/lib/pkgconfig/libnl-*.pc 2>/dev/null

# ---- libndp 1.8 ----------------------------------------------------------
cd "$ROOT/deps/nm-build"
[ -d libndp-1.8 ] || tar xf libndp-1.8.tar.gz
cd libndp-1.8
if [ ! -x configure ]; then
  echo "=== autoreconf libndp ==="
  ./autogen.sh 2>&1 | tail -4 || autoreconf -i 2>&1 | tail -4
fi
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true
echo "=== configuring libndp ==="
./configure \
  --host=x86_64-pc-linux-musl \
  --build="$(gcc -dumpmachine)" \
  --prefix="$SYSROOT" \
  --disable-static \
  --enable-shared \
  2>&1 | tail -8
echo "=== building libndp ==="
make -j"$(nproc)" 2>&1 | tail -6
make install 2>&1 | tail -3
echo "--- libndp installed:"
ls -la "$SYSROOT"/lib/libndp.so* 2>/dev/null
ls "$SYSROOT"/lib/pkgconfig/libndp.pc 2>/dev/null

echo "=== M1 pkg-config sanity (as NM's meson will see them) ==="
for p in libnl-3.0 libnl-genl-3.0 libnl-route-3.0 libndp libudev uuid; do
  printf '%-18s ' "$p"; PKG_CONFIG_LIBDIR="$SYSROOT/lib/pkgconfig" pkg-config --modversion "$p" 2>&1 || echo "MISSING"
done
