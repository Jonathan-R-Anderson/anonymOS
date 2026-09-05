#!/bin/bash
# M0: build a REAL dbus-daemon + libdbus-1 for the EpinAnonymOS musl target.
set -e
# Every long command below is piped to `tail`, and a pipeline's exit status is the LAST command's.
# Without pipefail, set -e never saw configure or make fail: the script ran to the end and printed
# "=== RESULT ===" having built nothing.  That is how this stayed broken without anyone noticing --
# the build appeared to succeed every single time.
set -o pipefail
# Derive the project root from this script rather than hardcoding it.  This read
# ROOT=/home/bruns/Documents/EpinAnonymOS, a path that stopped existing when the project was
# renamed to anonymOS -- so every invocation failed at the first path and dbus was silently
# never built.  install/bin stayed empty, the Makefile stage block (which tests for
# install/bin/dbus-daemon) never ran, no module_path line was emitted, and the kernel then
# reported "hos-dbus-launch spawn failed" at every boot.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
MUSL=$ROOT/deps/musl/install
SYSROOT=$ROOT/deps/gtk-stack/sysroot
CC=$MUSL/bin/musl-clang
SRC=$ROOT/deps/dbus-build/dbus-1.14.10
PREFIX=$ROOT/deps/dbus-build/install
CLANG_RES=$(clang -print-resource-dir)

export CC
export CFLAGS="-O2 -fPIC -isystem $CLANG_RES/include -I$SYSROOT/include -I$MUSL/include"
export LDFLAGS="-Wl,--allow-multiple-definition -no-pie -L$SYSROOT/lib -L$MUSL/lib"
# expat lives in the gtk-stack sysroot (static .a + header); feed dbus directly, bypass pkg-config.
export EXPAT_CFLAGS="-I$SYSROOT/include"
export EXPAT_LIBS="-L$SYSROOT/lib -lexpat"
# musl supports Linux abstract sockets + these; skip the AC_TRY_RUN probes (cross = can't run target).
export ac_cv_have_abstract_sockets=yes
export ac_cv_func_posix_getpwnam_r=yes
export cross_compiling=yes

# dbus turns maintainer mode on by default, so any timestamp skew makes `make` re-run autoreconf.
# This box has no autoconf-archive, so that regeneration left AX_CHECK_ENABLE_DEBUG unexpanded and
# configure died with a shell syntax error at line 4566.  The corruption is written into the tree,
# so distclean cannot undo it -- only re-extracting can.  Detect it and start clean.
TARBALL=$ROOT/deps/dbus-build/dbus-1.14.10.tar.xz
if [ -f "$SRC/configure" ] && ! grep -q '^AX_CHECK_ENABLE_DEBUG' "$SRC/configure"; then
  cd "$SRC"
  [ -f Makefile ] && make distclean >/dev/null 2>&1 || true
else
  echo "=== source tree absent or configure corrupt; re-extracting from the tarball ==="
  rm -rf "$SRC"
  tar xJf "$TARBALL" -C "$ROOT/deps/dbus-build"
  cd "$SRC"
fi

./configure \
  --host=x86_64-pc-linux-musl \
  --disable-maintainer-mode \
  --build="$(gcc -dumpmachine)" \
  --prefix="$PREFIX" \
  --exec-prefix="$PREFIX" \
  --with-xml=expat \
  --disable-systemd \
  --disable-selinux \
  --disable-apparmor \
  --disable-libaudit \
  --disable-x11-autolaunch \
  --without-x \
  --disable-tests \
  --disable-modular-tests \
  --disable-installed-tests \
  --disable-doxygen-docs \
  --disable-xml-docs \
  --disable-ducktype-docs \
  --disable-asserts \
  --disable-static \
  --enable-shared \
  --with-system-socket=/run/dbus/system_bus_socket \
  --with-system-pid-file=/run/dbus/pid \
  --with-dbus-user=root \
  2>&1 | tail -25

echo "=== configure done, building ==="
make -j"$(nproc)" 2>&1 | tail -20
echo "=== build done, installing to $PREFIX ==="
make install 2>&1 | tail -8
echo "=== RESULT ==="
file "$PREFIX/bin/dbus-daemon" 2>/dev/null
ls -la "$PREFIX/bin/dbus-daemon" "$PREFIX/lib/libdbus-1.so"* 2>/dev/null
