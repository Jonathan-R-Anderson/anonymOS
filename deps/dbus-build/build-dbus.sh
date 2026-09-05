#!/bin/bash
# M0: build a REAL dbus-daemon + libdbus-1 for the EpinAnonymOS musl target.
set -e
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

cd "$SRC"
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true

./configure \
  --host=x86_64-pc-linux-musl \
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
