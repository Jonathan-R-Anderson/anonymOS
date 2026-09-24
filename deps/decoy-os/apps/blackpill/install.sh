#!/bin/sh
set -e

R="$1"

APP_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

echo "[blackpill] Building..."

cd "$APP_DIR"

git submodule update --init --recursive

# The default `make` only compiles the out-of-tree module; it needs a kernel
# that's already been configured and built (Module.symvers must exist). On a
# fresh checkout that hasn't happened, so run the one-time setup first — apk
# deps, x86_64_defconfig+rust.config, full kernel build. Guarded so it's a
# no-op once the kernel is built.
if [ ! -f linux/Module.symvers ]; then
	echo "[blackpill] Kernel not built yet — running first-time-setup..."
	make first-time-setup
fi

make

echo "[blackpill] Installing kernel module into $R..."

make install INSTALL_MOD_PATH="$R"

echo "[blackpill] Installation complete."

make vm