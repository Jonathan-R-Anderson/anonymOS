#!/bin/sh
set -e

R="$1"

APP_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

echo "[blackpill] Building..."

cd "$APP_DIR"

make

echo "[blackpill] Installing kernel module into $R..."

make install INSTALL_MOD_PATH="$R"

echo "[blackpill] Installation complete."

make vm

