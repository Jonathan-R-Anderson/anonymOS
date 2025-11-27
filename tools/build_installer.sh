#!/bin/bash
set -e

mkdir -p build/installer

echo "[*] Compiling installer..."
ldc2 -mtriple=x86_64-unknown-linux-gnu -betterC -defaultlib= -debuglib= \
    -I src/installer \
    src/installer/runtime.d src/installer/main.d \
    -of=build/installer/installer.o -c

echo "[*] Linking installer..."
ld.lld -static -o build/installer/installer build/installer/installer.o -e _start

echo "[✓] Installer built: build/installer/installer"
