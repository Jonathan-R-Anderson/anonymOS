#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$PWD}"
# Resolve absolute path for ROOT
ROOT=$(cd "$ROOT" && pwd)

ZSH_SRC="$ROOT/3rdparty/zsh"
OUT_DIR="${OUT_DIR:-build}"

# Resolve absolute path for OUT_DIR
if [[ ! "$OUT_DIR" = /* ]]; then
    OUT_DIR="$ROOT/$OUT_DIR"
fi

ZSH_BUILD_DIR="$OUT_DIR/zsh-build"
ZSH_DEST="$OUT_DIR/zsh-dist"

if [ ! -d "$ZSH_SRC" ]; then
    echo "zsh source not found at $ZSH_SRC"
    exit 1
fi

mkdir -p "$ZSH_BUILD_DIR"
mkdir -p "$ZSH_DEST"

echo "[*] Configuring zsh..."
cd "$ZSH_BUILD_DIR"

# Try to configure for static build
# We use the host compiler but try to link statically
# This is a best-effort attempt to get a binary that might run on the kernel
# if the kernel supports the linux syscall ABI (which it seems to partially do)

if [ ! -f Makefile ]; then
    "$ZSH_SRC/configure" \
        --prefix="$ZSH_DEST" \
        --disable-dynamic \
        --disable-gdbm \
        --disable-pcre \
        --disable-cap \
        --without-term-lib \
        LDFLAGS="-static" \
        CFLAGS="-Os" || {
            echo "Configure failed. Trying without static flag..."
            "$ZSH_SRC/configure" \
                --prefix="$ZSH_DEST" \
                --disable-dynamic \
                --disable-gdbm \
                --disable-pcre \
                --disable-cap \
                --without-term-lib \
                CFLAGS="-Os"
        }
fi

echo "[*] Building zsh..."
make -j$(nproc)

echo "[*] Installing zsh..."
make install.bin

# Copy oh-my-zsh
OHMYZSH_SRC="$ROOT/3rdparty/ohmyzsh"
if [ -d "$OHMYZSH_SRC" ]; then
    echo "[*] Bundling oh-my-zsh..."
    # Remove destination if it exists to avoid permission errors on overwrite
    rm -rf "$ZSH_DEST/share/oh-my-zsh"
    mkdir -p "$ZSH_DEST/share/oh-my-zsh"
    
    # Use tar to copy excluding .git directory
    tar -C "$OHMYZSH_SRC" --exclude=.git -cf - . | tar -C "$ZSH_DEST/share/oh-my-zsh" -xf -
    
    # Create a default .zshrc that uses oh-my-zsh
    mkdir -p "$ZSH_DEST/etc"
    cat > "$ZSH_DEST/etc/zshrc" <<EOF
export ZSH=/usr/share/oh-my-zsh
ZSH_THEME="robbyrussell"
plugins=(git)
source \$ZSH/oh-my-zsh.sh
EOF
fi

echo "[✓] zsh built and bundled in $ZSH_DEST"
