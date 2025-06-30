#!/usr/bin/env bash
# Build the full –sh interpreter for anonymOS, statically linked against the
# freestanding druntime/phobos we build under build/ldc-runtime/.
set -euo pipefail

BUILD_DIR="$(pwd)/build"
RUNTIME_LIBDIR="$BUILD_DIR/ldc-runtime/lib"
TARGET="$BUILD_DIR/bin/sh"
SRC_DIR="third_party/sh"
POSIX_DIR="third_party/posix"
STUB="kernel/kernel/lib/posix_stubs.d"

# convenience path used later
TARGET_DIR="$(dirname "$TARGET")"
mkdir -p "$TARGET_DIR"

echo ">>> Compiling full /bin/sh interpreter (with druntime) …"

# Collect all .d sources in the shell repo (skip tests)
SH_SOURCES=$(find "$SRC_DIR/src" -name '*.d' | tr '\n' ' ')
POSIX_SOURCES=$(find "$POSIX_DIR/src" -name '*.d' | tr '\n' ' ' || true)

ldc2 -O2 -release --d-version=Posix --d-version=GNU \
     -mtriple=x86_64-unknown-elf -mcpu=x86-64 \
     -I"$SRC_DIR" -I"$SRC_DIR/src" -I"$POSIX_DIR/src" \
     $SH_SOURCES $POSIX_SOURCES "$STUB" \
     -L-L"$RUNTIME_LIBDIR" -L-lphobos2-ldc -L-ldruntime-ldc \
     -of="$TARGET"

echo "Shell binary ready: $TARGET"

# Create installation script for runtime use
cat > "$TARGET_DIR/install_comprehensive_shell.sh" << 'INSTALL_EOF'
#!/bin/sh
# Runtime installer for comprehensive shell
echo "Installing comprehensive shell from /third_party/sh..."
cd /third_party/sh
if [ -x "build_betterc.sh" ]; then
    bash build_betterc.sh
    cp interpreter /bin/sh_comprehensive
    echo "Comprehensive shell installed as /bin/sh_comprehensive"
elif [ -x "interpreter" ]; then
    cp interpreter /bin/sh_comprehensive
    echo "Comprehensive shell installed as /bin/sh_comprehensive"
else
    echo "Comprehensive shell source available but not compiled"
    echo "D compiler needed to build: /bin/dmd"
fi
INSTALL_EOF
chmod +x "$TARGET_DIR/install_comprehensive_shell.sh"

echo "Comprehensive shell integration complete!"
echo "- Shell binary: $TARGET_DIR/sh"
echo "- Runtime installer: $TARGET_DIR/install_comprehensive_shell.sh"
exit 0 