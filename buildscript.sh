#!/usr/bin/env bash
set -euo pipefail

# ===================== Config (override via env) =====================
ROOT="${ROOT:-$PWD}"
LLVM_DIR="${LLVM_DIR:-$ROOT/llvm-project}"
SRC_DIR="${SRC_DIR:-$LLVM_DIR/compiler-rt/lib/builtins}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-builtins}"
SH_ROOT="${SH_ROOT:-$ROOT/-sh}"
SH_TARGET="${SH_TARGET:-lfe-sh}"
SHELL_DC="${SHELL_DC:-ldc2}"

# Cross target + sysroot (x86_64 only for this script)
: "${TARGET:=x86_64-unknown-elf}"
: "${SYSROOT:=$HOME/sysroots/$TARGET}"

# Kernel sources / outputs
KERNEL_D="${KERNEL_D:-src/kernel.d}"
STARTUP_SRC="${STARTUP_SRC:-src/boot.s}"
LINKER_SCRIPT="${LINKER_SCRIPT:-linker.ld}"
OUT_DIR="${OUT_DIR:-build}"
KERNEL_O="$OUT_DIR/kernel.o"
STARTUP_O="$OUT_DIR/startup.o"
KERNEL_ELF="$OUT_DIR/kernel.elf"

# ISO packaging
ISO_STAGING_DIR="${ISO_STAGING_DIR:-$OUT_DIR/isodir}"
ISO_IMAGE="${ISO_IMAGE:-$OUT_DIR/os.iso}"
ISO_SYSROOT_PATH="${ISO_SYSROOT_PATH:-opt/sysroot}"
ISO_TOOLCHAIN_PATH="${ISO_TOOLCHAIN_PATH:-opt/toolchain}"
ISO_SHELL_PATH="${ISO_SHELL_PATH:-opt/shell}"

# Optional toolchain bundle inside ISO (set to a path to enable)
CROSS_TOOLCHAIN_DIR="${CROSS_TOOLCHAIN_DIR:-}"

# Optional path to a DMD source tree to copy into the ISO image.  The kernel
# build expects to find the sources under opt/toolchain/dmd when verifying the
# toolchain build.  Default to the real tree at $ROOT/dmd when present.  Callers
# can still override this via the DMD_SOURCE_DIR environment variable.
if [ -z "${DMD_SOURCE_DIR:-}" ] && [ -d "$ROOT/dmd" ]; then
  DMD_SOURCE_DIR="$ROOT/dmd"
fi
# Destination within the ISO for the DMD sources (relative to the staging dir).
DMD_ISO_DEST="${DMD_ISO_DEST:-$ISO_TOOLCHAIN_PATH/dmd}"

# Optional toy linker wrapper (used if present), else we fall back to ld.lld
TOY_LD="${TOY_LD:-$ROOT/tools/toy-ld}"

# Debug/Opt flags (DEBUG=1 default). Set DEBUG=0 for release-ish build.
: "${DEBUG:=1}"

# Optional QEMU autolaunch after ISO creation
: "${QEMU_RUN:=0}"       # set to 1 to run QEMU
: "${QEMU_GDB:=0}"       # set to 1 to add -s -S for GDB
: "${QEMU_BIN:=qemu-system-x86_64}"

# Map TARGET -> builtins suffix & LLD machine
case "$TARGET" in
  x86_64-*-elf|x86_64-unknown-elf)
    LIBSUFFIX="x86_64"
    LLD_MACH="elf_x86_64"
    ;;
  *)
    echo "Unsupported TARGET '$TARGET' — this script emits x86_64 ELF only." >&2
    exit 1
    ;;
esac

# ===================== Tool checks =====================
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1"; exit 1; }; }
need clang
need cmake
need make
need ldc2
need grub-mkrescue
command -v xorriso >/dev/null 2>&1 || command -v mkisofs >/dev/null 2>&1 || command -v genisoimage >/dev/null 2>&1 || {
  echo "Missing ISO creation tool (xorriso, mkisofs, or genisoimage)"; exit 1; }

# Prefer LLVM binutils if available
AR_BIN="$(command -v llvm-ar || command -v ar)"
RANLIB_BIN="$(command -v llvm-ranlib || command -v ranlib)"

# Linker backend: use toy-ld if executable, else ld.lld (or ld as last resort)
LINK_BACKEND=""
if [ -x "$TOY_LD" ]; then
  LINK_BACKEND="$TOY_LD"
else
  if command -v ld.lld >/dev/null 2>&1; then
    LINK_BACKEND="ld.lld"
  elif command -v ld >/dev/null 2>&1; then
    LINK_BACKEND="ld"
  else
    echo "Missing linker backend (need toy-ld, ld.lld, or ld)" >&2; exit 1
  fi
fi

# ===================== Get LLVM source if needed =====================
if [ ! -d "$LLVM_DIR" ]; then
  echo "[*] Cloning llvm-project..."
  git clone --depth=1 https://github.com/llvm/llvm-project.git "$LLVM_DIR"
fi

# ===================== Build & install compiler-rt builtins =====================
mkdir -p "$SYSROOT/usr/lib" "$SYSROOT/usr/include" "$BUILD_DIR" "$OUT_DIR"

GEN="Ninja"; command -v ninja >/dev/null 2>&1 || GEN="Unix Makefiles"
rm -rf "$BUILD_DIR"

cmake -S "$SRC_DIR" -B "$BUILD_DIR" -G "$GEN" \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_ASM_COMPILER=clang \
  -DCMAKE_AR="$AR_BIN" \
  -DCMAKE_RANLIB="$RANLIB_BIN" \
  -DCMAKE_C_COMPILER_TARGET="$TARGET" \
  -DCMAKE_ASM_COMPILER_TARGET="$TARGET" \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCOMPILER_RT_BAREMETAL_BUILD=ON \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCMAKE_INSTALL_PREFIX="$SYSROOT/usr" \
  -DCMAKE_INSTALL_LIBDIR="lib"

if [ "$GEN" = "Ninja" ]; then
  ninja -C "$BUILD_DIR"
  ninja -C "$BUILD_DIR" install
else
  cmake --build "$BUILD_DIR" --parallel
  cmake --install "$BUILD_DIR"
fi

# Symlink to flat usr/lib if CMake used usr/lib/generic/
GENERIC="$SYSROOT/usr/lib/generic/libclang_rt.builtins-${LIBSUFFIX}.a"
FLAT="$SYSROOT/usr/lib/libclang_rt.builtins-${LIBSUFFIX}.a"
if [ -f "$GENERIC" ] && [ ! -f "$FLAT" ]; then
  ln -sf "$GENERIC" "$FLAT"
fi

echo "[✓] Builtins:"
ls -l "$SYSROOT/usr/lib"/libclang_rt.builtins-*.a || true

# ===================== Compile kernel (freestanding D) =====================
mkdir -p "$OUT_DIR"

if [ "$DEBUG" = "1" ]; then
  DFLAGS="-g -O0"
else
  DFLAGS="-O3 -release"
fi

# D object
ldc2 -I. -Isrc -mtriple="$TARGET" -betterC $DFLAGS \
     -c "$KERNEL_D" -of="$KERNEL_O"

# Startup (asm)
clang --target="$TARGET" -c "$STARTUP_SRC" -o "$STARTUP_O"

# ===================== Link kernel with builtins =====================
LIBDIR="$SYSROOT/usr/lib"
[ -f "$FLAT" ] || LIBDIR="$SYSROOT/usr/lib/generic"

if [ "$LINK_BACKEND" = "ld.lld" ] || [ "$LINK_BACKEND" = "ld" ]; then
  # Native linker path
  "$LINK_BACKEND" ${LLD_MACH:+-m "$LLD_MACH"} -T "$LINKER_SCRIPT" -nostdlib \
      "$STARTUP_O" "$KERNEL_O" \
      -L"$LIBDIR" \
      -l:libclang_rt.builtins-${LIBSUFFIX}.a \
      -o "$KERNEL_ELF"
else
  # toy-ld wrapper
  "$LINK_BACKEND" -T "$LINKER_SCRIPT" -nostdlib \
      "$STARTUP_O" "$KERNEL_O" \
      -L"$LIBDIR" \
      -l:libclang_rt.builtins-${LIBSUFFIX}.a \
      -o "$KERNEL_ELF"
fi

echo "[✓] Linked: $KERNEL_ELF"

# ===================== Build packaged shell (-sh) =====================
SHELL_BINARY="$SH_ROOT/$SH_TARGET"

if [ -d "$SH_ROOT/src" ]; then
  echo "[*] Building -sh shell from $SH_ROOT"
  make -C "$SH_ROOT" DC="$SHELL_DC" "$SH_TARGET"
  if [ -f "$SHELL_BINARY" ]; then
    mkdir -p "$OUT_DIR/shell"
    cp "$SHELL_BINARY" "$OUT_DIR/shell/"
    if [ -d "$SH_ROOT/config" ]; then
      cp -a "$SH_ROOT/config/." "$OUT_DIR/shell/"
    fi
  else
    echo "[!] Built shell binary not found at $SHELL_BINARY" >&2
  fi
else
  echo "[!] Skipping shell build: $SH_ROOT/src missing" >&2
fi

# ===================== GRUB staging & ISO =====================
rm -rf "$ISO_STAGING_DIR"
mkdir -p "$ISO_STAGING_DIR/boot/grub"

cp "$KERNEL_ELF" "$ISO_STAGING_DIR/boot/kernel.elf"

if [ -f "$SHELL_BINARY" ]; then
  SHELL_DEST="$ISO_STAGING_DIR/$ISO_SHELL_PATH"
  mkdir -p "$SHELL_DEST"
  cp "$SHELL_BINARY" "$SHELL_DEST/"
  if [ -d "$SH_ROOT/config" ]; then
    cp -a "$SH_ROOT/config/." "$SHELL_DEST/"
  fi
fi

cat >"$ISO_STAGING_DIR/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0

menuentry "Toy OS" {
    multiboot /boot/kernel.elf
    boot
}
EOF

# Copy sysroot (handy for inspection on a mounted ISO)
SYSROOT_DEST="$ISO_STAGING_DIR/$ISO_SYSROOT_PATH"
rm -rf "$SYSROOT_DEST"
mkdir -p "$SYSROOT_DEST"
cp -a "$SYSROOT"/. "$SYSROOT_DEST"/

# Bundle toolchain only if provided and exists
if [ -n "${CROSS_TOOLCHAIN_DIR}" ] && [ -d "${CROSS_TOOLCHAIN_DIR}" ]; then
  TOOLCHAIN_DEST="$ISO_STAGING_DIR/$ISO_TOOLCHAIN_PATH"
  rm -rf "$TOOLCHAIN_DEST"
  mkdir -p "$TOOLCHAIN_DEST"
  cp -a "$CROSS_TOOLCHAIN_DIR"/. "$TOOLCHAIN_DEST"/
  echo "[i] Bundled toolchain from: $CROSS_TOOLCHAIN_DIR"
fi

# Copy DMD sources into the ISO so the kernel can inspect the toolchain build.
if [ -n "${DMD_SOURCE_DIR:-}" ] && [ -d "${DMD_SOURCE_DIR}" ]; then
  DMD_DEST="$ISO_STAGING_DIR/$DMD_ISO_DEST"
  rm -rf "$DMD_DEST"
  mkdir -p "$DMD_DEST"
  cp -a "$DMD_SOURCE_DIR"/. "$DMD_DEST"/
  echo "[i] Copied DMD sources from: $DMD_SOURCE_DIR"
elif [ -n "${DMD_SOURCE_DIR:-}" ]; then
  echo "[!] DMD sources directory not found, skipping copy: $DMD_SOURCE_DIR" >&2
fi

rm -f "$ISO_IMAGE"
grub-mkrescue -o "$ISO_IMAGE" "$ISO_STAGING_DIR"
echo "[✓] ISO image: $ISO_IMAGE"

# ===================== Optional: QEMU autolaunch =====================
if [ "$QEMU_RUN" = "1" ]; then
  need "$QEMU_BIN"
  QEMU_ARGS=(-cdrom "$ISO_IMAGE" -serial stdio)
  [ "$QEMU_GDB" = "1" ] && QEMU_ARGS+=(-s -S)
  echo "[→] Launching: $QEMU_BIN ${QEMU_ARGS[*]}"
  exec "$QEMU_BIN" "${QEMU_ARGS[@]}"
fi
