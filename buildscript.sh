#!/usr/bin/env bash
set -euo pipefail

# ===================== Config (override via env) =====================
ROOT="${ROOT:-$PWD}"
LLVM_DIR="${LLVM_DIR:-$ROOT/llvm-project}"
SRC_DIR="${SRC_DIR:-$LLVM_DIR/compiler-rt/lib/builtins}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-builtins}"

# Cross target + sysroot
: "${TARGET:=x86_64-unknown-elf}"
: "${SYSROOT:=$HOME/sysroots/$TARGET}"

# Your kernel sources / outputs
KERNEL_D="${KERNEL_D:-src/kernel.d}"

# Startup assembly source (defaults to our local boot stub)
STARTUP_SRC="${STARTUP_SRC:-src/boot.s}"
LINKER_SCRIPT="${LINKER_SCRIPT:-linker.ld}"
OUT_DIR="${OUT_DIR:-build}"
KERNEL_O="$OUT_DIR/kernel.o"
STARTUP_O="$OUT_DIR/startup.o"
KERNEL_ELF="$OUT_DIR/kernel.elf"
CROSS_TOOLCHAIN_DIR="$HOME/x-tools/i386-unknown-elf"
ISO_STAGING_DIR="${ISO_STAGING_DIR:-$OUT_DIR/isodir}"
ISO_IMAGE="${ISO_IMAGE:-$OUT_DIR/os.iso}"
ISO_SYSROOT_PATH="${ISO_SYSROOT_PATH:-opt/sysroot}"
ISO_TOOLCHAIN_PATH="${ISO_TOOLCHAIN_PATH:-opt/toolchain}"
: "${CROSS_TOOLCHAIN_DIR:?Set CROSS_TOOLCHAIN_DIR to the root of the cross toolchain you want to bundle}"
TOY_LD="${TOY_LD:-$ROOT/tools/toy-ld}"

# Map TARGET -> builtins archive suffix used by compiler-rt
case "$TARGET" in
  x86_64-*-elf|x86_64-unknown-elf)
    LIBSUFFIX="x86_64"
    ;;
  *)
    echo "Unsupported TARGET '$TARGET' — the toy linker only emits Linux x86_64 ELF binaries." >&2
    exit 1
    ;;
esac

# ===================== Tool checks =====================
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1"; exit 1; }; }
need clang
need cmake
need ldc2
need ninja || true   # ok if missing; we’ll fall back to Makefiles
need grub-mkrescue
command -v xorriso >/dev/null 2>&1 || \
  command -v mkisofs >/dev/null 2>&1 || \
  command -v genisoimage >/dev/null 2>&1 || {
    echo "Missing ISO creation tool (xorriso, mkisofs, or genisoimage)";
    exit 1;
  }

# Prefer LLVM binutils if available
AR_BIN="$(command -v llvm-ar || command -v ar)"
RANLIB_BIN="$(command -v llvm-ranlib || command -v ranlib)"

if [ ! -x "$TOY_LD" ]; then
  echo "Missing toy linker wrapper '$TOY_LD'" >&2
  exit 1
fi

if ! command -v ld.lld >/dev/null 2>&1 && ! command -v ld >/dev/null 2>&1; then
  echo "Missing linker backend (need ld.lld or ld)" >&2
  exit 1
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
echo $KERNEL_D

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
# D object
ldc2 -mtriple="$TARGET" -betterC -O3 -release \
     -c "$KERNEL_D" -of="$KERNEL_O"

# Startup (asm)
clang --target="$TARGET" -c "$STARTUP_SRC" -o "$STARTUP_O"

# ===================== Link kernel with builtins =====================
# Prefer flat path; fall back to generic if needed
LIBDIR="$SYSROOT/usr/lib"
[ -f "$FLAT" ] || LIBDIR="$SYSROOT/usr/lib/generic"

"$TOY_LD" -T "$LINKER_SCRIPT" -nostdlib \
         "$STARTUP_O" "$KERNEL_O" \
         -L"$LIBDIR" \
         -l:libclang_rt.builtins-${LIBSUFFIX}.a \
         -o "$KERNEL_ELF"

echo "[✓] Linked: $KERNEL_ELF"

# ===================== GRUB staging & ISO =====================
if [ ! -d "$CROSS_TOOLCHAIN_DIR" ]; then
  echo "Cross toolchain directory '$CROSS_TOOLCHAIN_DIR' does not exist" >&2
  exit 1
fi

rm -rf "$ISO_STAGING_DIR"
mkdir -p "$ISO_STAGING_DIR/boot/grub"

cp "$KERNEL_ELF" "$ISO_STAGING_DIR/boot/kernel.elf"

cat >"$ISO_STAGING_DIR/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0

menuentry "Toy OS" {
    multiboot /boot/kernel.elf
    boot
}
EOF

SYSROOT_DEST="$ISO_STAGING_DIR/$ISO_SYSROOT_PATH"
TOOLCHAIN_DEST="$ISO_STAGING_DIR/$ISO_TOOLCHAIN_PATH"

rm -rf "$SYSROOT_DEST" "$TOOLCHAIN_DEST"
mkdir -p "$SYSROOT_DEST" "$TOOLCHAIN_DEST"

if [ -d "$SYSROOT" ]; then
  cp -a "$SYSROOT"/. "$SYSROOT_DEST"/
else
  echo "Sysroot directory '$SYSROOT' does not exist" >&2
  exit 1
fi

cp -a "$CROSS_TOOLCHAIN_DIR"/. "$TOOLCHAIN_DEST"/

rm -f "$ISO_IMAGE"
grub-mkrescue -o "$ISO_IMAGE" "$ISO_STAGING_DIR"

echo "[✓] ISO image: $ISO_IMAGE"
