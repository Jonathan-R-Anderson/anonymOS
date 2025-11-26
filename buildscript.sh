#!/usr/bin/env bash
set -euo pipefail

# ===================== Config (override via env) =====================
ROOT="${ROOT:-$PWD}"
OUT_DIR="${OUT_DIR:-build}"
LLVM_DIR="${LLVM_DIR:-$ROOT/3rdparty/llvm-project}"
SRC_DIR="${SRC_DIR:-$LLVM_DIR/compiler-rt/lib/builtins}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-builtins}"
SH_ROOT="${SH_ROOT:-$ROOT/3rdparty/-sh}"
SH_TARGET="${SH_TARGET:-lfe-sh}"
SHELL_DC="${SHELL_DC:-ldc2}"
POSIXUTILS_ROOT="${POSIXUTILS_ROOT:-$ROOT/src/anonymos/kernel/posixutils}"
POSIXUTILS_DC="${POSIXUTILS_DC:-$SHELL_DC}"
DESKTOP_ASSETS_DIR="${DESKTOP_ASSETS_DIR:-$ROOT/assets/desktop}"
DESKTOP_STAGING_DIR="${DESKTOP_STAGING_DIR:-$OUT_DIR/desktop-stack}"
DESKTOP_BIN_DIR="$DESKTOP_STAGING_DIR/bin"
DESKTOP_ETC_DIR="$DESKTOP_STAGING_DIR/etc"

# Cross target + sysroot (x86_64 only for this script)
# Default to a Linux-flavored triple so ldc defines the POSIX/glibc runtime
# versions that `core.stdc` headers expect. Using a bare `*-elf` triple leaves
# those versions unset, which in turn makes basic C types like `c_long` and
# `wchar_t` undefined when compiling with `-betterC`.
: "${TARGET:=x86_64-unknown-linux-gnu}"
: "${SYSROOT:=$HOME/sysroots/$TARGET}"

# Kernel sources / outputs
KERNEL_D="${KERNEL_D:-src/anonymos/kernel/kernel.d}"
STARTUP_SRC="${STARTUP_SRC:-src/boot.s}"
LINKER_SCRIPT="${LINKER_SCRIPT:-linker.ld}"
KERNEL_O="$OUT_DIR/kernel.o"
STARTUP_O="$OUT_DIR/startup.o"
KERNEL_ELF="$OUT_DIR/kernel.elf"
POSIXUTILS_OUT="${POSIXUTILS_OUT:-$OUT_DIR/posixutils}"
POSIXUTILS_BIN_DIR="$POSIXUTILS_OUT/bin"
KERNEL_POSIX_STAGING="${KERNEL_POSIX_STAGING:-$OUT_DIR/kernel-posixutils}"
KERNEL_POSIX_BIN_STAGING="$KERNEL_POSIX_STAGING/bin"

# ISO packaging
ISO_STAGING_DIR="${ISO_STAGING_DIR:-$OUT_DIR/isodir}"
ISO_IMAGE="${ISO_IMAGE:-$OUT_DIR/os.iso}"
ISO_SYSROOT_PATH="${ISO_SYSROOT_PATH:-opt/sysroot}"
ISO_TOOLCHAIN_PATH="${ISO_TOOLCHAIN_PATH:-opt/toolchain}"
ISO_SHELL_PATH="${ISO_SHELL_PATH:-opt/shell}"
KERNEL_POSIX_ISO_PATH="${KERNEL_POSIX_ISO_PATH:-kernel/posixutils}"
GRUB_CFG_SRC="${GRUB_CFG_SRC:-src/grub/grub.cfg}"

# Optional toolchain bundle inside ISO (set to a path to enable)
CROSS_TOOLCHAIN_DIR="${CROSS_TOOLCHAIN_DIR:-}"

# Optional path to a DMD source tree to copy into the ISO image.  The kernel
# build expects to find the sources under opt/toolchain/dmd when verifying the
# toolchain build.  Default to the real tree at $ROOT/dmd when present.  Callers
# can still override this via the DMD_SOURCE_DIR environment variable.
if [ -z "${DMD_SOURCE_DIR:-}" ] && [ -d "$ROOT/3rdparty/dmd" ]; then
  DMD_SOURCE_DIR="$ROOT/3rdparty/dmd"
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
: "${QEMU_USB:=1}"       # set to 0 to skip adding USB controller + HID devices
: "${QEMU_PS2:=1}"       # set to 0 to skip explicit ISA i8042 (PS/2) device
: "${QEMU_DISPLAY:=}"    # optional extra display args, e.g. "-display gtk" or "-display sdl"

# Map TARGET -> builtins suffix & LLD machine
case "$TARGET" in
  x86_64-*-elf|x86_64-unknown-elf|x86_64-*-linux-gnu)
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
command -v python3 >/dev/null 2>&1 || { echo "Missing tool: python3"; exit 1; }
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

# ===================== Build POSIX utilities =====================
if [ -d "$POSIXUTILS_ROOT" ]; then
  echo "[*] Building POSIX utilities from $POSIXUTILS_ROOT"
  POSIX_ARGS=("$ROOT/tools/build_posixutils.py" --dc "$POSIXUTILS_DC" --source "$POSIXUTILS_ROOT" --output "$POSIXUTILS_BIN_DIR"
)
  if [ -n "${POSIXUTILS_FLAGS:-}" ]; then
    POSIX_ARGS+=(--flags "$POSIXUTILS_FLAGS")
  fi
  python3 "${POSIX_ARGS[@]}"
  if [ -d "$POSIXUTILS_BIN_DIR" ]; then
    rm -rf "$KERNEL_POSIX_STAGING"
    mkdir -p "$KERNEL_POSIX_BIN_STAGING"
    cp -a "$POSIXUTILS_BIN_DIR/." "$KERNEL_POSIX_BIN_STAGING/"
    if [ -f "$POSIXUTILS_OUT/objects.tsv" ]; then
      cp "$POSIXUTILS_OUT/objects.tsv" "$KERNEL_POSIX_STAGING/"
    fi
  fi
else
  echo "[!] POSIX utilities source directory not found: $POSIXUTILS_ROOT" >&2
fi

# ===================== Build desktop/display stack stubs =====================
mkdir -p "$DESKTOP_BIN_DIR" "$DESKTOP_ETC_DIR/X11/xinit"

install_desktop_stub() {
  local name="$1"
  local target="$DESKTOP_BIN_DIR/$name"
  local source="$DESKTOP_ASSETS_DIR/stubs/display-component.sh"
  if [ -f "$source" ] && [ ! -f "$target" ]; then
    cp "$source" "$target"
    chmod +x "$target"
    echo "[*] Installed desktop stub: $target"
  else
    echo "[!] Desktop stub source missing: $source" >&2
  fi
}

if [ -d "$DESKTOP_ASSETS_DIR" ]; then
  install_desktop_stub "Xorg"
  install_desktop_stub "xinit"
  install_desktop_stub "xdm"
  install_desktop_stub "lightdm"
  install_desktop_stub "gdm"
  install_desktop_stub "i3"

  SESSION_SCRIPT_SRC="$DESKTOP_ASSETS_DIR/session-start.sh"
  SESSION_SCRIPT_DEST="$DESKTOP_ETC_DIR/X11/xinit/minimal-i3-session"
  if [ -f "$SESSION_SCRIPT_SRC" ]; then
    cp "$SESSION_SCRIPT_SRC" "$SESSION_SCRIPT_DEST"
    chmod +x "$SESSION_SCRIPT_DEST"
    echo "[*] Installed session script: $SESSION_SCRIPT_DEST"
  else
    echo "[!] Session startup script missing: $SESSION_SCRIPT_SRC" >&2
  fi
else
  echo "[!] Desktop assets directory not found: $DESKTOP_ASSETS_DIR" >&2
fi

# ===================== Compile kernel (freestanding D) =====================
mkdir -p "$OUT_DIR"

if [ "$DEBUG" = "1" ]; then
  DFLAGS="-g -O0"
else
  DFLAGS="-O3 -release"
fi

# Always enable userland bootstrap support
DFLAGS+=" -d-version=MinimalOsUserland -d-version=MinimalOsUserlandLinked"
# Kernel build is freestanding; avoid host libc interop even when the target
# triple defines version(Posix).
DFLAGS+=" -d-version=MinimalOsFreestanding -disable-red-zone"

# D objects (kernel + dependencies + userland)
KERNEL_SOURCES=(
  "$KERNEL_D"
  "src/anonymos/kernel/memory.d"
  "src/anonymos/kernel/heap.d"
  "src/anonymos/kernel/cpu.d"
  "src/anonymos/kernel/interrupts.d"
  "src/anonymos/kernel/posixbundle.d"
  "src/anonymos/kernel/compiler_builder_entry.d"
  "src/anonymos/kernel/shell_integration.d"
  "src/anonymos/kernel/exceptions.d"
  "src/anonymos/kernel/dma.d"
  "src/anonymos/console.d"
  "src/anonymos/serial.d"
  "src/anonymos/hardware.d"
  "src/anonymos/display/canvas.d"
  "src/anonymos/display/font_stack.d"
  "src/anonymos/display/bitmap_font.d"
  "src/anonymos/display/framebuffer.d"
  "src/anonymos/display/input_pipeline.d"
  "src/anonymos/display/input_handler.d"
  "src/anonymos/display/wallpaper_types.d"
  "src/anonymos/display/wallpaper_builtin.d"
  "src/anonymos/display/wallpaper.d"
  "src/anonymos/display/splash.d"
  "src/anonymos/display/window_manager/manager.d"
  "src/anonymos/display/window_manager/renderer.d"
  "src/anonymos/display/compositor.d"
  "src/anonymos/display/desktop.d"
  "src/anonymos/display/server.d"
  "src/anonymos/display/x11_stack.d"
  "src/anonymos/display/modesetting.d"
  "src/anonymos/display/gpu_accel.d"
  "src/anonymos/drivers/pci.d"
  "src/anonymos/drivers/usb_hid.d"
  "src/anonymos/drivers/hid_keyboard.d"
  "src/anonymos/drivers/hid_mouse.d"
  "src/anonymos/compiler.d"
  "src/anonymos/fallback_shell.d"
  "src/anonymos/syscalls/posix.d"
  "src/anonymos/multiboot.d"
  "src/anonymos/kernel/posixutils/context.d"
  "src/anonymos/kernel/posixutils/registry.d"
  "src/anonymos/toolchain.d"
  "src/sh_metadata.d"
  "src/anonymos/userland.d"
  "src/anonymos/fs.d"
  "src/anonymos/syscalls/linux.d"
  "src/anonymos/syscalls/syscalls.d"
  "src/anonymos/elf.d"
  "src/anonymos/objects.d"
  "src/anonymos/kernel/pagetable.d"
  "src/anonymos/kernel/usermode.d"
  "src/anonymos/kernel/physmem.d"
  "src/anonymos/kernel/vm_map.d"
  "src/anonymos/security_config.d"
)

# Ensure shell integration is always present (kmain registers compiler-builder).
ensure_kernel_source() {
  local needle="$1"
  for src in "${KERNEL_SOURCES[@]}"; do
    if [[ "$src" == "$needle" ]]; then
      return
    fi
  done
  echo "[+] Adding required kernel source: $needle"
  KERNEL_SOURCES+=("$needle")
}

ensure_kernel_source "src/anonymos/kernel/shell_integration.d"

KERNEL_OBJECTS=()
for source in "${KERNEL_SOURCES[@]}"; do
  base="$(basename "${source%.d}")"
  obj="$OUT_DIR/${base}.o"
  echo "[*] Compiling D source: $source -> $obj"
  ldc2 -I. -Isrc -J. -Jsrc/anonymos -mtriple="$TARGET" -betterC $DFLAGS \
       -c "$source" -of="$obj"
  KERNEL_OBJECTS+=("$obj")
done

# Startup (asm)
CLANGFLAGS=("--target=$TARGET")
if [ "$DEBUG" = "1" ]; then
  CLANGFLAGS+=("-g")
else
  CLANGFLAGS+=("-O2")
fi
echo "[*] Compiling startup ASM: $STARTUP_SRC -> $STARTUP_O"
clang "${CLANGFLAGS[@]}" -c "$STARTUP_SRC" -o "$STARTUP_O"

# ===================== Link kernel with builtins =====================
LIBDIR="$SYSROOT/usr/lib"
[ -f "$FLAT" ] || LIBDIR="$SYSROOT/usr/lib/generic"

echo "[*] Linking kernel: $KERNEL_ELF"
if [ "$LINK_BACKEND" = "ld.lld" ] || [ "$LINK_BACKEND" = "ld" ]; then
  # Native linker path
  "$LINK_BACKEND" ${LLD_MACH:+-m "$LLD_MACH"} -T "$LINKER_SCRIPT" -nostdlib \
      "$STARTUP_O" "${KERNEL_OBJECTS[@]}" \
      -L"$LIBDIR" \
      -l:libclang_rt.builtins-${LIBSUFFIX}.a \
      -o "$KERNEL_ELF"
else
  # toy-ld wrapper
  "$LINK_BACKEND" -T "$LINKER_SCRIPT" -nostdlib \
      "$STARTUP_O" "${KERNEL_OBJECTS[@]}" \
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

# ===================== Build zsh and oh-my-zsh =====================
if [ -x "$ROOT/tools/build_zsh.sh" ]; then
  echo "[*] Building zsh..."
  "$ROOT/tools/build_zsh.sh"
else
  echo "[!] tools/build_zsh.sh not found or not executable" >&2
fi

# ===================== Bundle POSIX utilities into shell staging =====================
if [ -d "$POSIXUTILS_BIN_DIR" ]; then
  mkdir -p "$OUT_DIR/shell/bin"
  cp -a "$POSIXUTILS_BIN_DIR/." "$OUT_DIR/shell/bin/"
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
  if [ -d "$POSIXUTILS_BIN_DIR" ]; then
    mkdir -p "$SHELL_DEST/bin"
    cp -a "$POSIXUTILS_BIN_DIR/." "$SHELL_DEST/bin/"
  fi
fi

# Ensure the kernel can find the POSIX utility manifest (and the paths it
# references) once the ISO boots.  The runtime probes
# build/posixutils/objects.tsv, so mirror the build/posixutils directory into
# the ISO image, not just the shell's copy of the binaries.
POSIX_ISO_DEST="$ISO_STAGING_DIR/build/posixutils"
if [ -d "$POSIXUTILS_OUT" ]; then
  rm -rf "$POSIX_ISO_DEST"
  mkdir -p "$POSIX_ISO_DEST"
  cp -a "$POSIXUTILS_OUT/." "$POSIX_ISO_DEST/"
fi

if [ -d "$KERNEL_POSIX_STAGING" ]; then
  POSIX_KERNEL_DEST="$ISO_STAGING_DIR/$KERNEL_POSIX_ISO_PATH"
  rm -rf "$POSIX_KERNEL_DEST"
  mkdir -p "$POSIX_KERNEL_DEST"
  cp -a "$KERNEL_POSIX_STAGING/." "$POSIX_KERNEL_DEST/"
fi

# Copy zsh artifacts
ZSH_DIST="$OUT_DIR/zsh-dist"
if [ -d "$ZSH_DIST" ]; then
  echo "[*] Bundling zsh into ISO..."
  mkdir -p "$ISO_STAGING_DIR/bin"
  mkdir -p "$ISO_STAGING_DIR/etc"
  mkdir -p "$ISO_STAGING_DIR/usr/share"
  
  if [ -f "$ZSH_DIST/bin/zsh" ]; then
    cp "$ZSH_DIST/bin/zsh" "$ISO_STAGING_DIR/bin/"
  fi
  
  if [ -d "$ZSH_DIST/share/oh-my-zsh" ]; then
    # Strip git metadata to avoid permission issues with packed objects
    rm -rf "$ZSH_DIST/share/oh-my-zsh/.git" \
           "$ZSH_DIST/share/oh-my-zsh/ohmyzsh/.git"
    cp -r "$ZSH_DIST/share/oh-my-zsh" "$ISO_STAGING_DIR/usr/share/"
  fi
  
  if [ -f "$ZSH_DIST/etc/zshrc" ]; then
    cp "$ZSH_DIST/etc/zshrc" "$ISO_STAGING_DIR/etc/"
  fi
fi

# Desktop/display stack staging
if [ -d "$DESKTOP_STAGING_DIR" ]; then
  if [ -d "$DESKTOP_BIN_DIR" ]; then
    mkdir -p "$ISO_STAGING_DIR/bin"
    cp -a "$DESKTOP_BIN_DIR/." "$ISO_STAGING_DIR/bin/"
  fi
  if [ -d "$DESKTOP_ETC_DIR" ]; then
    mkdir -p "$ISO_STAGING_DIR/etc"
    cp -a "$DESKTOP_ETC_DIR/." "$ISO_STAGING_DIR/etc/"
  fi
  DESKTOP_LIB_DIR="$DESKTOP_STAGING_DIR/lib"
  if [ -d "$DESKTOP_LIB_DIR" ]; then
    mkdir -p "$ISO_STAGING_DIR/lib"
    cp -a "$DESKTOP_LIB_DIR/." "$ISO_STAGING_DIR/lib/"
    # Ensure /lib64 exists for 64-bit loader
    if [ ! -e "$ISO_STAGING_DIR/lib64" ]; then
       ln -s lib "$ISO_STAGING_DIR/lib64"
    fi
  fi
fi

# Create initrd from desktop staging
INITRD_IMG="$ISO_STAGING_DIR/boot/initrd.tar"
if [ -d "$DESKTOP_STAGING_DIR" ]; then
    echo "[*] Creating initrd from $DESKTOP_STAGING_DIR"
    tar -cf "$INITRD_IMG" -C "$DESKTOP_STAGING_DIR" .
fi

if [ -f "$GRUB_CFG_SRC" ]; then
  cp "$GRUB_CFG_SRC" "$ISO_STAGING_DIR/boot/grub/grub.cfg"
else
  cat >"$ISO_STAGING_DIR/boot/grub/grub.cfg" <<EOF
set timeout=0
set default=0

menuentry "AnonymOS" {
    multiboot /boot/kernel.elf
    module /boot/initrd.tar initrd
    boot
}
EOF
fi

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
  QEMU_ARGS=(-cdrom "$ISO_IMAGE" -serial stdio -machine pc,i8042=on)
  if [ "$QEMU_USB" = "1" ]; then
    echo "[!] QEMU_USB=1: guest xHCI driver is partially stubbed; USB input may be routed via legacy PS/2" >&2
    # Provide an xHCI controller with USB HID devices so the guest can enumerate
    # keyboard/mouse when a USB host stack is present.
    # QEMU_ARGS+=(-device qemu-xhci -device usb-kbd -device usb-tablet -D /tmp/qemu-ps2.log)
    QEMU_ARGS+=(-device ps2-mouse -D /tmp/qemu-ps2.log)
  fi
  if [ -n "$QEMU_DISPLAY" ]; then
    QEMU_ARGS+=($QEMU_DISPLAY)
  fi
  [ "$QEMU_GDB" = "1" ] && QEMU_ARGS+=(-s -S)
  echo "[→] Launching: $QEMU_BIN ${QEMU_ARGS[*]}"
  exec "$QEMU_BIN" "${QEMU_ARGS[@]}"
fi
