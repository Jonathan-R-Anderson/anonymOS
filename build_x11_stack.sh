#!/usr/bin/env bash
# Comprehensive build script for i3 window manager and full X11 stack from source
# This builds everything needed for a working X11 environment

set -euo pipefail

# ===================== Configuration =====================
ROOT="${ROOT:-$PWD}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/build-x11}"
INSTALL_PREFIX="${INSTALL_PREFIX:-$ROOT/build/x11-stack}"
SYSROOT="${SYSROOT:-$ROOT/build/toolchain/sysroot}"
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"

# Number of parallel jobs
JOBS="${JOBS:-$(nproc)}"

# Source directories
SOURCES_DIR="$BUILD_ROOT/sources"
BUILD_DIR="$BUILD_ROOT/build"

# Component versions
I3_VERSION="${I3_VERSION:-4.23}"
XORG_SERVER_VERSION="${XORG_SERVER_VERSION:-21.1.11}"
XINIT_VERSION="${XINIT_VERSION:-1.4.2}"
XDM_VERSION="${XDM_VERSION:-1.1.16}"

# Core X11 libraries
LIBXCB_VERSION="${LIBXCB_VERSION:-1.16}"
XCB_PROTO_VERSION="${XCB_PROTO_VERSION:-1.16.0}"
XCB_UTIL_VERSION="${XCB_UTIL_VERSION:-0.4.1}"
XCB_UTIL_IMAGE_VERSION="${XCB_UTIL_IMAGE_VERSION:-0.4.1}"
XCB_UTIL_KEYSYMS_VERSION="${XCB_UTIL_KEYSYMS_VERSION:-0.4.1}"
XCB_UTIL_RENDERUTIL_VERSION="${XCB_UTIL_RENDERUTIL_VERSION:-0.3.10}"
XCB_UTIL_WM_VERSION="${XCB_UTIL_WM_VERSION:-0.4.2}"
XCB_UTIL_CURSOR_VERSION="${XCB_UTIL_CURSOR_VERSION:-0.1.5}"

LIBX11_VERSION="${LIBX11_VERSION:-1.8.7}"
XPROTO_VERSION="${XPROTO_VERSION:-2024.1}"
XTRANS_VERSION="${XTRANS_VERSION:-1.5.0}"

# Additional X libraries needed by Xorg
LIBXEXT_VERSION="${LIBXEXT_VERSION:-1.3.6}"
LIBXFIXES_VERSION="${LIBXFIXES_VERSION:-6.0.1}"
LIBXDAMAGE_VERSION="${LIBXDAMAGE_VERSION:-1.1.6}"
LIBXXF86VM_VERSION="${LIBXXF86VM_VERSION:-1.1.5}"
LIBXRANDR_VERSION="${LIBXRANDR_VERSION:-1.5.4}"
LIBXRENDER_VERSION="${LIBXRENDER_VERSION:-0.9.11}"
LIBXI_VERSION="${LIBXI_VERSION:-1.8.1}"
LIBXTST_VERSION="${LIBXTST_VERSION:-1.2.4}"
LIBXKBFILE_VERSION="${LIBXKBFILE_VERSION:-1.1.3}"
LIBXFONT2_VERSION="${LIBXFONT2_VERSION:-2.0.6}"
LIBXAU_VERSION="${LIBXAU_VERSION:-1.0.11}"
LIBXDMCP_VERSION="${LIBXDMCP_VERSION:-1.1.5}"

# Graphics and rendering
LIBDRM_VERSION="${LIBDRM_VERSION:-2.4.120}"
MESA_VERSION="${MESA_VERSION:-24.0.2}"
PIXMAN_VERSION="${PIXMAN_VERSION:-0.43.4}"
LIBEPOXY_VERSION="${LIBEPOXY_VERSION:-1.5.10}"

# Fonts
FREETYPE_VERSION="${FREETYPE_VERSION:-2.13.2}"
FONTCONFIG_VERSION="${FONTCONFIG_VERSION:-2.15.0}"
LIBPNG_VERSION="${LIBPNG_VERSION:-1.6.43}"

# i3 dependencies
LIBEV_VERSION="${LIBEV_VERSION:-4.33}"
YAJL_VERSION="${YAJL_VERSION:-2.1.0}"
CAIRO_VERSION="${CAIRO_VERSION:-1.18.0}"
PANGO_VERSION="${PANGO_VERSION:-1.52.0}"
LIBSTARTUP_NOTIFICATION_VERSION="${LIBSTARTUP_NOTIFICATION_VERSION:-0.12}"

# Utilities
XKBCOMP_VERSION="${XKBCOMP_VERSION:-1.4.7}"
XKEYBOARD_CONFIG_VERSION="${XKEYBOARD_CONFIG_VERSION:-2.5.1}"

# ===================== Helper Functions =====================
log() {
    echo "[build-x11] $*"
}

error() {
    echo "[build-x11] ERROR: $*" >&2
    exit 1
}

ensure_dir() {
    mkdir -p "$1"
}

download_xorg() {
    local component="$1"
    local version="$2"
    local filename="${component}-${version}.tar.xz"
    
    if ! ls "${component}-${version}".tar.* >/dev/null 2>&1; then
        log "Downloading $component $version..."
        wget "https://xorg.freedesktop.org/archive/individual/$3/${filename}" || \
        wget "https://xorg.freedesktop.org/releases/individual/$3/${filename}" || \
        error "Failed to download $component"
    fi
}

build_autotools() {
    local name="$1"
    local tarball="$2"
    shift 2
    local extra_flags=("$@")
    
    log "Building $name..."
    cd "$BUILD_DIR"
    tar -xf "$SOURCES_DIR/$tarball"
    local dir="${tarball%.tar.*}"
    cd "$dir"
    
    ./configure --prefix="$INSTALL_PREFIX" \
        --disable-static \
        --enable-shared \
        "${extra_flags[@]}"
    
    make -j"$JOBS"
    make install
    log "$name installed."
}

build_meson() {
    local name="$1"
    local source_dir="$2"
    shift 2
    local extra_flags=("$@")
    
    log "Building $name..."
    cd "$source_dir"
    
    meson setup build --prefix="$INSTALL_PREFIX" \
        --buildtype=release \
        "${extra_flags[@]}"
    
    ninja -C build
    ninja -C build install
    log "$name installed."
}

# ===================== Setup =====================
log "Setting up build environment..."
ensure_dir "$SOURCES_DIR"
ensure_dir "$BUILD_DIR"
ensure_dir "$INSTALL_PREFIX"

# Export build flags
export PKG_CONFIG_PATH="$INSTALL_PREFIX/lib/pkgconfig:$INSTALL_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"
export PATH="$INSTALL_PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export CFLAGS="-O2 -I$INSTALL_PREFIX/include"
export CXXFLAGS="-O2 -I$INSTALL_PREFIX/include"
export LDFLAGS="-L$INSTALL_PREFIX/lib"
export ACLOCAL_PATH="$INSTALL_PREFIX/share/aclocal"

# ===================== Download All Sources =====================
log "Downloading all source packages..."
cd "$SOURCES_DIR"

# Protocol definitions
download_xorg "xcb-proto" "$XCB_PROTO_VERSION" "proto"
download_xorg "xorgproto" "$XPROTO_VERSION" "proto"
download_xorg "xtrans" "$XTRANS_VERSION" "lib"

# Core X libraries
download_xorg "libxcb" "$LIBXCB_VERSION" "lib"
download_xorg "libX11" "$LIBX11_VERSION" "lib"
download_xorg "libXau" "$LIBXAU_VERSION" "lib"
download_xorg "libXdmcp" "$LIBXDMCP_VERSION" "lib"

# xcb-util libraries
download_xorg "xcb-util" "$XCB_UTIL_VERSION" "lib"
download_xorg "xcb-util-image" "$XCB_UTIL_IMAGE_VERSION" "lib"
download_xorg "xcb-util-keysyms" "$XCB_UTIL_KEYSYMS_VERSION" "lib"
download_xorg "xcb-util-renderutil" "$XCB_UTIL_RENDERUTIL_VERSION" "lib"
download_xorg "xcb-util-wm" "$XCB_UTIL_WM_VERSION" "lib"
download_xorg "xcb-util-cursor" "$XCB_UTIL_CURSOR_VERSION" "lib"

# Extension libraries
download_xorg "libXext" "$LIBXEXT_VERSION" "lib"
download_xorg "libXfixes" "$LIBXFIXES_VERSION" "lib"
download_xorg "libXdamage" "$LIBXDAMAGE_VERSION" "lib"
download_xorg "libXxf86vm" "$LIBXXF86VM_VERSION" "lib"
download_xorg "libXrandr" "$LIBXRANDR_VERSION" "lib"
download_xorg "libXrender" "$LIBXRENDER_VERSION" "lib"
download_xorg "libXi" "$LIBXI_VERSION" "lib"
download_xorg "libXtst" "$LIBXTST_VERSION" "lib"
download_xorg "libxkbfile" "$LIBXKBFILE_VERSION" "lib"
download_xorg "libXfont2" "$LIBXFONT2_VERSION" "lib"

# Xorg server and utilities
download_xorg "xorg-server" "$XORG_SERVER_VERSION" "xserver"
download_xorg "xinit" "$XINIT_VERSION" "app"
download_xorg "xdm" "$XDM_VERSION" "app"
download_xorg "xkbcomp" "$XKBCOMP_VERSION" "app"
download_xorg "xkeyboard-config" "$XKEYBOARD_CONFIG_VERSION" "data"

# Graphics libraries
if [ ! -f "libdrm-${LIBDRM_VERSION}.tar.xz" ]; then
    log "Downloading libdrm..."
    wget "https://dri.freedesktop.org/libdrm/libdrm-${LIBDRM_VERSION}.tar.xz"
fi

if [ ! -f "pixman-${PIXMAN_VERSION}.tar.gz" ]; then
    log "Downloading pixman..."
    wget "https://cairographics.org/releases/pixman-${PIXMAN_VERSION}.tar.gz"
fi

if [ ! -f "libepoxy-${LIBEPOXY_VERSION}.tar.xz" ]; then
    log "Downloading libepoxy..."
    wget "https://github.com/anholt/libepoxy/releases/download/${LIBEPOXY_VERSION}/libepoxy-${LIBEPOXY_VERSION}.tar.xz"
fi

# Font libraries
if [ ! -f "libpng-${LIBPNG_VERSION}.tar.xz" ]; then
    log "Downloading libpng..."
    wget "https://download.sourceforge.net/libpng/libpng-${LIBPNG_VERSION}.tar.xz"
fi

if [ ! -f "freetype-${FREETYPE_VERSION}.tar.xz" ]; then
    log "Downloading freetype..."
    wget "https://download.savannah.gnu.org/releases/freetype/freetype-${FREETYPE_VERSION}.tar.xz"
fi

if [ ! -f "fontconfig-${FONTCONFIG_VERSION}.tar.xz" ]; then
    log "Downloading fontconfig..."
    wget "https://www.freedesktop.org/software/fontconfig/release/fontconfig-${FONTCONFIG_VERSION}.tar.xz"
fi

# i3 dependencies
if [ ! -f "libev-${LIBEV_VERSION}.tar.gz" ]; then
    log "Downloading libev..."
    wget "http://dist.schmorp.de/libev/libev-${LIBEV_VERSION}.tar.gz"
fi

if [ ! -d "yajl" ]; then
    log "Cloning yajl..."
    git clone --depth=1 https://github.com/lloyd/yajl.git
fi

if [ ! -f "cairo-${CAIRO_VERSION}.tar.xz" ]; then
    log "Downloading cairo..."
    wget "https://cairographics.org/releases/cairo-${CAIRO_VERSION}.tar.xz"
fi

if [ ! -f "pango-${PANGO_VERSION}.tar.xz" ]; then
    log "Downloading pango..."
    wget "https://download.gnome.org/sources/pango/${PANGO_VERSION%.*}/pango-${PANGO_VERSION}.tar.xz"
fi

if [ ! -f "libstartup-notification-${LIBSTARTUP_NOTIFICATION_VERSION}.tar.gz" ]; then
    log "Downloading libstartup-notification..."
    wget "https://www.freedesktop.org/software/startup-notification/releases/libstartup-notification-${LIBSTARTUP_NOTIFICATION_VERSION}.tar.gz"
fi

# i3 window manager
if [ ! -d "i3" ]; then
    log "Cloning i3..."
    git clone --depth=1 --branch "$I3_VERSION" https://github.com/i3/i3.git
fi

log "All sources downloaded."

# ===================== Build Process =====================

# Phase 1: Protocol definitions
build_autotools "xcb-proto" "xcb-proto-${XCB_PROTO_VERSION}.tar.xz"
build_meson "xorgproto" "$BUILD_DIR/xorgproto-${XPROTO_VERSION}"
cd "$BUILD_DIR" && tar -xf "$SOURCES_DIR/xorgproto-${XPROTO_VERSION}.tar.xz"
build_autotools "xtrans" "xtrans-${XTRANS_VERSION}.tar.xz"

# Phase 2: Core X libraries
build_autotools "libXau" "libXau-${LIBXAU_VERSION}.tar.xz"
build_autotools "libXdmcp" "libXdmcp-${LIBXDMCP_VERSION}.tar.xz"
build_autotools "libxcb" "libxcb-${LIBXCB_VERSION}.tar.xz"
build_autotools "libX11" "libX11-${LIBX11_VERSION}.tar.xz"

# Phase 3: xcb-util libraries
build_autotools "xcb-util" "xcb-util-${XCB_UTIL_VERSION}.tar.xz"
build_autotools "xcb-util-image" "xcb-util-image-${XCB_UTIL_IMAGE_VERSION}.tar.xz"
build_autotools "xcb-util-keysyms" "xcb-util-keysyms-${XCB_UTIL_KEYSYMS_VERSION}.tar.xz"
build_autotools "xcb-util-renderutil" "xcb-util-renderutil-${XCB_UTIL_RENDERUTIL_VERSION}.tar.xz"
build_autotools "xcb-util-wm" "xcb-util-wm-${XCB_UTIL_WM_VERSION}.tar.xz"
build_autotools "xcb-util-cursor" "xcb-util-cursor-${XCB_UTIL_CURSOR_VERSION}.tar.xz"

# Phase 4: X extension libraries
build_autotools "libXext" "libXext-${LIBXEXT_VERSION}.tar.xz"
build_autotools "libXfixes" "libXfixes-${LIBXFIXES_VERSION}.tar.xz"
build_autotools "libXdamage" "libXdamage-${LIBXDAMAGE_VERSION}.tar.xz"
build_autotools "libXxf86vm" "libXxf86vm-${LIBXXF86VM_VERSION}.tar.xz"
build_autotools "libXrandr" "libXrandr-${LIBXRANDR_VERSION}.tar.xz"
build_autotools "libXrender" "libXrender-${LIBXRENDER_VERSION}.tar.xz"
build_autotools "libXi" "libXi-${LIBXI_VERSION}.tar.xz"
build_autotools "libXtst" "libXtst-${LIBXTST_VERSION}.tar.xz"
build_autotools "libxkbfile" "libxkbfile-${LIBXKBFILE_VERSION}.tar.xz"

# Phase 5: Graphics libraries
build_autotools "libpng" "libpng-${LIBPNG_VERSION}.tar.xz"
build_autotools "pixman" "pixman-${PIXMAN_VERSION}.tar.gz"
build_meson "libdrm" "$BUILD_DIR/libdrm-${LIBDRM_VERSION}" -Dintel=disabled -Dradeon=disabled -Damdgpu=disabled -Dnouveau=disabled
cd "$BUILD_DIR" && tar -xf "$SOURCES_DIR/libdrm-${LIBDRM_VERSION}.tar.xz"
build_meson "libepoxy" "$BUILD_DIR/libepoxy-${LIBEPOXY_VERSION}"
cd "$BUILD_DIR" && tar -xf "$SOURCES_DIR/libepoxy-${LIBEPOXY_VERSION}.tar.xz"

# Phase 6: Font libraries
build_autotools "freetype" "freetype-${FREETYPE_VERSION}.tar.xz"
build_autotools "fontconfig" "fontconfig-${FONTCONFIG_VERSION}.tar.xz"
build_autotools "libXfont2" "libXfont2-${LIBXFONT2_VERSION}.tar.xz"

# Phase 7: Keyboard configuration
build_autotools "xkeyboard-config" "xkeyboard-config-${XKEYBOARD_CONFIG_VERSION}.tar.gz"
build_autotools "xkbcomp" "xkbcomp-${XKBCOMP_VERSION}.tar.xz"

# Phase 8: Xorg server
build_autotools "xorg-server" "xorg-server-${XORG_SERVER_VERSION}.tar.xz" \
    --enable-xorg \
    --disable-xwayland \
    --disable-xnest \
    --disable-xvfb \
    --with-xkb-output=/var/lib/xkb

# Phase 9: X utilities
build_autotools "xinit" "xinit-${XINIT_VERSION}.tar.xz"
build_autotools "xdm" "xdm-${XDM_VERSION}.tar.xz"

# Phase 10: i3 dependencies
build_autotools "libev" "libev-${LIBEV_VERSION}.tar.gz"

log "Building yajl..."
cd "$BUILD_DIR"
rm -rf yajl-build
cp -r "$SOURCES_DIR/yajl" yajl-build
cd yajl-build
./configure --prefix="$INSTALL_PREFIX"
make -j"$JOBS"
make install

build_autotools "cairo" "cairo-${CAIRO_VERSION}.tar.xz"
build_meson "pango" "$BUILD_DIR/pango-${PANGO_VERSION}"
cd "$BUILD_DIR" && tar -xf "$SOURCES_DIR/pango-${PANGO_VERSION}.tar.xz"
build_autotools "libstartup-notification" "libstartup-notification-${LIBSTARTUP_NOTIFICATION_VERSION}.tar.gz"

# Phase 11: i3 window manager
log "Building i3..."
cd "$BUILD_DIR"
rm -rf i3-build
cp -r "$SOURCES_DIR/i3" i3-build
cd i3-build
meson setup build --prefix="$INSTALL_PREFIX" \
    -Ddocs=false \
    -Dmans=false
ninja -C build
ninja -C build install

# ===================== Post-build Configuration =====================
log "Creating configuration files..."

# Create default i3 config
mkdir -p "$INSTALL_PREFIX/etc/i3"
cat > "$INSTALL_PREFIX/etc/i3/config" <<'EOF'
# i3 config file for minimal_os

# Mod key (Mod1 = Alt, Mod4 = Super/Windows)
set $mod Mod4

# Font for window titles
font pango:monospace 8

# Start a terminal (adjust to your terminal emulator)
bindsym $mod+Return exec xterm

# Kill focused window
bindsym $mod+Shift+q kill

# Change focus
bindsym $mod+j focus left
bindsym $mod+k focus down
bindsym $mod+l focus up
bindsym $mod+semicolon focus right

# Move focused window
bindsym $mod+Shift+j move left
bindsym $mod+Shift+k move down
bindsym $mod+Shift+l move up
bindsym $mod+Shift+semicolon move right

# Split orientation
bindsym $mod+h split h
bindsym $mod+v split v

# Fullscreen
bindsym $mod+f fullscreen toggle

# Restart i3
bindsym $mod+Shift+r restart

# Exit i3
bindsym $mod+Shift+e exit

# Workspaces
bindsym $mod+1 workspace 1
bindsym $mod+2 workspace 2
bindsym $mod+3 workspace 3
bindsym $mod+4 workspace 4

# Move to workspace
bindsym $mod+Shift+1 move container to workspace 1
bindsym $mod+Shift+2 move container to workspace 2
bindsym $mod+Shift+3 move container to workspace 3
bindsym $mod+Shift+4 move container to workspace 4
EOF

# Create xinitrc
mkdir -p "$INSTALL_PREFIX/etc/X11/xinit"
cat > "$INSTALL_PREFIX/etc/X11/xinit/xinitrc" <<'EOF'
#!/bin/sh
# Default xinitrc for minimal_os

# Start i3 window manager
exec i3
EOF
chmod +x "$INSTALL_PREFIX/etc/X11/xinit/xinitrc"

# ===================== Summary =====================
log ""
log "=========================================="
log "X11 Stack Build Complete!"
log "=========================================="
log "Installation directory: $INSTALL_PREFIX"
log ""
log "Key binaries:"
log "  Xorg:   $INSTALL_PREFIX/bin/Xorg"
log "  xinit:  $INSTALL_PREFIX/bin/xinit"
log "  xdm:    $INSTALL_PREFIX/bin/xdm"
log "  i3:     $INSTALL_PREFIX/bin/i3"
log ""
log "Configuration:"
log "  i3 config: $INSTALL_PREFIX/etc/i3/config"
log "  xinitrc:   $INSTALL_PREFIX/etc/X11/xinit/xinitrc"
log ""
log "Next steps:"
log "  1. Integrate binaries into your OS image"
log "  2. Update userland.d service paths"
log "  3. Test in QEMU"
log "=========================================="
