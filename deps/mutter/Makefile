# ==========================================================================
# deps/mutter/Makefile
#
# Wayland compositor stack: Mutter 44 + KMS native backend (software render)
#
# Dependency order:
#   wayland-protocols → libdrm → libevdev → libudev-zero → mtdev → libinput →
#   libseat → json-glib → gsettings-desktop-schemas → iso-codes →
#   xkeyboard-config →
#   Mesa (swrast, no LLVM) → graphene → lcms2 →
#   xorgproto → xtrans → xcb-proto → libpthread-stubs → libXau → libXdmcp →
#   libxcb → libX11 → libXext → libXfixes → libXrender → libXdamage →
#   libXcomposite → libXrandr → libXinerama → libXi → libXtst → libXcursor →
#   libxkbfile → xkbcommon-x11 →
#   libelogind shim → libgudev → gnome-desktop → mutter
#
# All packages built statically against the musl sysroot from gtk-stack.
#
# Output:
#   sysroot/  — shared with gtk-stack (libs + headers added in-place)
#   mutter    — Mutter compositor binary loaded as an ISO module
# ==========================================================================

PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF         := $(abspath .)
MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CXX     := $(MUSL_INSTALL)/bin/musl-clang++
CXXRT_STAMP  := $(abspath ../cxxrt/stamps/libcxx.done)
# Share the sysroot with gtk-stack so all GTK/GLib/Wayland libs are found
SYSROOT      := $(abspath ../gtk-stack/sysroot)
STAMPS       := $(SELF)/stamps
DLDIR        := $(SELF)/downloads
BLDDIR       := $(SELF)/build
HOST_PYTHON  := $(HOST_TOOLS_BIN)/python3
HOST_PIP     := $(HOST_PYTHON) -m pip
HOST_PY_STAMP:= $(HOST_TOOLS_ROOT)/.python-meson-build.stamp
HOST_FLEX    := $(HOST_TOOLS_BIN)/flex
HOST_WL_SCANNER_PC := $(SYSROOT)/share/pkgconfig/wayland-scanner.pc
SYSROOT_USR_WL_PROTOCOLS := $(SYSROOT)/usr/share/wayland-protocols

# ── Cross-compilation tools ────────────────────────────────────────────────
CC      := $(MUSL_CC)
CXX     := $(MUSL_CXX)
AR      := llvm-ar
STRIP   := llvm-strip
RANLIB  := llvm-ranlib
NM      := llvm-nm

BASE_CFLAGS   := -O2 -fPIC \
                 -I$(SYSROOT)/include \
                 -I$(SYSROOT)/include/freetype2 \
                 -I$(SYSROOT)/include/libpng16 \
                 -I$(MUSL_INSTALL)/include
BASE_CXXFLAGS := $(BASE_CFLAGS)
BASE_LDFLAGS  := -static -no-pie \
                 -L$(SYSROOT)/lib \
                 -L$(MUSL_INSTALL)/lib

PKG_CONFIG_ENV := \
    PKG_CONFIG_LIBDIR="$(SYSROOT)/lib/pkgconfig:$(SYSROOT)/share/pkgconfig" \
    PKG_CONFIG_PATH="" \
    PKG_CONFIG_SYSROOT_DIR="$(SYSROOT)"

CONFIGURE_COMMON := \
    CC="$(CC)" CXX="$(CXX)" AR="$(AR)" STRIP="$(STRIP)" RANLIB="$(RANLIB)" NM="$(NM)" \
    CPPFLAGS="$(BASE_CFLAGS)" CFLAGS="$(BASE_CFLAGS)" CXXFLAGS="$(BASE_CXXFLAGS)" LDFLAGS="$(BASE_LDFLAGS)" \
    $(PKG_CONFIG_ENV) \
    --prefix="$(SYSROOT)" \
    --host=x86_64-linux-musl \
    --build=x86_64-linux-gnu \
    --disable-shared \
    --enable-static

XORG_CONFIGURE_COMMON := \
    $(CONFIGURE_COMMON) \
    --enable-malloc0returnsnull=no

# Meson cross-file (auto-generated)
MESON_CROSS := $(SELF)/musl-cross.ini

# ── Library versions ───────────────────────────────────────────────────────
WL_PROTO_VER  := 1.36
LIBDRM_VER    := 2.4.120
LIBEVDEV_VER  := 1.13.2
UDEV0_VER     := 1.0.3
MTDEV_VER     := 1.1.7
LIBINPUT_VER  := 1.25.0
LIBSEAT_VER   := 0.9.1
JSONGLIB_VER  := 1.8.0
JSONGLIB_MAJ  := 1.8
GSET_SCHEMAS_VER := 47.1
ISO_CODES_VER := 4.16.0
XKB_CONFIG_VER := 2.41
XKBCOMMON_VER := 1.7.0
CAIRO_VER     := 1.18.2
MESA_VER      := 23.3.5
GRAPHENE_VER  := 1.10.8
GRAPHENE_MAJ  := 1.10
LCMS2_VER     := 2.16
XORGPROTO_VER := 2024.1
XTRANS_VER    := 1.6.0
XCBPROTO_VER  := 1.17.0
PTHREAD_STUBS_VER := 0.5
LIBXAU_VER    := 1.0.12
LIBXDMCP_VER  := 1.1.5
LIBXCB_VER    := 1.17.0
LIBX11_VER    := 1.8.12
LIBXEXT_VER   := 1.3.6
LIBXFIXES_VER := 6.0.1
LIBXRENDER_VER := 0.9.12
LIBXDAMAGE_VER := 1.1.6
LIBXCOMPOSITE_VER := 0.4.6
LIBXRANDR_VER := 1.5.4
LIBXINERAMA_VER := 1.1.5
LIBXI_VER     := 1.8.2
LIBXTST_VER   := 1.2.5
LIBXCURSOR_VER := 1.2.3
LIBXKBFILE_VER := 1.1.3
LIBGUDEV_VER  := 238
GNOME_DESK_VER := 44.1
MUTTER_VER    := 44.9
HOST_FLEX_VER := 2.6.4

# ── Download URLs ─────────────────────────────────────────────────────────
WL_PROTO_URL  := https://gitlab.freedesktop.org/wayland/wayland-protocols/-/releases/$(WL_PROTO_VER)/downloads/wayland-protocols-$(WL_PROTO_VER).tar.xz
LIBDRM_URL    := https://dri.freedesktop.org/libdrm/libdrm-$(LIBDRM_VER).tar.xz
LIBEVDEV_URL  := https://www.freedesktop.org/software/libevdev/libevdev-$(LIBEVDEV_VER).tar.xz
UDEV0_URL     := https://github.com/illiliti/libudev-zero/archive/refs/tags/$(UDEV0_VER).tar.gz
MTDEV_URL     := https://bitmath.se/org/code/mtdev/mtdev-$(MTDEV_VER).tar.gz
LIBINPUT_URL  := https://gitlab.freedesktop.org/libinput/libinput/-/archive/$(LIBINPUT_VER)/libinput-$(LIBINPUT_VER).tar.gz
LIBSEAT_URL   := https://git.sr.ht/~kennylevinsen/seatd/archive/$(LIBSEAT_VER).tar.gz
JSONGLIB_URL  := https://download.gnome.org/sources/json-glib/$(JSONGLIB_MAJ)/json-glib-$(JSONGLIB_VER).tar.xz
GSET_URL      := https://download.gnome.org/sources/gsettings-desktop-schemas/47/gsettings-desktop-schemas-$(GSET_SCHEMAS_VER).tar.xz
ISO_CODES_URL := https://salsa.debian.org/iso-codes-team/iso-codes/-/archive/v$(ISO_CODES_VER)/iso-codes-v$(ISO_CODES_VER).tar.gz
XKB_CONFIG_URL := https://www.x.org/archive/individual/data/xkeyboard-config/xkeyboard-config-$(XKB_CONFIG_VER).tar.xz
XKBCOMMON_URL := https://xkbcommon.org/download/libxkbcommon-$(XKBCOMMON_VER).tar.xz
CAIRO_URL     := https://cairographics.org/releases/cairo-$(CAIRO_VER).tar.xz
MESA_URL      := https://archive.mesa3d.org/mesa-$(MESA_VER).tar.xz
GRAPHENE_URL  := https://download.gnome.org/sources/graphene/$(GRAPHENE_MAJ)/graphene-$(GRAPHENE_VER).tar.xz
LCMS2_URL     := https://downloads.sourceforge.net/project/lcms/lcms/$(LCMS2_VER)/lcms2-$(LCMS2_VER).tar.gz
XORGPROTO_URL := https://xorg.freedesktop.org/archive/individual/proto/xorgproto-$(XORGPROTO_VER).tar.xz
XTRANS_URL    := https://xorg.freedesktop.org/archive/individual/lib/xtrans-$(XTRANS_VER).tar.xz
XCBPROTO_URL  := https://xorg.freedesktop.org/archive/individual/proto/xcb-proto-$(XCBPROTO_VER).tar.xz
PTHREAD_STUBS_URL := https://xorg.freedesktop.org/archive/individual/lib/libpthread-stubs-$(PTHREAD_STUBS_VER).tar.xz
LIBXAU_URL    := https://xorg.freedesktop.org/archive/individual/lib/libXau-$(LIBXAU_VER).tar.xz
LIBXDMCP_URL  := https://xorg.freedesktop.org/archive/individual/lib/libXdmcp-$(LIBXDMCP_VER).tar.xz
LIBXCB_URL    := https://xorg.freedesktop.org/archive/individual/lib/libxcb-$(LIBXCB_VER).tar.xz
LIBX11_URL    := https://xorg.freedesktop.org/archive/individual/lib/libX11-$(LIBX11_VER).tar.xz
LIBXEXT_URL   := https://xorg.freedesktop.org/archive/individual/lib/libXext-$(LIBXEXT_VER).tar.xz
LIBXFIXES_URL := https://xorg.freedesktop.org/archive/individual/lib/libXfixes-$(LIBXFIXES_VER).tar.xz
LIBXRENDER_URL := https://xorg.freedesktop.org/archive/individual/lib/libXrender-$(LIBXRENDER_VER).tar.xz
LIBXDAMAGE_URL := https://xorg.freedesktop.org/archive/individual/lib/libXdamage-$(LIBXDAMAGE_VER).tar.xz
LIBXCOMPOSITE_URL := https://xorg.freedesktop.org/archive/individual/lib/libXcomposite-$(LIBXCOMPOSITE_VER).tar.xz
LIBXRANDR_URL := https://xorg.freedesktop.org/archive/individual/lib/libXrandr-$(LIBXRANDR_VER).tar.xz
LIBXINERAMA_URL := https://xorg.freedesktop.org/archive/individual/lib/libXinerama-$(LIBXINERAMA_VER).tar.xz
LIBXI_URL     := https://xorg.freedesktop.org/archive/individual/lib/libXi-$(LIBXI_VER).tar.xz
LIBXTST_URL   := https://xorg.freedesktop.org/archive/individual/lib/libXtst-$(LIBXTST_VER).tar.xz
LIBXCURSOR_URL := https://xorg.freedesktop.org/archive/individual/lib/libXcursor-$(LIBXCURSOR_VER).tar.xz
LIBXKBFILE_URL := https://xorg.freedesktop.org/archive/individual/lib/libxkbfile-$(LIBXKBFILE_VER).tar.xz
LIBGUDEV_URL  := https://download.gnome.org/sources/libgudev/$(LIBGUDEV_VER)/libgudev-$(LIBGUDEV_VER).tar.xz
GNOME_DESK_URL:= https://download.gnome.org/sources/gnome-desktop/44/gnome-desktop-$(GNOME_DESK_VER).tar.xz
MUTTER_URL    := https://download.gnome.org/sources/mutter/44/mutter-$(MUTTER_VER).tar.xz
HOST_FLEX_URL := https://github.com/westes/flex/releases/download/v$(HOST_FLEX_VER)/flex-$(HOST_FLEX_VER).tar.gz

# ── Targets ───────────────────────────────────────────────────────────────
.PHONY: all cxxrt-ready wayland-protocols libdrm libevdev libudev-zero mtdev libinput \
        libseat json-glib gsettings-desktop-schemas iso-codes xkeyboard-config cairo-xlib mesa graphene lcms2 \
        xorgproto xtrans xcb-proto libpthread-stubs libxau libxdmcp libxcb libx11 libxext \
        libxfixes libxrender libxdamage libxcomposite libxrandr libxinerama libxi libxtst \
        libxcursor libxkbfile xkbcommon-x11 libelogind-shim libgudev gnome-desktop mutter \
        clean distclean

all: mutter

cxxrt-ready:
	$(MAKE) $(MAKE_BUILD_FLAGS) -C ../cxxrt all

mutter: $(STAMPS)/mutter.done
	@if [ -f $(BLDDIR)/mutter-$(MUTTER_VER)/build/src/mutter ]; then \
		cp $(BLDDIR)/mutter-$(MUTTER_VER)/build/src/mutter $(SELF)/mutter; \
		echo "mutter binary: $(SELF)/mutter"; \
	fi

# ── Setup ─────────────────────────────────────────────────────────────────
$(STAMPS):
	mkdir -p $(STAMPS)

$(DLDIR):
	mkdir -p $(DLDIR)

$(BLDDIR):
	mkdir -p $(BLDDIR)

$(SYSROOT)/lib $(SYSROOT)/include:
	mkdir -p $(SYSROOT)/lib $(SYSROOT)/include

$(HOST_PY_STAMP):
	@echo "[host-python] Ensuring python meson build modules..."
	@mkdir -p $(HOST_TOOLS_ROOT)
	@$(HOST_PYTHON) -c 'import packaging, mako' >/dev/null 2>&1 || $(HOST_PIP) install packaging mako
	@touch $@

$(HOST_FLEX): | $(DLDIR) $(BLDDIR)
	@echo "[host-flex] Building..."
	test -f $(DLDIR)/flex-$(HOST_FLEX_VER).tar.gz || \
	    wget -q -O $(DLDIR)/flex-$(HOST_FLEX_VER).tar.gz $(HOST_FLEX_URL)
	rm -rf $(BLDDIR)/flex-$(HOST_FLEX_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/flex-$(HOST_FLEX_VER).tar.gz
	cd $(BLDDIR)/flex-$(HOST_FLEX_VER) && \
	    ./configure --prefix="$(HOST_TOOLS_ROOT)" && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install

$(HOST_WL_SCANNER_PC):
	@echo "[host-wayland-scanner] Generating pkg-config shim..."
	@mkdir -p $(dir $@)
	@WL_SCANNER_VER=$$(pkg-config --modversion wayland-scanner); \
	printf '%s\n' \
	    'wayland_scanner=wayland-scanner' \
	    '' \
	    'Name: wayland-scanner' \
	    'Description: Host wayland-scanner shim for Meson native dependency lookup' \
	    "Version: $$WL_SCANNER_VER" \
	    'Libs:' \
	    'Cflags:' > $@

$(SYSROOT_USR_WL_PROTOCOLS): | $(SYSROOT)/include
	@echo "[sysroot] Linking /usr/share/wayland-protocols compatibility path..."
	@mkdir -p $(dir $@)
	@ln -sfn ../../share/wayland-protocols $@

# Generate meson cross-file for musl target
$(MESON_CROSS): $(HOST_PY_STAMP) $(MUSL_CC) $(MUSL_CXX) $(CXXRT_STAMP) $(SELF)/Makefile | $(STAMPS)
	@echo "Generating meson cross-file..."
	@{ \
		printf '%s\n' '[binaries]'; \
		printf "c = '%s'\n" "$(CC)"; \
		printf "cpp = '%s'\n" "$(CXX)"; \
		printf "ar = '%s'\n" "$(AR)"; \
		printf "strip = '%s'\n" "$(STRIP)"; \
		printf "ranlib = '%s'\n" "$(RANLIB)"; \
		printf "nm = '%s'\n" "$(NM)"; \
		printf '%s\n' "pkg-config = 'pkg-config'"; \
		WS=$$(which wayland-scanner 2>/dev/null || echo ""); \
		if [ -n "$$WS" ]; then \
			printf "wayland_scanner = '%s'\n" "$$WS"; \
		fi; \
		printf '\n[built-in options]\n'; \
		printf "c_args = ['-O2', '-fPIC', '-I%s/include', '-I%s/include/freetype2', '-I%s/include/libpng16', '-I%s/include']\n" \
			"$(SYSROOT)" "$(SYSROOT)" "$(SYSROOT)" "$(MUSL_INSTALL)"; \
		printf "cpp_args = ['-O2', '-fPIC', '-I%s/include', '-I%s/include/freetype2', '-I%s/include/libpng16', '-I%s/include']\n" \
			"$(SYSROOT)" "$(SYSROOT)" "$(SYSROOT)" "$(MUSL_INSTALL)"; \
		printf "c_link_args = ['-no-pie', '-L%s/lib', '-L%s/lib']\n" \
			"$(SYSROOT)" "$(MUSL_INSTALL)"; \
		printf "cpp_link_args = ['-no-pie', '-L%s/lib', '-L%s/lib']\n" \
			"$(SYSROOT)" "$(MUSL_INSTALL)"; \
		printf '\n[properties]\n'; \
		printf "sys_root = '%s'\n" "$(SYSROOT)"; \
		printf '\n[host_machine]\n'; \
		printf '%s\n' "system = 'linux'"; \
		printf '%s\n' "cpu_family = 'x86_64'"; \
		printf '%s\n' "cpu = 'x86_64'"; \
		printf '%s\n' "endian = 'little'"; \
	} > $(MESON_CROSS)

MESON_SETUP = $(PKG_CONFIG_ENV) \
    meson setup \
    --cross-file=$(MESON_CROSS) \
    --prefix=$(SYSROOT) \
    --default-library=static \
    --buildtype=release \
    -Db_staticpic=true

# ── 1. wayland-protocols (XML files + headers only) ───────────────────────
$(STAMPS)/wl-proto.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[1/11] wayland-protocols $(WL_PROTO_VER)"
	test -f $(DLDIR)/wayland-protocols-$(WL_PROTO_VER).tar.xz || \
	    wget -q -O $(DLDIR)/wayland-protocols-$(WL_PROTO_VER).tar.xz $(WL_PROTO_URL)
	rm -rf $(BLDDIR)/wayland-protocols-$(WL_PROTO_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/wayland-protocols-$(WL_PROTO_VER).tar.xz
	cd $(BLDDIR)/wayland-protocols-$(WL_PROTO_VER) && \
	    $(MESON_SETUP) build \
	        -Dtests=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

wayland-protocols: $(STAMPS)/wl-proto.done

# ── 2. libdrm (DRM userspace — only POSIX/virtual driver, no GPU) ─────────
$(STAMPS)/libdrm.done: $(STAMPS)/wl-proto.done | $(MESON_CROSS)
	@echo "[2/11] libdrm $(LIBDRM_VER)"
	test -f $(DLDIR)/libdrm-$(LIBDRM_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libdrm-$(LIBDRM_VER).tar.xz $(LIBDRM_URL)
	cd $(BLDDIR) && tar xf $(DLDIR)/libdrm-$(LIBDRM_VER).tar.xz
	cd $(BLDDIR)/libdrm-$(LIBDRM_VER) && \
	    $(MESON_SETUP) build \
	        -Dintel=disabled \
	        -Damdgpu=disabled \
	        -Dradeon=disabled \
	        -Dnouveau=disabled \
	        -Dvmwgfx=disabled \
	        -Dfreedreno=disabled \
	        -Dvc4=disabled \
	        -Detnaviv=disabled \
	        -Dtests=false \
	        -Dman-pages=disabled && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

libdrm: $(STAMPS)/libdrm.done

# ── 3. libevdev (kernel input event reading library) ──────────────────────
$(STAMPS)/libevdev.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[3/11] libevdev $(LIBEVDEV_VER)"
	test -f $(DLDIR)/libevdev-$(LIBEVDEV_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libevdev-$(LIBEVDEV_VER).tar.xz $(LIBEVDEV_URL)
	cd $(BLDDIR) && tar xf $(DLDIR)/libevdev-$(LIBEVDEV_VER).tar.xz
	cd $(BLDDIR)/libevdev-$(LIBEVDEV_VER) && \
	    $(MESON_SETUP) build \
	        -Dtests=disabled \
	        -Ddocumentation=disabled && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

libevdev: $(STAMPS)/libevdev.done

# ── 4. libudev-zero (minimal libudev drop-in, no systemd) ────────────────
$(STAMPS)/libudev-zero.done: $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[4/11] libudev-zero $(UDEV0_VER)"
	test -f $(DLDIR)/libudev-zero-$(UDEV0_VER).tar.gz || \
	    wget -q -O $(DLDIR)/libudev-zero-$(UDEV0_VER).tar.gz $(UDEV0_URL)
	cd $(BLDDIR) && tar xf $(DLDIR)/libudev-zero-$(UDEV0_VER).tar.gz
	cd $(BLDDIR)/libudev-zero-$(UDEV0_VER) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) \
	        CC="$(CC)" \
	        CFLAGS="$(BASE_CFLAGS)" \
	        LDFLAGS="-static" \
	        PREFIX=$(SYSROOT) \
	        install
	@printf '%s\n' \
	    'prefix=$(SYSROOT)' \
	    'exec_prefix=$${prefix}' \
	    'libdir=$${exec_prefix}/lib' \
	    'includedir=$${prefix}/include' \
	    'udevdir=$${prefix}/lib/udev' \
	    '' \
	    'Name: udev' \
	    'Description: HanonymOS udev metadata shim for libudev-zero' \
	    'Version: 251' \
	    'Libs:' \
	    'Cflags:' > $(SYSROOT)/lib/pkgconfig/udev.pc
	rm -f $(SYSROOT)/lib/libudev.so $(SYSROOT)/lib/libudev.so.1
	touch $@

libudev-zero: $(STAMPS)/libudev-zero.done

# ── 5. mtdev (multitouch event translation library) ───────────────────────
$(STAMPS)/mtdev.done: | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[5/12] mtdev $(MTDEV_VER)"
	test -f $(DLDIR)/mtdev-$(MTDEV_VER).tar.gz || \
	    wget -q -O $(DLDIR)/mtdev-$(MTDEV_VER).tar.gz $(MTDEV_URL)
	rm -rf $(BLDDIR)/mtdev-$(MTDEV_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/mtdev-$(MTDEV_VER).tar.gz
	mkdir -p $(BLDDIR)/mtdev-$(MTDEV_VER)/_build
	cd $(BLDDIR)/mtdev-$(MTDEV_VER)/_build && \
	    ../configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

mtdev: $(STAMPS)/mtdev.done

# ── 6. libinput (input handling: evdev + seat) ────────────────────────────
$(STAMPS)/libinput.done: $(STAMPS)/libevdev.done $(STAMPS)/libudev-zero.done $(STAMPS)/mtdev.done $(SELF)/Makefile | $(MESON_CROSS)
	@echo "[6/12] libinput $(LIBINPUT_VER)"
	test -f $(DLDIR)/libinput-$(LIBINPUT_VER).tar.gz || \
	    wget -q -O $(DLDIR)/libinput-$(LIBINPUT_VER).tar.gz $(LIBINPUT_URL)
	rm -rf $(BLDDIR)/libinput-$(LIBINPUT_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libinput-$(LIBINPUT_VER).tar.gz
	sed -i "s/shared_library('input'/static_library('input'/" \
	    $(BLDDIR)/libinput-$(LIBINPUT_VER)/meson.build
	sed -i "/version : libinput_so_version,/d" \
	    $(BLDDIR)/libinput-$(LIBINPUT_VER)/meson.build
	sed -i "/link_args : version_flag,/d" \
	    $(BLDDIR)/libinput-$(LIBINPUT_VER)/meson.build
	sed -i "/link_depends : mapfile,/d" \
	    $(BLDDIR)/libinput-$(LIBINPUT_VER)/meson.build
	cd $(BLDDIR)/libinput-$(LIBINPUT_VER) && \
	    $(MESON_SETUP) build \
	        -Dlibwacom=false \
	        -Dtests=false \
	        -Dinstall-tests=false \
	        -Ddocumentation=false \
	        -Ddebug-gui=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

libinput: $(STAMPS)/libinput.done

# ── 6. libseat (seat management with built-in seatd — no daemon needed) ──
$(STAMPS)/libseat.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[6/11] libseat $(LIBSEAT_VER)"
	test -f $(DLDIR)/seatd-$(LIBSEAT_VER).tar.gz || \
	    wget -q -O $(DLDIR)/seatd-$(LIBSEAT_VER).tar.gz $(LIBSEAT_URL)
	cd $(BLDDIR) && tar xf $(DLDIR)/seatd-$(LIBSEAT_VER).tar.gz && \
	    mv seatd-$(LIBSEAT_VER) libseat-$(LIBSEAT_VER) 2>/dev/null || true
	cd $(BLDDIR)/libseat-$(LIBSEAT_VER) && \
	    $(MESON_SETUP) build \
	        -Dwerror=false \
	        -Dlibseat-builtin=enabled \
	        -Dlibseat-logind=disabled \
	        -Dserver=disabled \
	        -Dexamples=disabled \
	        -Dman-pages=disabled && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

libseat: $(STAMPS)/libseat.done

# ── 7. json-glib (GLib JSON library for Mutter) ───────────────────────────
$(STAMPS)/json-glib.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[7/11] json-glib $(JSONGLIB_VER)"
	test -f $(DLDIR)/json-glib-$(JSONGLIB_VER).tar.xz || \
	    wget -q -O $(DLDIR)/json-glib-$(JSONGLIB_VER).tar.xz $(JSONGLIB_URL)
	cd $(BLDDIR) && tar xf $(DLDIR)/json-glib-$(JSONGLIB_VER).tar.xz
	cd $(BLDDIR)/json-glib-$(JSONGLIB_VER) && \
	    $(MESON_SETUP) build \
	        -Dintrospection=disabled \
	        -Dtests=false \
	        -Dman=false \
	        -Dgtk_doc=disabled && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

json-glib: $(STAMPS)/json-glib.done

# ── 8. gsettings-desktop-schemas (schema XMLs only, no runtime code) ─────
$(STAMPS)/gsettings-schemas.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[8/11] gsettings-desktop-schemas $(GSET_SCHEMAS_VER)"
	test -f $(DLDIR)/gsettings-desktop-schemas-$(GSET_SCHEMAS_VER).tar.xz || \
	    wget -q -O $(DLDIR)/gsettings-desktop-schemas-$(GSET_SCHEMAS_VER).tar.xz $(GSET_URL)
	cd $(BLDDIR) && tar xf $(DLDIR)/gsettings-desktop-schemas-$(GSET_SCHEMAS_VER).tar.xz
	cd $(BLDDIR)/gsettings-desktop-schemas-$(GSET_SCHEMAS_VER) && \
	    $(MESON_SETUP) build \
	        -Dintrospection=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

gsettings-desktop-schemas: $(STAMPS)/gsettings-schemas.done

# ── 9. iso-codes (locale/country data for gnome-desktop) ─────────────────
$(STAMPS)/iso-codes.done: | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[9/12] iso-codes $(ISO_CODES_VER)"
	test -f $(DLDIR)/iso-codes-v$(ISO_CODES_VER).tar.gz || \
	    wget -q -O $(DLDIR)/iso-codes-v$(ISO_CODES_VER).tar.gz $(ISO_CODES_URL)
	rm -rf $(BLDDIR)/iso-codes-v$(ISO_CODES_VER)
	rm -rf $(SYSROOT)/share/iso-codes $(SYSROOT)/share/xml/iso-codes $(SYSROOT)/share/pkgconfig/iso-codes.pc
	find $(SYSROOT)/share/locale -path '*/LC_MESSAGES/iso_*' -delete 2>/dev/null || true
	cd $(BLDDIR) && tar xf $(DLDIR)/iso-codes-v$(ISO_CODES_VER).tar.gz
	cd $(BLDDIR)/iso-codes-v$(ISO_CODES_VER) && \
	    ./configure --prefix="$(SYSROOT)" && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

iso-codes: $(STAMPS)/iso-codes.done

# ── 10. xkeyboard-config (keyboard layout/rules data) ─────────────────────
$(STAMPS)/xkeyboard-config.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[10/13] xkeyboard-config $(XKB_CONFIG_VER)"
	test -f $(DLDIR)/xkeyboard-config-$(XKB_CONFIG_VER).tar.xz || \
	    wget -q -O $(DLDIR)/xkeyboard-config-$(XKB_CONFIG_VER).tar.xz $(XKB_CONFIG_URL)
	rm -rf $(BLDDIR)/xkeyboard-config-$(XKB_CONFIG_VER)
	rm -rf $(SYSROOT)/share/X11/xkb $(SYSROOT)/share/pkgconfig/xkeyboard-config.pc
	cd $(BLDDIR) && tar xf $(DLDIR)/xkeyboard-config-$(XKB_CONFIG_VER).tar.xz
	cd $(BLDDIR)/xkeyboard-config-$(XKB_CONFIG_VER) && \
	    $(MESON_SETUP) build \
	        -Dnls=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

xkeyboard-config: $(STAMPS)/xkeyboard-config.done

# ── 11. Mesa (EGL + softpipe software renderer — no LLVM) ────────────────
# softpipe is the CPU-based Gallium driver; requires no GPU and no LLVM.
$(STAMPS)/mesa.done: $(STAMPS)/libdrm.done $(STAMPS)/wl-proto.done $(HOST_FLEX) $(HOST_WL_SCANNER_PC) $(SYSROOT_USR_WL_PROTOCOLS) $(SELF)/Makefile | $(MESON_CROSS) cxxrt-ready
	@echo "[11/13] Mesa $(MESA_VER)"
	test -f $(DLDIR)/mesa-$(MESA_VER).tar.xz || \
	    wget -q -O $(DLDIR)/mesa-$(MESA_VER).tar.xz $(MESA_URL)
	rm -rf $(BLDDIR)/mesa-$(MESA_VER)
	rm -f $(SYSROOT)/lib/libEGL.so $(SYSROOT)/lib/libEGL.so.* \
	      $(SYSROOT)/lib/libGLESv2.so $(SYSROOT)/lib/libGLESv2.so.* \
	      $(SYSROOT)/lib/libgbm.so $(SYSROOT)/lib/libgbm.so.* \
	      $(SYSROOT)/lib/libglapi.so $(SYSROOT)/lib/libglapi.so.* \
	      $(SYSROOT)/lib/libOSMesa.so $(SYSROOT)/lib/libOSMesa.so.*
	cd $(BLDDIR) && tar xf $(DLDIR)/mesa-$(MESA_VER).tar.xz
	sed -i "s/libgbm = shared_library(/libgbm = static_library(/" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/gbm/meson.build
	sed -i "/version : '1.0.0',/d" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/gbm/meson.build
	sed -i "s/libglapi = shared_library(/libglapi = static_library(/" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/mapi/shared-glapi/meson.build
	sed -i "/soversion : /d;/version : '0.0.0',/d" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/mapi/shared-glapi/meson.build
	sed -i "s/libgles2 = shared_library(/libgles2 = static_library(/" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/mapi/es2api/meson.build
	sed -i "/vs_module_defs : gles2_def,/d;/soversion : /d;/version : '2.0.0',/d;/darwin_versions : '3.0.0',/d" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/mapi/es2api/meson.build
	sed -i "s/libegl = shared_library(/libegl = static_library(/" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/egl/meson.build
	sed -i "/vs_module_defs : egl_def/d;/version : egl_lib_version,/d;/soversion : egl_lib_soversion,/d" \
	    $(BLDDIR)/mesa-$(MESA_VER)/src/egl/meson.build
	cd $(BLDDIR)/mesa-$(MESA_VER) && \
	    $(MESON_SETUP) build \
	        -Dgallium-drivers=swrast,virgl \
	        -Dvulkan-drivers= \
	        -Dzstd=disabled \
	        -Dllvm=disabled \
	        -Dplatforms=wayland \
	        -Degl=enabled \
	        -Dgles1=disabled \
	        -Dgles2=enabled \
	        -Dglx=disabled \
	        -Dglvnd=false \
	        -Dosmesa=false \
	        -Dgbm=enabled \
	        -Dtools= \
	        -Dglx-direct=false \
	        -Dshared-glapi=enabled \
	        -Db_lto=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

mesa: $(STAMPS)/mesa.done

# ── 12. graphene (vector math types used by Cogl/Mutter) ──────────────────
$(STAMPS)/graphene.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[12/16] graphene $(GRAPHENE_VER)"
	test -f $(DLDIR)/graphene-$(GRAPHENE_VER).tar.xz || \
	    wget -q -O $(DLDIR)/graphene-$(GRAPHENE_VER).tar.xz $(GRAPHENE_URL)
	rm -rf $(BLDDIR)/graphene-$(GRAPHENE_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/graphene-$(GRAPHENE_VER).tar.xz
	cd $(BLDDIR)/graphene-$(GRAPHENE_VER) && \
	    $(MESON_SETUP) build \
	        -Dgobject_types=true \
	        -Dgtk_doc=false \
	        -Dintrospection=disabled \
	        -Dtests=false \
	        -Dinstalled_tests=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

graphene: $(STAMPS)/graphene.done

# ── 13. lcms2 (ICC color transforms used by Mutter color management) ──────
$(STAMPS)/lcms2.done: | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[13/16] lcms2 $(LCMS2_VER)"
	test -f $(DLDIR)/lcms2-$(LCMS2_VER).tar.gz || \
	    wget -q -O $(DLDIR)/lcms2-$(LCMS2_VER).tar.gz $(LCMS2_URL)
	rm -rf $(BLDDIR)/lcms2-$(LCMS2_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/lcms2-$(LCMS2_VER).tar.gz
	cd $(BLDDIR)/lcms2-$(LCMS2_VER) && \
	    ./configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

lcms2: $(STAMPS)/lcms2.done

# ── 14. libelogind shim (enough sd-login API for Mutter's native backend) ─
$(STAMPS)/libelogind-shim.done: $(SELF)/libelogind-shim.c $(SELF)/sd-login-shim.h | $(STAMPS) $(BLDDIR) $(SYSROOT)/lib $(SYSROOT)/include
	@echo "[14/16] libelogind shim"
	mkdir -p $(SYSROOT)/include/systemd $(SYSROOT)/lib/pkgconfig
	$(CC) $(BASE_CFLAGS) -I$(SELF) -c $(SELF)/libelogind-shim.c -o $(BLDDIR)/libelogind-shim.o
	$(AR) rcs $(SYSROOT)/lib/libelogind.a $(BLDDIR)/libelogind-shim.o
	$(RANLIB) $(SYSROOT)/lib/libelogind.a
	cp $(SELF)/sd-login-shim.h $(SYSROOT)/include/systemd/sd-login.h
	@printf '%s\n' \
	    'prefix=$(SYSROOT)' \
	    'exec_prefix=$${prefix}' \
	    'libdir=$${exec_prefix}/lib' \
	    'includedir=$${prefix}/include' \
	    '' \
	    'Name: libelogind' \
	    'Description: HanonymOS elogind compatibility shim for Mutter' \
	    'Version: 255.4-shim' \
	    'Libs: -L$${libdir} -lelogind' \
	    'Cflags: -I$${includedir}' > $(SYSROOT)/lib/pkgconfig/libelogind.pc
	touch $@

libelogind-shim: $(STAMPS)/libelogind-shim.done

# ── 15. libgudev (GObject wrapper over libudev for Mutter's native backend) ─
$(STAMPS)/libgudev.done: $(STAMPS)/libudev-zero.done | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[15/17] libgudev $(LIBGUDEV_VER)"
	test -f $(DLDIR)/libgudev-$(LIBGUDEV_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libgudev-$(LIBGUDEV_VER).tar.xz $(LIBGUDEV_URL)
	rm -rf $(BLDDIR)/libgudev-$(LIBGUDEV_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libgudev-$(LIBGUDEV_VER).tar.xz
	cd $(BLDDIR)/libgudev-$(LIBGUDEV_VER) && \
	    $(MESON_SETUP) build \
	        -Dtests=disabled \
	        -Dintrospection=disabled \
	        -Dvapi=disabled \
	        -Dgtk_doc=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

libgudev: $(STAMPS)/libgudev.done

# ── 16. X11 client stack for Mutter's always-on X11 code paths ───────────
$(STAMPS)/xorgproto.done: | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[xorgproto] Building $(XORGPROTO_VER)..."
	test -f $(DLDIR)/xorgproto-$(XORGPROTO_VER).tar.xz || \
	    wget -q -O $(DLDIR)/xorgproto-$(XORGPROTO_VER).tar.xz $(XORGPROTO_URL)
	rm -rf $(BLDDIR)/xorgproto-$(XORGPROTO_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/xorgproto-$(XORGPROTO_VER).tar.xz
	cd $(BLDDIR)/xorgproto-$(XORGPROTO_VER) && \
	    $(MESON_SETUP) build \
	        -Dlegacy=true && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

xorgproto: $(STAMPS)/xorgproto.done

$(STAMPS)/xtrans.done: $(STAMPS)/xorgproto.done | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[xtrans] Building $(XTRANS_VER)..."
	test -f $(DLDIR)/xtrans-$(XTRANS_VER).tar.xz || \
	    wget -q -O $(DLDIR)/xtrans-$(XTRANS_VER).tar.xz $(XTRANS_URL)
	rm -rf $(BLDDIR)/xtrans-$(XTRANS_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/xtrans-$(XTRANS_VER).tar.xz
	cd $(BLDDIR)/xtrans-$(XTRANS_VER) && \
	    ./configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

xtrans: $(STAMPS)/xtrans.done

$(STAMPS)/xcb-proto.done: $(STAMPS)/xorgproto.done | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[xcb-proto] Building $(XCBPROTO_VER)..."
	test -f $(DLDIR)/xcb-proto-$(XCBPROTO_VER).tar.xz || \
	    wget -q -O $(DLDIR)/xcb-proto-$(XCBPROTO_VER).tar.xz $(XCBPROTO_URL)
	rm -rf $(BLDDIR)/xcb-proto-$(XCBPROTO_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/xcb-proto-$(XCBPROTO_VER).tar.xz
	cd $(BLDDIR)/xcb-proto-$(XCBPROTO_VER) && \
	    PYTHON="$(HOST_PYTHON)" \
	    ./configure --prefix="$(SYSROOT)" && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

xcb-proto: $(STAMPS)/xcb-proto.done

$(STAMPS)/libpthread-stubs.done: $(STAMPS)/xorgproto.done | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libpthread-stubs] Building $(PTHREAD_STUBS_VER)..."
	test -f $(DLDIR)/libpthread-stubs-$(PTHREAD_STUBS_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libpthread-stubs-$(PTHREAD_STUBS_VER).tar.xz $(PTHREAD_STUBS_URL)
	rm -rf $(BLDDIR)/libpthread-stubs-$(PTHREAD_STUBS_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libpthread-stubs-$(PTHREAD_STUBS_VER).tar.xz
	cd $(BLDDIR)/libpthread-stubs-$(PTHREAD_STUBS_VER) && \
	    ./configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libpthread-stubs: $(STAMPS)/libpthread-stubs.done

$(STAMPS)/libxau.done: $(STAMPS)/xorgproto.done | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXau] Building $(LIBXAU_VER)..."
	test -f $(DLDIR)/libXau-$(LIBXAU_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXau-$(LIBXAU_VER).tar.xz $(LIBXAU_URL)
	rm -rf $(BLDDIR)/libXau-$(LIBXAU_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXau-$(LIBXAU_VER).tar.xz
	cd $(BLDDIR)/libXau-$(LIBXAU_VER) && \
	    ./configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxau: $(STAMPS)/libxau.done

$(STAMPS)/libxdmcp.done: $(STAMPS)/xorgproto.done | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXdmcp] Building $(LIBXDMCP_VER)..."
	test -f $(DLDIR)/libXdmcp-$(LIBXDMCP_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXdmcp-$(LIBXDMCP_VER).tar.xz $(LIBXDMCP_URL)
	rm -rf $(BLDDIR)/libXdmcp-$(LIBXDMCP_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXdmcp-$(LIBXDMCP_VER).tar.xz
	cd $(BLDDIR)/libXdmcp-$(LIBXDMCP_VER) && \
	    ./configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxdmcp: $(STAMPS)/libxdmcp.done

$(STAMPS)/libxcb.done: $(STAMPS)/xcb-proto.done $(STAMPS)/libpthread-stubs.done $(STAMPS)/libxau.done $(STAMPS)/libxdmcp.done | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libxcb] Building $(LIBXCB_VER)..."
	test -f $(DLDIR)/libxcb-$(LIBXCB_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libxcb-$(LIBXCB_VER).tar.xz $(LIBXCB_URL)
	rm -rf $(BLDDIR)/libxcb-$(LIBXCB_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libxcb-$(LIBXCB_VER).tar.xz
	cd $(BLDDIR)/libxcb-$(LIBXCB_VER) && \
	    PYTHON="$(HOST_PYTHON)" \
	    PYTHONPATH="$$(echo $(SYSROOT)/lib/python*/site-packages)" \
	    ./configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxcb: $(STAMPS)/libxcb.done

$(STAMPS)/libx11.done: $(STAMPS)/xtrans.done $(STAMPS)/libxcb.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libX11] Building $(LIBX11_VER)..."
	test -f $(DLDIR)/libX11-$(LIBX11_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libX11-$(LIBX11_VER).tar.xz $(LIBX11_URL)
	rm -rf $(BLDDIR)/libX11-$(LIBX11_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libX11-$(LIBX11_VER).tar.xz
	cd $(BLDDIR)/libX11-$(LIBX11_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libx11: $(STAMPS)/libx11.done

$(STAMPS)/libxext.done: $(STAMPS)/libx11.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXext] Building $(LIBXEXT_VER)..."
	test -f $(DLDIR)/libXext-$(LIBXEXT_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXext-$(LIBXEXT_VER).tar.xz $(LIBXEXT_URL)
	rm -rf $(BLDDIR)/libXext-$(LIBXEXT_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXext-$(LIBXEXT_VER).tar.xz
	cd $(BLDDIR)/libXext-$(LIBXEXT_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxext: $(STAMPS)/libxext.done

$(STAMPS)/libxfixes.done: $(STAMPS)/libxext.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXfixes] Building $(LIBXFIXES_VER)..."
	test -f $(DLDIR)/libXfixes-$(LIBXFIXES_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXfixes-$(LIBXFIXES_VER).tar.xz $(LIBXFIXES_URL)
	rm -rf $(BLDDIR)/libXfixes-$(LIBXFIXES_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXfixes-$(LIBXFIXES_VER).tar.xz
	cd $(BLDDIR)/libXfixes-$(LIBXFIXES_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxfixes: $(STAMPS)/libxfixes.done

$(STAMPS)/libxrender.done: $(STAMPS)/libx11.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXrender] Building $(LIBXRENDER_VER)..."
	test -f $(DLDIR)/libXrender-$(LIBXRENDER_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXrender-$(LIBXRENDER_VER).tar.xz $(LIBXRENDER_URL)
	rm -rf $(BLDDIR)/libXrender-$(LIBXRENDER_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXrender-$(LIBXRENDER_VER).tar.xz
	cd $(BLDDIR)/libXrender-$(LIBXRENDER_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxrender: $(STAMPS)/libxrender.done

$(STAMPS)/libxdamage.done: $(STAMPS)/libxfixes.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXdamage] Building $(LIBXDAMAGE_VER)..."
	test -f $(DLDIR)/libXdamage-$(LIBXDAMAGE_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXdamage-$(LIBXDAMAGE_VER).tar.xz $(LIBXDAMAGE_URL)
	rm -rf $(BLDDIR)/libXdamage-$(LIBXDAMAGE_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXdamage-$(LIBXDAMAGE_VER).tar.xz
	cd $(BLDDIR)/libXdamage-$(LIBXDAMAGE_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxdamage: $(STAMPS)/libxdamage.done

$(STAMPS)/libxcomposite.done: $(STAMPS)/libxdamage.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXcomposite] Building $(LIBXCOMPOSITE_VER)..."
	test -f $(DLDIR)/libXcomposite-$(LIBXCOMPOSITE_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXcomposite-$(LIBXCOMPOSITE_VER).tar.xz $(LIBXCOMPOSITE_URL)
	rm -rf $(BLDDIR)/libXcomposite-$(LIBXCOMPOSITE_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXcomposite-$(LIBXCOMPOSITE_VER).tar.xz
	cd $(BLDDIR)/libXcomposite-$(LIBXCOMPOSITE_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxcomposite: $(STAMPS)/libxcomposite.done

$(STAMPS)/libxrandr.done: $(STAMPS)/libxrender.done $(STAMPS)/libxext.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXrandr] Building $(LIBXRANDR_VER)..."
	test -f $(DLDIR)/libXrandr-$(LIBXRANDR_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXrandr-$(LIBXRANDR_VER).tar.xz $(LIBXRANDR_URL)
	rm -rf $(BLDDIR)/libXrandr-$(LIBXRANDR_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXrandr-$(LIBXRANDR_VER).tar.xz
	cd $(BLDDIR)/libXrandr-$(LIBXRANDR_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxrandr: $(STAMPS)/libxrandr.done

$(STAMPS)/libxinerama.done: $(STAMPS)/libxext.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXinerama] Building $(LIBXINERAMA_VER)..."
	test -f $(DLDIR)/libXinerama-$(LIBXINERAMA_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXinerama-$(LIBXINERAMA_VER).tar.xz $(LIBXINERAMA_URL)
	rm -rf $(BLDDIR)/libXinerama-$(LIBXINERAMA_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXinerama-$(LIBXINERAMA_VER).tar.xz
	cd $(BLDDIR)/libXinerama-$(LIBXINERAMA_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxinerama: $(STAMPS)/libxinerama.done

$(STAMPS)/libxi.done: $(STAMPS)/libxfixes.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXi] Building $(LIBXI_VER)..."
	test -f $(DLDIR)/libXi-$(LIBXI_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXi-$(LIBXI_VER).tar.xz $(LIBXI_URL)
	rm -rf $(BLDDIR)/libXi-$(LIBXI_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXi-$(LIBXI_VER).tar.xz
	cd $(BLDDIR)/libXi-$(LIBXI_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxi: $(STAMPS)/libxi.done

$(STAMPS)/libxtst.done: $(STAMPS)/libxi.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXtst] Building $(LIBXTST_VER)..."
	test -f $(DLDIR)/libXtst-$(LIBXTST_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXtst-$(LIBXTST_VER).tar.xz $(LIBXTST_URL)
	rm -rf $(BLDDIR)/libXtst-$(LIBXTST_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXtst-$(LIBXTST_VER).tar.xz
	cd $(BLDDIR)/libXtst-$(LIBXTST_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxtst: $(STAMPS)/libxtst.done

$(STAMPS)/libxcursor.done: $(STAMPS)/libxrender.done $(STAMPS)/libxfixes.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libXcursor] Building $(LIBXCURSOR_VER)..."
	test -f $(DLDIR)/libXcursor-$(LIBXCURSOR_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libXcursor-$(LIBXCURSOR_VER).tar.xz $(LIBXCURSOR_URL)
	rm -rf $(BLDDIR)/libXcursor-$(LIBXCURSOR_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libXcursor-$(LIBXCURSOR_VER).tar.xz
	cd $(BLDDIR)/libXcursor-$(LIBXCURSOR_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxcursor: $(STAMPS)/libxcursor.done

$(STAMPS)/libxkbfile.done: $(STAMPS)/libx11.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR)
	@echo "[libxkbfile] Building $(LIBXKBFILE_VER)..."
	test -f $(DLDIR)/libxkbfile-$(LIBXKBFILE_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libxkbfile-$(LIBXKBFILE_VER).tar.xz $(LIBXKBFILE_URL)
	rm -rf $(BLDDIR)/libxkbfile-$(LIBXKBFILE_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libxkbfile-$(LIBXKBFILE_VER).tar.xz
	cd $(BLDDIR)/libxkbfile-$(LIBXKBFILE_VER) && \
	    ./configure $(XORG_CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libxkbfile: $(STAMPS)/libxkbfile.done

$(STAMPS)/xkbcommon-x11.done: $(STAMPS)/libxcb.done $(STAMPS)/libx11.done $(STAMPS)/xkeyboard-config.done | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[xkbcommon-x11] Rebuilding libxkbcommon $(XKBCOMMON_VER) with X11 support..."
	test -f $(DLDIR)/libxkbcommon-$(XKBCOMMON_VER).tar.xz || \
	    wget -q -O $(DLDIR)/libxkbcommon-$(XKBCOMMON_VER).tar.xz $(XKBCOMMON_URL)
	rm -rf $(BLDDIR)/libxkbcommon-$(XKBCOMMON_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/libxkbcommon-$(XKBCOMMON_VER).tar.xz
	perl -0pi -e "s/libxkbcommon_test_internal = static_library\\(/if false\\nlibxkbcommon_test_internal = static_library(/; s/\\nconfigure_file\\(output: 'config.h'/\\nendif\\n\\nconfigure_file(output: 'config.h'/" \
	    $(BLDDIR)/libxkbcommon-$(XKBCOMMON_VER)/meson.build
	cd $(BLDDIR)/libxkbcommon-$(XKBCOMMON_VER) && \
	    PATH="$(HOST_TOOLS_BIN):$$PATH" \
	    $(MESON_SETUP) build \
	        -Denable-docs=false \
	        -Denable-tools=false \
	        -Denable-wayland=false \
	        -Denable-x11=true \
	        -Denable-xkbregistry=false && \
	    PATH="$(HOST_TOOLS_BIN):$$PATH" $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

xkbcommon-x11: $(STAMPS)/xkbcommon-x11.done

# ── 16. Cairo refresh (enable Xlib/XCB backends in shared sysroot) ───────
$(STAMPS)/cairo-xlib.done: $(STAMPS)/libx11.done $(STAMPS)/libxcb.done $(STAMPS)/libxrender.done $(STAMPS)/libxext.done $(SELF)/Makefile | $(STAMPS) $(DLDIR) $(BLDDIR) $(MESON_CROSS)
	@echo "[cairo-xlib] Rebuilding Cairo $(CAIRO_VER) with Xlib/XCB enabled..."
	test -f $(DLDIR)/cairo-$(CAIRO_VER).tar.xz || \
	    wget -q -O $(DLDIR)/cairo-$(CAIRO_VER).tar.xz $(CAIRO_URL)
	rm -rf $(BLDDIR)/cairo-$(CAIRO_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/cairo-$(CAIRO_VER).tar.xz
	sed -i "/subdir('util')/d" \
	    $(BLDDIR)/cairo-$(CAIRO_VER)/meson.build
	sed -i "/cairo-xlib-xcb-surface\\.c/d" \
	    $(BLDDIR)/cairo-$(CAIRO_VER)/src/meson.build
	perl -0pi -e 's/#if !HAVE_XRENDERCREATELINEARGRADIENT\n#define XRenderCreateLinearGradient[^\n]*\n\ntypedef struct _XLinearGradient \{.*?\n\} XLinearGradient;\n#endif/#if !HAVE_XRENDERCREATELINEARGRADIENT\n#define XRenderCreateLinearGradient\t\t\t_int_consume\n#endif/s; s/#if !HAVE_XRENDERCREATERADIALGRADIENT\n#define XRenderCreateRadialGradient[^\n]*\n\ntypedef struct _XCircle \{.*?\n\} XRadialGradient;\n#endif/#if !HAVE_XRENDERCREATERADIALGRADIENT\n#define XRenderCreateRadialGradient\t\t\t_int_consume\n#endif/s; s/#if !HAVE_XRENDERCREATECONICALGRADIENT\n#define XRenderCreateConicalGradient[^\n]*\n\ntypedef struct _XConicalGradient \{.*?\n\} XConicalGradient;\n#endif/#if !HAVE_XRENDERCREATECONICALGRADIENT\n#define XRenderCreateConicalGradient\t\t\t_int_consume\n#endif/s' \
	    $(BLDDIR)/cairo-$(CAIRO_VER)/src/cairo-xlib-xrender-private.h
	cd $(BLDDIR)/cairo-$(CAIRO_VER) && \
	    $(MESON_SETUP) build \
	        -Dxlib=enabled \
	        -Dxcb=disabled \
	        -Dxlib-xcb=disabled \
	        -Dquartz=disabled \
	        -Dfontconfig=enabled \
	        -Dfreetype=enabled \
	        -Dpng=enabled \
	        -Dzlib=enabled \
	        -Dtests=disabled \
	        -Dgtk_doc=false \
	        -Dgtk2-utils=disabled \
	        -Dspectre=disabled \
	        -Dsymbol-lookup=disabled && \
	    PATH="$(HOST_TOOLS_BIN):$$PATH" $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

cairo-xlib: $(STAMPS)/cairo-xlib.done

# ── 17. gnome-desktop (background + window management helpers) ───────────
$(STAMPS)/gnome-desktop.done: $(STAMPS)/gsettings-schemas.done $(STAMPS)/iso-codes.done $(STAMPS)/xkeyboard-config.done $(SELF)/Makefile | $(MESON_CROSS)
	@echo "[17/18] gnome-desktop $(GNOME_DESK_VER)"
	test -f $(DLDIR)/gnome-desktop-$(GNOME_DESK_VER).tar.xz || \
	    wget -q -O $(DLDIR)/gnome-desktop-$(GNOME_DESK_VER).tar.xz $(GNOME_DESK_URL)
	rm -rf $(BLDDIR)/gnome-desktop-$(GNOME_DESK_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/gnome-desktop-$(GNOME_DESK_VER).tar.xz
	sed -i "s/dependency('libseccomp')/dependency('libseccomp', required: false)/" \
	    $(BLDDIR)/gnome-desktop-$(GNOME_DESK_VER)/meson.build
	perl -0pi -e "s/subdir\\('tests'\\)/if get_option('installed_tests')\\n  subdir('tests')\\nendif/" \
	    $(BLDDIR)/gnome-desktop-$(GNOME_DESK_VER)/meson.build
	perl -0pi -e "s/\\n  foreach program: test_programs/\\n  if get_option('debug_tools')\\n    foreach program: test_programs/" \
	    $(BLDDIR)/gnome-desktop-$(GNOME_DESK_VER)/libgnome-desktop/meson.build
	perl -0pi -e "s/\\n  endforeach\\nendif/\\n    endforeach\\n  endif\\nendif/" \
	    $(BLDDIR)/gnome-desktop-$(GNOME_DESK_VER)/libgnome-desktop/meson.build
	cd $(BLDDIR)/gnome-desktop-$(GNOME_DESK_VER) && \
	    $(MESON_SETUP) build \
	        -Ddesktop_docs=false \
	        -Ddebug_tools=false \
	        -Dgtk_doc=false \
	        -Dintrospection=false \
	        -Dsystemd=disabled \
	        -Dudev=disabled \
	        -Dbuild_gtk4=false \
	        -Dinstalled_tests=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

gnome-desktop: $(STAMPS)/gnome-desktop.done

# ── 18. Mutter 44 (KMS native backend, Wayland compositor) ───────────────
# Built for the native Wayland path without Xwayland, remote desktop,
# profiler, introspection, or test suites. Mutter 44.9 still expects its
# built-in X11 client/backend code to exist even when Xwayland is off, so the
# local patch set keeps the normal X11 source graph, swaps the colord-backed
# color manager for a no-op implementation, strips the unused dbus-1 lookup,
# disables the optional gnome-desktop-4 dependency, and skips the GTK4-based
# frames helper.
$(STAMPS)/mutter.done: \
	        $(STAMPS)/libdrm.done \
	        $(STAMPS)/libinput.done \
	        $(STAMPS)/libseat.done \
	        $(STAMPS)/json-glib.done \
	        $(STAMPS)/cairo-xlib.done \
	        $(STAMPS)/mesa.done \
	        $(STAMPS)/graphene.done \
	        $(STAMPS)/lcms2.done \
	        $(STAMPS)/xkbcommon-x11.done \
	        $(STAMPS)/libxcomposite.done \
	        $(STAMPS)/libxdamage.done \
	        $(STAMPS)/libxcursor.done \
	        $(STAMPS)/libxinerama.done \
	        $(STAMPS)/libxrandr.done \
	        $(STAMPS)/libxtst.done \
	        $(STAMPS)/libxkbfile.done \
	        $(STAMPS)/libelogind-shim.done \
	        $(STAMPS)/libgudev.done \
	        $(STAMPS)/gnome-desktop.done \
	        $(SELF)/Makefile | $(MESON_CROSS)
	@echo "[18/18] mutter $(MUTTER_VER)"
	test -f $(DLDIR)/mutter-$(MUTTER_VER).tar.xz || \
	    wget -q -O $(DLDIR)/mutter-$(MUTTER_VER).tar.xz $(MUTTER_URL)
	rm -rf $(BLDDIR)/mutter-$(MUTTER_VER)
	cd $(BLDDIR) && tar xf $(DLDIR)/mutter-$(MUTTER_VER).tar.xz
	sed -i "/dbus_dep = dependency('dbus-1')/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/meson.build
	sed -i "/ice_dep = dependency('ice')/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/meson.build
	sed -i "/colord_dep = dependency('colord', version: colord_req)/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/meson.build
	sed -i "/gtk4_dep = dependency('gtk4', version: gtk4_req)/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/meson.build
	sed -i "s/xau_dep = dependency('xau')/xau_dep = dependency('xau')\\n  xdmcp_dep = dependency('xdmcp')/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/meson.build
	sed -i "/colord_dep,/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/ice_dep,/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "s/    xau_dep,/    xau_dep,\\n    xdmcp_dep,/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	perl -0pi -e "s/dependencies: \\[\\n      x11_dep,\\n      xcomposite_dep,\\n    \\],/dependencies: [\\n      x11_dep,\\n      x11_xcb_dep,\\n      xau_dep,\\n      xdmcp_dep,\\n      xcomposite_dep,\\n    ],/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/backends\\/meta-color-device\\.c/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/backends\\/meta-color-profile\\.c/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/backends\\/meta-color-store\\.c/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/backends\\/x11\\/meta-color-manager-x11\\.[ch]/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	cp $(SELF)/meta-color-manager-stub.c \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/backends/meta-color-manager.c
	sed -i "s|#include \"backends/x11/meta-color-manager-x11.h\"|#include \"backends/meta-color-manager.h\"|" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/backends/x11/meta-backend-x11.c
	sed -i "s/META_TYPE_COLOR_MANAGER_X11/META_TYPE_COLOR_MANAGER/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/backends/x11/meta-backend-x11.c
	sed -i "s/libmutter_cogl = shared_library/libmutter_cogl = static_library/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/cogl/cogl/meson.build
	sed -i "/version: '0.0.0',/d;/soversion: 0,/d;/install_rpath: pkglibdir,/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/cogl/cogl/meson.build
	sed -i "s/libmutter_cogl_pango = shared_library/libmutter_cogl_pango = static_library/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/cogl/cogl-pango/meson.build
	sed -i "/version: '0.0.0',/d;/soversion: 0,/d;/install_rpath: pkglibdir,/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/cogl/cogl-pango/meson.build
	sed -i "s/libmutter_clutter = shared_library/libmutter_clutter = static_library/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/clutter/clutter/meson.build
	sed -i "/version: '0.0.0',/d;/soversion: 0,/d;/install_rpath: pkglibdir,/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/clutter/clutter/meson.build
	sed -i "s/libmutter = shared_library/libmutter = static_library/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/version: '0.0.0',/d;/soversion: 0,/d;/install_rpath: pkglibdir,/d" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "s|#include <hb-glib.h>|#include <hb.h>|" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/clutter/clutter/clutter-main.c
	sed -i "s/hb_glib_script_to_script ((GUnicodeScript) scripts\\[i\\])/hb_script_from_iso15924_tag (g_unicode_script_to_iso15924 ((GUnicodeScript) scripts[i]))/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/clutter/clutter/clutter-main.c
	perl -0pi -e "s/\nif have_x11_client\n  subdir\\('frames'\\)\nendif/\n/" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/meson.build
	sed -i "/g_subprocess_wait_async/i\\  if (!x11_display->frames_client)\\n    return;\\n" \
	    $(BLDDIR)/mutter-$(MUTTER_VER)/src/x11/meta-x11-display.c
	cd $(BLDDIR)/mutter-$(MUTTER_VER) && \
	    $(MESON_SETUP) build \
	        -Dopengl=false \
	        -Dwayland=true \
	        -Dxwayland=false \
	        -Dglx=false \
	        -Dnative_backend=true \
	        -Dlibgnome_desktop=false \
	        -Dsystemd=false \
	        -Degl_device=false \
	        -Dwayland_eglstream=false \
	        -Dremote_desktop=false \
	        -Dsound_player=false \
	        -Dlibwacom=false \
	        -Dstartup_notification=false \
	        -Dsm=false \
	        -Dintrospection=false \
	        -Ddocs=false \
	        -Dprofiler=false \
	        -Dtests=false \
	        -Dcogl_tests=false \
	        -Dclutter_tests=false \
	        -Dcore_tests=false \
	        -Dnative_tests=false \
	        -Dkvm_tests=false \
	        -Dtty_tests=false \
	        -Dinstalled_tests=false \
	        -Db_lto=false && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS)
	touch $@

# ── Cleanup ───────────────────────────────────────────────────────────────
clean:
	rm -rf $(BLDDIR) $(SELF)/mutter

distclean: clean
	rm -rf $(DLDIR) $(STAMPS) $(MESON_CROSS)
