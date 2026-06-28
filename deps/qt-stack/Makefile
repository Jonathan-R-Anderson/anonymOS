# ==========================================================================
# deps/qt-stack/Makefile
#
# Static Qt 6 cross-built against musl + libc++ (deps/cxxrt), for the in-OS
# Calamares installer (roadmap/INSTALLER.md §D1).  Mirrors deps/gtk-stack:
# musl-clang{,++}, -static -no-pie, output into sysroot/.
#
# Qt version is pinned to the HOST Qt (QT_HOST_PATH supplies moc/rcc/uic and
# MUST match the target version).  Debian here ships 6.4.2.
#
# Reuses deps/gtk-stack/sysroot for the shared prereqs (zlib, libpng, freetype,
# fontconfig, harfbuzz, pcre2, glib, wayland, wayland-protocols, xkbcommon).
#
# Targets:   qtbase  (foundation)  →  qtwayland (qwayland platform plugin)
# Output:    sysroot/  (static libs, headers, cmake configs)
# ==========================================================================
PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF          := $(abspath .)
MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CXX      := $(MUSL_INSTALL)/bin/musl-clang++
CXXRT_STAMP   := $(abspath ../cxxrt/stamps/libcxx.done)
GTK_SYSROOT   := $(abspath ../gtk-stack/sysroot)
SYSROOT       := $(SELF)/sysroot
STAMPS        := $(SELF)/stamps
DLDIR         := $(SELF)/downloads
BLDDIR        := $(SELF)/build
TOOLCHAIN     := $(SELF)/qt-cross.cmake

# Host Qt (provides moc/rcc/uic/qmlcachegen for the cross build).  Debian multiarch.
# NB: no inline comments on these — a trailing space leaks into the URL.
QT_VER        ?= 6.4.2
QT_BRANCH     := $(basename $(QT_VER))
HOST_QT_PREFIX ?= /usr
HOST_QT_CMAKE  ?= /usr/lib/x86_64-linux-gnu/cmake

QT_BASE_URL   := https://download.qt.io/archive/qt/$(QT_BRANCH)/$(QT_VER)/submodules

RUN := $(BUILD_RESOURCE_RUN)
export EPIN_ROOT := $(PROJECT_ROOT)

# CMake configure shorthand for a Qt submodule:
#   $(1)=module name (qtbase…)  builds build/$(1)-build, installs into SYSROOT.
CMAKE_CROSS = cmake -G Ninja -S $(BLDDIR)/$(1)-src -B $(BLDDIR)/$(1)-build \
    -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
    -DCMAKE_INSTALL_PREFIX=$(SYSROOT) \
    -DCMAKE_PREFIX_PATH="$(SYSROOT);$(GTK_SYSROOT)" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DQT_HOST_PATH=$(HOST_QT_PREFIX) \
    -DQT_HOST_PATH_CMAKE_DIR=$(HOST_QT_CMAKE)

.PHONY: all qtbase qtwayland clean
all: qtwayland

dirs:
	@mkdir -p $(SYSROOT) $(STAMPS) $(DLDIR) $(BLDDIR)

# ── download helper: $(1)=tarball basename (without ext) ─────────────────────
define fetch
	@mkdir -p $(DLDIR); \
	if [ ! -f $(DLDIR)/$(1)-everywhere-src-$(QT_VER).tar.xz ]; then \
	  echo "[qt-stack] fetching $(1) $(QT_VER)"; \
	  curl -fSL --retry 3 -o $(DLDIR)/$(1)-everywhere-src-$(QT_VER).tar.xz \
	     $(QT_BASE_URL)/$(1)-everywhere-src-$(QT_VER).tar.xz; \
	fi
endef
define unpack
	@rm -rf $(BLDDIR)/$(1)-src; mkdir -p $(BLDDIR)/$(1)-src; \
	tar -xf $(DLDIR)/$(1)-everywhere-src-$(QT_VER).tar.xz \
	    -C $(BLDDIR)/$(1)-src --strip-components=1
endef

# ── qtbase (Core/Gui/Widgets/Network, static, GLES2, Wayland-ready) ──────────
qtbase: $(STAMPS)/qtbase
$(STAMPS)/qtbase: $(MUSL_CXX) $(CXXRT_STAMP) $(TOOLCHAIN) $(SELF)/Makefile | dirs
	$(call fetch,qtbase)
	$(call unpack,qtbase)
	# Only DISABLE what we don't want; let Qt auto-detect the rest (forcing a feature ON
	# when its lib isn't found in the cross-sysroot is a hard configure error).  Bundled
	# md4c/b2/pcre2 cover gaps.  GLES2/EGL come from the gtk-stack Mesa sysroot if found.
	$(RUN) $(call CMAKE_CROSS,qtbase) \
	    -DQT_QPA_DEFAULT_PLATFORM=wayland \
	    -DFEATURE_xcb=OFF -DFEATURE_dbus=OFF -DFEATURE_sql=OFF -DFEATURE_icu=OFF \
	    -DFEATURE_testlib=OFF -DFEATURE_gtk3=OFF \
	    -DINPUT_opengl=no -DFEATURE_egl=OFF \
	    -DINPUT_libmd4c=qt -DINPUT_libb2=qt \
	    -DQT_BUILD_EXAMPLES=OFF -DQT_BUILD_TESTS=OFF -DQT_BUILD_BENCHMARKS=OFF
	$(RUN) cmake --build $(BLDDIR)/qtbase-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/qtbase-build
	@touch $@

# ── qtwayland (the qwayland platform plugin, static) ─────────────────────────
# PREREQUISITE (D1.1 two-stage): qtwayland's cross build needs the HOST tool
# `qtwaylandscanner` + Qt PRIVATE headers (Qt::CorePrivate).  Debian's qt6-base-dev does
# NOT ship private headers, and qt6-base-private-dev / qt6-wayland-dev aren't installed.
# So first build a HOST qtbase (native, with -DQT_FEATURE_private_tests / private headers)
# + host qtwayland tools, point HOST_QT_PREFIX at it, then this target works.  Until then
# qtwayland is blocked on the host toolchain, not on the cross recipe (qtbase proves that).
qtwayland: $(STAMPS)/qtwayland
$(STAMPS)/qtwayland: $(STAMPS)/qtbase
	$(call fetch,qtwayland)
	$(call unpack,qtwayland)
	$(RUN) $(call CMAKE_CROSS,qtwayland) -DFEATURE_wayland_server=OFF
	$(RUN) cmake --build $(BLDDIR)/qtwayland-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/qtwayland-build
	@touch $@

clean:
	rm -rf $(BLDDIR) $(STAMPS)
