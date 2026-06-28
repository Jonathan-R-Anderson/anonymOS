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

# Host Qt (provides moc/rcc/uic/qmlcachegen + qtwaylandscanner for the cross build).
# NB: no inline comments on these — a trailing space leaks into the URL.
QT_VER        ?= 6.4.2
QT_BRANCH     := $(basename $(QT_VER))
# Self-contained host Qt we build natively (D1.1 two-stage).  Debian's /usr Qt ships
# moc/rcc/uic but NO qtwaylandscanner and NO private headers, and there is no sudo to
# install qt6-base-private-dev / qt6-wayland-dev — so the cross qtwayland build can't
# import Qt6::qtwaylandscanner from it.  We build our own coherent host prefix instead.
HOST_QT        := $(SELF)/host-qt
HOST_QT_PREFIX ?= $(HOST_QT)
HOST_QT_CMAKE  ?= $(HOST_QT)/lib/cmake
HOST_CC        ?= cc
HOST_CXX       ?= c++

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

.PHONY: all host-qt qtbase qtwayland clean
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
# Wipe BOTH the src AND the build dir: a Qt CMake build dir caches QT_HOST_PATH /
# QT_HOST_PATH_CMAKE_DIR etc., so reconfiguring a stale build dir with changed -D flags
# leaves a split host-path state (the host-toolchain switch hit exactly this).  A clean
# build dir guarantees the configure bakes a consistent host path.
define unpack
	@rm -rf $(BLDDIR)/$(1)-src $(BLDDIR)/$(1)-build; mkdir -p $(BLDDIR)/$(1)-src; \
	tar -xf $(DLDIR)/$(1)-everywhere-src-$(QT_VER).tar.xz \
	    -C $(BLDDIR)/$(1)-src --strip-components=1
endef

# ── host-qt (D1.1): native host qtbase + host qtwayland, self-contained ───────
# A coherent host Qt prefix so the cross qtwayland build can import the host
# Qt6::qtwaylandscanner tool (+ matching moc/rcc/uic, same 6.4.2 version).  Built
# natively with the system compiler (cc/c++), SHARED libs (host-only, never shipped).
# Minimal feature set: Core + Gui + the host tools are all qtwayland's scanner and
# its CMake export need; widgets/network/sql/printsupport/dbus are dropped for speed.
# xkbcommon is OFF too: Ubuntu's system xkbcommon-keysyms.h (1.6.0) predates the
# XKB_KEY_dead_* keysyms Qt 6.4.2 references, so qxkbcommon.cpp won't compile on the
# host — and a tool-only host Qt needs no keyboard support anyway (the cross build gets
# real xkbcommon from deps/gtk-stack/sysroot, 1.7.0, which has those keysyms).
host-qt: $(STAMPS)/host-qt
$(STAMPS)/host-qt: $(SELF)/Makefile | dirs
	$(call fetch,qtbase)
	$(call fetch,qtwayland)
	# (1) host qtbase — provides the host tool-chain + Qt6 CMake package + private headers
	@rm -rf $(BLDDIR)/qtbase-host-src; mkdir -p $(BLDDIR)/qtbase-host-src; \
	  tar -xf $(DLDIR)/qtbase-everywhere-src-$(QT_VER).tar.xz \
	      -C $(BLDDIR)/qtbase-host-src --strip-components=1
	# CMAKE_FIND_PACKAGE_TARGETS_GLOBAL=ON: Qt 6.4.2 + CMake >= 3.28 otherwise dies promoting
	# Threads::Threads (found in a parent scope) to IMPORTED_GLOBAL from src/corelib — forbidden
	# across directory scopes.  This makes find_package create its targets global inline, so Qt's
	# manual (now-redundant) promotion is skipped.  The cross qtbase build dodges it via its
	# toolchain-file scoping; the native host build needs the flag.
	$(RUN) cmake -G Ninja -S $(BLDDIR)/qtbase-host-src -B $(BLDDIR)/qtbase-host-build \
	    -DCMAKE_INSTALL_PREFIX=$(HOST_QT) -DCMAKE_BUILD_TYPE=Release \
	    -DCMAKE_C_COMPILER=$(HOST_CC) -DCMAKE_CXX_COMPILER=$(HOST_CXX) \
	    -DCMAKE_FIND_PACKAGE_TARGETS_GLOBAL=ON \
	    -DBUILD_SHARED_LIBS=ON \
	    -DFEATURE_xcb=OFF -DFEATURE_dbus=OFF -DFEATURE_sql=OFF -DFEATURE_icu=OFF \
	    -DFEATURE_widgets=OFF -DFEATURE_printsupport=OFF -DFEATURE_network=OFF \
	    -DFEATURE_concurrent=OFF -DFEATURE_testlib=OFF -DFEATURE_xkbcommon=OFF \
	    -DINPUT_libmd4c=qt -DINPUT_libb2=qt \
	    -DQT_BUILD_EXAMPLES=OFF -DQT_BUILD_TESTS=OFF -DQT_BUILD_BENCHMARKS=OFF
	$(RUN) cmake --build $(BLDDIR)/qtbase-host-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/qtbase-host-build
	# (2) host qtwayland — builds & installs the host qtwaylandscanner tool + its CMake
	#     export (Qt6::qtwaylandscanner), which the cross qtwayland build imports.
	@rm -rf $(BLDDIR)/qtwayland-host-src; mkdir -p $(BLDDIR)/qtwayland-host-src; \
	  tar -xf $(DLDIR)/qtwayland-everywhere-src-$(QT_VER).tar.xz \
	      -C $(BLDDIR)/qtwayland-host-src --strip-components=1
	$(RUN) cmake -G Ninja -S $(BLDDIR)/qtwayland-host-src -B $(BLDDIR)/qtwayland-host-build \
	    -DCMAKE_INSTALL_PREFIX=$(HOST_QT) -DCMAKE_BUILD_TYPE=Release \
	    -DCMAKE_C_COMPILER=$(HOST_CC) -DCMAKE_CXX_COMPILER=$(HOST_CXX) \
	    -DCMAKE_FIND_PACKAGE_TARGETS_GLOBAL=ON \
	    -DCMAKE_PREFIX_PATH=$(HOST_QT) \
	    -DFEATURE_wayland_server=OFF
	$(RUN) cmake --build $(BLDDIR)/qtwayland-host-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/qtwayland-host-build
	@touch $@

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
# D1.1 two-stage: the cross build needs the HOST tool `qtwaylandscanner` (imported as
# Qt6::qtwaylandscanner from QT_HOST_PATH) + the CROSS Qt private headers.  The private
# headers come from our from-source cross qtbase (sysroot); the host scanner comes from
# the self-contained `host-qt` prefix built above (HOST_QT_PREFIX points there).
qtwayland: $(STAMPS)/qtwayland
$(STAMPS)/qtwayland: $(STAMPS)/qtbase $(STAMPS)/host-qt
	$(call fetch,qtwayland)
	$(call unpack,qtwayland)
	$(RUN) $(call CMAKE_CROSS,qtwayland) -DFEATURE_wayland_server=OFF
	$(RUN) cmake --build $(BLDDIR)/qtwayland-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/qtwayland-build
	@touch $@

clean:
	rm -rf $(BLDDIR) $(STAMPS)
