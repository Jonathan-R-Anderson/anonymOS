# deps/weston/Makefile — build the Linux device-stack libraries (libdrm,
# libevdev, libudev-zero, libinput, libdisplay-info, libseat) that weston
# needs, then build weston itself from the committed source tree.
#
# The anonymOS kernel implements the evdev (/dev/input/event*) and DRM/KMS
# (/dev/dri/card0) syscall UAPI in-kernel, so these are *real* libraries (not
# stubs) — they issue the real open()/ioctl()/read() calls that the kernel
# answers.  At link time they satisfy weston's symbols; at runtime they drive
# the kernel's device emulation.
#
# Modelled on deps/hyprland-hos/Makefile.deps (the libdisplay-info recipe there
# is the proven template for a meson cross-built static library).

# Resolve paths from the current working directory (make -C sets CURDIR
# reliably regardless of how this Makefile is invoked).
SELF          := $(CURDIR)
PROJECT_ROOT  := $(abspath $(SELF)/../..)
include $(PROJECT_ROOT)/build.opts

SYSROOT       := $(abspath $(SELF)/../gtk-stack/sysroot)
MUSL_INSTALL  := $(abspath $(SELF)/../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
DL_DIR        := $(SELF)/downloads
BUILD_DIR     := $(SELF)/build
STAMP_DIR     := $(SELF)/stamps
WESTON_SRC    := $(abspath $(SELF)/../weston-14.0.0)
CROSS_FILE    := $(abspath $(SELF)/../gtk-stack/stamps/meson-cross.ini)

# pkg-config environment (must match gtk-stack so the cross-file's sysroot
# .pc files are found, not the host's /usr ones).
PKG_CONFIG_ENV := \
	PKG_CONFIG_LIBDIR="$(SYSROOT)/lib/pkgconfig:$(SYSROOT)/share/pkgconfig" \
	PKG_CONFIG_PATH="" \
	PKG_CONFIG_SYSROOT_DIR=""

# Common meson setup flags for static cross-builds into the sysroot.
MESON_CROSS_FLAGS := \
	--cross-file=$(CROSS_FILE) \
	--prefix=$(SYSROOT) \
	--libdir=lib \
	--buildtype=release \
	--default-library=static

.PHONY: all clean distclean libdrm

all: $(STAMP_DIR)/weston-built

# gtk-stack's gtk3 links -ldrm, but libdrm is built HERE and deps/Makefile orders weston
# AFTER gtk-stack.  The headers and libdrm.pc are committed while libdrm.a is gitignored
# (.gitignore:22 "*.a"), so pkg-config happily advertises -ldrm and a fresh checkout only
# finds out 662 files into the gtk3 link: "/usr/bin/ld: cannot find -ldrm".  A machine
# that had built once already has the .a sitting in the shared sysroot and never sees it.
# Expose libdrm as its own target so deps/Makefile can build it BEFORE gtk-stack -- it
# depends on nothing but musl + the cross file, so this creates no cycle.
libdrm: $(STAMP_DIR)/libdrm-built

# ── Dependency order ──────────────────────────────────────────────────────────
# libdrm       (no deps)
# libevdev     (no deps)
# libudev-zero (no deps — it is its own device manager)
# libinput     → libudev + libevdev
# libdisplay-info (no deps)
# libseat      → libudev (embedded seatd backend)
# weston       → all of the above

$(STAMP_DIR)/libinput-built: $(STAMP_DIR)/libudev-built $(STAMP_DIR)/libevdev-built
$(STAMP_DIR)/libseat-built: $(STAMP_DIR)/libudev-built
$(STAMP_DIR)/weston-built: $(STAMP_DIR)/libdrm-built $(STAMP_DIR)/libevdev-built \
                           $(STAMP_DIR)/libudev-built $(STAMP_DIR)/libinput-built \
                           $(STAMP_DIR)/libdisplay-info-built $(STAMP_DIR)/libseat-built \
                           $(CROSS_FILE)

# Prerequisite: gtk-stack must be built (sysroot + cross-file exist).
$(CROSS_FILE):
	@echo "[weston] gtk-stack not built — run: make deps-desktop"
	@exit 1

$(MUSL_CC):
	@echo "[weston] musl not built — run: make deps-core"
	@exit 1

dirs:
	@mkdir -p $(DL_DIR) $(BUILD_DIR) $(STAMP_DIR)

# ════════════════════════════════════════════════════════════════════════════
# 1. libdrm 2.4.120
# ════════════════════════════════════════════════════════════════════════════
LIBDRM_VER := 2.4.120

$(DL_DIR)/libdrm-$(LIBDRM_VER).tar.xz: | dirs
	@echo "[weston] Downloading libdrm $(LIBDRM_VER)..."
	@curl -fsSL -o $@ https://dri.freedesktop.org/libdrm/libdrm-$(LIBDRM_VER).tar.xz

$(STAMP_DIR)/libdrm-built: $(DL_DIR)/libdrm-$(LIBDRM_VER).tar.xz $(MUSL_CC) $(CROSS_FILE)
	@echo "[weston] Building libdrm..."
	rm -rf $(BUILD_DIR)/libdrm-$(LIBDRM_VER)
	mkdir -p $(BUILD_DIR)/libdrm-$(LIBDRM_VER)
	tar -C $(BUILD_DIR)/libdrm-$(LIBDRM_VER) -xf $< --strip-components=1
	env $(PKG_CONFIG_ENV) meson setup $(BUILD_DIR)/libdrm-$(LIBDRM_VER)/_build $(BUILD_DIR)/libdrm-$(LIBDRM_VER) \
		$(MESON_CROSS_FLAGS) \
		-Dintel=disabled -Dradeon=disabled -Damdgpu=disabled \
		-Dnouveau=disabled -Dvmwgfx=disabled -Detnaviv=disabled \
		-Dtests=false
	ninja -C $(BUILD_DIR)/libdrm-$(LIBDRM_VER)/_build $(NINJA_BUILD_FLAGS) install
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# 2. libevdev 1.13.2
# ════════════════════════════════════════════════════════════════════════════
LIBEVDEV_VER := 1.13.2

$(DL_DIR)/libevdev-$(LIBEVDEV_VER).tar.xz: | dirs
	@echo "[weston] Downloading libevdev $(LIBEVDEV_VER)..."
	@curl -fsSL -o $@ https://www.freedesktop.org/software/libevdev/libevdev-$(LIBEVDEV_VER).tar.xz

$(STAMP_DIR)/libevdev-built: $(DL_DIR)/libevdev-$(LIBEVDEV_VER).tar.xz $(MUSL_CC) $(CROSS_FILE)
	@echo "[weston] Building libevdev..."
	rm -rf $(BUILD_DIR)/libevdev-$(LIBEVDEV_VER)
	mkdir -p $(BUILD_DIR)/libevdev-$(LIBEVDEV_VER)
	tar -C $(BUILD_DIR)/libevdev-$(LIBEVDEV_VER) -xf $< --strip-components=1
	env $(PKG_CONFIG_ENV) meson setup $(BUILD_DIR)/libevdev-$(LIBEVDEV_VER)/_build $(BUILD_DIR)/libevdev-$(LIBEVDEV_VER) \
		$(MESON_CROSS_FLAGS) \
		-Dtests=disabled -Ddocumentation=disabled
	ninja -C $(BUILD_DIR)/libevdev-$(LIBEVDEV_VER)/_build $(NINJA_BUILD_FLAGS) install
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# 3. libudev-zero 1.0.4
#    A tiny (~500 line) drop-in libudev replacement that works with any device
#    manager.  anonymOS provides /sys class dirs in-kernel, so libudev-zero
#    enumerates them and issues the real ioctls the kernel answers.
# ════════════════════════════════════════════════════════════════════════════
LIBUDEV_ZERO_VER := 1.0.4

$(DL_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER).tar.gz: | dirs
	@echo "[weston] Downloading libudev-zero $(LIBUDEV_ZERO_VER)..."
	@curl -fsSL -o $@ https://github.com/illiliti/libudev-zero/archive/refs/tags/$(LIBUDEV_ZERO_VER).tar.gz

$(STAMP_DIR)/libudev-built: $(DL_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER).tar.gz $(MUSL_CC) $(CROSS_FILE) $(SELF)/Makefile
	@echo "[weston] Building libudev-zero..."
	rm -rf $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER)
	mkdir -p $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER)
	tar -C $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER) -xf $< --strip-components=1
	# anonymOS fix: bound the property-list walk.
	# udev_list_entry_get_by_name() walks the list with a plain NULL-terminated loop,
	# so ONE corrupt/self-referential `next` pointer spins forever INSIDE Weston --
	# no syscall, no log line, no desktop.  libinput hits it on every input device:
	# it looks up LIBINPUT_CALIBRATION_MATRIX, a property that is normally ABSENT, so
	# the lookup always walks all the way to the end of the list.  Diagnosed by
	# sampling guest RIP over the QEMU monitor: CPL=3, pinned in a 4-instruction
	# loop on a node whose next == itself.  See docs/BOOT_DEBUG_LOG.md.
	# Bound the walk so an absent key fails closed (NULL = "not found", which is
	# exactly what libinput expects) instead of hanging the compositor forever.
	sed -i \
	    -e 's/^    if (!list_entry || !name) {$$/    unsigned long guard = 100000;\n    if (!list_entry || !name) {/' \
	    -e 's/^    while ((list_entry = list_entry->next));$$/    while ((list_entry = list_entry->next) \&\& --guard);/' \
	    $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER)/udev_list.c
	# Fail loudly if upstream text changes and the sed silently no-ops -- otherwise
	# the build would quietly reproduce the hang.
	@grep -q -- '--guard' $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER)/udev_list.c || \
	    { echo "[weston] ERROR: libudev-zero cycle-guard patch did not apply"; exit 1; }
	# libudev-zero uses a plain Makefile (not meson).  Cross-build the static
	# library with musl-clang, then install into the sysroot.
	cd $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER) && \
	    make CC=$(MUSL_CC) AR=$(shell command -v ar) \
	        PREFIX=$(SYSROOT) LIBDIR=$(SYSROOT)/lib INCLUDEDIR=$(SYSROOT)/include \
	        PKGCONFIGDIR=$(SYSROOT)/lib/pkgconfig SHAREDIR=$(SYSROOT)/share \
	        libudev.a libudev.pc
	# Install the static lib + headers + pkgconfig into the sysroot.
	cd $(BUILD_DIR)/libudev-zero-$(LIBUDEV_ZERO_VER) && \
	    cp libudev.a $(SYSROOT)/lib/libudev.a && \
	    cp udev.h $(SYSROOT)/include/libudev.h && \
	    cp libudev.pc $(SYSROOT)/lib/pkgconfig/libudev.pc
	# libudev.pc from libudev-zero declares itself as libudev; weston/hyprland
	# also look for udev.pc, so provide a symlink.
	ln -sf libudev.pc $(SYSROOT)/lib/pkgconfig/udev.pc
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# 4. libinput 1.29.2  (depends on libudev + libevdev)
# ════════════════════════════════════════════════════════════════════════════
LIBINPUT_VER := 1.29.2

$(DL_DIR)/libinput-$(LIBINPUT_VER).tar.gz: | dirs
	@echo "[weston] Downloading libinput $(LIBINPUT_VER)..."
	@curl -fsSL -o $@ https://gitlab.freedesktop.org/libinput/libinput/-/archive/$(LIBINPUT_VER)/libinput-$(LIBINPUT_VER).tar.gz

$(STAMP_DIR)/libinput-built: $(DL_DIR)/libinput-$(LIBINPUT_VER).tar.gz $(STAMP_DIR)/libudev-built $(STAMP_DIR)/libevdev-built $(CROSS_FILE)
	@echo "[weston] Building libinput..."
	rm -rf $(BUILD_DIR)/libinput-$(LIBINPUT_VER)
	mkdir -p $(BUILD_DIR)/libinput-$(LIBINPUT_VER)
	tar -C $(BUILD_DIR)/libinput-$(LIBINPUT_VER) -xzf $< --strip-components=1
	# libinput forces shared_library() in its meson.build (line ~445), which
	# ignores --default-library=static.  Patch it to static_library() and strip
	# the shared-only kwargs (version/link_args/link_depends) so weston links
	# libinput statically (the running OS has no /usr/lib to dlopen from).
	sed -i \
	    -e "s/lib_libinput = shared_library/lib_libinput = static_library/" \
	    -e "/version : libinput_so_version,/d" \
	    -e "/link_args : version_flag,/d" \
	    -e "/link_depends : mapfile,/d" \
	    $(BUILD_DIR)/libinput-$(LIBINPUT_VER)/meson.build
	env $(PKG_CONFIG_ENV) meson setup $(BUILD_DIR)/libinput-$(LIBINPUT_VER)/_build $(BUILD_DIR)/libinput-$(LIBINPUT_VER) \
		$(MESON_CROSS_FLAGS) \
		-Ddebug-gui=false -Dtests=false -Ddocumentation=false \
		-Dlibwacom=false -Dmtdev=false
	ninja -C $(BUILD_DIR)/libinput-$(LIBINPUT_VER)/_build $(NINJA_BUILD_FLAGS) install
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# 5. libdisplay-info 0.2.0
# ════════════════════════════════════════════════════════════════════════════
LIBDI_VER := 0.2.0

$(DL_DIR)/libdisplay-info-$(LIBDI_VER).tar.gz: | dirs
	@echo "[weston] Downloading libdisplay-info $(LIBDI_VER)..."
	@curl -fsSL -o $@ https://gitlab.freedesktop.org/emersion/libdisplay-info/-/archive/$(LIBDI_VER)/libdisplay-info-$(LIBDI_VER).tar.gz

$(STAMP_DIR)/libdisplay-info-built: $(DL_DIR)/libdisplay-info-$(LIBDI_VER).tar.gz $(MUSL_CC) $(CROSS_FILE)
	@echo "[weston] Building libdisplay-info..."
	rm -rf $(BUILD_DIR)/libdisplay-info-$(LIBDI_VER)
	mkdir -p $(BUILD_DIR)/libdisplay-info-$(LIBDI_VER)
	tar -C $(BUILD_DIR)/libdisplay-info-$(LIBDI_VER) -xzf $< --strip-components=1
	env $(PKG_CONFIG_ENV) meson setup $(BUILD_DIR)/libdisplay-info-$(LIBDI_VER)/_build $(BUILD_DIR)/libdisplay-info-$(LIBDI_VER) \
		$(MESON_CROSS_FLAGS)
	ninja -C $(BUILD_DIR)/libdisplay-info-$(LIBDI_VER)/_build $(NINJA_BUILD_FLAGS) install
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# 6. libseat 0.9.1  (depends on libudev; embedded seatd backend)
# ════════════════════════════════════════════════════════════════════════════
LIBSEAT_VER := 0.9.1

$(DL_DIR)/libseat-$(LIBSEAT_VER).tar.gz: | dirs
	@echo "[weston] Downloading libseat $(LIBSEAT_VER)..."
	@curl -fsSL -o $@ https://git.sr.ht/~kennylevinsen/seatd/archive/$(LIBSEAT_VER).tar.gz

$(STAMP_DIR)/libseat-built: $(DL_DIR)/libseat-$(LIBSEAT_VER).tar.gz $(STAMP_DIR)/libudev-built $(CROSS_FILE)
	@echo "[weston] Building libseat (seatd $(LIBSEAT_VER))..."
	rm -rf $(BUILD_DIR)/seatd-$(LIBSEAT_VER)
	mkdir -p $(BUILD_DIR)/seatd-$(LIBSEAT_VER)
	tar -C $(BUILD_DIR)/seatd-$(LIBSEAT_VER) -xf $< --strip-components=1
	env $(PKG_CONFIG_ENV) meson setup $(BUILD_DIR)/seatd-$(LIBSEAT_VER)/_build $(BUILD_DIR)/seatd-$(LIBSEAT_VER) \
		$(MESON_CROSS_FLAGS) \
		-Dlibseat-logind=disabled -Dlibseat-seatd=enabled -Dlibseat-builtin=enabled \
		-Dserver=disabled -Dexamples=disabled -Dman-pages=disabled -Dwerror=false
	ninja -C $(BUILD_DIR)/seatd-$(LIBSEAT_VER)/_build $(NINJA_BUILD_FLAGS) install
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# 7. weston 14.0.0  (depends on all six device-stack libraries)
#    Builds from the committed source tree at deps/weston-14.0.0/ into the
#    build-epin/ directory that the top-level Makefile's WESTON_BUILD points at.
#    Configuration: DRM backend, Pixman software renderer (no GL/EGL), desktop
#    shell, weston-terminal tool.  The sessionless-input patch in
#    libweston/libinput-seat.c ensures weston still comes up if libinput can't
#    enumerate devices (the kernel delivers input directly).
#    NOTE (renderer-gl): this block header has always said "no GL/EGL", but the flag
#    below said -Drenderer-gl=true, and that mismatch is what broke the build: the GL
#    renderer compiles gl-shader-config-color-transformation.c, whose glDeleteTextures/
#    glGenTextures/... references cannot be satisfied because the shared sysroot has no
#    usable GLESv2 (Mesa is not built into it).  Symptom: hundreds of "undefined
#    reference to `gl*`" at the very last link of the whole dependency chain.
#    The OS runs Pixman anyway -- the boot log says "Using Pixman renderer" and the DRM
#    backend reports no atomic modesetting and no GBM modifiers -- so GL was dead weight.
#    Flip this back to true only once libGLESv2/libEGL/libgbm really are installed into
#    deps/gtk-stack/sysroot (see roadmap R2 / VIRGL_BLOB_ROADMAP for that work).
# ════════════════════════════════════════════════════════════════════════════
$(STAMP_DIR)/weston-built: $(WESTON_SRC)/meson.build | $(STAMP_DIR)/libdrm-built $(STAMP_DIR)/libevdev-built $(STAMP_DIR)/libudev-built $(STAMP_DIR)/libinput-built $(STAMP_DIR)/libdisplay-info-built $(STAMP_DIR)/libseat-built
	@echo "[weston] Configuring weston (build-epin)..."
	rm -rf $(WESTON_SRC)/build-epin
	env $(PKG_CONFIG_ENV) meson setup $(WESTON_SRC)/build-epin $(WESTON_SRC) \
		--cross-file=$(CROSS_FILE) \
		--prefix=$(SYSROOT) \
		--libdir=lib \
		--buildtype=release \
		--default-library=shared \
		-Dbackend-drm=true \
		-Dbackend-drm-screencast-vaapi=false \
		-Dbackend-headless=true \
		-Dbackend-pipewire=false \
		-Dbackend-rdp=false \
		-Dbackend-vnc=false \
		-Dscreenshare=false \
		-Dbackend-wayland=false \
		-Dbackend-x11=false \
		-Dbackend-default=drm \
		-Drenderer-gl=false \
		-Dxwayland=false \
		-Dsystemd=false \
		-Dremoting=false \
		-Dpipewire=false \
		-Dshell-desktop=true \
		-Dshell-fullscreen=false \
		-Dshell-ivi=false \
		-Dshell-kiosk=false \
		-Dcolor-management-lcms=false \
		-Dimage-jpeg=false \
		-Dimage-webp=false \
		-Dtools=terminal \
		-Ddemo-clients=false \
		-Dsimple-clients=[] \
		-Dresize-pool=false \
		-Dwcap-decode=false \
		-Dtests=false \
		-Dtest-junit-xml=false \
		-Ddoc=false
	@echo "[weston] Building weston..."
	ninja -C $(WESTON_SRC)/build-epin $(NINJA_BUILD_FLAGS)
	@echo "[weston] Built: $(WESTON_SRC)/build-epin/frontend/weston"
	@touch $@

# ════════════════════════════════════════════════════════════════════════════
# Cleanup
# ════════════════════════════════════════════════════════════════════════════
clean:
	rm -rf $(BUILD_DIR) $(STAMP_DIR)

distclean: clean
	rm -rf $(DL_DIR) $(WESTON_SRC)/build-epin
