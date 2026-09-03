PROJECT_ROOT ?= $(abspath ..)
include $(PROJECT_ROOT)/build.opts

.PHONY: all core desktop full musl libdrm cxxrt busybox openrc dbus dconf networkmanager elogind logind pipewire pipewire-pulse wireplumber gtk-stack staged-desktop mutter weston hyprland hyprland-sysroot-libs hyprland-status gnome-settings-daemon gnome-control-center gnome-shell gdm gnome clean distclean

CORE_DEPS := musl busybox openrc dbus dconf networkmanager elogind logind pipewire pipewire-pulse wireplumber
DESKTOP_DEPS := gtk-stack staged-desktop mutter weston

all: core

core: $(CORE_DEPS)

desktop: core $(DESKTOP_DEPS)

full: desktop

musl:
	$(MAKE) $(MAKE_BUILD_FLAGS) -C musl all

cxxrt: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C cxxrt all

busybox: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C busybox all

openrc: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C openrc all

dbus: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat dbus

dconf: dbus
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat dconf

networkmanager: dbus
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat networkmanager

elogind: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat elogind

logind: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat logind

pipewire: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat pipewire

pipewire-pulse: pipewire
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat pipewire-pulse

wireplumber: pipewire dbus
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat wireplumber

# libdrm physically lives in deps/weston, but gtk-stack LINKS against it, so it has to
# be built first.  See the note in deps/weston/Makefile: libdrm.a is gitignored while
# its .pc is committed, so without this a fresh checkout dies at "cannot find -ldrm".
libdrm: musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C weston libdrm

gtk-stack: cxxrt libdrm
	$(MAKE) $(MAKE_BUILD_FLAGS) -C gtk-stack all

staged-desktop: gtk-stack
	$(MAKE) $(MAKE_BUILD_FLAGS) -C staged-desktop all

# Weston needs the gtk-stack sysroot + cross-file (for meson), which requires
# gtk-stack to be built first.  deps/weston/Makefile builds the six device-stack
# libraries (libdrm/libevdev/libudev-zero/libinput/libdisplay-info/libseat)
# then weston itself into deps/weston-14.0.0/build-epin.
weston: gtk-stack
	$(MAKE) $(MAKE_BUILD_FLAGS) -C weston all

gnome-settings-daemon: dconf dbus
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat gnome-settings-daemon

gnome-control-center: gnome-settings-daemon gtk-stack
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat gnome-control-center

mutter: gtk-stack cxxrt musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C mutter all

# ── Hyprland sysroot prerequisites ───────────────────────────────────────────
# deps/mutter builds these archives into deps/gtk-stack/sysroot, but its stamps/*.done
# are COMMITTED to git while the .a files they certify are gitignored.  On a fresh
# checkout make therefore believes each one is already built while the archive is
# absent, and nothing notices until Hyprland's FINAL LINK -- ~45 minutes in -- fails
# with a wall of "no such file or directory: .../libX11.a".  That is one wasted build
# per missing library, discovered one at a time.
#
# Reconcile stamp against artifact here instead: if the archive is missing, drop the
# stale stamp and rebuild that target.  Costs 16 file tests when everything is present.
#
# Ordered <artifact under gtk-stack/sysroot>:<phony target in deps/mutter>.  Paths are
# not all archives: xtrans ships transport sources that libX11 #includes directly, and
# only its two .h files were ever committed -- so key it on one of the missing .c files.
# Order matters: a dependency is listed before what needs it, so one pass suffices.
HYPRLAND_SYSROOT_LIBS := \
	include/X11/Xtrans/transport.c:xtrans \
	lib/libXau.a:libxau              lib/libXdmcp.a:libxdmcp \
	lib/libxcb.a:libxcb              lib/libX11.a:libx11 \
	lib/libXext.a:libxext            lib/libXfixes.a:libxfixes \
	lib/libXrender.a:libxrender      lib/libXcursor.a:libxcursor \
	lib/libmtdev.a:mtdev             lib/liblcms2.a:lcms2 \
	lib/libevdev.a:libevdev          lib/libudev.a:libudev-zero \
	lib/libseat.a:libseat            lib/libinput.a:libinput \
	lib/libglapi.so:mesa

hyprland-sysroot-libs:
	@for pair in $(HYPRLAND_SYSROOT_LIBS); do \
		art=$${pair%%:*}; tgt=$${pair##*:}; \
		if [ ! -e gtk-stack/sysroot/$$art ]; then \
			echo "[deps] $$art absent -> mutter/stamps/$$tgt.done is stale; rebuilding '$$tgt'"; \
			rm -f mutter/stamps/$$tgt.done; \
			$(MAKE) $(MAKE_BUILD_FLAGS) -C mutter $$tgt || exit 1; \
		fi; \
	done

hyprland: gtk-stack cxxrt musl hyprland-sysroot-libs
	$(MAKE) $(MAKE_BUILD_FLAGS) -C hyprland-hos all

hyprland-status:
	$(MAKE) $(MAKE_BUILD_FLAGS) -C hyprland-hos status

gnome-shell: mutter
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat gnome-shell

gdm: gnome-shell logind
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat gdm

gnome:
	$(MAKE) $(MAKE_BUILD_FLAGS) -C gnome all

clean:
	$(MAKE) $(MAKE_BUILD_FLAGS) -C musl      clean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C cxxrt     clean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C busybox   clean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C openrc    clean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat    clean

distclean:
	$(MAKE) $(MAKE_BUILD_FLAGS) -C musl      distclean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C cxxrt     distclean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C busybox   distclean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C openrc    distclean
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat    distclean
