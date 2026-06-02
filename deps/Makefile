PROJECT_ROOT ?= $(abspath ..)
include $(PROJECT_ROOT)/build.opts

.PHONY: all core desktop full musl cxxrt busybox openrc dbus dconf networkmanager elogind logind pipewire pipewire-pulse wireplumber gtk-stack staged-desktop mutter hyprland hyprland-status gnome-settings-daemon gnome-control-center gnome-shell gdm gnome clean distclean

CORE_DEPS := musl busybox openrc dbus dconf networkmanager elogind logind pipewire pipewire-pulse wireplumber
DESKTOP_DEPS := gtk-stack staged-desktop mutter

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

gtk-stack: cxxrt
	$(MAKE) $(MAKE_BUILD_FLAGS) -C gtk-stack all

staged-desktop: gtk-stack
	$(MAKE) $(MAKE_BUILD_FLAGS) -C staged-desktop all

gnome-settings-daemon: dconf dbus
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat gnome-settings-daemon

gnome-control-center: gnome-settings-daemon gtk-stack
	$(MAKE) $(MAKE_BUILD_FLAGS) -C compat gnome-control-center

mutter: gtk-stack cxxrt musl
	$(MAKE) $(MAKE_BUILD_FLAGS) -C mutter all

hyprland: gtk-stack cxxrt musl
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
