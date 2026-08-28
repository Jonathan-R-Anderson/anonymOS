PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF         := $(abspath .)
MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
SRC          := $(SELF)/compat_app.c

# compat_app.c is NOT in the repo — but the stub binaries it produces are, committed
# next to each target below.  $(wildcard) turns the source into an OPTIONAL
# prerequisite so a checkout without it keeps the committed binaries instead of
# dying with "No rule to make target '.../compat_app.c'".  Commit compat_app.c and
# every stub is rebuilt from source again, exactly as before.
COMPAT_SRC   := $(wildcard $(SRC))

ELOGIND_OUT      := $(abspath ../elogind/elogind)
LOGIND_OUT       := $(abspath ../elogind/logind)
DBUS_OUT         := $(abspath ../dbus/dbus-daemon)
DCONF_OUT        := $(abspath ../dconf/dconf-service)
NETWORKMANAGER_OUT := $(abspath ../networkmanager/NetworkManager)
PIPEWIRE_OUT     := $(abspath ../pipewire/pipewire)
PIPEWIRE_PULSE_OUT := $(abspath ../pipewire/pipewire-pulse)
WIREPLUMBER_OUT  := $(abspath ../wireplumber/wireplumber)
GTK_HELLO_OUT    := $(abspath ../gtk-stack/gtk-hello)
GSD_OUT          := $(abspath ../gnome-settings-daemon/gnome-settings-daemon)
GCC_OUT          := $(abspath ../gnome-control-center/gnome-control-center)
MUTTER_OUT       := $(abspath ../mutter/mutter)
GNOME_SHELL_OUT  := $(abspath ../gnome-shell/gnome-shell)
GDM_OUT          := $(abspath ../gdm/gdm)

COMMON_CFLAGS := -O2 -static

# $(call compat_app,<app name>,<mode>[,<extra -D flags>]) — one stub, 14 identities.
# Modes: 0 = one-shot, 1 = resident service, 2 = forward to COMPAT_FORWARD_PATH.
define compat_app
	@mkdir -p $(dir $@)
	@if [ -n "$(COMPAT_SRC)" ]; then \
		echo "[compat] building $(@F) (mode $(2))"; \
		$(MUSL_CC) $(COMMON_CFLAGS) \
			-DCOMPAT_APP_NAME='"$(1)"' \
			-DCOMPAT_APP_MODE=$(2) \
			$(3) \
			$(SRC) -o $@; \
	elif [ -f $@ ]; then \
		echo "[compat] $(@F): keeping the committed stub (compat_app.c not in this checkout)"; \
		touch $@; \
	else \
		echo "[compat] $(@F): missing, and compat_app.c is not in this checkout" >&2; \
		exit 1; \
	fi
endef

.PHONY: all elogind logind dbus dconf networkmanager pipewire pipewire-pulse wireplumber gtk-hello gnome-settings-daemon gnome-control-center mutter gnome-shell gdm clean distclean

all: elogind logind dbus dconf networkmanager pipewire pipewire-pulse wireplumber gtk-hello gnome-settings-daemon gnome-control-center mutter gnome-shell gdm

elogind: $(ELOGIND_OUT)

logind: $(LOGIND_OUT)

dbus: $(DBUS_OUT)

dconf: $(DCONF_OUT)

networkmanager: $(NETWORKMANAGER_OUT)

pipewire: $(PIPEWIRE_OUT)

pipewire-pulse: $(PIPEWIRE_PULSE_OUT)

wireplumber: $(WIREPLUMBER_OUT)

gtk-hello: $(GTK_HELLO_OUT)

gnome-settings-daemon: $(GSD_OUT)

gnome-control-center: $(GCC_OUT)

mutter: $(MUTTER_OUT)

gnome-shell: $(GNOME_SHELL_OUT)

gdm: $(GDM_OUT)

$(ELOGIND_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,elogind,1)

$(LOGIND_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,logind,1)

$(DBUS_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,dbus-daemon,1)

$(DCONF_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,dconf-service,1)

$(NETWORKMANAGER_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,NetworkManager,1)

$(PIPEWIRE_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,pipewire,1)

$(PIPEWIRE_PULSE_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,pipewire-pulse,1)

$(WIREPLUMBER_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,wireplumber,1)

$(GTK_HELLO_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,gtk-hello,0)

$(GSD_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,gnome-settings-daemon,1)

$(GCC_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,gnome-control-center,0)

$(MUTTER_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,mutter,1)

$(GNOME_SHELL_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,gnome-shell,2,-DCOMPAT_FORWARD_PATH='"/sbin/mutter"')

$(GDM_OUT): $(COMPAT_SRC) $(MUSL_CC)
	$(call compat_app,gdm,2,-DCOMPAT_FORWARD_PATH='"/sbin/gnome-shell"')

# NOTE: without compat_app.c in the checkout these binaries are the only copy —
# `make clean` here deletes them and nothing can rebuild them (`git checkout deps`
# restores them).
clean:
	rm -f $(ELOGIND_OUT) $(LOGIND_OUT) $(DBUS_OUT) $(DCONF_OUT) $(NETWORKMANAGER_OUT) $(PIPEWIRE_OUT) $(PIPEWIRE_PULSE_OUT) $(WIREPLUMBER_OUT) $(GTK_HELLO_OUT) $(GSD_OUT) $(GCC_OUT) $(MUTTER_OUT) $(GNOME_SHELL_OUT) $(GDM_OUT)

distclean: clean
