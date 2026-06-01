PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF         := $(abspath .)
MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
SRC          := $(SELF)/compat_app.c

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

$(ELOGIND_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"elogind"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(LOGIND_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"logind"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(DBUS_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"dbus-daemon"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(DCONF_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"dconf-service"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(NETWORKMANAGER_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"NetworkManager"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(PIPEWIRE_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"pipewire"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(PIPEWIRE_PULSE_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"pipewire-pulse"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(WIREPLUMBER_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"wireplumber"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(GTK_HELLO_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"gtk-hello"' \
		-DCOMPAT_APP_MODE=0 \
		$(SRC) -o $@

$(GSD_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"gnome-settings-daemon"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(GCC_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"gnome-control-center"' \
		-DCOMPAT_APP_MODE=0 \
		$(SRC) -o $@

$(MUTTER_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"mutter"' \
		-DCOMPAT_APP_MODE=1 \
		$(SRC) -o $@

$(GNOME_SHELL_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"gnome-shell"' \
		-DCOMPAT_APP_MODE=2 \
		-DCOMPAT_FORWARD_PATH='"/sbin/mutter"' \
		$(SRC) -o $@

$(GDM_OUT): $(SRC) $(MUSL_CC)
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(COMMON_CFLAGS) \
		-DCOMPAT_APP_NAME='"gdm"' \
		-DCOMPAT_APP_MODE=2 \
		-DCOMPAT_FORWARD_PATH='"/sbin/gnome-shell"' \
		$(SRC) -o $@

clean:
	rm -f $(ELOGIND_OUT) $(LOGIND_OUT) $(DBUS_OUT) $(DCONF_OUT) $(NETWORKMANAGER_OUT) $(PIPEWIRE_OUT) $(PIPEWIRE_PULSE_OUT) $(WIREPLUMBER_OUT) $(GTK_HELLO_OUT) $(GSD_OUT) $(GCC_OUT) $(MUTTER_OUT) $(GNOME_SHELL_OUT) $(GDM_OUT)

distclean: clean
