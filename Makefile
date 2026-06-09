# =========================================================
# Project Setup
# =========================================================

PROJECT_ROOT := $(CURDIR)
export PROJECT_ROOT

include build.opts

.PHONY: all clean progs-haskell deps-core deps-desktop deps-hyprland build-display-conf build-font-assets build-gui-assets
.NOTPARALLEL:

# =========================================================
# Main Build
# =========================================================

all:
	@echo "==== Build Start ===="

	$(MAKE) -j1 build/libkernel_d.a
	$(MAKE) -j1 kernel.elf
	$(MAKE) -j1 hos.iso

	@echo ""
	@echo "✅ Build complete!"

# =========================================================
# D Kernel
# =========================================================

build/libkernel_d.a:
	@echo "==== Building D Kernel ===="
	+$(MAKE) -j1 -C src/kernel/d

# =========================================================
# Kernel Link
# =========================================================

kernel.elf: \
	build/libkernel_d.a \
	src/kernel/d/linker.ld

	@echo "==== Linking Kernel ===="

	$(CROSSCOMPILE_LD) \
		-T src/kernel/d/linker.ld \
		--whole-archive build/libkernel_d.a \
		--no-whole-archive \
		-o kernel.elf

# =========================================================
# ISO Build
# =========================================================

BUSYBOX_BIN   := deps/busybox/busybox
TEST_DRM_BIN  := build/test-drm
COMPOSITOR_BIN := build/compositor
HELLO_GUI_BIN := build/hello-gui
WLPROBE_BIN   := build/wl-probe
WLSHM_DEMO_BIN := build/wl-shm-demo
WLTERM_BIN    := build/wl-term
WLCAIRO_DEMO_BIN := build/wl-cairo-demo
WLFILES_BIN := build/wl-files
WLDOMAINMGR_BIN := build/wl-domain-manager
IDLE_BIN := build/idle
DISPLAYINFO_BIN := build/display-info
GTK_HELLO_BIN := deps/gtk-stack/gtk-hello
HYPRLAND_BIN := deps/hyprland/Hyprland
# GW3: Weston (reference Wayland compositor + Pixman software renderer). When
# WESTON=1 and the binary is built, it is staged as a boot module named "weston"
# and the kernel selects it as init ahead of Hyprland. Set WESTON=0 to fall back
# to Hyprland for comparison.
WESTON       ?= 1
WESTON_BUILD := deps/weston-14.0.0/build-epin
WESTON_BIN   := $(WESTON_BUILD)/frontend/weston
XKB_SRC_DIR  := deps/gtk-stack/sysroot/share/X11/xkb
XKB_BLOB     := build/xkb.blob
ASSET_SRC_DIR := build/assets
ASSET_BLOB    := build/assets.blob
ASSET_BLOBS_DIR := build/asset-blobs
FONT_BLOB     := $(ASSET_BLOBS_DIR)/fonts.blob
ICON_BLOB     := $(ASSET_BLOBS_DIR)/icons.blob
CURSOR_BLOB   := $(ASSET_BLOBS_DIR)/cursors.blob
WALLPAPER_BLOB := $(ASSET_BLOBS_DIR)/wallpapers.blob
THEME_BLOB    := $(ASSET_BLOBS_DIR)/themes.blob
DISPLAY_CONF := build/display.conf
WAYLAND_SYSROOT := deps/gtk-stack/sysroot
WAYLAND_SCANNER ?= wayland-scanner
MUSL_CC := deps/musl/install/bin/musl-clang
XDG_SHELL_XML := $(WAYLAND_SYSROOT)/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml
XDG_SHELL_HEADER := build/xdg-shell-client-protocol.h
XDG_SHELL_CODE := build/xdg-shell-protocol.c
FONT_SRC_DIR ?= /usr/share/fonts/truetype/noto
FONT_LICENSE_FILE ?= /usr/share/doc/fonts-noto-core/copyright
DMZ_CURSOR_SRC_DIR ?= /usr/share/icons/DMZ-White
DMZ_CURSOR_LICENSE_FILE ?= /usr/share/doc/dmz-cursor-theme/copyright

DISPLAY_WIDTH ?= 1280
DISPLAY_HEIGHT ?= 800
DISPLAY_SCALE ?= 1
DISPLAY_REFRESH ?= 60
DISPLAY_FORCE_MODE ?= 0
GUI_AUTOSTART ?= cairo
GUI_LAUNCHER_DEMO ?= 0

FREESTANDING_CFLAGS := -static -nostdlib -nostartfiles -fno-stack-protector \
	-fno-pic -fno-pie -m64 -O2 -e _start

$(TEST_DRM_BIN): src/util/test-drm.c
	@echo "==== Building test-drm ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(COMPOSITOR_BIN): src/util/compositor.c
	@echo "==== Building compositor ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(HELLO_GUI_BIN): src/util/hello-gui.c
	@echo "==== Building hello-gui ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(WLPROBE_BIN): src/util/wl-probe.c
	@echo "==== Building wl-probe (GUI G1 client probe) ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(DISPLAYINFO_BIN): src/util/display-info.c
	@echo "==== Building display-info (GUI G7 display diagnostics) ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

build-display-conf:
	@echo "==== Generating display.conf (GUI G7 mode config) ===="
	mkdir -p $(dir $(DISPLAY_CONF))
	printf 'display.width=%s\n' "$(DISPLAY_WIDTH)" > $(DISPLAY_CONF)
	printf 'display.height=%s\n' "$(DISPLAY_HEIGHT)" >> $(DISPLAY_CONF)
	printf 'display.scale=%s\n' "$(DISPLAY_SCALE)" >> $(DISPLAY_CONF)
	printf 'display.refresh=%s\n' "$(DISPLAY_REFRESH)" >> $(DISPLAY_CONF)
	printf 'display.force_mode=%s\n' "$(DISPLAY_FORCE_MODE)" >> $(DISPLAY_CONF)
	printf 'gui.autostart=%s\n' "$(GUI_AUTOSTART)" >> $(DISPLAY_CONF)
	printf 'gui.launcher_demo=%s\n' "$(GUI_LAUNCHER_DEMO)" >> $(DISPLAY_CONF)

build-font-assets:
	@echo "==== Staging Noto fonts (GUI G9 text rendering) ===="
	@test -f "$(FONT_SRC_DIR)/NotoSans-Regular.ttf" || { echo "Missing $(FONT_SRC_DIR)/NotoSans-Regular.ttf"; exit 1; }
	@test -f "$(FONT_SRC_DIR)/NotoSans-Bold.ttf" || { echo "Missing $(FONT_SRC_DIR)/NotoSans-Bold.ttf"; exit 1; }
	@test -f "$(FONT_SRC_DIR)/NotoSansMono-Regular.ttf" || { echo "Missing $(FONT_SRC_DIR)/NotoSansMono-Regular.ttf"; exit 1; }
	@test -f "$(FONT_SRC_DIR)/NotoSansMono-Bold.ttf" || { echo "Missing $(FONT_SRC_DIR)/NotoSansMono-Bold.ttf"; exit 1; }
	rm -rf $(ASSET_SRC_DIR)/fonts/noto
	mkdir -p $(ASSET_SRC_DIR)/fonts/noto
	cp "$(FONT_SRC_DIR)/NotoSans-Regular.ttf" $(ASSET_SRC_DIR)/fonts/noto/
	cp "$(FONT_SRC_DIR)/NotoSans-Bold.ttf" $(ASSET_SRC_DIR)/fonts/noto/
	cp "$(FONT_SRC_DIR)/NotoSansMono-Regular.ttf" $(ASSET_SRC_DIR)/fonts/noto/
	cp "$(FONT_SRC_DIR)/NotoSansMono-Bold.ttf" $(ASSET_SRC_DIR)/fonts/noto/
	@if [ -f "$(FONT_LICENSE_FILE)" ]; then \
		cp "$(FONT_LICENSE_FILE)" $(ASSET_SRC_DIR)/fonts/noto/LICENSE.OFL-1.1.txt; \
	else \
		printf 'Noto fonts are distributed under the SIL Open Font License 1.1.\n' > $(ASSET_SRC_DIR)/fonts/noto/LICENSE.OFL-1.1.txt; \
	fi

build-gui-assets: build-font-assets
	@echo "==== Staging GUI image/icon/cursor/theme assets (GUI G10 pipeline) ===="
	python3 scripts/stage-gui-assets.py $(ASSET_SRC_DIR) \
		--cursor-src "$(DMZ_CURSOR_SRC_DIR)" \
		--cursor-license "$(DMZ_CURSOR_LICENSE_FILE)"

$(XDG_SHELL_HEADER): $(XDG_SHELL_XML)
	@echo "==== Generating xdg-shell client header ===="
	mkdir -p $(dir $@)
	$(WAYLAND_SCANNER) client-header $< $@

$(XDG_SHELL_CODE): $(XDG_SHELL_XML)
	@echo "==== Generating xdg-shell protocol code ===="
	mkdir -p $(dir $@)
	$(WAYLAND_SCANNER) private-code $< $@

$(WLSHM_DEMO_BIN): src/util/wl-shm-demo.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-shm-demo (GUI G2 client window) ===="
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -Ibuild \
		-o $@ src/util/wl-shm-demo.c $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libwayland-client.a \
		$(WAYLAND_SYSROOT)/lib/libffi.a \
		-pthread

$(WLTERM_BIN): src/util/wl-term.c src/util/gui_font.h $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-term (GUI G4/G9 antialiased terminal) ===="
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild -Isrc/util \
		-o $@ src/util/wl-term.c $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libwayland-client.a \
		$(WAYLAND_SYSROOT)/lib/libffi.a \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$(WAYLAND_SYSROOT)/lib/libbz2.a \
		$(WAYLAND_SYSROOT)/lib/libpng16.a \
		$(WAYLAND_SYSROOT)/lib/libz.a \
		-lm \
		-pthread

$(WLCAIRO_DEMO_BIN): src/util/wl-cairo-demo.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-cairo-demo (GUI G11 Cairo/FreeType toolkit demo) ===="
	@PANGOCAIRO_CFLAGS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --cflags pangocairo wayland-client)" ; \
	PANGOCAIRO_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs pangocairo wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -Ibuild $$PANGOCAIRO_CFLAGS \
		-o $@ src/util/wl-cairo-demo.c $(XDG_SHELL_CODE) \
		$$PANGOCAIRO_LIBS \
		-pthread

$(WLFILES_BIN): src/util/wl-files.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-files (GUI G17 file manager) ===="
	@CAIRO_CFLAGS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --cflags cairo wayland-client)" ; \
	CAIRO_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs cairo wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild $$CAIRO_CFLAGS \
		-o $@ src/util/wl-files.c $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$$CAIRO_LIBS \
		-lm \
		-pthread

$(IDLE_BIN): src/util/idle.c
	@echo "==== Building idle task (scheduler idle spinner) ===="
	$(MUSL_CC) -static -O2 -o $@ src/util/idle.c

$(WLDOMAINMGR_BIN): src/util/wl-domain-manager.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-domain-manager (IDENTITY_DOMAIN Qubes-style manager) ===="
	@CAIRO_CFLAGS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --cflags cairo wayland-client)" ; \
	CAIRO_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs cairo wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild $$CAIRO_CFLAGS \
		-o $@ src/util/wl-domain-manager.c $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$$CAIRO_LIBS \
		-lm \
		-pthread

hos.iso: kernel.elf $(BUSYBOX_BIN) $(TEST_DRM_BIN) $(COMPOSITOR_BIN) $(HELLO_GUI_BIN) $(WLPROBE_BIN) $(DISPLAYINFO_BIN) $(WLSHM_DEMO_BIN) $(WLTERM_BIN) $(WLCAIRO_DEMO_BIN) $(WLFILES_BIN) $(WLDOMAINMGR_BIN) $(IDLE_BIN) build-display-conf build-gui-assets $(wildcard $(HYPRLAND_BIN)) $(wildcard $(GTK_HELLO_BIN))
	@echo "==== Building ISO ===="

	rm -rf cd
	mkdir -p cd/boot/limine

	cp kernel.elf cd/boot/kernel.elf

	cp src/boot/limine.conf \
		cd/boot/limine/limine.conf
	sed -i \
		-e 's/^    resolution: .*/    resolution: $(DISPLAY_WIDTH)x$(DISPLAY_HEIGHT)x32/' \
		-e 's/^    cmdline: .*/    cmdline: display.width=$(DISPLAY_WIDTH) display.height=$(DISPLAY_HEIGHT) display.scale=$(DISPLAY_SCALE) display.refresh=$(DISPLAY_REFRESH) display.force_mode=$(DISPLAY_FORCE_MODE) gui.autostart=$(GUI_AUTOSTART)/' \
		cd/boot/limine/limine.conf

	cp src/boot/limine-bios.sys \
		src/boot/limine-bios-cd.bin \
		src/boot/limine-uefi-cd.bin \
		cd/boot/limine/

	@if [ -f $(BUSYBOX_BIN) ]; then \
		cp $(BUSYBOX_BIN) cd/busybox; \
		echo "Included busybox"; \
	else \
		echo "❌ busybox missing — run: make deps"; \
	fi

	cp $(TEST_DRM_BIN) cd/test-drm
	@echo "Included test-drm"

	cp $(COMPOSITOR_BIN) cd/compositor
	@echo "Included compositor"

	cp $(HELLO_GUI_BIN) cd/hello-gui
	@echo "Included hello-gui"

	cp $(WLPROBE_BIN) cd/wl-probe
	@echo "Included wl-probe (GUI G1)"

	cp $(DISPLAYINFO_BIN) cd/display-info
	@echo "Included display-info (GUI G7)"

	cp $(WLSHM_DEMO_BIN) cd/wl-shm-demo
	@echo "Included wl-shm-demo (GUI G2)"

	cp $(WLTERM_BIN) cd/wl-term
	@echo "Included wl-term (GUI G4)"

	cp $(IDLE_BIN) cd/idle
	@echo "Included idle task (scheduler idle spinner)"

	cp $(WLCAIRO_DEMO_BIN) cd/wl-cairo-demo
	printf '\n    module_path: boot():/wl-cairo-demo\n' >> cd/boot/limine/limine.conf
	@echo "Included wl-cairo-demo (GUI G11)"

	cp $(WLFILES_BIN) cd/wl-files
	printf '\n    module_path: boot():/wl-files\n' >> cd/boot/limine/limine.conf
	@echo "Included wl-files (GUI G17)"

	@if [ -f $(GTK_HELLO_BIN) ]; then \
		cp $(GTK_HELLO_BIN) cd/gtk-hello; \
		printf '\n    module_path: boot():/gtk-hello\n' >> cd/boot/limine/limine.conf; \
		echo "Included gtk-hello (GUI G11 toolkit demo)"; \
	else \
		echo "gtk-hello missing — run: make deps-desktop"; \
	fi

	cp $(BUSYBOX_BIN) cd/-sh
	@echo "Included -sh (busybox login shell for GUI G4 terminal)"

	cp $(DISPLAY_CONF) cd/display.conf
	@echo "Included display.conf + display-info (GUI G7)"

	@if [ -n "$(DYNTEST)" ] && [ -f src/test-dyn/dyntest ]; then \
		cp src/test-dyn/dyntest cd/dyntest; \
		cp src/test-dyn/libfoo.so cd/libfoo.so; \
		cp deps/musl/install/lib/libc.so cd/ld-musl-x86_64.so.1; \
		printf '\n    module_path: boot():/dyntest\n    module_path: boot():/libfoo.so\n    module_path: boot():/ld-musl-x86_64.so.1\n' >> cd/boot/limine/limine.conf; \
		echo "Included dynamic-linker test (make DYNTEST=1) — dyntest overrides init"; \
	fi

	@if [ -f $(HYPRLAND_BIN) ]; then \
		cp $(HYPRLAND_BIN) cd/Hyprland; \
		cp deps/musl/install/lib/libc.so cd/ld-musl-x86_64.so.1; \
		cp deps/gtk-stack/sysroot/lib/dri/kms_swrast_dri.so cd/kms_swrast_dri.so; \
		cp deps/gtk-stack/sysroot/lib/dri/kms_swrast_dri.so cd/swrast_dri.so; \
		printf '\n    module_path: boot():/Hyprland\n    module_path: boot():/ld-musl-x86_64.so.1\n    module_path: boot():/kms_swrast_dri.so\n    module_path: boot():/swrast_dri.so\n' >> cd/boot/limine/limine.conf; \
		echo "Included Hyprland (dynamic) + ld-musl + kms_swrast/swrast _dri.so"; \
		if [ ! -f $(XKB_BLOB) ] && [ -d $(XKB_SRC_DIR) ]; then \
			python3 scripts/pack-xkb.py $(XKB_SRC_DIR) $(XKB_BLOB); \
		fi; \
		if [ -f $(XKB_BLOB) ]; then \
			cp $(XKB_BLOB) cd/xkb.blob; \
			printf '\n    module_path: boot():/xkb.blob\n' >> cd/boot/limine/limine.conf; \
			echo "Included xkb.blob (xkeyboard-config data)"; \
		fi; \
		if [ -d $(ASSET_SRC_DIR) ]; then \
			rm -rf $(ASSET_BLOBS_DIR); \
			mkdir -p $(ASSET_BLOBS_DIR); \
			python3 scripts/pack-assets.py $(ASSET_SRC_DIR) $(ASSET_BLOB) usr/share --category-dir $(ASSET_BLOBS_DIR); \
			cp $(FONT_BLOB) cd/fonts.blob; \
			cp $(ICON_BLOB) cd/icons.blob; \
			cp $(CURSOR_BLOB) cd/cursors.blob; \
			cp $(WALLPAPER_BLOB) cd/wallpapers.blob; \
			cp $(THEME_BLOB) cd/themes.blob; \
			printf '\n    module_path: boot():/fonts.blob\n' >> cd/boot/limine/limine.conf; \
			printf '    module_path: boot():/icons.blob\n' >> cd/boot/limine/limine.conf; \
			printf '    module_path: boot():/cursors.blob\n' >> cd/boot/limine/limine.conf; \
			printf '    module_path: boot():/wallpapers.blob\n' >> cd/boot/limine/limine.conf; \
			printf '    module_path: boot():/themes.blob\n' >> cd/boot/limine/limine.conf; \
			echo "Included GUI asset category blobs (fonts/icons/cursors/wallpapers/themes)"; \
		fi; \
	else \
		echo "Hyprland not built — run: make deps-hyprland"; \
	fi

	@if [ "$(WESTON)" = "1" ] && [ -f $(WESTON_BIN) ]; then \
		cp $(WESTON_BIN) cd/weston; \
		cp deps/musl/install/lib/libc.so cd/ld-musl-x86_64.so.1; \
		cp $(WESTON_BUILD)/frontend/libexec_weston.so.0.0.0  cd/libexec_weston.so.0; \
		cp $(WESTON_BUILD)/libweston/libweston-14.so.0.0.0    cd/libweston-14.so.0; \
		cp $(WESTON_BUILD)/libweston/backend-drm/drm-backend.so cd/drm-backend.so; \
		cp $(WESTON_BUILD)/desktop-shell/desktop-shell.so       cd/desktop-shell.so; \
		cp $(WESTON_BUILD)/clients/weston-desktop-shell         cd/weston-desktop-shell; \
		cp $(WESTON_BUILD)/clients/weston-keyboard              cd/weston-keyboard; \
		cp $(WLDOMAINMGR_BIN)                                   cd/wl-domain-manager; \
		cp src/desktop.conf                                     cd/desktop.conf; \
		printf '\n    module_path: boot():/weston\n    module_path: boot():/ld-musl-x86_64.so.1\n    module_path: boot():/libexec_weston.so.0\n    module_path: boot():/libweston-14.so.0\n    module_path: boot():/drm-backend.so\n    module_path: boot():/desktop-shell.so\n    module_path: boot():/weston-desktop-shell\n    module_path: boot():/weston-keyboard\n    module_path: boot():/wl-domain-manager\n    module_path: boot():/desktop.conf\n' >> cd/boot/limine/limine.conf; \
		if [ -f $(WESTON_BUILD)/clients/weston-terminal ]; then \
			cp $(WESTON_BUILD)/clients/weston-terminal cd/weston-terminal; \
			printf '    module_path: boot():/weston-terminal\n' >> cd/boot/limine/limine.conf; \
			echo "Included Weston (GW3) + desktop-shell + terminal — overrides Hyprland as init"; \
		else \
			echo "Included Weston (GW3) + desktop-shell (no weston-terminal — build with -Dtools=terminal) — overrides Hyprland as init"; \
		fi; \
		if [ ! -f $(XKB_BLOB) ] && [ -d $(XKB_SRC_DIR) ]; then \
			python3 scripts/pack-xkb.py $(XKB_SRC_DIR) $(XKB_BLOB); \
		fi; \
		if [ -f $(XKB_BLOB) ] && ! grep -q 'boot():/xkb.blob' cd/boot/limine/limine.conf; then \
			cp $(XKB_BLOB) cd/xkb.blob; \
			printf '    module_path: boot():/xkb.blob\n' >> cd/boot/limine/limine.conf; \
		fi; \
	elif [ "$(WESTON)" = "1" ]; then \
		echo "Weston not built — run: make deps-weston (staying on Hyprland)"; \
	fi

	$(XORRISO) -as mkisofs \
		-b boot/limine/limine-bios-cd.bin \
		-no-emul-boot \
		-boot-load-size 4 \
		-boot-info-table \
		--efi-boot boot/limine/limine-uefi-cd.bin \
		-efi-boot-part \
		--efi-boot-image \
		--protective-msdos-label \
		cd \
		-o hos.iso

# =========================================================
# Legacy: Haskell userspace programs (optional, not part of main build)
# =========================================================

progs-haskell: \
	build/librts.a \
	build/prog-libs/hos-common-0.0.1.hl

	@echo "==== Building Haskell Userspace Programs ===="
	+$(MAKE) -j1 -C src/progs

deps-core:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps core

deps-desktop:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps desktop

deps-hyprland:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps hyprland

build/librts.a:
	@echo "==== Building JHC RTS ===="
	+$(MAKE) -j1 -C src/libs/rts

build/prog-libs/hos-common-0.0.1.hl:
	@echo "==== Building JHC Common Library ===="
	+$(MAKE) -j1 -C src/libs/common

# =========================================================
# Cleanup
# =========================================================

clean:
	@echo "==== Cleaning ===="

	rm -rf \
		build \
		cd \
		hos.iso \
		kernel.elf
