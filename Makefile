# =========================================================
# Project Setup
# =========================================================

PROJECT_ROOT := $(CURDIR)
export PROJECT_ROOT

include build.opts

.PHONY: all clean iso zsh scp-client progs-haskell deps-core deps-desktop deps-weston deps-hyprland build-display-conf build-font-assets build-gui-assets build-zksync-wallet boot-integrity-contract anonymos-config anonymos-config-test build-config-manifest stage-iso-tree veracrypt-efi hos-install.iso

# ZSH_INTEGRATION_ROADMAP Z0: build real upstream zsh as a static musl binary
# (against a musl-built ncursesw with compiled-in terminal fallbacks).  This only
# *builds* zsh — it is NOT yet staged into the installer ISO (that is Z1).  `make zsh`.
zsh:
	$(MAKE) -C deps/zsh
.NOTPARALLEL:

# DECLARITIVE_MODEL_ROADMAP: the host-side declarative-config compiler
# (anonymos-config), written in D + Phobos (the project's DC ?= ldc2 toolchain,
# see build.opts).  This is a HOST tool, so it deliberately does NOT use the
# kernel's cross DFLAGS: it needs std.json/std.digest/std.file.  Builds the CLI
# (check|build|diff|switch|rollback|graph|schema) that lowers one JSON file into
# the existing src/kernel/d/core object model.  `make anonymos-config`.
anonymos-config:
	$(MAKE) -C anonymos-config
anonymos-config-test:
	$(MAKE) -C anonymos-config test

# =========================================================
# Main Build
# =========================================================

all:
	@echo "==== Build Start ===="

	# Build the host-side anonymos-config compiler (needed for the config manifest).
	$(MAKE) -j1 anonymos-config
	# Build dependencies: musl, busybox, gtk-stack (weston/gtk-hello), zsh, and
	# (if WESTON=1) the weston compositor + its device-stack libraries.
	$(MAKE) -j1 deps-desktop
	$(MAKE) -j1 zsh
	# Build the kernel + installer ISO.
	$(MAKE) -j1 build/libkernel_d.a
	$(MAKE) -j1 kernel.elf
	$(MAKE) -j1 iso

	@echo ""
	@echo "✅ Build complete!"

# =========================================================
# D Kernel
# =========================================================

build/libkernel_d.a:
	@echo "==== Building D Kernel ===="
	+$(MAKE) -j1 -C src/kernel/d

boot-integrity-contract:
	scripts/compile-contracts.sh

build-zksync-wallet:
	@echo "==== Packing zkSync wallet boot-integrity app ===="
	python3 scripts/pack-zksync-wallet.py \
		$(ZKSYNC_WALLET_STATIC) \
		$(ZKSYNC_WALLET_BLOB) \
		system/web/zksync-wallet \
		--contract $(BOOT_INTEGRITY_CONTRACT) \
		--abi $(BOOT_INTEGRITY_ABI) \
		--artifact $(BOOT_INTEGRITY_ARTIFACT)

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
BUSYBOX_DYN_BIN := deps/busybox/busybox-dyn   # dynamic-musl busybox (udhcpc for LKL-routed DHCP)
TEST_DRM_BIN  := build/test-drm
DRM_GPU_TEST_BIN := build/drm-gpu-test
DRM_GL_TEST_BIN  := build/drm-gl-test
COMPOSITOR_BIN := build/compositor
HELLO_GUI_BIN := build/hello-gui
WLPROBE_BIN   := build/wl-probe
WLSHM_DEMO_BIN := build/wl-shm-demo
WLTERM_BIN    := build/wl-term
WLCAIRO_DEMO_BIN := build/wl-cairo-demo
INSTALLER_BIN := build/wl-installer
WLFILES_BIN := build/wl-files
WLDOMAINMGR_BIN := build/wl-domain-manager
WLWIFIMENU_BIN := build/wl-wifi-menu
WLLOGVIEW_BIN := build/wl-logview
# GNOME-style top bar for the Hyprland desktop (wlr-layer-shell, unlike the Weston panel)
WLLAYERBAR_BIN := build/wl-layer-bar
# GNOME-style toolbar popovers + utility programs (native wl_shm clients)
WLOVERVIEW_BIN := build/wl-overview
WLCALENDAR_BIN := build/wl-calendar
WLQUICKSET_BIN := build/wl-quicksettings
WLCALC_BIN := build/wl-calc
WLCLOCKS_BIN := build/wl-clocks
WLIMGVIEW_BIN := build/wl-imgview
WLCHARS_BIN := build/wl-chars
WLSYSMON_BIN := build/wl-sysmon
WLEDITOR_BIN := build/wl-editor
WLSCREENSHOT_BIN := build/wl-screenshot
IDLE_BIN := build/idle
HOS_SH_BIN := build/hos-sh
HOS_WIFI_BIN := build/hos-wifi
NSHIM_SO := build/libnshim.so
NETTEST_BIN := build/hos-nettest
NETLAUNCH_BIN := build/hos-netlaunch
DBUSLAUNCH_BIN := build/hos-dbus-launch
DBUSTEST_BIN := build/hos-dbus-test
NMLAUNCH_BIN := build/hos-nm-launch
NMCLITEST_BIN := build/hos-nmcli-test
WPALAUNCH_BIN := build/hos-wpa-launch
WIFIAGENT_BIN := build/hos-wifi-agent
UDHCPCSCRIPT_BIN := build/hos-udhcpc-script   # udhcpc lease handler (ELF; forks busybox-dyn to set IP)
UDHCPCLAUNCH_BIN := build/hos-udhcpc-launch   # kernel-spawned launcher: execs busybox-dyn udhcpc (LKL DHCP)
SCPTEST_BIN      := build/hos-scp-test        # one-command scp/upload self-test (/scp-test)
HTTPUPLOAD_BIN   := build/hos-http-upload      # direct send/recv HTTP client (avoids musl stdio syscall bypass)
LOGUPLOAD_BIN := build/hos-log-upload
WIFITERM_BIN := build/hos-wifiterm
THREADTEST_BIN := build/hos-thread-test
STORE_APP_BIN := build/store-app
ZSH_BIN := deps/zsh/zsh           # Z1: real upstream zsh (built by deps/zsh/Makefile, Z0)
DISPLAYINFO_BIN := build/display-info
GTK_HELLO_BIN := deps/gtk-stack/gtk-hello
HYPRLAND_BIN := deps/hyprland/Hyprland
DECOY_IMAGE := deps/decoy-os/build/decoy.ext4
PREBOOT_EFI := deps/veracrypt/build/preboot.efi
STAGE2_EFI := deps/veracrypt/build/stage2.efi
# GW3: Weston (reference Wayland compositor + Pixman software renderer). When
# WESTON=1 and the binary is built, it is staged as a boot module named "weston"
# and the kernel selects it as init ahead of Hyprland. Set WESTON=0 to fall back
# to Hyprland for comparison.
WESTON       ?= 1
WESTON_BUILD ?= deps/weston-14.0.0/build-epin
WESTON_BIN   := $(WESTON_BUILD)/frontend/weston

# =========================================================
# Installer (Calamares) cross-build — roadmap/INSTALLER.md §D1–D3.
# OPT-IN: these are NOT part of the default build / installer ISO, so a normal build is
# unaffected.  Build the pieces explicitly:
#   make qt-stack       # §D1 static Qt 6 (qtbase + qtwayland)            [DONE]
#   make calamares-deps # §D3 Calamares C++ deps (yaml-cpp, …)           [yaml-cpp DONE]
#   make parted-stack   # §D2 partitioning backend (util-linux/libparted) [TODO]
#   make calamares      # §D3 the Calamares installer ELF                 [needs §D2]
#   make veracrypt      # §E1 stripped VeraCrypt crypto core (libvc_crypto) [crypto DONE, KAT PASS]
#   make decoy          # §G deterministic decoy activity generator engine    [engine DONE, tests PASS]
#   make decoy-os       # §H1 decoy Linux distro (Alpine, seeded fake history) [rootfs DONE]
# =========================================================
.PHONY: qt-stack parted-stack calamares-deps calamares veracrypt decoy decoy-os installer-deps
qt-stack:
	+$(MAKE) -C deps/qt-stack all
calamares-deps:
	+$(MAKE) -C deps/calamares yaml-cpp
parted-stack:
	+$(MAKE) -C deps/parted-stack all
calamares:
	+$(MAKE) -C deps/calamares calamares
veracrypt:
	+$(MAKE) -C deps/veracrypt test
	+$(MAKE) -C deps/veracrypt header-test
decoy:
	+$(MAKE) -C deps/decoy test
decoy-os:
	+$(MAKE) -C deps/decoy-os image verify
$(DECOY_IMAGE):
	+$(MAKE) -C deps/decoy-os image verify
veracrypt-efi:
	+$(MAKE) -C deps/veracrypt efi
installer-deps: qt-stack calamares-deps parted-stack calamares veracrypt
XKB_SRC_DIR  := deps/gtk-stack/sysroot/share/X11/xkb
XKB_BLOB     := build/xkb.blob
ZSHFNS_SRC   := deps/zsh/zsh-5.9
ZSHFNS_BLOB  := build/zshfns.blob
ZSHPLUG_SRC  := deps/zsh-plugins
ZSHPLUG_BLOB := build/zshplugins.blob
OMZ_BLOB     := build/omz.blob
ASSET_SRC_DIR := build/assets
ASSET_BLOB    := build/assets.blob
ASSET_BLOBS_DIR := build/asset-blobs
FONT_BLOB     := $(ASSET_BLOBS_DIR)/fonts.blob
ICON_BLOB     := $(ASSET_BLOBS_DIR)/icons.blob
CURSOR_BLOB   := $(ASSET_BLOBS_DIR)/cursors.blob
WALLPAPER_BLOB := $(ASSET_BLOBS_DIR)/wallpapers.blob
THEME_BLOB    := $(ASSET_BLOBS_DIR)/themes.blob
ZKSYNC_WALLET_STATIC := deps/zksync-wallet-vue/src/static/boot-integrity
ZKSYNC_WALLET_BLOB := build/zksync-wallet.blob
BOOT_INTEGRITY_CONTRACT := contracts/BootIntegrityRegistry.sol
BOOT_INTEGRITY_ABI := contracts/BootIntegrityRegistry.abi.json
BOOT_INTEGRITY_ARTIFACT := build/contracts/BootIntegrityRegistry.artifact.json
BOOT_INTEGRITY_MANIFEST := build/zksync-attestation.json
ZKSYNC_NETWORK ?= zksync-sepolia
ZKSYNC_CHAIN_ID ?= 300
ZKSYNC_RPC_URL ?= https://sepolia.era.zksync.dev
BOOT_INTEGRITY_CONTRACT_ADDRESS ?=
BOOT_INTEGRITY_DEPLOY_TX ?=
DISPLAY_CONF := build/display.conf
# DECLARITIVE_MODEL_ROADMAP §4: the verified declarative-config boot manifest.
# Generated from a default system.json by the host `anonymos-config emit-manifest`
# (a flat, parser-free, HMAC-signed TLV blob the kernel lowers at boot).  Set
# DECLARATIVE_CONFIG to override the source JSON; set DECLARATIVE_CONFIG=none to
# skip staging a manifest entirely (kernel falls through to hardcoded init).
DECLARATIVE_CONFIG ?= anonymos-config/examples/system.json
CONFIG_MANIFEST := build/manifest.blob
ANONYMOS_CONFIG_BIN := anonymos-config/build/anonymos-config
WAYLAND_SYSROOT := deps/gtk-stack/sysroot
WAYLAND_SCANNER ?= wayland-scanner
MUSL_CC := deps/musl/install/bin/musl-clang
OPENSSH_SCP_BIN ?=
OPENSSH_SSH_BIN ?=
DROPBEAR_SCP_BIN := deps/dropbear/install/bin/scp
DROPBEAR_SSH_BIN := deps/dropbear/install/bin/dbclient
SCP_CLIENT ?= 1
ifeq ($(SCP_CLIENT),1)
SCP_CLIENT_STAGE_DEPS := $(DROPBEAR_SCP_BIN) $(DROPBEAR_SSH_BIN)
else
SCP_CLIENT_STAGE_DEPS :=
endif

scp-client: $(DROPBEAR_SCP_BIN) $(DROPBEAR_SSH_BIN)

$(DROPBEAR_SCP_BIN) $(DROPBEAR_SSH_BIN): deps/dropbear/Makefile
	+$(MAKE) -C deps/dropbear all

# R0 — Rust->musl toolchain (the analogue of musl-clang for the Wayland clients; install via rustup
# + `rustup target add x86_64-unknown-linux-musl`).  Builds NON-PIE static-musl AnonymOS binaries.
RUSTC ?= $(HOME)/.cargo/bin/rustc
RUST_TARGET := x86_64-unknown-linux-musl
RUSTFLAGS_STATIC := --target $(RUST_TARGET) -C target-feature=+crt-static -C relocation-model=static -O
HELLO_WL_BIN := build/hello-wl
HOSTERM_BIN := build/hos-term
XDG_SHELL_XML := $(WAYLAND_SYSROOT)/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml
XDG_SHELL_HEADER := build/xdg-shell-client-protocol.h
XDG_SHELL_CODE := build/xdg-shell-protocol.c
# wlr-layer-shell: the standard bar/panel protocol Hyprland (wlroots) implements
LAYER_SHELL_XML := deps/hyprland/protocols/wlr-layer-shell-unstable-v1.xml
LAYER_SHELL_HEADER := build/wlr-layer-shell-unstable-v1-client-protocol.h
LAYER_SHELL_CODE := build/wlr-layer-shell-unstable-v1-protocol.c
# Font/cursor source paths: auto-detect across distros (Ubuntu keeps Noto under
# /usr/share/fonts/truetype/noto, Arch/Fedora under /usr/share/fonts/noto).
# Override with FONT_SRC_DIR=/path if your distro differs.
FONT_SRC_DIR ?= $(shell for d in /usr/share/fonts/truetype/noto /usr/share/fonts/noto /usr/local/share/fonts/noto; do [ -f "$$d/NotoSans-Regular.ttf" ] && echo "$$d" && break; done)
FONT_LICENSE_FILE ?= $(shell for f in /usr/share/doc/fonts-noto-core/copyright /usr/share/licenses/noto-fonts/LICENSE; do [ -f "$$f" ] && echo "$$f" && break; done)
DMZ_CURSOR_SRC_DIR ?= $(shell for d in /usr/share/icons/DMZ-White /usr/share/icons/Whiteglass; do [ -d "$$d" ] && echo "$$d" && break; done)
DMZ_CURSOR_LICENSE_FILE ?= $(shell for f in /usr/share/doc/dmz-cursor-theme/copyright /usr/share/licenses/dmz-cursor-theme/COPYING; do [ -f "$$f" ] && echo "$$f" && break; done)

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

$(DRM_GPU_TEST_BIN): src/util/drm-gpu-test.c
	@echo "==== Building drm-gpu-test (R2.4a userspace virgl render-node test) ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

# R2.4b: a dynamic-musl GLES2 program that renders through Mesa's virgl driver.
# Gated on the gtk-stack sysroot (libEGL.a etc.); skips cleanly if Mesa isn't built.
$(DRM_GL_TEST_BIN): src/util/drm-gl-test.c
	@if [ -f deps/gtk-stack/sysroot/lib/libEGL.a ]; then \
	  echo "==== Building drm-gl-test (R2.4b GLES2-via-virgl test) ===="; \
	  $(MUSL_CC) -O2 -Ideps/gtk-stack/sysroot/include -Ideps/gtk-stack/sysroot/include/libdrm -o $@ $< \
	    -Ldeps/gtk-stack/sysroot/lib -Wl,--start-group \
	      -lEGL -lGLESv2 -lgbm -lglapi -ldrm -lexpat -lz -lffi \
	      -lwayland-server -lwayland-client -lwayland-egl \
	    -Wl,--end-group -lpthread -lm; \
	else echo "drm-gl-test: skipped (gtk-stack sysroot not built)"; touch $@; fi

GL_WL_TEST_BIN := build/gl-wl-test
$(GL_WL_TEST_BIN): src/util/gl-wl-test.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@if [ -f deps/gtk-stack/sysroot/lib/libEGL.a ]; then \
	  echo "==== Building gl-wl-test (R3 EGL/GLES2 Wayland client) ===="; \
	  $(MUSL_CC) -O2 -Ideps/gtk-stack/sysroot/include -Ibuild -o $@ $< $(XDG_SHELL_CODE) \
	    -Ldeps/gtk-stack/sysroot/lib -Wl,--start-group \
	      -lEGL -lGLESv2 -lgbm -lglapi -ldrm -lexpat -lz -lffi \
	      -lwayland-server -lwayland-client -lwayland-egl \
	    -Wl,--end-group -lpthread -lm; \
	else echo "gl-wl-test: skipped (gtk-stack sysroot not built)"; touch $@; fi

# L2: the LKL embedder (Linux kernel as a library). Prebuilt out-of-tree against ~/lkl-build
# (see src/lkl/README.md); staged as a boot module only when present.
LKL_BOOT_BIN := $(HOME)/lkl-build/lkl-boot-musl
GL_TERM_BIN := build/gl-term
$(GL_TERM_BIN): src/util/gl-term.c src/util/gui_font.h $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@if [ -f deps/gtk-stack/sysroot/lib/libEGL.a ]; then \
	  echo "==== Building gl-term (R3 GLES2 Wayland terminal) ===="; \
	  $(MUSL_CC) -O2 -Ideps/gtk-stack/sysroot/include -Ideps/gtk-stack/sysroot/include/freetype2 -Ibuild -Isrc/util \
	    -o $@ src/util/gl-term.c $(XDG_SHELL_CODE) \
	    -Ldeps/gtk-stack/sysroot/lib -Wl,--start-group \
	      -lEGL -lGLESv2 -lgbm -lglapi -ldrm -lexpat -lz -lffi \
	      -lwayland-server -lwayland-client -lwayland-egl \
	      -lfreetype -lpng16 -lbz2 \
	    -Wl,--end-group -lpthread -lm; \
	else echo "gl-term: skipped (gtk-stack sysroot not built)"; touch $@; fi

$(COMPOSITOR_BIN): src/util/compositor.c
	@echo "==== Building compositor ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(HELLO_GUI_BIN): src/util/hello-gui.c
	@echo "==== Building hello-gui ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(WLPROBE_BIN): src/util/wl-probe.c
	@echo "==== Building wl-probe (GUI G1 client probe) ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(STORE_APP_BIN): src/util/store-app.c
	@echo "==== Building store-app (F4.2 persisted-object-store app image) ===="
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

# DECLARITIVE_MODEL_ROADMAP §4: lower the default declarative config into the
# HMAC-signed binary manifest the kernel applies at boot.  Built by the host
# `anonymos-config` compiler (D + Phobos); needs ldc2 on the host (brew install
# ldc on macOS, or `ldc` in the Docker build image).  Set DECLARATIVE_CONFIG=none
# to omit the manifest and fall back to hardcoded init.
build-config-manifest: $(ANONYMOS_CONFIG_BIN)
ifneq ($(DECLARATIVE_CONFIG),none)
	@echo "==== Generating manifest.blob from $(DECLARATIVE_CONFIG) (§4 config boot) ===="
	mkdir -p $(dir $(CONFIG_MANIFEST))
	$(ANONYMOS_CONFIG_BIN) emit-manifest -o $(CONFIG_MANIFEST) $(DECLARATIVE_CONFIG)
else
	@echo "==== DECLARATIVE_CONFIG=none — skipping manifest.blob (hardcoded init) ===="
endif

$(ANONYMOS_CONFIG_BIN):
	$(MAKE) -C anonymos-config

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
	@if [ -f deps/fonts/SymbolsNerdFontMono-Regular.ttf ]; then \
		cp deps/fonts/SymbolsNerdFontMono-Regular.ttf $(ASSET_SRC_DIR)/fonts/noto/SymbolsNerdFont.ttf; \
		echo "R5: staged SymbolsNerdFont (Nerd/powerline glyph fallback for gl-term)"; \
	fi
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

# wlr-layer-shell bindings (references xdg_popup, so the header follows xdg-shell's)
$(LAYER_SHELL_HEADER): $(LAYER_SHELL_XML) $(XDG_SHELL_HEADER)
	@echo "==== Generating wlr-layer-shell client header ===="
	mkdir -p $(dir $@)
	$(WAYLAND_SCANNER) client-header $< $@

$(LAYER_SHELL_CODE): $(LAYER_SHELL_XML)
	@echo "==== Generating wlr-layer-shell protocol code ===="
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

# INSTALLER D4.1: the live "Install EpinAnonymOS to Disk" desktop entry's launch target.
# Currently the §D4.5 placeholder stub (real Calamares drops in at the same /calamares path
# once §D1-D3 land).  Same Cairo/FreeType/Wayland build as wl-cairo-demo.
$(INSTALLER_BIN): src/util/wl-installer.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-installer (INSTALLER D4.1 'Install to Disk' entry; D4.5 stub) ===="
	@PANGOCAIRO_CFLAGS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --cflags pangocairo wayland-client)" ; \
	PANGOCAIRO_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs pangocairo wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -Ibuild $$PANGOCAIRO_CFLAGS \
		-o $@ src/util/wl-installer.c $(XDG_SHELL_CODE) \
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

$(HOS_WIFI_BIN): src/util/hos-wifi.c src/lkl/hos-net-proto.h
	@echo "==== Building hos-wifi (H1b native netlink client -> cap-gated LKL net provider) ===="
	$(MUSL_CC) -static -O2 -Isrc/lkl -o $@ src/util/hos-wifi.c

# H1b.3 LD_PRELOAD verification: interposer .so + dynamic target + static launcher
$(NSHIM_SO): src/util/libnshim.c src/lkl/hos-net-proto.h
	@echo "==== Building libnshim.so (H1b.3 transparent socket-family interposer) ===="
	$(MUSL_CC) -O2 -fPIC -shared -pthread -Isrc/lkl -o $@ src/util/libnshim.c

$(NETTEST_BIN): src/util/hos-nettest.c src/lkl/hos-net-proto.h
	@echo "==== Building hos-nettest (H1b.3 dynamic-musl LD_PRELOAD target) ===="
	$(MUSL_CC) -O2 -Isrc/lkl -o $@ src/util/hos-nettest.c

$(NETLAUNCH_BIN): src/util/hos-netlaunch.c src/lkl/hos-net-proto.h
	@echo "==== Building hos-netlaunch (H1b.3 static LD_PRELOAD launcher) ===="
	$(MUSL_CC) -static -O2 -Isrc/lkl -o $@ src/util/hos-netlaunch.c

$(DBUSLAUNCH_BIN): src/util/hos-dbus-launch.c
	@echo "==== Building hos-dbus-launch (M0 static launcher for the persistent system bus) ===="
	$(MUSL_CC) -static -O2 -o $@ src/util/hos-dbus-launch.c

$(DBUSTEST_BIN): src/util/hos-dbus-test.c
	@echo "==== Building hos-dbus-test (M0 static launcher: dbus-send GetId EXTERNAL-auth test) ===="
	$(MUSL_CC) -static -O2 -o $@ src/util/hos-dbus-test.c

$(NMLAUNCH_BIN): src/util/hos-nm-launch.c
	@echo "==== Building hos-nm-launch (M2b static launcher for the real NetworkManager daemon) ===="
	$(MUSL_CC) -static -O2 -o $@ src/util/hos-nm-launch.c

$(WPALAUNCH_BIN): src/util/hos-wpa-launch.c
	@echo "==== Building hos-wpa-launch (M5 static launcher for wpa_supplicant -u D-Bus mode) ===="
	$(MUSL_CC) -static -O2 -o $@ src/util/hos-wpa-launch.c

$(UDHCPCSCRIPT_BIN): src/util/hos-udhcpc-script.c
	@echo "==== Building hos-udhcpc-script (udhcpc lease handler -> busybox-dyn ifconfig/route on LKL) ===="
	$(MUSL_CC) -static -O2 -Wall -o $@ src/util/hos-udhcpc-script.c

$(UDHCPCLAUNCH_BIN): src/util/hos-udhcpc-launch.c
	@echo "==== Building hos-udhcpc-launch (kernel-spawned launcher for busybox-dyn udhcpc under the shim) ===="
	$(MUSL_CC) -static -O2 -Wall -o $@ src/util/hos-udhcpc-launch.c

$(SCPTEST_BIN): src/util/hos-scp-test.c
	@echo "==== Building hos-scp-test (one-command /scp-test upload self-test) ===="
	$(MUSL_CC) -static -O2 -Wall -o $@ src/util/hos-scp-test.c

$(HTTPUPLOAD_BIN): src/util/hos-http-upload.c
	@echo "==== Building hos-http-upload (dynamic direct-socket LKL HTTP client) ===="
	$(MUSL_CC) -O2 -Wall -o $@ src/util/hos-http-upload.c

$(WIFIAGENT_BIN): src/util/hos-wifi-agent.c
	@echo "==== Building hos-wifi-agent (M6 libdbus NM<->file bridge for the Wi-Fi menu) ===="
	$(MUSL_CC) -O2 -Wall -o $@ src/util/hos-wifi-agent.c \
		-I$(WAYLAND_SYSROOT)/include/dbus-1.0 -I$(WAYLAND_SYSROOT)/lib/dbus-1.0/include \
		$(WAYLAND_SYSROOT)/lib/libdbus-1.so -Wl,-rpath,/

$(NMCLITEST_BIN): src/util/hos-nmcli-test.c src/lkl/hos-net-proto.h
	@echo "==== Building hos-nmcli-test (M2b nmcli D-Bus probe) ===="
	$(MUSL_CC) -static -O2 -Isrc/lkl -o $@ src/util/hos-nmcli-test.c

$(LOGUPLOAD_BIN): src/util/hos-log-upload.c
	@echo "==== Building hos-log-upload (debug log snapshot + scp launcher) ===="
	$(MUSL_CC) -static -O2 -Wall -Wextra -o $@ src/util/hos-log-upload.c

$(WIFITERM_BIN): src/util/hos-wifiterm.c
	@echo "==== Building hos-wifiterm (TEMP lightweight terminal launcher) ===="
	$(MUSL_CC) -static -O2 -o $@ src/util/hos-wifiterm.c

$(THREADTEST_BIN): src/util/hos-thread-test.c
	@echo "==== Building hos-thread-test (diag: cross-thread wakeup) ===="
	$(MUSL_CC) -static -O2 -pthread -o $@ src/util/hos-thread-test.c

# Track B: the native EpinAnonymOS object shell (-sh / dash), written in D (-betterC,
# same language as the kernel) and linked against musl for crt0 + stdio. It drives the
# native object syscall ABI (HOS_SYS_QUERY) instead of the Linux-compat layer.
$(HOS_SH_BIN): src/util/hos-sh.d
	@echo "==== Building hos-sh (native object shell, D + musl) ===="
	ldc2 -betterC -O2 -release -boundscheck=off -c src/util/hos-sh.d -of=build/hos-sh.o
	$(MUSL_CC) -static -o $@ build/hos-sh.o

# R0 — hello-wl: a "hello, Wayland" client in Rust, static-musl, validating the Rust toolchain.
$(HELLO_WL_BIN): src/util/hello-wl.rs
	@echo "==== Building hello-wl (R0: Rust->musl static AnonymOS Wayland client) ===="
	$(RUSTC) --edition 2021 $(RUSTFLAGS_STATIC) $< -o $@

$(HOSTERM_BIN): src/util/hos-term.rs src/util/term_font8x8.rs
	@echo "==== Building hos-term (R1: Rust CPU/SHM Wayland terminal hosting zsh) ===="
	$(RUSTC) --edition 2021 $(RUSTFLAGS_STATIC) $< -o $@

# Z1: real upstream zsh (static musl). Built by deps/zsh/Makefile (Z0) from the
# vendored, checksum-pinned tarballs; the committed binary makes the ISO build a no-op.
$(ZSH_BIN):
	$(MAKE) -C deps/zsh

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

$(WLWIFIMENU_BIN): src/util/wl-wifi-menu.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-wifi-menu (M6 top-right Wi-Fi menu) ===="
	@WL_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild \
		-o $@ src/util/wl-wifi-menu.c $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$(WAYLAND_SYSROOT)/lib/libpng16.a $(WAYLAND_SYSROOT)/lib/libbz2.a $(WAYLAND_SYSROOT)/lib/libz.a \
		$$WL_LIBS \
		-lm \
		-pthread

$(WLLOGVIEW_BIN): src/util/wl-logview.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-logview (scrollable diagnostic log viewer) ===="
	@WL_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild \
		-o $@ src/util/wl-logview.c $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$(WAYLAND_SYSROOT)/lib/libpng16.a $(WAYLAND_SYSROOT)/lib/libbz2.a $(WAYLAND_SYSROOT)/lib/libz.a \
		$$WL_LIBS \
		-lm \
		-pthread

# GNOME top bar for Hyprland — like the utilities but ALSO links the wlr-layer-shell
# protocol code (it anchors a layer surface, which the xdg-only pattern rule can't do).
$(WLLAYERBAR_BIN): src/util/wl-layer-bar.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE) $(LAYER_SHELL_HEADER) $(LAYER_SHELL_CODE)
	@echo "==== Building wl-layer-bar (GNOME top bar for Hyprland, wlr-layer-shell) ===="
	@WL_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild \
		-o $@ $< $(XDG_SHELL_CODE) $(LAYER_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$(WAYLAND_SYSROOT)/lib/libpng16.a $(WAYLAND_SYSROOT)/lib/libbz2.a $(WAYLAND_SYSROOT)/lib/libz.a \
		$$WL_LIBS \
		-lm \
		-pthread

# GNOME toolbar popovers + utility programs — all share the wl-wifi-menu link line
# (freetype + png/bz2/z + wayland-client).  Static pattern rule scoped to exactly
# these targets, so it never shadows the explicit wl-* rules above.
$(WLOVERVIEW_BIN) $(WLCALENDAR_BIN) $(WLQUICKSET_BIN) $(WLCALC_BIN) $(WLCLOCKS_BIN) $(WLIMGVIEW_BIN) $(WLCHARS_BIN) $(WLSYSMON_BIN) $(WLEDITOR_BIN) $(WLSCREENSHOT_BIN): build/wl-%: src/util/wl-%.c $(XDG_SHELL_HEADER) $(XDG_SHELL_CODE)
	@echo "==== Building wl-$* (GNOME utility) ===="
	@WL_LIBS="$$(PKG_CONFIG_LIBDIR='$(WAYLAND_SYSROOT)/lib/pkgconfig:$(WAYLAND_SYSROOT)/share/pkgconfig' PKG_CONFIG_PATH='' PKG_CONFIG_SYSROOT_DIR='' pkg-config --static --libs wayland-client)" ; \
	$(MUSL_CC) -static -O2 -Wall -Wextra \
		-I$(WAYLAND_SYSROOT)/include -I$(WAYLAND_SYSROOT)/include/freetype2 -Ibuild \
		-o $@ $< $(XDG_SHELL_CODE) \
		$(WAYLAND_SYSROOT)/lib/libfreetype.a \
		$(WAYLAND_SYSROOT)/lib/libpng16.a $(WAYLAND_SYSROOT)/lib/libbz2.a $(WAYLAND_SYSROOT)/lib/libz.a \
		$$WL_LIBS \
		-lm \
		-pthread

$(BUSYBOX_DYN_BIN):
	$(MAKE) -C deps/busybox busybox-dyn

stage-iso-tree: kernel.elf $(WLWIFIMENU_BIN) $(WLLAYERBAR_BIN) $(WLLOGVIEW_BIN) $(WLOVERVIEW_BIN) $(WLCALENDAR_BIN) $(WLQUICKSET_BIN) $(WLCALC_BIN) $(WLCLOCKS_BIN) $(WLIMGVIEW_BIN) $(WLCHARS_BIN) $(WLSYSMON_BIN) $(WLEDITOR_BIN) $(WLSCREENSHOT_BIN) $(BUSYBOX_BIN) $(BUSYBOX_DYN_BIN) $(TEST_DRM_BIN) $(DRM_GPU_TEST_BIN) $(DRM_GL_TEST_BIN) $(GL_WL_TEST_BIN) $(GL_TERM_BIN) $(COMPOSITOR_BIN) $(HELLO_GUI_BIN) $(WLPROBE_BIN) $(DISPLAYINFO_BIN) $(WLSHM_DEMO_BIN) $(WLTERM_BIN) $(WLCAIRO_DEMO_BIN) $(INSTALLER_BIN) $(WLFILES_BIN) $(WLDOMAINMGR_BIN) $(IDLE_BIN) $(HOS_SH_BIN) $(HOS_WIFI_BIN) $(NSHIM_SO) $(NETTEST_BIN) $(NETLAUNCH_BIN) $(DBUSLAUNCH_BIN) $(DBUSTEST_BIN) $(NMLAUNCH_BIN) $(WPALAUNCH_BIN) $(WIFIAGENT_BIN) $(UDHCPCSCRIPT_BIN) $(UDHCPCLAUNCH_BIN) $(SCPTEST_BIN) $(HTTPUPLOAD_BIN) $(LOGUPLOAD_BIN) $(SCP_CLIENT_STAGE_DEPS) $(THREADTEST_BIN) $(NMCLITEST_BIN) $(WIFITERM_BIN) $(STORE_APP_BIN) $(ZSH_BIN) $(DECOY_IMAGE) build-display-conf build-config-manifest build-gui-assets build-zksync-wallet $(wildcard $(HYPRLAND_BIN)) $(wildcard $(GTK_HELLO_BIN))
	@echo "==== Staging installer ISO boot tree ===="

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

	cp $(DRM_GPU_TEST_BIN) cd/drm-gpu-test
	@echo "Included drm-gpu-test (R2.4a userspace virgl render-node test)"

	@if [ -s $(DRM_GL_TEST_BIN) ]; then \
		cp $(DRM_GL_TEST_BIN) cd/drm-gl-test; \
		printf '\n    module_path: boot():/drm-gl-test\n' >> cd/boot/limine/limine.conf; \
		echo "Included drm-gl-test (R2.4b Mesa virgl GLES2 test)"; \
	fi

	@if [ -s $(GL_WL_TEST_BIN) ]; then \
		cp $(GL_WL_TEST_BIN) cd/gl-wl-test; \
		printf '\n    module_path: boot():/gl-wl-test\n' >> cd/boot/limine/limine.conf; \
		echo "Included gl-wl-test (R3 EGL/GLES2 Wayland client)"; \
	fi

	@if [ -s $(GL_TERM_BIN) ]; then \
		cp $(GL_TERM_BIN) cd/gl-term; \
		printf '\n    module_path: boot():/gl-term\n' >> cd/boot/limine/limine.conf; \
		echo "Included gl-term (R3 GLES2 Wayland terminal)"; \
	fi

	@if [ -s $(LKL_BOOT_BIN) ]; then \
		cp $(LKL_BOOT_BIN) cd/lkl-boot; \
		printf '\n    module_path: boot():/lkl-boot\n' >> cd/boot/limine/limine.conf; \
		echo "Included lkl-boot (L2: boot LKL — the Linux kernel as a library — on EpinAnonymOS)"; \
	fi

	cp $(COMPOSITOR_BIN) cd/compositor
	@echo "Included compositor"

	cp $(HELLO_GUI_BIN) cd/hello-gui
	@echo "Included hello-gui"

	cp $(WLPROBE_BIN) cd/wl-probe
	@echo "Included wl-probe (GUI G1)"

	cp $(STORE_APP_BIN) cd/store-app
	@echo "Included store-app (F4.2 object-store app image)"

	cp $(DISPLAYINFO_BIN) cd/display-info
	@echo "Included display-info (GUI G7)"

	cp $(WLSHM_DEMO_BIN) cd/wl-shm-demo
	@echo "Included wl-shm-demo (GUI G2)"

	cp $(WLTERM_BIN) cd/wl-term
	@echo "Included wl-term (GUI G4)"

	cp $(IDLE_BIN) cd/idle
	@echo "Included idle task (scheduler idle spinner)"

	cp $(HOS_SH_BIN) cd/hos-sh
	@echo "Included hos-sh (native object shell)"

	cp $(HOS_WIFI_BIN) cd/hos-wifi
	@echo "Included hos-wifi (H1a native WiFi client for the cap-gated LKL net provider)"

	cp $(NETLAUNCH_BIN) cd/hos-netlaunch
	cp $(NETTEST_BIN) cd/hos-nettest
	cp $(NSHIM_SO) cd/libnshim.so
	printf '\n    module_path: boot():/hos-netlaunch\n    module_path: boot():/hos-nettest\n    module_path: boot():/libnshim.so\n' >> cd/boot/limine/limine.conf
	@# M0: stage the REAL system dbus-daemon (dynamic musl) + libdbus-1.so.3 + dbus-send + launcher
	@if [ -f deps/dbus-build/install/bin/dbus-daemon ]; then \
		cp deps/dbus-build/install/bin/dbus-daemon cd/dbus-daemon; \
		cp deps/dbus-build/install/bin/dbus-send cd/dbus-send; \
		cp deps/dbus-build/install/lib/libdbus-1.so.3.32.4 cd/libdbus-1.so.3; \
		cp $(DBUSLAUNCH_BIN) cd/hos-dbus-launch; \
		cp $(DBUSTEST_BIN) cd/hos-dbus-test; \
		printf '    module_path: boot():/dbus-daemon\n    module_path: boot():/dbus-send\n    module_path: boot():/libdbus-1.so.3\n    module_path: boot():/hos-dbus-launch\n    module_path: boot():/hos-dbus-test\n' >> cd/boot/limine/limine.conf; \
		echo "Included M0 real dbus-daemon (system bus) + libdbus-1.so.3 + dbus-send + hos-dbus-launch + hos-dbus-test"; \
	fi
	@# M2b: stage the REAL NetworkManager daemon + nmcli + libnm.so.0 + libndp.so.0 + launcher
	@if [ -f deps/nm-build/NetworkManager-1.44.2/build-epin/src/core/NetworkManager ]; then \
		cp deps/nm-build/NetworkManager-1.44.2/build-epin/src/core/NetworkManager cd/NetworkManager; \
		cp deps/nm-build/NetworkManager-1.44.2/build-epin/src/nmcli/nmcli cd/nmcli; \
		cp deps/nm-build/NetworkManager-1.44.2/build-epin/src/libnm-client-impl/libnm.so.0.1.0 cd/libnm.so.0; \
		cp deps/gtk-stack/sysroot/lib/libndp.so.0.2.0 cd/libndp.so.0; \
		cp $(NMLAUNCH_BIN) cd/hos-nm-launch; \
		cp $(NMCLITEST_BIN) cd/hos-nmcli-test; \
		cp $(WIFIAGENT_BIN) cd/hos-wifi-agent; \
		cp $(BUSYBOX_DYN_BIN) cd/busybox-dyn; \
		cp $(UDHCPCSCRIPT_BIN) cd/udhcpc-script; \
		cp $(UDHCPCLAUNCH_BIN) cd/hos-udhcpc-launch; \
		cp $(SCPTEST_BIN) cd/scp-test; \
		cp $(HTTPUPLOAD_BIN) cd/hos-http-upload; \
		printf '    module_path: boot():/NetworkManager\n    module_path: boot():/nmcli\n    module_path: boot():/libnm.so.0\n    module_path: boot():/libndp.so.0\n    module_path: boot():/hos-nm-launch\n    module_path: boot():/hos-nmcli-test\n    module_path: boot():/hos-wifi-agent\n    module_path: boot():/busybox-dyn\n    module_path: boot():/udhcpc-script\n    module_path: boot():/hos-udhcpc-launch\n    module_path: boot():/scp-test\n    module_path: boot():/hos-http-upload\n' >> cd/boot/limine/limine.conf; \
		echo "Included M2b real NetworkManager daemon + nmcli + libnm.so.0 + libndp.so.0 + hos-nm-launch + hos-nmcli-test"; \
	fi
	cp $(THREADTEST_BIN) cd/hos-thread-test
	printf '    module_path: boot():/hos-thread-test\n' >> cd/boot/limine/limine.conf
	@echo "Included hos-thread-test (diag: cross-thread wakeup)"
	cp $(WIFITERM_BIN) cd/hos-wifiterm
	printf '    module_path: boot():/hos-wifiterm\n' >> cd/boot/limine/limine.conf
	@echo "Included hos-wifiterm (TEMP lightweight WiFi-check terminal)"
	@# H3: stage wpa_supplicant (dynamic musl) + libnl-tiny.so if built
	@if [ -f deps/wpa-build/wpa_supplicant-2.10/wpa_supplicant/wpa_supplicant ]; then \
		cp deps/wpa-build/wpa_supplicant-2.10/wpa_supplicant/wpa_supplicant cd/wpa_supplicant; \
		cp deps/wpa-build/wpa_supplicant-2.10/wpa_supplicant/wpa_cli cd/wpa_cli; \
		cp deps/wpa-build/libnl-tiny/libnl-tiny.so cd/libnl-tiny.so; \
		cp $(WPALAUNCH_BIN) cd/hos-wpa-launch; \
		printf '    module_path: boot():/wpa_supplicant\n    module_path: boot():/wpa_cli\n    module_path: boot():/libnl-tiny.so\n    module_path: boot():/hos-wpa-launch\n' >> cd/boot/limine/limine.conf; \
		echo "Included wpa_supplicant (M5: D-Bus mode for NM, under the shim) + libnl-tiny.so + hos-wpa-launch"; \
	fi
	cp $(LOGUPLOAD_BIN) cd/hos-log-upload
	printf '    module_path: boot():/hos-log-upload\n' >> cd/boot/limine/limine.conf
	@echo "Included hos-log-upload (debug log snapshot + scp launcher)"
	@# Never bake a developer's Wi-Fi credentials into a normal OS image merely because
	@# local/debug-net.conf exists.  Headless hardware debugging can opt in explicitly
	@# with `make EMBED_DEBUG_NET=1 ...`; the default image always starts disconnected
	@# and is configured through wl-wifi-menu's scan/select/password flow.
	@if [ "$(EMBED_DEBUG_NET)" = "1" ] && [ -f local/debug-net.conf ]; then \
		cp local/debug-net.conf cd/epin-debug-net.conf; \
		printf '    module_path: boot():/epin-debug-net.conf\n' >> cd/boot/limine/limine.conf; \
		echo "Included explicitly requested debug network credentials (/epin-debug-net.conf)"; \
	fi
	@# Opt-in emergency/headless path: only this marker disables D-Bus/NM/the interactive scanner.
	@if [ "$(EMBED_DEBUG_NET)" = "1" ] && [ -f local/debug-fast-net.conf ]; then \
		cp local/debug-fast-net.conf cd/epin-debug-fast-net.conf; \
		printf '    module_path: boot():/epin-debug-fast-net.conf\n' >> cd/boot/limine/limine.conf; \
		echo "Included headless fast-network marker (/epin-debug-fast-net.conf)"; \
	fi
	@if [ -f local/epin-debug-ssh-key ]; then \
		cp local/epin-debug-ssh-key cd/epin-debug-ssh-key; \
		printf '    module_path: boot():/epin-debug-ssh-key\n' >> cd/boot/limine/limine.conf; \
		echo "Included local debug SSH key (/epin-debug-ssh-key)"; \
	fi
	@if [ -n "$(OPENSSH_SCP_BIN)" ] && [ -n "$(OPENSSH_SSH_BIN)" ]; then \
		cp "$(OPENSSH_SCP_BIN)" cd/scp; \
		cp "$(OPENSSH_SSH_BIN)" cd/ssh; \
		printf '    module_path: boot():/scp\n    module_path: boot():/ssh\n' >> cd/boot/limine/limine.conf; \
		echo "Included scp/ssh from OPENSSH_SCP_BIN and OPENSSH_SSH_BIN"; \
	elif [ -f "$(DROPBEAR_SCP_BIN)" ] && [ -f "$(DROPBEAR_SSH_BIN)" ]; then \
		cp "$(DROPBEAR_SCP_BIN)" cd/scp; \
		cp "$(DROPBEAR_SSH_BIN)" cd/ssh; \
		printf '    module_path: boot():/scp\n    module_path: boot():/ssh\n' >> cd/boot/limine/limine.conf; \
		echo "Included Dropbear scp/dbclient debug client"; \
	elif [ -f local/scp ] && [ -f local/ssh ]; then \
		cp local/scp cd/scp; \
		cp local/ssh cd/ssh; \
		printf '    module_path: boot():/scp\n    module_path: boot():/ssh\n' >> cd/boot/limine/limine.conf; \
		echo "Included local scp/ssh debug clients"; \
	else \
		echo "No scp/ssh client staged; hos-log-upload will report that at boot"; \
	fi
	@if ! grep -q 'boot():/ld-musl-x86_64.so.1' cd/boot/limine/limine.conf; then \
		cp deps/musl/install/lib/libc.so cd/ld-musl-x86_64.so.1; \
		printf '    module_path: boot():/ld-musl-x86_64.so.1\n' >> cd/boot/limine/limine.conf; \
	fi
	@echo "Included H1b.3 LD_PRELOAD test (hos-netlaunch -> hos-nettest + libnshim.so via ld-musl)"

	cp $(ZSH_BIN) cd/zsh
	@echo "Included zsh (Z2: real upstream zsh, dynamic musl)"
	# Z2: dynamic zsh loads libc.so via ld-musl (PT_INTERP, staged by the WESTON dynamic
	# block) and dlopens its zmodules.  Stage every zmodule .so as a boot module; the
	# kernel resolves zsh's dlopen("/system/shell/zsh/lib/zsh/5.9/zsh/<m>.so") by basename.
	@for so in deps/zsh/modules/*.so; do \
	  b=$$(basename $$so); cp $$so cd/$$b; \
	  printf '    module_path: boot():/%s\n' "$$b" >> cd/boot/limine/limine.conf; \
	done
	@echo "Included $$(ls deps/zsh/modules/*.so | wc -l) zsh zmodules (.so) for dynamic loading"

	cp $(WLCAIRO_DEMO_BIN) cd/wl-cairo-demo
	printf '\n    module_path: boot():/wl-cairo-demo\n' >> cd/boot/limine/limine.conf
	@echo "Included wl-cairo-demo (GUI G11)"

	cp $(WLFILES_BIN) cd/wl-files
	printf '\n    module_path: boot():/wl-files\n' >> cd/boot/limine/limine.conf
	@echo "Included wl-files (GUI G17)"

	cp $(INSTALLER_BIN) cd/calamares
	printf '\n    module_path: boot():/calamares\n' >> cd/boot/limine/limine.conf
	@echo "Included wl-installer as /calamares (INSTALLER D4.1 'Install to Disk' entry; D4.5 stub)"

	cp $(DECOY_IMAGE) cd/decoy-linux.ext4
	printf '\n    module_path: boot():/decoy-linux.ext4\n' >> cd/boot/limine/limine.conf
	@echo "Included decoy-linux.ext4 (INSTALLER H1 decoy Linux disk image)"

	cp $(ZKSYNC_WALLET_BLOB) cd/zksync-wallet.blob
	printf '\n    module_path: boot():/zksync-wallet.blob\n' >> cd/boot/limine/limine.conf
	@echo "Included zksync-wallet.blob (ZKsync boot-integrity wallet + contract ABI)"

	@if [ -x "$(RUSTC)" ]; then \
	   $(MAKE) --no-print-directory $(HELLO_WL_BIN) && cp $(HELLO_WL_BIN) cd/hello-wl && \
	   printf '\n    module_path: boot():/hello-wl\n' >> cd/boot/limine/limine.conf && \
	   echo "Included hello-wl (R0: Rust->musl Wayland validation)"; \
	 else echo "Skipping hello-wl (R0: $(RUSTC) not found — rustup + 'rustup target add $(RUST_TARGET)')"; fi

	@if [ -x "$(RUSTC)" ]; then \
	   $(MAKE) --no-print-directory $(HOSTERM_BIN) && cp $(HOSTERM_BIN) cd/hos-term && \
	   printf '\n    module_path: boot():/hos-term\n' >> cd/boot/limine/limine.conf && \
	   echo "Included hos-term (R1: Rust CPU/SHM terminal)"; \
	 else echo "Skipping hos-term (R1: $(RUSTC) not found)"; fi

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

	# DECLARITIVE_MODEL_ROADMAP §4: stage the verified config manifest as a boot
	# module (kernel finds "manifest.blob" and applies it before PID1).  Omitted
	# entirely when DECLARATIVE_CONFIG=none.
	@if [ "$(DECLARATIVE_CONFIG)" != "none" ] && [ -f $(CONFIG_MANIFEST) ]; then \
		cp $(CONFIG_MANIFEST) cd/manifest.blob; \
		printf '\n    module_path: boot():/manifest.blob\n' >> cd/boot/limine/limine.conf; \
		echo "Included manifest.blob (§4 declarative config: $(DECLARATIVE_CONFIG))"; \
	fi

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
		if [ -f deps/gtk-stack/sysroot/lib/dri/kms_swrast_dri.so ]; then \
			cp deps/gtk-stack/sysroot/lib/dri/kms_swrast_dri.so cd/kms_swrast_dri.so; \
			cp deps/gtk-stack/sysroot/lib/dri/kms_swrast_dri.so cd/swrast_dri.so; \
			printf '\n    module_path: boot():/Hyprland\n    module_path: boot():/ld-musl-x86_64.so.1\n    module_path: boot():/kms_swrast_dri.so\n    module_path: boot():/swrast_dri.so\n' >> cd/boot/limine/limine.conf; \
			if [ -f deps/gtk-stack/sysroot/lib/libglapi.so ]; then \
				cp deps/gtk-stack/sysroot/lib/libglapi.so cd/libglapi.so; \
				printf '    module_path: boot():/libglapi.so\n' >> cd/boot/limine/limine.conf; \
				echo "Included libglapi.so (shared GL dispatch — unifies app + DRI-driver glapi)"; \
			fi; \
			if [ -f deps/gtk-stack/sysroot/lib/dri/virtio_gpu_dri.so ]; then \
				cp deps/gtk-stack/sysroot/lib/dri/virtio_gpu_dri.so cd/virtio_gpu_dri.so; \
				printf '    module_path: boot():/virtio_gpu_dri.so\n' >> cd/boot/limine/limine.conf; \
				echo "Included virtio_gpu_dri.so (R2.4b: Mesa virgl GPU driver)"; \
			fi; \
		else \
			printf '\n    module_path: boot():/Hyprland\n    module_path: boot():/ld-musl-x86_64.so.1\n' >> cd/boot/limine/limine.conf; \
		fi; \
		echo "Included Hyprland (dynamic) + ld-musl"; \
		if [ ! -f $(XKB_BLOB) ] && [ -d $(XKB_SRC_DIR) ]; then \
			python3 scripts/pack-xkb.py $(XKB_SRC_DIR) $(XKB_BLOB); \
		fi; \
		if [ -f $(XKB_BLOB) ]; then \
			cp $(XKB_BLOB) cd/xkb.blob; \
			printf '\n    module_path: boot():/xkb.blob\n' >> cd/boot/limine/limine.conf; \
			echo "Included xkb.blob (xkeyboard-config data)"; \
		fi; \
		if [ ! -f $(ZSHFNS_BLOB) ] && [ -d $(ZSHFNS_SRC)/Completion ]; then \
			python3 scripts/pack-zshfns.py $(ZSHFNS_SRC) $(ZSHFNS_BLOB) 5.9; \
		fi; \
		if [ -f $(ZSHFNS_BLOB) ]; then \
			cp $(ZSHFNS_BLOB) cd/zshfns.blob; \
			printf '\n    module_path: boot():/zshfns.blob\n' >> cd/boot/limine/limine.conf; \
			echo "Included zshfns.blob (Z8: zsh functions + completion)"; \
		fi; \
		if [ ! -f $(ZSHPLUG_BLOB) ] && [ -d $(ZSHPLUG_SRC) ]; then \
			python3 scripts/pack-zshplugins.py $(ZSHPLUG_BLOB) $(ZSHPLUG_SRC) >/dev/null; \
		fi; \
		if [ -f $(ZSHPLUG_BLOB) ]; then \
			cp $(ZSHPLUG_BLOB) cd/zshplugins.blob; \
			printf '\n    module_path: boot():/zshplugins.blob\n' >> cd/boot/limine/limine.conf; \
			echo "Included zshplugins.blob (Z9: zsh plugins — syntax-highlighting/autosuggestions/anonymos)"; \
		fi; \
		if [ ! -f $(OMZ_BLOB) ] && ls $(ZSHPLUG_SRC)/ohmyzsh*.tar.gz >/dev/null 2>&1; then \
			python3 scripts/pack-omz.py $(OMZ_BLOB) $(ZSHPLUG_SRC) >/dev/null; \
		fi; \
		if [ -f $(OMZ_BLOB) ]; then \
			cp $(OMZ_BLOB) cd/omz.blob; \
			printf '\n    module_path: boot():/omz.blob\n' >> cd/boot/limine/limine.conf; \
			echo "Included omz.blob (Z9b: Oh My Zsh + Powerlevel9k + AnonymOS profile)"; \
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
		if [ "$(WESTON)" != "1" ]; then \
			cp $(WLLAYERBAR_BIN)   cd/wl-layer-bar; \
			cp $(WLOVERVIEW_BIN)   cd/wl-overview; \
			cp $(WLCALENDAR_BIN)   cd/wl-calendar; \
			cp $(WLWIFIMENU_BIN)   cd/wl-wifi-menu; \
			cp $(WLQUICKSET_BIN)   cd/wl-quicksettings; \
			printf '\n    module_path: boot():/wl-layer-bar\n    module_path: boot():/wl-overview\n    module_path: boot():/wl-calendar\n    module_path: boot():/wl-wifi-menu\n    module_path: boot():/wl-quicksettings\n' >> cd/boot/limine/limine.conf; \
			echo "Included GNOME top bar (wl-layer-bar, wlr-layer-shell) + Activities/clock/wifi utilities for Hyprland"; \
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
		if [ -f $(WESTON_BUILD)/libweston/renderer-gl/gl-renderer.so ]; then \
			cp $(WESTON_BUILD)/libweston/renderer-gl/gl-renderer.so cd/gl-renderer.so; \
		fi; \
		cp $(WESTON_BUILD)/clients/weston-desktop-shell         cd/weston-desktop-shell; \
		cp $(WESTON_BUILD)/clients/weston-keyboard              cd/weston-keyboard; \
		cp $(WLDOMAINMGR_BIN)                                   cd/wl-domain-manager; \
		cp $(WLWIFIMENU_BIN)                                    cd/wl-wifi-menu; \
		cp $(WLLOGVIEW_BIN)                                     cd/wl-logview; \
		cp $(WLOVERVIEW_BIN)                                    cd/wl-overview; \
		cp $(WLCALENDAR_BIN)                                    cd/wl-calendar; \
		cp $(WLQUICKSET_BIN)                                    cd/wl-quicksettings; \
		cp $(WLCALC_BIN)                                        cd/wl-calc; \
		cp $(WLCLOCKS_BIN)                                      cd/wl-clocks; \
		cp $(WLIMGVIEW_BIN)                                     cd/wl-imgview; \
		cp $(WLCHARS_BIN)                                       cd/wl-chars; \
		cp $(WLSYSMON_BIN)                                      cd/wl-sysmon; \
		cp $(WLEDITOR_BIN)                                      cd/wl-editor; \
		cp $(WLSCREENSHOT_BIN)                                  cd/wl-screenshot; \
		cp src/desktop.conf                                     cd/desktop.conf; \
		printf '\n    module_path: boot():/weston\n    module_path: boot():/ld-musl-x86_64.so.1\n    module_path: boot():/libexec_weston.so.0\n    module_path: boot():/libweston-14.so.0\n    module_path: boot():/drm-backend.so\n    module_path: boot():/desktop-shell.so\n    module_path: boot():/weston-desktop-shell\n    module_path: boot():/weston-keyboard\n    module_path: boot():/wl-domain-manager\n    module_path: boot():/wl-wifi-menu\n    module_path: boot():/wl-logview\n    module_path: boot():/wl-overview\n    module_path: boot():/wl-calendar\n    module_path: boot():/wl-quicksettings\n    module_path: boot():/wl-calc\n    module_path: boot():/wl-clocks\n    module_path: boot():/wl-imgview\n    module_path: boot():/wl-chars\n    module_path: boot():/wl-sysmon\n    module_path: boot():/wl-editor\n    module_path: boot():/wl-screenshot\n    module_path: boot():/desktop.conf\n' >> cd/boot/limine/limine.conf; \
		if [ -f cd/gl-renderer.so ]; then \
			printf '    module_path: boot():/gl-renderer.so\n' >> cd/boot/limine/limine.conf; \
		fi; \
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

	python3 scripts/build-boot-integrity-manifest.py cd $(BOOT_INTEGRITY_MANIFEST) \
		--network "$(ZKSYNC_NETWORK)" \
		--chain-id "$(ZKSYNC_CHAIN_ID)" \
		--rpc-url "$(ZKSYNC_RPC_URL)" \
		--contract-address "$(BOOT_INTEGRITY_CONTRACT_ADDRESS)" \
		--deployment-tx "$(BOOT_INTEGRITY_DEPLOY_TX)"
	cp $(BOOT_INTEGRITY_MANIFEST) cd/zksync-attestation.json
	printf '\n    module_path: boot():/zksync-attestation.json\n' >> cd/boot/limine/limine.conf
	@echo "Included zksync-attestation.json (boot-module hash manifest)"

# =========================================================
# INSTALLER ISO (hos-install.iso) — the only full ISO artifact. It contains the
# normal boot tree PLUS a prebuilt FAT32 "esp-image"
# boot module (limine BOOTX64.EFI + kernel + modules + limine.conf).  Boot it (UEFI) with a
# blank target disk; the desktop "Install to Disk" button writes that image, behind a single-
# ESP GPT, onto the disk, so the machine then boots EpinAnonymOS from disk (no install medium).
# See scripts/mk-install-iso.sh and scripts/vbox-install-test.sh.
# =========================================================
iso: hos-install.iso

# UPDATE U1-C: build the A/B slot-arbiter UEFI app (build/arbiter.efi).
arbiter-efi:
	+$(MAKE) -C boot/arbiter

hos-install.iso: stage-iso-tree veracrypt-efi arbiter-efi
	scripts/mk-install-iso.sh

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

deps-weston:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps weston

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
		hos-install.iso \
		esp.img \
		kernel.elf
