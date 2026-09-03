PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF          := $(abspath .)
HYPRLAND_SRC  := $(abspath ../hyprland)
HYPRLAND_BLD  := $(HYPRLAND_SRC)/build-hanonymos
HYPRLAND_OUT  := $(HYPRLAND_SRC)/Hyprland
SYSROOT       := $(abspath ../gtk-stack/sysroot)
MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CXX      := $(MUSL_INSTALL)/bin/musl-clang++
HOST_PYTHON   := $(HOST_TOOLS_BIN)/python3
HOST_PIP      := $(HOST_PYTHON) -m pip
HOST_MESON_VER:= 1.10.2
HOST_MESON    := $(HOST_TOOLS_BIN)/meson
HOST_CMAKE_VER:= 3.30.9
HOST_CMAKE    := $(HOST_TOOLS_BIN)/cmake

PKG_CONFIG_LIBDIR := $(SYSROOT)/lib/pkgconfig:$(SYSROOT)/share/pkgconfig:$(MUSL_INSTALL)/lib/pkgconfig
PKG_CONFIG_ENV := PKG_CONFIG_LIBDIR="$(PKG_CONFIG_LIBDIR)" PKG_CONFIG_PATH=

# NB libglapi is the one .so in this otherwise-static list, and deliberately so.
# deps/mutter's mesa build keeps glapi SHARED (see its "R2.4b dual-glapi fix" note): the
# app's GL entry points and the dlopened DRI driver must share ONE _glapi dispatch table,
# so a static copy would give the app an empty table.  Mesa therefore never produces a
# libglapi.a -- the one in the sysroot is the EMPTY STUB deps/gtk-stack creates so that
# packages adding -lglapi can link.  Linking that stub here left every _glapi_tls_Dispatch
# and _glapi_get_proc_address reference from the real libEGL.a/libGLESv2.a undefined.
# The ISO stages libglapi.so as a boot module for the same reason (../../Makefile:1089).
HYPRLAND_EXTRA_LIBS := \
	-Wl,--start-group \
	$(SYSROOT)/lib/libseat.a \
	$(SYSROOT)/lib/libinput.a \
	$(SYSROOT)/lib/libudev.a \
	$(SYSROOT)/lib/libevdev.a \
	$(SYSROOT)/lib/libmtdev.a \
	$(SYSROOT)/lib/libdisplay-info.a \
	$(SYSROOT)/lib/libwayland-client.a \
	$(SYSROOT)/lib/libwayland-server.a \
	$(SYSROOT)/lib/libwayland-egl.a \
	$(SYSROOT)/lib/libXcursor.a \
	$(SYSROOT)/lib/libXfixes.a \
	$(SYSROOT)/lib/libXrender.a \
	$(SYSROOT)/lib/libXext.a \
	$(SYSROOT)/lib/libX11.a \
	$(SYSROOT)/lib/libxcb.a \
	$(SYSROOT)/lib/libXau.a \
	$(SYSROOT)/lib/libXdmcp.a \
	$(SYSROOT)/lib/libglapi.so \
	$(SYSROOT)/lib/libgbm.a \
	$(SYSROOT)/lib/libdrm.a \
	$(SYSROOT)/lib/libzip.a \
	$(SYSROOT)/lib/libjpeg.a \
	$(SYSROOT)/lib/libwebp.a \
	$(SYSROOT)/lib/libsharpyuv.a \
	$(SYSROOT)/lib/libmagic.a \
	$(SYSROOT)/lib/librsvg-2.a \
	$(SYSROOT)/lib/libjxl.a \
	$(SYSROOT)/lib/libjxl_cms.a \
	$(SYSROOT)/lib/libjxl_threads.a \
	$(SYSROOT)/lib/libhwy.a \
	$(SYSROOT)/lib/libbrotlienc.a \
	$(SYSROOT)/lib/libbrotlidec.a \
	$(SYSROOT)/lib/libbrotlicommon.a \
	$(SYSROOT)/lib/libpng16.a \
	$(SYSROOT)/lib/libbz2.a \
	$(SYSROOT)/lib/libfreetype.a \
	$(SYSROOT)/lib/libfontconfig.a \
	$(SYSROOT)/lib/libcairo.a \
	$(SYSROOT)/lib/libpixman-1.a \
	$(SYSROOT)/lib/libpangocairo-1.0.a \
	$(SYSROOT)/lib/libpangoft2-1.0.a \
	$(SYSROOT)/lib/libpango-1.0.a \
	$(SYSROOT)/lib/libharfbuzz.a \
	$(SYSROOT)/lib/libfribidi.a \
	$(SYSROOT)/lib/libgio-2.0.a \
	$(SYSROOT)/lib/libgobject-2.0.a \
	$(SYSROOT)/lib/libgmodule-2.0.a \
	$(SYSROOT)/lib/libglib-2.0.a \
	$(SYSROOT)/lib/libpcre2-8.a \
	$(SYSROOT)/lib/libffi.a \
	$(SYSROOT)/lib/libexpat.a \
	$(SYSROOT)/lib/libz.a \
	$(MUSL_INSTALL)/lib/libc++.a \
	$(MUSL_INSTALL)/lib/libc++abi.a \
	$(MUSL_INSTALL)/lib/libunwind.a \
	-Wl,--whole-archive $(SYSROOT)/lib/libhos-cxx-compat.a -Wl,--no-whole-archive \
	-Wl,--end-group

HYPRLAND_CMAKE_FLAGS := \
	-G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX=$(SYSROOT) \
	-DCMAKE_SYSROOT=$(MUSL_INSTALL) \
	-DCMAKE_PREFIX_PATH=$(SYSROOT)\;$(MUSL_INSTALL) \
	-DCMAKE_FIND_ROOT_PATH=$(SYSROOT)\;$(MUSL_INSTALL) \
	-DCMAKE_FIND_LIBRARY_SUFFIXES=.a \
	-DCMAKE_C_COMPILER=$(MUSL_CC) \
	-DCMAKE_CXX_COMPILER=$(MUSL_CXX) \
	-DCMAKE_ASM_COMPILER=$(MUSL_CC) \
	-DCMAKE_CXX_STANDARD=26 \
	-DCMAKE_CXX_SCAN_FOR_MODULES=OFF \
	-DCMAKE_DISABLE_PRECOMPILE_HEADERS=ON \
	-DCMAKE_EXE_LINKER_FLAGS="-no-pie -Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1 -Wl,--export-dynamic -Wl,--allow-multiple-definition" \
	-DCMAKE_CXX_STANDARD_LIBRARIES="$(HYPRLAND_EXTRA_LIBS)" \
	-DNO_XWAYLAND=ON \
	-DNO_SYSTEMD=ON \
	-DNO_UWSM=ON \
	-DUSE_TRACY=OFF \
	-DUSE_TRACY_GPU=OFF

include Makefile.deps
include Makefile.upgrades

.PHONY: all prepare check raw-check host-meson host-cmake patch-hyprland-source configure build status clean distclean clean-deps

all: build

prepare: host-meson
	$(MAKE) --no-print-directory deps
	$(MAKE) --no-print-directory upgrades

host-meson:
	@set -e; \
	if [ -x "$(HOST_MESON)" ] && "$(HOST_PYTHON)" "$(HOST_MESON)" --version >/dev/null 2>&1; then \
		if ! head -n1 "$(HOST_MESON)" | grep -qx '#!$(HOST_PYTHON)'; then \
			sed -i '1s|^#!.*|#!$(HOST_PYTHON)|' "$(HOST_MESON)"; \
		fi; \
	else \
		$(HOST_PIP) install --upgrade "meson==$(HOST_MESON_VER)"; \
	fi; \
	"$(HOST_MESON)" --version >/dev/null

host-cmake:
	@set -e; \
	current="$$( [ -x "$(HOST_CMAKE)" ] && "$(HOST_CMAKE)" --version | sed -n '1s/.* //p' || true )"; \
	if [ "$$current" != "$(HOST_CMAKE_VER)" ]; then \
		echo "[hyprland] Installing host CMake $(HOST_CMAKE_VER) into $(HOST_TOOLS_ROOT)"; \
		$(HOST_PIP) install --upgrade "cmake==$(HOST_CMAKE_VER)"; \
	fi; \
	"$(HOST_CMAKE)" --version | sed -n '1p'

patch-hyprland-source:
	@od -An -tx1 -v $(HYPRLAND_SRC)/example/hyprland.lua | \
		sed 's/[0-9a-f][0-9a-f]/0x&,/g' > $(HYPRLAND_SRC)/src/config/lua/DefaultConfigLua.inc
	@sed -i 's|#embed "../../../example/hyprland.lua"|#include "DefaultConfigLua.inc"|' \
		$(HYPRLAND_SRC)/src/config/lua/DefaultConfig.hpp
	@sed -i 's|std::string{"0x"} + value|std::string{"0x"} + std::string{value}|' \
		$(HYPRLAND_SRC)/src/config/shared/parserUtils/ParserUtils.cpp
	@if ! grep -q 'screenshareTypeName' $(HYPRLAND_SRC)/src/managers/screenshare/ScreenshareSession.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-libcxx-screenshare.patch; \
	fi
	@if ! grep -q 'Sessionless backend active' $(HYPRLAND_SRC)/src/Compositor.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-sessionless-active.patch; \
	fi
	@if ! grep -q 'HOS CPU-readback clear frame path' $(HYPRLAND_SRC)/src/render/GLRenderer.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-hos-render-present.patch; \
	fi
	@if ! grep -q 'no shm_open()/POSIX shm' $(HYPRLAND_SRC)/src/helpers/MiscFunctions.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-shm-memfd.patch; \
	fi
	@if ! grep -q 'GUI roadmap G6: the CPU-readback renderer' $(HYPRLAND_SRC)/src/protocols/core/Compositor.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-g6-shm-buffer-retain.patch; \
	fi
	@if ! grep -q 'fixed fallback monitor scale 1' $(HYPRLAND_SRC)/src/config/shared/monitor/MonitorRuleManager.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-g7-fallback-scale.patch; \
	fi
	@if ! grep -q 'GUI roadmap G8: wl_shm clients' $(HYPRLAND_SRC)/src/protocols/core/Compositor.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-g8-surface-commit-damage.patch; \
	fi
	@if ! grep -q 'GUI roadmap G5: report mapped window' $(HYPRLAND_SRC)/src/render/GLRenderer.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-g5-identity-borders.patch; \
	fi
	@if ! grep -q 'hosComposeShmWindows' $(HYPRLAND_SRC)/src/render/GLRenderer.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-g9-shm-cpu-compose.patch; \
	fi
	@if ! grep -q 'hasRenderableBuffer' $(HYPRLAND_SRC)/src/protocols/XDGShell.cpp; then \
		patch -d $(HYPRLAND_SRC) -p1 < $(SELF)/patches/hyprland-g11-xdg-shm-buffer-map.patch; \
	fi

check: prepare raw-check

raw-check:
	@set -e; \
	missing=0; \
	for dep in \
		'aquamarine >= 0.11.0' \
		'hyprlang >= 0.6.7' \
		'hyprcursor >= 0.1.13' \
		'hyprutils >= 0.13.1' \
		'hyprwire' \
		'hyprgraphics >= 0.5.1' \
		'hyprland-protocols >= 0.6.4' \
		'xkbcommon >= 1.11.0' \
		'wayland-server >= 1.22.91' \
		'wayland-protocols >= 1.47' \
		'libinput >= 1.29' \
		'uuid' \
		'cairo' \
		'pango' \
		'pangocairo' \
		'pixman-1' \
		'xcursor' \
		'libdrm' \
		'gbm' \
		'egl' \
		'glesv2' \
		'gio-2.0' \
		're2' \
		'muparser' \
		'lcms2' \
		'lua >= 5.5' \
	; do \
		if ! env $(PKG_CONFIG_ENV) pkg-config --exists "$$dep"; then \
			echo "[hyprland] missing or too old: $$dep"; \
			missing=1; \
		fi; \
	done; \
	if ! command -v hyprwayland-scanner >/dev/null 2>&1 && \
	   ! [ -x "$(SYSROOT)/bin/hyprwayland-scanner" ]; then \
		echo "[hyprland] missing or too old: hyprwayland-scanner >= 0.3.10"; \
		missing=1; \
	fi; \
	if ! command -v hyprwire-scanner >/dev/null 2>&1 && \
	   ! [ -x "$(HOST_TOOLS_BIN)/hyprwire-scanner" ]; then \
		echo "[hyprland] missing: hyprwire-scanner"; \
		missing=1; \
	fi; \
	if ! find "$(SYSROOT)" "$(MUSL_INSTALL)" -path '*glslang*Config.cmake' -o -path '*glslang-config.cmake' 2>/dev/null | grep -q .; then \
		echo "[hyprland] missing or too old: glslang CMake package"; \
		missing=1; \
	fi; \
	if [ "$$missing" -ne 0 ]; then \
		echo "[hyprland] Build is intentionally blocked until these packages are built into $(SYSROOT)."; \
		echo "[hyprland] The upstream source is present in $(HYPRLAND_SRC)."; \
		if [ "$(HYPRLAND_ALLOW_MISSING)" = "1" ]; then exit 0; fi; \
		exit 1; \
	fi

configure: check host-cmake patch-hyprland-source
	env $(PKG_CONFIG_ENV) PATH="$(HOST_TOOLS_BIN):$$PATH" "$(HOST_CMAKE)" --no-warn-unused-cli \
		$(HYPRLAND_CMAKE_FLAGS) \
		-S $(HYPRLAND_SRC) \
		-B $(HYPRLAND_BLD)

build: configure host-cmake
	env $(PKG_CONFIG_ENV) PATH="$(HOST_TOOLS_BIN):$$PATH" "$(HOST_CMAKE)" --build $(HYPRLAND_BLD) \
		--config Release --target Hyprland -- $(NINJA_BUILD_FLAGS)
	cp $(HYPRLAND_BLD)/Hyprland $(HYPRLAND_OUT)
	@echo "Hyprland binary: $(HYPRLAND_OUT)"

status:
	@echo "Hyprland source: $(HYPRLAND_SRC)"
	@if [ -d $(HYPRLAND_SRC)/.git ]; then \
		git -C $(HYPRLAND_SRC) rev-parse --short HEAD; \
		git -C $(HYPRLAND_SRC) submodule status; \
	fi
	@$(MAKE) --no-print-directory HYPRLAND_ALLOW_MISSING=1 raw-check

clean:
	rm -rf $(HYPRLAND_BLD)
	rm -f $(HYPRLAND_OUT)

clean-deps:
	rm -rf build stamps

distclean: clean clean-deps
