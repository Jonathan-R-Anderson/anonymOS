# ==========================================================================
# deps/gtk-stack/Makefile
#
# Full GTK3 static dependency chain, built against musl libc.
#
# Dependency order:
#   zlib → libffi → pcre2 → libpng → pixman → bzip2 → freetype →
#   expat → fontconfig → harfbuzz → glib → wayland → wayland-protocols →
#   xkbcommon → gl-headers → cairo → pango → gdk-pixbuf → atk → epoxy → gtk3
#
# Output:
#   sysroot/       — all static libs, headers, pc files
#   gtk-hello      — minimal GTK3 test binary (ISO module)
# ==========================================================================

PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF          := $(abspath .)
MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CXX      := $(MUSL_INSTALL)/bin/musl-clang++
CXXRT_STAMP   := $(abspath ../cxxrt/stamps/libcxx.done)
SYSROOT       := $(SELF)/sysroot
STAMPS        := $(SELF)/stamps
DLDIR         := $(SELF)/downloads
BLDDIR        := $(SELF)/build
HOST_PYTHON   := $(HOST_TOOLS_BIN)/python3
HOST_PIP      := $(HOST_PYTHON) -m pip
# PEP-668 (Arch, newer Debian/Fedora) marks the system python as externally
# managed and refuses bare `pip install`. --break-system-packages is harmless on
# older distros and required on those, so always pass it.
HOST_PIP_INSTALL := $(HOST_PIP) install --break-system-packages
HOST_PY_STAMP := $(HOST_TOOLS_ROOT)/.python-packaging.stamp
HOST_BISON    := $(HOST_TOOLS_BIN)/bison
HOST_MESON_VER:= 1.10.2

# ── Cross-compilation tools ───────────────────────────────────────────────────
CC      := $(MUSL_CC)
CXX     := $(MUSL_CXX)
AR      := llvm-ar
STRIP   := llvm-strip
RANLIB  := llvm-ranlib
NM      := llvm-nm
OBJCOPY := llvm-objcopy

CLANG_RESOURCE_INCLUDE := $(LLVM_PREFIX)/lib/clang/18/include

BASE_CFLAGS  := -O2 -fPIC \
                -isystem $(CLANG_RESOURCE_INCLUDE) \
                -I$(SYSROOT)/include \
                -I$(SYSROOT)/include/freetype2 \
                -I$(SYSROOT)/include/libpng16 \
                -I$(MUSL_INSTALL)/include
BASE_CXXFLAGS:= $(BASE_CFLAGS)
BASE_LDFLAGS := -static -no-pie -L$(SYSROOT)/lib -L$(MUSL_INSTALL)/lib
GL_HEADER_DIRS := EGL GL GLES GLES2 GLES3 KHR

# Skip info-page generation/installation in every autotools `make install` —
# install-info fails on hosts without texinfo and the info pages are irrelevant
# to a static sysroot. MAKEINFO=true makes configure skip building them.
MAKEINFO := true
export MAKEINFO

PKG_CONFIG_ENV := \
    PKG_CONFIG_LIBDIR="$(SYSROOT)/lib/pkgconfig:$(SYSROOT)/share/pkgconfig" \
    PKG_CONFIG_PATH="" \
    PKG_CONFIG_SYSROOT_DIR="$(SYSROOT)"

# Autoconf configure shorthand
CONFIGURE_COMMON := \
    CC="$(CC)" CXX="$(CXX)" AR="$(AR)" STRIP="$(STRIP)" RANLIB="$(RANLIB)" NM="$(NM)" \
    CPPFLAGS="$(BASE_CFLAGS)" CFLAGS="$(BASE_CFLAGS)" CXXFLAGS="$(BASE_CXXFLAGS)" LDFLAGS="$(BASE_LDFLAGS)" \
    $(PKG_CONFIG_ENV) \
    --prefix="$(SYSROOT)" \
    --host=x86_64-linux-musl \
    --build=x86_64-linux-gnu \
    --disable-shared \
    --enable-static

# ── Library versions ──────────────────────────────────────────────────────────
ZLIB_VER    := 1.3.1
LIBFFI_VER  := 3.4.6
PCRE2_VER   := 10.44
LIBPNG_VER  := 1.6.43
PIXMAN_VER  := 0.43.4
BZIP2_VER   := 1.0.8
FT_VER      := 2.13.3
EXPAT_VER   := 2.6.4
EXPAT_TAG   := R_$(subst .,_,$(EXPAT_VER))
FCONF_VER   := 2.15.0
HBUZZ_VER   := 9.0.0
GLIB_VER    := 2.80.4
GLIB_MAJ    := 2.80
WAYLAND_VER := 1.23.1
WPROTO_VER  := 1.45
XKB_VER     := 1.7.0
CAIRO_VER   := 1.18.2
PANGO_VER   := 1.54.0
PANGO_MAJ   := 1.54
GDKPB_VER   := 2.42.12
GDKPB_MAJ   := 2.42
ATK_VER     := 2.38.0
ATK_MAJ     := 2.38
EPOXY_VER   := 1.5.10
GTK3_VER    := 3.24.43
GTK3_MAJ    := 3.24
HOST_BISON_VER := 3.8.2

# ── Phony targets ─────────────────────────────────────────────────────────────
.PHONY: all clean distclean dirs \
    zlib libffi pcre2 libpng pixman bzip2 freetype expat \
    fontconfig harfbuzz glib wayland wayland-protocols xkbcommon \
    gl-headers cairo pango gdk-pixbuf atk epoxy gtk3

all: gtk-hello

dirs:
	mkdir -p $(SYSROOT) $(STAMPS) $(DLDIR) $(BLDDIR)

# $(HOST_TOOLS_BIN)/python3 is read by gtk-stack, mutter, hyprland-hos and elogind, and
# build.opts:13 puts $(HOST_TOOLS_BIN) on PATH -- but NOTHING in the tree creates it.
# The container papers over it (Dockerfile:164 symlinks /usr/bin/python3); a native
# build just died with "deps/.host-tools/bin/python3: not found" (exit 127).  Link it
# to whatever python3 is on PATH, so both paths work.
$(HOST_PYTHON):
	@mkdir -p $(HOST_TOOLS_BIN)
	@p="$$(command -v python3 || true)"; \
	 if [ -z "$$p" ]; then echo "[host-python] no python3 on PATH" >&2; exit 1; fi; \
	 ln -sfn "$$p" $@; \
	 echo "[host-python] linked $@ -> $$p"

$(HOST_PY_STAMP): $(HOST_PYTHON) $(SELF)/Makefile
	@echo "[host-python] Ensuring python packaging module..."
	@mkdir -p $(HOST_TOOLS_ROOT)
	@$(HOST_PYTHON) -c 'import packaging' >/dev/null 2>&1 || $(HOST_PIP_INSTALL) packaging
	@if [ -x "$(HOST_TOOLS_BIN)/meson" ] && \
	    $(HOST_PYTHON) "$(HOST_TOOLS_BIN)/meson" --version >/dev/null 2>&1; then \
	    if ! head -n1 "$(HOST_TOOLS_BIN)/meson" | grep -qx '#!$(HOST_PYTHON)'; then \
	        sed -i '1s|^#!.*|#!$(HOST_PYTHON)|' "$(HOST_TOOLS_BIN)/meson"; \
	    fi; \
	else \
	    $(HOST_PIP_INSTALL) --upgrade "meson==$(HOST_MESON_VER)"; \
	fi
	@touch $@

$(HOST_BISON): $(DLDIR)/bison-$(HOST_BISON_VER).tar.xz | dirs
	@echo "[host-bison] Building..."
	rm -rf $(BLDDIR)/bison-$(HOST_BISON_VER)
	tar -C $(BLDDIR) -xf $<
	cd $(BLDDIR)/bison-$(HOST_BISON_VER) && \
	    ./configure --prefix="$(HOST_TOOLS_ROOT)" INSTALL_INFO=true && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) INSTALL_INFO=true && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) INSTALL_INFO=true install

# ── Sysroot path relocation ───────────────────────────────────────────────────
# The committed sysroot metadata (.la/.pc/.cmake) carries absolute paths from
# the original developer's machine (/home/bruns/Documents/{Epin,H}anonymOS).
# Rewrite them to this checkout's $(PROJECT_ROOT) before any package build reads
# them. Idempotent: after the first run the literal is gone, so re-runs no-op.
$(STAMPS)/sysroot-relocated: $(SELF)/Makefile | dirs
	@echo "[gtk-stack] Relocating sysroot metadata to $(PROJECT_ROOT) ..."
	@find $(SYSROOT) -type f \( -name '*.pc' -o -name '*.la' -o -name '*.cmake' \) \
	    -exec sed -i \
	      -e 's|/home/bruns/Documents/EpinAnonymOS|$(PROJECT_ROOT)|g' \
	      -e 's|/home/bruns/Documents/HanonymOS|$(PROJECT_ROOT)|g' \
	      -e 's|/home/bruns/Documents/haskellos|$(PROJECT_ROOT)|g' \
	      {} +
	@touch $@

# ── Meson cross-file (shared by all meson-based packages) ─────────────────────
# Depends on sysroot-relocated so the regenerated cross-file (and every package
# that consumes it) sees correct, local paths.
$(STAMPS)/meson-cross.ini: $(STAMPS)/sysroot-relocated $(MUSL_CC) $(MUSL_CXX) $(CXXRT_STAMP) $(HOST_PY_STAMP) $(SELF)/Makefile | dirs
	@echo "[gtk-stack] Generating meson cross-file..."
	@printf '[binaries]\n'                                             >  $@
	@printf "c = '%s'\n"            "$(CC)"                           >> $@
	@printf "cpp = '%s'\n"          "$(CXX)"                          >> $@
	@printf "ar = '%s'\n"           "$(AR)"                           >> $@
	@printf "strip = '%s'\n"        "$(STRIP)"                        >> $@
	@printf "ranlib = '%s'\n"       "$(RANLIB)"                       >> $@
	@printf "pkg-config = 'pkg-config'\n"                              >> $@
	@# Use host wayland-scanner (build-time codegen tool)
	@printf "wayland-scanner = '%s'\n" "$$(which wayland-scanner 2>/dev/null || echo wayland-scanner)" >> $@
	@printf '\n[built-in options]\n'                                   >> $@
	@printf "c_args = ['-O2', '-fPIC', '-isystem', '%s',\n" \
	    "$(CLANG_RESOURCE_INCLUDE)"                                    >> $@
	@printf "          '-I%s/include', '-I%s/include/freetype2', '-I%s/include/libpng16', '-I%s/include']\n" \
	    "$(SYSROOT)" "$(SYSROOT)" "$(SYSROOT)" "$(MUSL_INSTALL)"      >> $@
	@printf "cpp_args = ['-O2', '-fPIC', '-isystem', '%s',\n" \
	    "$(CLANG_RESOURCE_INCLUDE)"                                    >> $@
	@printf "            '-I%s/include', '-I%s/include/freetype2', '-I%s/include/libpng16', '-I%s/include']\n" \
	    "$(SYSROOT)" "$(SYSROOT)" "$(SYSROOT)" "$(MUSL_INSTALL)"      >> $@
	@printf "c_link_args = ['-Wl,--allow-multiple-definition', '-no-pie', '-L%s/lib', '-L%s/lib']\n" \
	    "$(SYSROOT)" "$(MUSL_INSTALL)"                                 >> $@
	@printf "cpp_link_args = ['-Wl,--allow-multiple-definition', '-no-pie', '-L%s/lib', '-L%s/lib']\n" \
	    "$(SYSROOT)" "$(MUSL_INSTALL)"                                 >> $@
	@printf '\n[properties]\n'                                         >> $@
	@printf "need_exe_wrapper = true\n"                                 >> $@
	@printf "sys_root = '%s'\n" "$(SYSROOT)"                           >> $@
	@printf '\n[host_machine]\n'                                       >> $@
	@printf "system = 'linux'\n"                                        >> $@
	@printf "cpu_family = 'x86_64'\n"                                   >> $@
	@printf "cpu = 'x86_64'\n"                                          >> $@
	@printf "endian = 'little'\n"                                       >> $@

CROSS_FILE := $(STAMPS)/meson-cross.ini

# Meson configure shorthand
define MESON_SETUP
PATH="$(HOST_TOOLS_BIN):$$PATH" \
$(PKG_CONFIG_ENV) \
$(MESON) setup $(2) $(1) \
    --cross-file $(CROSS_FILE) \
    --prefix=$(SYSROOT) \
    --buildtype=release \
    --default-library=static
endef

# ── Download helper ───────────────────────────────────────────────────────────
# Usage: $(eval $(call FETCH,filename,url))
define FETCH
$(DLDIR)/$(1): | dirs
	@echo "[gtk-stack] Downloading $(1)..."
	@set -e; tmp="$$@.tmp"; rm -f "$$tmp" "$$@"; \
	curl -fsSL -o "$$tmp" $(2) || wget -q -O "$$tmp" $(2); \
	mv "$$tmp" "$$@"
endef

$(eval $(call FETCH,bison-$(HOST_BISON_VER).tar.xz,https://ftp.gnu.org/gnu/bison/bison-$(HOST_BISON_VER).tar.xz))

# ==========================================================================
# zlib
# ==========================================================================
$(eval $(call FETCH,zlib-$(ZLIB_VER).tar.gz,https://zlib.net/fossils/zlib-$(ZLIB_VER).tar.gz))

$(STAMPS)/zlib: $(DLDIR)/zlib-$(ZLIB_VER).tar.gz $(SELF)/Makefile | dirs
	@echo "[zlib] Building..."
	rm -rf $(BLDDIR)/zlib-$(ZLIB_VER)
	mkdir -p $(BLDDIR)/zlib-$(ZLIB_VER)
	tar -C $(BLDDIR) -xf $<
	cd $(BLDDIR)/zlib-$(ZLIB_VER) && \
	    CC="$(CC)" CFLAGS="$(BASE_CFLAGS)" LDFLAGS="$(BASE_LDFLAGS)" \
	    ./configure --prefix=$(SYSROOT) --static && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

zlib: $(STAMPS)/zlib

# ==========================================================================
# libffi
# ==========================================================================
$(eval $(call FETCH,libffi-$(LIBFFI_VER).tar.gz,https://github.com/libffi/libffi/releases/download/v$(LIBFFI_VER)/libffi-$(LIBFFI_VER).tar.gz))

$(STAMPS)/libffi: $(DLDIR)/libffi-$(LIBFFI_VER).tar.gz $(SELF)/Makefile | dirs
	@echo "[libffi] Building..."
	rm -rf $(BLDDIR)/libffi-$(LIBFFI_VER)
	tar -C $(BLDDIR) -xf $<
	mkdir -p $(BLDDIR)/libffi-$(LIBFFI_VER)/_build
	cd $(BLDDIR)/libffi-$(LIBFFI_VER)/_build && \
	    ../configure $(CONFIGURE_COMMON) \
	        --disable-multi-os-directory \
	        --disable-exec-static-tramp && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libffi: $(STAMPS)/libffi

# ==========================================================================
# pcre2
# ==========================================================================
$(eval $(call FETCH,pcre2-$(PCRE2_VER).tar.gz,https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$(PCRE2_VER)/pcre2-$(PCRE2_VER).tar.gz))

$(STAMPS)/pcre2: $(DLDIR)/pcre2-$(PCRE2_VER).tar.gz $(SELF)/Makefile | dirs
	@echo "[pcre2] Building..."
	rm -rf $(BLDDIR)/pcre2-$(PCRE2_VER)
	tar -C $(BLDDIR) -xf $<
	mkdir -p $(BLDDIR)/pcre2-$(PCRE2_VER)/_build
	cd $(BLDDIR)/pcre2-$(PCRE2_VER)/_build && \
	    ../configure $(CONFIGURE_COMMON) \
	        --enable-pcre2-8 \
	        --enable-unicode \
	        --disable-pcre2grep-libz \
	        --disable-pcre2grep-libbz2 \
	        --disable-pcre2test-libreadline && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

pcre2: $(STAMPS)/pcre2

# ==========================================================================
# libpng
# ==========================================================================
$(eval $(call FETCH,libpng-$(LIBPNG_VER).tar.gz,https://downloads.sourceforge.net/libpng/libpng-$(LIBPNG_VER).tar.gz))

$(STAMPS)/libpng: $(DLDIR)/libpng-$(LIBPNG_VER).tar.gz $(STAMPS)/zlib $(SELF)/Makefile | dirs
	@echo "[libpng] Building..."
	rm -rf $(BLDDIR)/libpng-$(LIBPNG_VER)
	tar -C $(BLDDIR) -xf $<
	mkdir -p $(BLDDIR)/libpng-$(LIBPNG_VER)/_build
	cd $(BLDDIR)/libpng-$(LIBPNG_VER)/_build && \
	    ../configure $(CONFIGURE_COMMON) && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

libpng: $(STAMPS)/libpng

# ==========================================================================
# pixman
# ==========================================================================
$(eval $(call FETCH,pixman-$(PIXMAN_VER).tar.gz,https://cairographics.org/releases/pixman-$(PIXMAN_VER).tar.gz))

$(STAMPS)/pixman: $(DLDIR)/pixman-$(PIXMAN_VER).tar.gz $(STAMPS)/meson-cross.ini $(SELF)/Makefile | dirs
	@echo "[pixman] Building..."
	rm -rf $(BLDDIR)/pixman-$(PIXMAN_VER)
	tar -C $(BLDDIR) -xf $<
	cd $(BLDDIR)/pixman-$(PIXMAN_VER) && \
	    $(MESON_SETUP) build \
	        -Dopenmp=disabled \
	        -Dgtk=disabled \
	        -Ddemos=disabled \
	        -Dtests=disabled \
	        -Dlibpng=disabled && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

pixman: $(STAMPS)/pixman

# ==========================================================================
# bzip2  (plain Makefile, no configure)
# ==========================================================================
$(eval $(call FETCH,bzip2-$(BZIP2_VER).tar.gz,https://sourceware.org/pub/bzip2/bzip2-$(BZIP2_VER).tar.gz))

$(STAMPS)/bzip2: $(DLDIR)/bzip2-$(BZIP2_VER).tar.gz $(SELF)/Makefile | dirs
	@echo "[bzip2] Building..."
	rm -rf $(BLDDIR)/bzip2-$(BZIP2_VER)
	tar -C $(BLDDIR) -xf $<
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(BLDDIR)/bzip2-$(BZIP2_VER) \
	    CC="$(CC)" AR="$(AR)" RANLIB="$(RANLIB)" \
	    CFLAGS="$(BASE_CFLAGS) -fPIC" \
	    libbz2.a
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(BLDDIR)/bzip2-$(BZIP2_VER) \
	    PREFIX="$(SYSROOT)" install
	touch $@

bzip2: $(STAMPS)/bzip2

# ==========================================================================
# freetype (built without HarfBuzz to break the circular dep)
# ==========================================================================
$(eval $(call FETCH,freetype-$(FT_VER).tar.xz,https://downloads.sourceforge.net/freetype/freetype-$(FT_VER).tar.xz))

$(STAMPS)/freetype: $(DLDIR)/freetype-$(FT_VER).tar.xz \
    $(STAMPS)/zlib $(STAMPS)/libpng $(STAMPS)/bzip2 $(SELF)/Makefile | dirs
	@echo "[freetype] Building (no harfbuzz)..."
	rm -rf $(BLDDIR)/freetype-$(FT_VER)
	tar -C $(BLDDIR) -xf $<
	mkdir -p $(BLDDIR)/freetype-$(FT_VER)/_build
	cd $(BLDDIR)/freetype-$(FT_VER)/_build && \
	    ../configure $(CONFIGURE_COMMON) \
	        --with-zlib=yes \
	        --with-bzip2=yes \
	        --with-png=yes \
	        --with-harfbuzz=no \
	        --with-brotli=no && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

freetype: $(STAMPS)/freetype

# ==========================================================================
# expat
# ==========================================================================
$(eval $(call FETCH,expat-$(EXPAT_VER).tar.gz,https://github.com/libexpat/libexpat/releases/download/$(EXPAT_TAG)/expat-$(EXPAT_VER).tar.gz))

$(STAMPS)/expat: $(DLDIR)/expat-$(EXPAT_VER).tar.gz $(SELF)/Makefile | dirs
	@echo "[expat] Building..."
	rm -rf $(BLDDIR)/expat-$(EXPAT_VER)
	tar -C $(BLDDIR) -xf $<
	mkdir -p $(BLDDIR)/expat-$(EXPAT_VER)/_build
	cd $(BLDDIR)/expat-$(EXPAT_VER)/_build && \
	    ../configure $(CONFIGURE_COMMON) \
	        --without-docbook \
	        --without-examples \
	        --without-tests && \
	    $(MAKE) $(MAKE_BUILD_FLAGS) && $(MAKE) $(MAKE_BUILD_FLAGS) install
	touch $@

expat: $(STAMPS)/expat

# ==========================================================================
# fontconfig  (meson)
# ==========================================================================
$(eval $(call FETCH,fontconfig-$(FCONF_VER).tar.xz,https://www.freedesktop.org/software/fontconfig/release/fontconfig-$(FCONF_VER).tar.xz))

$(STAMPS)/fontconfig: $(DLDIR)/fontconfig-$(FCONF_VER).tar.xz \
    $(STAMPS)/freetype $(STAMPS)/expat $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[fontconfig] Building..."
	rm -rf $(BLDDIR)/fontconfig-$(FCONF_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/fontconfig-$(FCONF_VER), \
	    $(BLDDIR)/fontconfig-$(FCONF_VER)/_build) \
	    -Ddoc=disabled \
	    -Dtests=disabled \
	    -Dtools=disabled
	$(NINJA) -C $(BLDDIR)/fontconfig-$(FCONF_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/fontconfig-$(FCONF_VER)/_build install
	touch $@

fontconfig: $(STAMPS)/fontconfig

# ==========================================================================
# harfbuzz  (meson, depends on freetype + glib; build without glib first)
# ==========================================================================
$(eval $(call FETCH,harfbuzz-$(HBUZZ_VER).tar.xz,https://github.com/harfbuzz/harfbuzz/releases/download/$(HBUZZ_VER)/harfbuzz-$(HBUZZ_VER).tar.xz))

$(STAMPS)/harfbuzz: $(DLDIR)/harfbuzz-$(HBUZZ_VER).tar.xz \
    $(STAMPS)/freetype $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[harfbuzz] Building..."
	rm -rf $(BLDDIR)/harfbuzz-$(HBUZZ_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/harfbuzz-$(HBUZZ_VER), \
	    $(BLDDIR)/harfbuzz-$(HBUZZ_VER)/_build) \
	    -Dglib=disabled \
	    -Dgobject=disabled \
	    -Dicu=disabled \
	    -Dtests=disabled \
	    -Ddocs=disabled \
	    -Dbenchmark=disabled \
	    -Dfreetype=enabled
	$(NINJA) -C $(BLDDIR)/harfbuzz-$(HBUZZ_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/harfbuzz-$(HBUZZ_VER)/_build install
	touch $@

harfbuzz: $(STAMPS)/harfbuzz

# ==========================================================================
# glib  (meson)
# ==========================================================================
$(eval $(call FETCH,glib-$(GLIB_VER).tar.xz,https://download.gnome.org/sources/glib/$(GLIB_MAJ)/glib-$(GLIB_VER).tar.xz))

$(STAMPS)/glib: $(DLDIR)/glib-$(GLIB_VER).tar.xz \
    $(STAMPS)/zlib $(STAMPS)/libffi $(STAMPS)/pcre2 $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[glib] Building..."
	rm -rf $(BLDDIR)/glib-$(GLIB_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/glib-$(GLIB_VER), \
	    $(BLDDIR)/glib-$(GLIB_VER)/_build) \
	    -Dtests=false \
	    -Dintrospection=disabled \
	    -Ddocumentation=false \
	    -Dman-pages=disabled \
	    -Dselinux=disabled \
	    -Dxattr=false \
	    -Dlibmount=disabled \
	    -Ddtrace=false \
	    -Dsysprof=disabled \
	    -Dinstalled_tests=false
	$(NINJA) -C $(BLDDIR)/glib-$(GLIB_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/glib-$(GLIB_VER)/_build install
	touch $@

glib: $(STAMPS)/glib

# ==========================================================================
# wayland  (meson; only wayland-client, no wayland-server scanner)
# ==========================================================================
$(eval $(call FETCH,wayland-$(WAYLAND_VER).tar.xz,https://gitlab.freedesktop.org/wayland/wayland/-/releases/$(WAYLAND_VER)/downloads/wayland-$(WAYLAND_VER).tar.xz))

$(STAMPS)/wayland: $(DLDIR)/wayland-$(WAYLAND_VER).tar.xz \
    $(STAMPS)/expat $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[wayland] Building (client only)..."
	rm -rf $(BLDDIR)/wayland-$(WAYLAND_VER)
	tar -C $(BLDDIR) -xf $<
	sed -E -i 's/ deprecated-since="[^"]*"//g' \
	    $(BLDDIR)/wayland-$(WAYLAND_VER)/protocol/wayland.xml
	sed -i "s#scanner_dep = dependency('wayland-scanner', native: true, version: meson.project_version())#wayland_scanner_for_build = find_program('wayland-scanner', native: true, required: true)#" \
	    $(BLDDIR)/wayland-$(WAYLAND_VER)/src/meson.build
	sed -i "/wayland_scanner_for_build = find_program(scanner_dep.get_variable(pkgconfig: 'wayland_scanner'))/d" \
	    $(BLDDIR)/wayland-$(WAYLAND_VER)/src/meson.build
	$(call MESON_SETUP, \
	    $(BLDDIR)/wayland-$(WAYLAND_VER), \
	    $(BLDDIR)/wayland-$(WAYLAND_VER)/_build) \
	    -Dscanner=false \
	    -Dlibraries=true \
	    -Dtests=false \
	    -Ddocumentation=false \
	    -Ddtd_validation=false
	$(NINJA) -C $(BLDDIR)/wayland-$(WAYLAND_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/wayland-$(WAYLAND_VER)/_build install
	mkdir -p $(SYSROOT)/share/wayland $(SYSROOT)/share/pkgconfig
	cp $(BLDDIR)/wayland-$(WAYLAND_VER)/protocol/wayland.xml \
	    $(SYSROOT)/share/wayland/wayland.xml
	printf 'prefix=%s\nexec_prefix=$${prefix}\ndatadir=$${prefix}/share\npkgdatadir=$${datadir}/wayland\nwayland_scanner=wayland-scanner\n\nName: wayland-scanner\nDescription: Host wayland-scanner shim for Meson native dependency lookup\nVersion: %s\nLibs:\nCflags:\n' \
	    "$(SYSROOT)" "$(WAYLAND_VER)" > $(SYSROOT)/share/pkgconfig/wayland-scanner.pc
	touch $@

wayland: $(STAMPS)/wayland

# ==========================================================================
# wayland-protocols  (meson; installs protocol XML + pkg-config metadata)
# ==========================================================================
$(eval $(call FETCH,wayland-protocols-$(WPROTO_VER).tar.xz,https://gitlab.freedesktop.org/wayland/wayland-protocols/-/releases/$(WPROTO_VER)/downloads/wayland-protocols-$(WPROTO_VER).tar.xz))

$(STAMPS)/wayland-protocols: $(DLDIR)/wayland-protocols-$(WPROTO_VER).tar.xz \
    $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[wayland-protocols] Building..."
	rm -rf $(BLDDIR)/wayland-protocols-$(WPROTO_VER)
	tar -C $(BLDDIR) -xf $<
	sed -i "11,16c\\prog_scanner = find_program('wayland-scanner', native: true, required: true)" \
	    $(BLDDIR)/wayland-protocols-$(WPROTO_VER)/meson.build
	sed -i "s#if dep_scanner.version().version_compare('>=1.22.90')#if false#" \
	    $(BLDDIR)/wayland-protocols-$(WPROTO_VER)/meson.build
	$(call MESON_SETUP, \
	    $(BLDDIR)/wayland-protocols-$(WPROTO_VER), \
	    $(BLDDIR)/wayland-protocols-$(WPROTO_VER)/_build) \
	    --wrap-mode=nofallback \
	    -Dtests=false
	$(NINJA) -C $(BLDDIR)/wayland-protocols-$(WPROTO_VER)/_build $(NINJA_BUILD_FLAGS) install
	touch $@

wayland-protocols: $(STAMPS)/wayland-protocols

# ==========================================================================
# xkbcommon  (meson)
# ==========================================================================
$(eval $(call FETCH,libxkbcommon-$(XKB_VER).tar.xz,https://xkbcommon.org/download/libxkbcommon-$(XKB_VER).tar.xz))

$(STAMPS)/xkbcommon: $(DLDIR)/libxkbcommon-$(XKB_VER).tar.xz \
    $(CROSS_FILE) $(HOST_BISON) $(SELF)/Makefile | dirs
	@echo "[xkbcommon] Building..."
	rm -rf $(BLDDIR)/libxkbcommon-$(XKB_VER)
	tar -C $(BLDDIR) -xf $<
	PATH="$(HOST_TOOLS_BIN):$$PATH" $(call MESON_SETUP, \
	    $(BLDDIR)/libxkbcommon-$(XKB_VER), \
	    $(BLDDIR)/libxkbcommon-$(XKB_VER)/_build) \
	    -Denable-docs=false \
	    -Denable-wayland=false \
	    -Denable-x11=false \
	    -Denable-xkbregistry=false
	PATH="$(HOST_TOOLS_BIN):$$PATH" $(NINJA) -C $(BLDDIR)/libxkbcommon-$(XKB_VER)/_build $(NINJA_BUILD_FLAGS)
	PATH="$(HOST_TOOLS_BIN):$$PATH" $(NINJA) -C $(BLDDIR)/libxkbcommon-$(XKB_VER)/_build install
	touch $@

xkbcommon: $(STAMPS)/xkbcommon

# ==========================================================================
# gl-headers  (stage host Khronos/OpenGL headers into the target sysroot)
# ==========================================================================
$(STAMPS)/gl-headers: $(SELF)/Makefile | dirs
	@echo "[gl-headers] Staging host GL/EGL headers (optional: skipped if absent)..."
	mkdir -p $(SYSROOT)/include
	@# Replace a header directory ONLY when the host actually has one to replace it
	@# with.  The sysroot ships its own copies of these six; blanket-deleting them
	@# first meant a machine without the Khronos dev packages (a container, say) was
	@# left with no GL headers at all, and libepoxy then failed to compile with
	@# "Has header KHR/khrplatform.h : NO".
	@for d in $(GL_HEADER_DIRS); do \
	    if [ -d "/usr/include/$$d" ]; then \
	        rm -rf "$(SYSROOT)/include/$$d"; \
	        cp -a "/usr/include/$$d" "$(SYSROOT)/include/"; \
	    elif [ -d "$(SYSROOT)/include/$$d" ]; then \
	        echo "[gl-headers] /usr/include/$$d absent — keeping the sysroot's own $$d headers"; \
	    else \
	        echo "[gl-headers] host header directory /usr/include/$$d not found — skipping (GL/EGL optional; software-rendering path unaffected)"; \
	    fi; \
	done
	# Create empty stub static libraries for EGL/gbm/GLESv2/glapi so packages
	# that detect the GL headers and add -lEGL etc. to their link line succeed.
	# anonymOS uses the Pixman software renderer — GL is never called at runtime,
	# so the stubs only need to satisfy the linker (empty archives with one .o).
	@for lib in EGL gbm GLESv2 glapi; do \
	    if [ ! -f "$(SYSROOT)/lib/lib$$lib.a" ]; then \
	        tmpobj=$$(mktemp /tmp/glstub_XXXXXX.o); \
	        printf '' | $(CC) -xc -c - -o $$tmpobj 2>/dev/null || \
	        printf '' | clang -xc -c - -o $$tmpobj 2>/dev/null; \
	        $(AR) rcs "$(SYSROOT)/lib/lib$$lib.a" $$tmpobj; \
	        rm -f $$tmpobj; \
	        echo "[gl-headers] created stub: lib$$lib.a"; \
	    fi; \
	done
	touch $@

gl-headers: $(STAMPS)/gl-headers

# ==========================================================================
# cairo  (meson)
# ==========================================================================
$(eval $(call FETCH,cairo-$(CAIRO_VER).tar.xz,https://cairographics.org/releases/cairo-$(CAIRO_VER).tar.xz))

$(STAMPS)/cairo: $(DLDIR)/cairo-$(CAIRO_VER).tar.xz \
    $(STAMPS)/pixman $(STAMPS)/libpng $(STAMPS)/freetype \
    $(STAMPS)/fontconfig $(STAMPS)/zlib $(STAMPS)/meson-cross.ini \
    $(SELF)/Makefile | dirs
	@echo "[cairo] Building..."
	rm -rf $(BLDDIR)/cairo-$(CAIRO_VER)
	tar -C $(BLDDIR) -xf $<
	cd $(BLDDIR)/cairo-$(CAIRO_VER) && \
	    $(MESON_SETUP) build \
	        -Dxlib=disabled \
	        -Dxcb=disabled \
	    -Dquartz=disabled \
	    -Dfontconfig=enabled \
	    -Dfreetype=enabled \
	    -Dpng=enabled \
	    -Dzlib=enabled \
	    -Dtests=disabled \
	    -Dgtk_doc=false \
	    -Dgtk2-utils=disabled \
	        -Dspectre=disabled \
	        -Dsymbol-lookup=disabled && \
	    $(NINJA) -C build $(NINJA_BUILD_FLAGS) install
	touch $@

cairo: $(STAMPS)/cairo

# ==========================================================================
# fribidi 1.0.16  (meson) — Unicode bidirectional algorithm, needed by pango.
# The committed sysroot has the headers + .pc but no libfribidi.a (gitignored).
# ==========================================================================
FRIBIDI_VER := 1.0.16
$(eval $(call FETCH,fribidi-$(FRIBIDI_VER).tar.xz,https://github.com/fribidi/fribidi/releases/download/v$(FRIBIDI_VER)/fribidi-$(FRIBIDI_VER).tar.xz))

$(STAMPS)/fribidi: $(DLDIR)/fribidi-$(FRIBIDI_VER).tar.xz $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[fribidi] Building..."
	rm -rf $(BLDDIR)/fribidi-$(FRIBIDI_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/fribidi-$(FRIBIDI_VER), \
	    $(BLDDIR)/fribidi-$(FRIBIDI_VER)/_build) \
	    -Ddocs=false -Dbin=false
	$(NINJA) -C $(BLDDIR)/fribidi-$(FRIBIDI_VER)/_build $(NINJA_BUILD_FLAGS) install
	touch $@

fribidi: $(STAMPS)/fribidi

# ==========================================================================
# pango  (meson)
# ==========================================================================
$(eval $(call FETCH,pango-$(PANGO_VER).tar.xz,https://download.gnome.org/sources/pango/$(PANGO_MAJ)/pango-$(PANGO_VER).tar.xz))

$(STAMPS)/pango: $(DLDIR)/pango-$(PANGO_VER).tar.xz \
    $(STAMPS)/glib $(STAMPS)/harfbuzz $(STAMPS)/fontconfig \
    $(STAMPS)/freetype $(STAMPS)/cairo $(STAMPS)/fribidi $(CROSS_FILE) \
    $(SELF)/Makefile | dirs
	@echo "[pango] Building..."
	rm -rf $(BLDDIR)/pango-$(PANGO_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/pango-$(PANGO_VER), \
	    $(BLDDIR)/pango-$(PANGO_VER)/_build) \
	    -Dintrospection=disabled \
	    -Dgtk_doc=false \
	    -Dbuild-testsuite=false \
	    -Dbuild-examples=false
	$(NINJA) -C $(BLDDIR)/pango-$(PANGO_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/pango-$(PANGO_VER)/_build install
	touch $@

pango: $(STAMPS)/pango

# ==========================================================================
# gdk-pixbuf  (meson)
# ==========================================================================
$(eval $(call FETCH,gdk-pixbuf-$(GDKPB_VER).tar.xz,https://download.gnome.org/sources/gdk-pixbuf/$(GDKPB_MAJ)/gdk-pixbuf-$(GDKPB_VER).tar.xz))

$(STAMPS)/gdk-pixbuf: $(DLDIR)/gdk-pixbuf-$(GDKPB_VER).tar.xz \
    $(STAMPS)/glib $(STAMPS)/libpng $(STAMPS)/zlib $(CROSS_FILE) \
    $(SELF)/Makefile | dirs
	@echo "[gdk-pixbuf] Building..."
	rm -rf $(BLDDIR)/gdk-pixbuf-$(GDKPB_VER)
	tar -C $(BLDDIR) -xf $<
	sed -i "s/included_loaders_deps += declare_dependency(link_with: mod)/included_loaders_deps += declare_dependency(link_with: mod, dependencies: loaders_deps)/" \
	    $(BLDDIR)/gdk-pixbuf-$(GDKPB_VER)/gdk-pixbuf/meson.build
	$(call MESON_SETUP, \
	    $(BLDDIR)/gdk-pixbuf-$(GDKPB_VER), \
	    $(BLDDIR)/gdk-pixbuf-$(GDKPB_VER)/_build) \
	    -Dman=false \
	    -Dgtk_doc=false \
	    -Dintrospection=disabled \
	    -Dtests=false \
	    -Dinstalled_tests=false \
	    -Dgio_sniffing=false \
	    -Dgif=disabled \
	    -Dothers=disabled \
	    -Dbuiltin_loaders=png \
	    -Dpng=enabled \
	    -Djpeg=disabled \
	    -Dtiff=disabled
	$(NINJA) -C $(BLDDIR)/gdk-pixbuf-$(GDKPB_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/gdk-pixbuf-$(GDKPB_VER)/_build install
	touch $@

gdk-pixbuf: $(STAMPS)/gdk-pixbuf

# ==========================================================================
# atk  (meson)
# ==========================================================================
$(eval $(call FETCH,atk-$(ATK_VER).tar.xz,https://download.gnome.org/sources/atk/$(ATK_MAJ)/atk-$(ATK_VER).tar.xz))

$(STAMPS)/atk: $(DLDIR)/atk-$(ATK_VER).tar.xz \
    $(STAMPS)/glib $(CROSS_FILE) | dirs
	@echo "[atk] Building..."
	rm -rf $(BLDDIR)/atk-$(ATK_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/atk-$(ATK_VER), \
	    $(BLDDIR)/atk-$(ATK_VER)/_build) \
	    -Dintrospection=false \
	    -Ddocs=false
	$(NINJA) -C $(BLDDIR)/atk-$(ATK_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/atk-$(ATK_VER)/_build install
	touch $@

atk: $(STAMPS)/atk

# ==========================================================================
# epoxy  (meson; EGL-only, no X11/GLX)
# ==========================================================================
$(eval $(call FETCH,libepoxy-$(EPOXY_VER).tar.gz,https://github.com/anholt/libepoxy/archive/refs/tags/$(EPOXY_VER).tar.gz))

$(STAMPS)/epoxy: $(DLDIR)/libepoxy-$(EPOXY_VER).tar.gz \
    $(STAMPS)/gl-headers $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[epoxy] Building..."
	rm -rf $(BLDDIR)/libepoxy-$(EPOXY_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/libepoxy-$(EPOXY_VER), \
	    $(BLDDIR)/libepoxy-$(EPOXY_VER)/_build) \
	    -Ddocs=false \
	    -Dtests=false \
	    -Dglx=no \
	    -Degl=yes \
	    -Dx11=false
	$(NINJA) -C $(BLDDIR)/libepoxy-$(EPOXY_VER)/_build $(NINJA_BUILD_FLAGS)
	$(NINJA) -C $(BLDDIR)/libepoxy-$(EPOXY_VER)/_build install
	touch $@

epoxy: $(STAMPS)/epoxy

# ==========================================================================
# gtk3  (meson)
# ==========================================================================
$(eval $(call FETCH,gtk+-$(GTK3_VER).tar.xz,https://download.gnome.org/sources/gtk+/$(GTK3_MAJ)/gtk+-$(GTK3_VER).tar.xz))

$(STAMPS)/gtk3: $(DLDIR)/gtk+-$(GTK3_VER).tar.xz \
    $(STAMPS)/glib $(STAMPS)/cairo $(STAMPS)/pango \
    $(STAMPS)/gdk-pixbuf $(STAMPS)/atk \
    $(STAMPS)/wayland $(STAMPS)/wayland-protocols \
    $(STAMPS)/xkbcommon $(STAMPS)/epoxy \
    $(CROSS_FILE) $(SELF)/Makefile | dirs
	@echo "[gtk3] Building..."
	rm -rf $(BLDDIR)/gtk+-$(GTK3_VER)
	tar -C $(BLDDIR) -xf $<
	$(call MESON_SETUP, \
	    $(BLDDIR)/gtk+-$(GTK3_VER), \
	    $(BLDDIR)/gtk+-$(GTK3_VER)/_build) \
	    --wrap-mode=nofallback \
	    -Dx11_backend=false \
	    -Dwayland_backend=true \
	    -Dbroadway_backend=false \
	    -Dwin32_backend=false \
	    -Dquartz_backend=false \
	    -Dxinerama=no \
	    -Dcloudproviders=false \
	    -Dprofiler=false \
	    -Dtracker3=false \
	    -Dprint_backends=file \
	    -Dcolord=no \
	    -Dintrospection=false \
	    -Dgtk_doc=false \
	    -Dman=false \
	    -Ddemos=true \
	    -Dexamples=true \
	    -Dtests=false \
	    -Dinstalled_tests=false \
	    -Dbuiltin_immodules=backend
	@# gtk.gresources.xml asks glib-compile-resources for `to-pixdata` preprocessing,
	@# which shells out to gdk-pixbuf-pixdata.  The cross-built one is installed in our
	@# own sysroot (static musl x86_64, so it runs fine on the build host) but is not on
	@# PATH, and without GDK_PIXBUF_PIXDATA set the resource step fails with
	@# "to-pixdata preprocessing requested, but GDK_PIXBUF_PIXDATA is not set".
	PIXDATA="$(SYSROOT)/bin/gdk-pixbuf-pixdata"; \
	[ -x "$$PIXDATA" ] || PIXDATA="$$(command -v gdk-pixbuf-pixdata 2>/dev/null)"; \
	echo "[gtk3] GDK_PIXBUF_PIXDATA=$$PIXDATA"; \
	export GDK_PIXBUF_PIXDATA="$$PIXDATA"; \
	$(NINJA) -C $(BLDDIR)/gtk+-$(GTK3_VER)/_build $(NINJA_BUILD_FLAGS) && \
	$(NINJA) -C $(BLDDIR)/gtk+-$(GTK3_VER)/_build install
	touch $@

gtk3: $(STAMPS)/gtk3

# ==========================================================================
# gtk-hello  — minimal GTK3/Wayland test app
# ==========================================================================
GTK_HELLO_SRC := $(SELF)/gtk_hello.c

$(GTK_HELLO_SRC):
	@echo "[gtk-hello] Writing test program..."
	@printf '#include <gtk/gtk.h>\n'                                    > $@
	@printf 'static void activate(GtkApplication *app, gpointer d) {\n' >> $@
	@printf '    GtkWidget *w = gtk_application_window_new(app);\n'    >> $@
	@printf '    gtk_window_set_title(GTK_WINDOW(w), "HanonymOS");\n'  >> $@
	@printf '    gtk_window_set_default_size(GTK_WINDOW(w), 640, 480);\n' >> $@
	@printf '    GtkWidget *l = gtk_label_new("HanonymOS Desktop");\n' >> $@
	@printf '    gtk_container_add(GTK_CONTAINER(w), l);\n'            >> $@
	@printf '    gtk_widget_show_all(w);\n'                             >> $@
	@printf '}\n'                                                       >> $@
	@printf 'int main(int argc, char **argv) {\n'                       >> $@
	@printf '    GtkApplication *app = gtk_application_new(\n'         >> $@
	@printf '        "os.hanonym.hello", G_APPLICATION_DEFAULT_FLAGS);\n' >> $@
	@printf '    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);\n' >> $@
	@printf '    int r = g_application_run(G_APPLICATION(app), argc, argv);\n' >> $@
	@printf '    g_object_unref(app);\n'                                >> $@
	@printf '    return r;\n'                                           >> $@
	@printf '}\n'                                                       >> $@

GTK3_CFLAGS := $(BASE_CFLAGS) \
    $$($(PKG_CONFIG_ENV) pkg-config --cflags gtk+-3.0)
GTK3_LIBS   := $$($(PKG_CONFIG_ENV) pkg-config --static --libs gtk+-3.0) \
    -Wl,-rpath,$(SYSROOT)/lib -Wl,-rpath-link,$(SYSROOT)/lib \
    -lwayland-server -lglapi \
    -lm -ldl -lpthread -lutil -lrt

gtk-hello: $(GTK_HELLO_SRC) $(STAMPS)/gtk3
	@echo "[gtk-hello] Compiling..."
	$(CC) $(GTK3_CFLAGS) -o $@ $< $(GTK3_LIBS)
	$(STRIP) $@
	@echo "[gtk-hello] Built: $(SELF)/gtk-hello"

# ==========================================================================
# Housekeeping
# ==========================================================================
clean:
	rm -rf $(BLDDIR) $(STAMPS) $(GTK_HELLO_SRC) gtk-hello

distclean: clean
	rm -rf $(SYSROOT) $(DLDIR)
