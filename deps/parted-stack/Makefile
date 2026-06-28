# ==========================================================================
# deps/parted-stack/Makefile
#
# The Calamares partitioning backend (roadmap/INSTALLER.md §D2.1), cross-built
# static against musl-clang.  Mirrors deps/gtk-stack's autotools-cross pattern
# (CC=musl-clang, --host=x86_64-linux-musl, -static -no-pie, output into sysroot/).
#
# Dependency order:
#   util-linux (libuuid + libblkid)  →  libparted (GPT/MBR table manipulation)
#
# KPMcore (§D2.2) then links Qt6 (deps/qt-stack) + libparted/libblkid (here).
#
# NOTE (the §D2 long-pole): util-linux + libparted need musl porting (Alpine carries
# the patches: __GLIBC__ guards, error.h/err.h, fts, etc.).  This Makefile is the
# build recipe; expect to add musl patches under patches/ as the cross-build surfaces
# them.  The roadmap's §D2(b) native object-FS partition module is the shippable
# default that sidesteps this swamp; D2.1/D2.2 are built in parallel for the standard
# Calamares `partition` module.
# ==========================================================================
PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF          := $(abspath .)
MUSL_INSTALL  := $(abspath ../musl/install)
SYSROOT       := $(SELF)/sysroot
STAMPS        := $(SELF)/stamps
DLDIR         := $(SELF)/downloads
BLDDIR        := $(SELF)/build

CLANG_RESOURCE_INCLUDE := $(LLVM_PREFIX)/lib/clang/18/include

# ── Cross tools (match deps/gtk-stack) ────────────────────────────────────────
CC      := $(MUSL_INSTALL)/bin/musl-clang
CXX     := $(MUSL_INSTALL)/bin/musl-clang++
AR      := llvm-ar
STRIP   := llvm-strip
RANLIB  := llvm-ranlib
NM      := llvm-nm

BASE_CFLAGS  := -O2 -fPIC -isystem $(CLANG_RESOURCE_INCLUDE) \
                -I$(SYSROOT)/include -I$(MUSL_INSTALL)/include
BASE_LDFLAGS := -static -no-pie -L$(SYSROOT)/lib -L$(MUSL_INSTALL)/lib

# pkg-config confined to this sysroot (so libparted finds util-linux's libuuid/blkid).
PKG_CONFIG_ENV := PKG_CONFIG_LIBDIR="$(SYSROOT)/lib/pkgconfig" PKG_CONFIG_PATH="" \
                  PKG_CONFIG_SYSROOT_DIR=""

RUN := $(BUILD_RESOURCE_RUN)

CONFIGURE_COMMON := \
    CC="$(CC)" CXX="$(CXX)" AR="$(AR)" STRIP="$(STRIP)" RANLIB="$(RANLIB)" NM="$(NM)" \
    CPPFLAGS="$(BASE_CFLAGS)" CFLAGS="$(BASE_CFLAGS)" LDFLAGS="$(BASE_LDFLAGS)" \
    $(PKG_CONFIG_ENV) \
    --prefix="$(SYSROOT)" --host=x86_64-linux-musl --build=x86_64-linux-gnu \
    --disable-shared --enable-static

UTIL_LINUX_VER ?= 2.40.2
UTIL_LINUX_SER ?= v2.40
PARTED_VER     ?= 3.6

.PHONY: all util-linux libparted clean
all: libparted

dirs:
	@mkdir -p $(SYSROOT) $(STAMPS) $(DLDIR) $(BLDDIR)

# ── util-linux: libuuid + libblkid only (no programs) ────────────────────────
util-linux: $(STAMPS)/util-linux
$(STAMPS)/util-linux: $(SELF)/Makefile | dirs
	@if [ ! -f $(DLDIR)/util-linux-$(UTIL_LINUX_VER).tar.xz ]; then \
	  echo "[parted-stack] fetching util-linux $(UTIL_LINUX_VER)"; \
	  curl -fSL --retry 3 -o $(DLDIR)/util-linux-$(UTIL_LINUX_VER).tar.xz \
	     https://www.kernel.org/pub/linux/utils/util-linux/$(UTIL_LINUX_SER)/util-linux-$(UTIL_LINUX_VER).tar.xz; \
	fi
	@rm -rf $(BLDDIR)/util-linux; mkdir -p $(BLDDIR)/util-linux
	tar -xf $(DLDIR)/util-linux-$(UTIL_LINUX_VER).tar.xz -C $(BLDDIR)/util-linux --strip-components=1
	cd $(BLDDIR)/util-linux && $(RUN) ./configure $(CONFIGURE_COMMON) \
	    --disable-all-programs --enable-libuuid --enable-libblkid \
	    --without-python --disable-nls --disable-asciidoc
	$(RUN) $(MAKE) -C $(BLDDIR)/util-linux $(MAKE_BUILD_FLAGS)
	$(RUN) $(MAKE) -C $(BLDDIR)/util-linux install
	@touch $@

# ── libparted: GPT/MBR table manipulation (links util-linux libuuid) ─────────
libparted: $(STAMPS)/libparted
$(STAMPS)/libparted: $(STAMPS)/util-linux
	@if [ ! -f $(DLDIR)/parted-$(PARTED_VER).tar.xz ]; then \
	  echo "[parted-stack] fetching parted $(PARTED_VER)"; \
	  curl -fSL --retry 3 -o $(DLDIR)/parted-$(PARTED_VER).tar.xz \
	     https://ftp.gnu.org/gnu/parted/parted-$(PARTED_VER).tar.xz; \
	fi
	@rm -rf $(BLDDIR)/parted; mkdir -p $(BLDDIR)/parted
	tar -xf $(DLDIR)/parted-$(PARTED_VER).tar.xz -C $(BLDDIR)/parted --strip-components=1
	cd $(BLDDIR)/parted && $(RUN) ./configure $(CONFIGURE_COMMON) \
	    --disable-device-mapper --without-readline --disable-nls \
	    --disable-rpath
	$(RUN) $(MAKE) -C $(BLDDIR)/parted $(MAKE_BUILD_FLAGS)
	$(RUN) $(MAKE) -C $(BLDDIR)/parted install
	@touch $@

clean:
	rm -rf $(BLDDIR) $(STAMPS) $(SYSROOT)
