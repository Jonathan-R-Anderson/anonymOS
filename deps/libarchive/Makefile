# deps/libarchive — musl-static bsdtar for the DECOY_DISTRO ISO9660 read step (D8).
# The distro live-ISO is ISO9660 (+ Rock Ridge/Joliet); bsdtar reads it and extracts the
# inner `casper/filesystem.squashfs` (or `LiveOS/squashfs.img`) that unsquashfs then
# decompresses. Built static against musl, reusing our liblzma + the gtk-stack zlib.
# Output: bsdtar (static) — staged into the installer ISO.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang

XZ_SYSROOT   := $(abspath ../xz/sysroot)
ZLIB_SYSROOT := $(abspath ../gtk-stack/sysroot)

LA_VERSION := 3.7.4
LA_TARBALL := libarchive-$(LA_VERSION).tar.gz
LA_URL     := https://github.com/libarchive/libarchive/releases/download/v$(LA_VERSION)/$(LA_TARBALL)
LA_SRC     := libarchive-$(LA_VERSION)
SELF       := $(abspath .)
BLD        := $(SELF)/build

BSDTAR := $(SELF)/bsdtar

.PHONY: all clean distclean
all: $(BSDTAR)

$(LA_TARBALL):
	@echo "[libarchive] downloading $(LA_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(LA_URL) || wget -q -O "$$tmp" $(LA_URL); \
	mv "$$tmp" "$@"

$(LA_SRC)/configure: $(LA_TARBALL)
	@echo "[libarchive] extracting..."
	@rm -rf $(LA_SRC); tar -xzf $(LA_TARBALL); touch $@

# Static bsdtar. We only need read support for ISO9660 (+ its filters) — disable the
# formats/crypto we don't use to keep it lean and dependency-light. zlib + liblzma give
# gzip/xz filter coverage; iso9660 read is built in.
$(BSDTAR): $(LA_SRC)/configure
	@echo "[libarchive] configuring + building static bsdtar (musl)..."
	@mkdir -p $(BLD)
	@mkdir -p $(BLD)
	@cd $(BLD) && \
	  CC="$(MUSL_CC)" \
	  CFLAGS="-O2 -I$(XZ_SYSROOT)/include -I$(ZLIB_SYSROOT)/include" \
	  LDFLAGS="-L$(XZ_SYSROOT)/lib -L$(ZLIB_SYSROOT)/lib" \
	  $(SELF)/$(LA_SRC)/configure \
	    --enable-static --disable-shared \
	    --disable-bsdcpio --disable-bsdcat \
	    --without-xml2 --without-expat --without-openssl --without-nettle \
	    --without-lzo2 --without-lz4 --without-zstd --without-bz2lib \
	    --without-libb2 --without-iconv --disable-acl --disable-xattr >/dev/null
	@# Force a fully-static final link via libtool's -all-static (compiler-probe-safe
	@# because it only applies at the make link stage, not during configure).
	@$(MAKE) -C $(BLD) bsdtar LDFLAGS="-all-static -L$(XZ_SYSROOT)/lib -L$(ZLIB_SYSROOT)/lib" >/dev/null
	@cp $(BLD)/bsdtar $(BSDTAR)
	@echo "[libarchive] built $(BSDTAR)"; file $(BSDTAR)

clean:
	rm -rf $(BLD) $(BSDTAR)
distclean: clean
	rm -f $(LA_TARBALL); rm -rf $(LA_SRC)
