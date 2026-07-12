# deps/xz — musl-static liblzma for the DECOY_DISTRO squashfs decompressor (D8).
# Ubuntu/Mint/Fedora live-ISO squashfs images are xz-compressed, so unsquashfs needs
# liblzma. Builds ONLY the static library (no xz CLI) against musl. Output:
# sysroot/lib/liblzma.a + sysroot/include/lzma.h — consumed by deps/squashfs-tools.
# Pinned to 5.4.6 (clean, pre-5.6 backdoor).
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang

XZ_VERSION := 5.4.6
XZ_TARBALL := xz-$(XZ_VERSION).tar.gz
XZ_URL     := https://github.com/tukaani-project/xz/releases/download/v$(XZ_VERSION)/$(XZ_TARBALL)
XZ_SRC     := xz-$(XZ_VERSION)
SELF       := $(abspath .)
BLD        := $(SELF)/build
SYSROOT    := $(SELF)/sysroot

LIBLZMA := $(SYSROOT)/lib/liblzma.a

.PHONY: all clean distclean
all: $(LIBLZMA)

$(XZ_TARBALL):
	@echo "[xz] downloading $(XZ_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(XZ_URL) || wget -q -O "$$tmp" $(XZ_URL); \
	mv "$$tmp" "$@"

$(XZ_SRC)/configure: $(XZ_TARBALL)
	@echo "[xz] extracting..."
	@rm -rf $(XZ_SRC); tar -xzf $(XZ_TARBALL); touch $@

$(LIBLZMA): $(XZ_SRC)/configure
	@echo "[xz] configuring + building liblzma (musl static)..."
	@mkdir -p $(BLD)
	@cd $(BLD) && CC="$(MUSL_CC)" CFLAGS="-O2 -fPIC" \
	  $(SELF)/$(XZ_SRC)/configure --prefix=$(SYSROOT) \
	    --enable-static --disable-shared \
	    --disable-xz --disable-xzdec --disable-lzmadec --disable-lzmainfo \
	    --disable-lzma-links --disable-scripts --disable-doc --disable-nls >/dev/null
	@$(MAKE) -C $(BLD) install-libLTLIBRARIES install-nobase_includeHEADERS >/dev/null 2>&1 \
	  || $(MAKE) -C $(BLD) install >/dev/null
	@echo "[xz] built $(LIBLZMA)"; ls -la $(LIBLZMA)

clean:
	rm -rf $(BLD) $(SYSROOT)
distclean: clean
	rm -f $(XZ_TARBALL); rm -rf $(XZ_SRC)
