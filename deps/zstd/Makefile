# deps/zstd — musl-static libzstd for the DECOY_DISTRO squashfs decompressor (D8).
# Ubuntu 22.04+ live-ISO squashfs images are zstd-compressed, so unsquashfs needs libzstd.
# Builds ONLY the static library via zstd's own lib Makefile against musl. Output:
# sysroot/lib/libzstd.a + sysroot/include/zstd.h — consumed by deps/squashfs-tools.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
MUSL_AR      := llvm-ar
MUSL_RANLIB  := llvm-ranlib

ZSTD_VERSION := 1.5.6
ZSTD_TARBALL := zstd-$(ZSTD_VERSION).tar.gz
ZSTD_URL     := https://github.com/facebook/zstd/releases/download/v$(ZSTD_VERSION)/$(ZSTD_TARBALL)
ZSTD_SRC     := zstd-$(ZSTD_VERSION)
SELF         := $(abspath .)
SYSROOT      := $(SELF)/sysroot

LIBZSTD := $(SYSROOT)/lib/libzstd.a

.PHONY: all clean distclean
all: $(LIBZSTD)

$(ZSTD_TARBALL):
	@echo "[zstd] downloading $(ZSTD_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(ZSTD_URL) || wget -q -O "$$tmp" $(ZSTD_URL); \
	mv "$$tmp" "$@"

$(ZSTD_SRC)/lib/Makefile: $(ZSTD_TARBALL)
	@echo "[zstd] extracting..."
	@rm -rf $(ZSTD_SRC); tar -xzf $(ZSTD_TARBALL); touch $@

$(LIBZSTD): $(ZSTD_SRC)/lib/Makefile
	@echo "[zstd] building libzstd.a (musl static)..."
	@$(MAKE) -C $(ZSTD_SRC)/lib \
	  CC="$(MUSL_CC)" AR="$(MUSL_AR)" RANLIB="$(MUSL_RANLIB)" \
	  CFLAGS="-O2 -fPIC" libzstd.a >/dev/null
	@mkdir -p $(SYSROOT)/lib $(SYSROOT)/include
	@cp $(ZSTD_SRC)/lib/libzstd.a $(SYSROOT)/lib/
	@cp $(ZSTD_SRC)/lib/zstd.h $(ZSTD_SRC)/lib/zdict.h $(ZSTD_SRC)/lib/zstd_errors.h $(SYSROOT)/include/ 2>/dev/null || \
	   cp $(ZSTD_SRC)/lib/zstd.h $(SYSROOT)/include/
	@echo "[zstd] built $(LIBZSTD)"; ls -la $(LIBZSTD)

clean:
	rm -rf $(SYSROOT); $(MAKE) -C $(ZSTD_SRC)/lib clean 2>/dev/null || true
distclean:
	rm -rf $(SYSROOT) $(ZSTD_SRC) $(ZSTD_TARBALL)
