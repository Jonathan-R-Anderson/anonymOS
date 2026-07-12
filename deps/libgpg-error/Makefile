# deps/libgpg-error — musl-static base lib for gpgv (DECOY_DISTRO D8 signature verify).
# libgcrypt + gnupg/gpgv depend on it. Builds ONLY the static library against musl.
# Output: sysroot/lib/libgpg-error.a + headers.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang

GE_VERSION := 1.48
GE_TARBALL := libgpg-error-$(GE_VERSION).tar.bz2
GE_URL     := https://gnupg.org/ftp/gcrypt/libgpg-error/$(GE_TARBALL)
GE_SRC     := libgpg-error-$(GE_VERSION)
SELF       := $(abspath .)
BLD        := $(SELF)/build
SYSROOT    := $(SELF)/sysroot

LIBGPGERROR := $(SYSROOT)/lib/libgpg-error.a

.PHONY: all clean distclean
all: $(LIBGPGERROR)

$(GE_TARBALL):
	@echo "[libgpg-error] downloading $(GE_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(GE_URL) || wget -q -O "$$tmp" $(GE_URL); \
	mv "$$tmp" "$@"

$(GE_SRC)/configure: $(GE_TARBALL)
	@echo "[libgpg-error] extracting..."
	@rm -rf $(GE_SRC); tar -xjf $(GE_TARBALL); touch $@

$(LIBGPGERROR): $(GE_SRC)/configure
	@echo "[libgpg-error] configuring + building (musl static)..."
	@mkdir -p $(BLD)
	@cd $(BLD) && CC="$(MUSL_CC)" CFLAGS="-O2" \
	  $(SELF)/$(GE_SRC)/configure --prefix=$(SYSROOT) \
	    --enable-static --disable-shared \
	    --disable-nls --disable-doc --disable-tests \
	    --host=x86_64-linux-musl >/dev/null
	@$(MAKE) -C $(BLD) >/dev/null
	@$(MAKE) -C $(BLD) install >/dev/null
	@# 1.48 ships gpgrt-config but not the legacy gpg-error-config that libgcrypt's
	@# configure probes for; provide a compat wrapper so downstream deps find it.
	@printf '#!/bin/sh\nexec "%s/bin/gpgrt-config" gpg-error "$$@"\n' "$(SYSROOT)" \
	  > $(SYSROOT)/bin/gpg-error-config
	@chmod +x $(SYSROOT)/bin/gpg-error-config
	@echo "[libgpg-error] built $(LIBGPGERROR)"; ls -la $(LIBGPGERROR)

clean:
	rm -rf $(BLD) $(SYSROOT)
distclean: clean
	rm -f $(GE_TARBALL); rm -rf $(GE_SRC)
