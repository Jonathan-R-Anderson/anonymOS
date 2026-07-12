# deps/libgcrypt — musl-static crypto lib for gpgv (DECOY_DISTRO D8 signature verify).
# Provides RSA/DSA/EdDSA + SHA-256/512 that gpgv uses to verify the distro's detached
# signature over SHA256SUMS. Static, against musl + our libgpg-error. Software-only
# (--disable-asm) to avoid cross-asm issues on the musl-clang path.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
GPGERR_SYSROOT := $(abspath ../libgpg-error/sysroot)

GC_VERSION := 1.10.3
GC_TARBALL := libgcrypt-$(GC_VERSION).tar.bz2
GC_URL     := https://gnupg.org/ftp/gcrypt/libgcrypt/$(GC_TARBALL)
GC_SRC     := libgcrypt-$(GC_VERSION)
SELF       := $(abspath .)
BLD        := $(SELF)/build
SYSROOT    := $(SELF)/sysroot

LIBGCRYPT := $(SYSROOT)/lib/libgcrypt.a

.PHONY: all clean distclean
all: $(LIBGCRYPT)

$(GC_TARBALL):
	@echo "[libgcrypt] downloading $(GC_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(GC_URL) || wget -q -O "$$tmp" $(GC_URL); \
	mv "$$tmp" "$@"

$(GC_SRC)/configure: $(GC_TARBALL)
	@echo "[libgcrypt] extracting..."
	@rm -rf $(GC_SRC); tar -xjf $(GC_TARBALL); touch $@

$(LIBGCRYPT): $(GC_SRC)/configure
	@echo "[libgcrypt] configuring + building (musl static, software-only)..."
	@mkdir -p $(BLD)
	@cd $(BLD) && CC="$(MUSL_CC)" CFLAGS="-O2" \
	  $(SELF)/$(GC_SRC)/configure --prefix=$(SYSROOT) \
	    --enable-static --disable-shared \
	    --with-libgpg-error-prefix=$(GPGERR_SYSROOT) \
	    --disable-asm --disable-padlock-support --disable-aesni-support \
	    --disable-doc --disable-tests \
	    --host=x86_64-linux-musl >/dev/null
	@$(MAKE) -C $(BLD) >/dev/null
	@$(MAKE) -C $(BLD) install >/dev/null
	@echo "[libgcrypt] built $(LIBGCRYPT)"; ls -la $(LIBGCRYPT)

clean:
	rm -rf $(BLD) $(SYSROOT)
distclean: clean
	rm -f $(GC_TARBALL); rm -rf $(GC_SRC)
