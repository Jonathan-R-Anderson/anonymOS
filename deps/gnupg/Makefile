# deps/gnupg — musl-static gpgv for the DECOY_DISTRO signature verify step (D8 tool #4).
# gpgv verifies the distro's DETACHED OpenPGP signature (SHA256SUMS.gpg) over SHA256SUMS
# against a pinned distro release key. GnuPG 1.4's gpgv is SELF-CONTAINED (its own mpi +
# cipher/hash — no external libgcrypt/libksba/libassuan) and verifies the RSA-4096 +
# SHA-256/512 signatures modern distros use — the smallest correct verifier to ship.
# Output: gpgv (static musl) — staged into the installer ISO.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
ZLIB_SYSROOT := $(abspath ../gtk-stack/sysroot)

GPG_VERSION := 1.4.23
GPG_TARBALL := gnupg-$(GPG_VERSION).tar.bz2
GPG_URL     := https://gnupg.org/ftp/gcrypt/gnupg/$(GPG_TARBALL)
GPG_SRC     := gnupg-$(GPG_VERSION)
SELF        := $(abspath .)
BLD         := $(SELF)/build

GPGV := $(SELF)/gpgv

.PHONY: all clean distclean
all: $(GPGV)

$(GPG_TARBALL):
	@echo "[gnupg] downloading $(GPG_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(GPG_URL) || wget -q -O "$$tmp" $(GPG_URL); \
	mv "$$tmp" "$@"

$(GPG_SRC)/configure: $(GPG_TARBALL)
	@echo "[gnupg] extracting..."
	@rm -rf $(GPG_SRC); tar -xjf $(GPG_TARBALL); touch $@

# Configure a lean, static, software-only gnupg 1.4 and build just gpgv. Disable the
# interactive/agent/extras we don't need; link our musl zlib for compressed packets.
$(GPGV): $(GPG_SRC)/configure
	@echo "[gnupg] configuring + building gpgv (musl static)..."
	@mkdir -p $(BLD)
	@# -fcommon: gnupg 1.4 predates -fno-common (modern clang default); its headers use
	@# tentative global definitions that otherwise collide at link (multiple definition).
	@cd $(BLD) && CC="$(MUSL_CC)" CFLAGS="-O2 -fcommon -I$(ZLIB_SYSROOT)/include" \
	  LDFLAGS="-static -L$(ZLIB_SYSROOT)/lib" \
	  $(SELF)/$(GPG_SRC)/configure \
	    --disable-nls --without-readline --disable-card-support \
	    --disable-gnupg-iconv --disable-agent-support \
	    --host=x86_64-linux-musl >/dev/null
	@$(MAKE) -C $(BLD)/util >/dev/null 2>&1 || true
	@$(MAKE) -C $(BLD)/mpi  >/dev/null 2>&1 || true
	@$(MAKE) -C $(BLD)/cipher >/dev/null 2>&1 || true
	@$(MAKE) -C $(BLD)/g10 gpgv >/dev/null
	@cp $(BLD)/g10/gpgv $(GPGV)
	@echo "[gnupg] built $(GPGV)"; file $(GPGV)

clean:
	rm -rf $(BLD) $(GPGV)
distclean: clean
	rm -f $(GPG_TARBALL); rm -rf $(GPG_SRC)
