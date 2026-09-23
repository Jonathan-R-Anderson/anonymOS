# deps/mtools — HOST mtools (mcopy/mmd/mformat/…), needed by scripts/mk-install-iso.sh
# and the decoy-os boot checks to assemble FAT ESP images.  Distros don't all ship it
# (Arch: 'mtools' package, Debian: 'mtools'); vendored + checksum-pinned like every
# other dep here, and installed into deps/.host-tools/bin — which build.opts already
# puts on PATH, so every make recipe and script finds the tools without changes.
# Built with the HOST compiler (it only manipulates FAT images, it never runs in the
# guest), so no musl cross flags are wanted.
PROJECT_ROOT ?= $(abspath ../..)

MT_VERSION := 4.0.48
MT_TARBALL := mtools-$(MT_VERSION).tar.gz
MT_URL     := https://ftp.gnu.org/gnu/mtools/$(MT_TARBALL)
MT_SHA     := 88f273c6629ad5464482e98a9980727f585eead8736c50717c95e36f05ca05dc
MT_SRC     := mtools-$(MT_VERSION)
SELF       := $(abspath .)
BLD        := $(SELF)/build
PREFIX     := $(abspath ../.host-tools)

.PHONY: all clean distclean
all: $(PREFIX)/bin/mcopy

$(MT_TARBALL):
	@echo "[mtools] downloading $(MT_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(MT_URL) || wget -q -O "$$tmp" $(MT_URL); \
	mv "$$tmp" "$@"
	echo "$(MT_SHA)  $@" | sha256sum -c -

$(MT_SRC)/configure: $(MT_TARBALL)
	@echo "[mtools] extracting..."
	@rm -rf $(MT_SRC); tar -xzf $(MT_TARBALL)
	@# autotools timestamp normalization, same reasoning as deps/xz: checked-out
	@# trees share one mtime and make would try to re-run aclocal on hosts
	@# without automake.
	@touch $(MT_SRC)/configure.ac $(MT_SRC)/aclocal.m4 $(MT_SRC)/configure \
	       $(MT_SRC)/config.h.in $(MT_SRC)/Makefile.in
	@touch $@

$(PREFIX)/bin/mcopy: $(MT_SRC)/configure
	@echo "[mtools] configuring + building (host compiler)..."
	@rm -rf $(BLD); mkdir -p $(BLD)
	@cd $(BLD) && ../$(MT_SRC)/configure --prefix=$(PREFIX) MAKEINFO=true >/dev/null
	@$(MAKE) -C $(BLD) MAKEINFO=true >/dev/null
	@$(MAKE) -C $(BLD) install MAKEINFO=true >/dev/null
	@echo "[mtools] installed mcopy/mmd/mformat/... -> $(PREFIX)/bin"

clean:
	rm -rf $(BLD)
distclean: clean
	rm -rf $(MT_SRC) $(MT_TARBALL)
