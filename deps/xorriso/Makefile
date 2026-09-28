# deps/xorriso — HOST xorriso, needed by scripts/mk-install-iso.sh to produce the
# hybrid installer ISO (BIOS El Torito + UEFI El Torito + protective MBR in one
# pass: `xorriso -as mkisofs --protective-msdos-label -efi-boot-part …`).  Neither
# cdrtools' mkisofs nor cdrkit's genisoimage implement those xorriso-specific
# options, and distros don't all ship the package — so vendor it, checksum-pinned
# like every other dep here, and install into deps/.host-tools/bin (build.opts
# already puts that on PATH).  The standalone tarball bundles libburn/libisofs/
# libisoburn, so nothing external is needed beyond a C compiler and zlib.
PROJECT_ROOT ?= $(abspath ../..)

XO_VERSION := 1.5.6.pl02
XO_TARBALL := xorriso-$(XO_VERSION).tar.gz
XO_URL     := https://ftp.gnu.org/gnu/xorriso/$(XO_TARBALL)
XO_SHA     := 786f9f5df9865cc5b0c1fecee3d2c0f5e04cab8c9a859bd1c9c7ccd4964fdae1
XO_SRC     := xorriso-1.5.6
SELF       := $(abspath .)
BLD        := $(SELF)/build
PREFIX     := $(abspath ../.host-tools)

.PHONY: all clean distclean
all: $(PREFIX)/bin/xorriso

$(XO_TARBALL):
	@echo "[xorriso] downloading $(XO_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(XO_URL) || wget -q -O "$$tmp" $(XO_URL); \
	mv "$$tmp" "$@"
	echo "$(XO_SHA)  $@" | sha256sum -c -

$(XO_SRC)/configure: $(XO_TARBALL)
	@echo "[xorriso] extracting..."
	@rm -rf $(XO_SRC); tar -xzf $(XO_TARBALL)
	@# autotools timestamp normalization, same reasoning as deps/xz.
	@touch $(XO_SRC)/configure.ac $(XO_SRC)/aclocal.m4 $(XO_SRC)/configure \
	       $(XO_SRC)/config.h.in $(XO_SRC)/Makefile.am $(XO_SRC)/Makefile.in
	@touch $@

$(PREFIX)/bin/xorriso: $(XO_SRC)/configure
	@echo "[xorriso] configuring + building (host compiler)..."
	@rm -rf $(BLD); mkdir -p $(BLD)
	@cd $(BLD) && ../$(XO_SRC)/configure --prefix=$(PREFIX) \
	    --disable-external-filters MAKEINFO=true >/dev/null
	@$(MAKE) -C $(BLD) MAKEINFO=true >/dev/null
	@$(MAKE) -C $(BLD) install MAKEINFO=true >/dev/null
	@echo "[xorriso] installed xorriso -> $(PREFIX)/bin"

clean:
	rm -rf $(BLD)
distclean: clean
	rm -rf $(XO_SRC) $(XO_TARBALL)
