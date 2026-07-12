# deps/squashfs-tools — musl-static unsquashfs for the DECOY_DISTRO ISO→rootfs step (D8).
# Extracts a distro live-ISO's filesystem.squashfs into a rootfs tree, which mke2fs -d
# then packs into the VeraCrypt decoy ext4. Built with gzip+xz+zstd codec support against
# our musl codec libs. Output: unsquashfs (static) — staged into the installer ISO.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang

# Codec libs (built by their own deps; zlib reused from the gtk-stack sysroot).
XZ_SYSROOT   := $(abspath ../xz/sysroot)
ZSTD_SYSROOT := $(abspath ../zstd/sysroot)
ZLIB_SYSROOT := $(abspath ../gtk-stack/sysroot)

SQ_VERSION := 4.6.1
SQ_TARBALL := squashfs-tools-$(SQ_VERSION).tar.gz
SQ_URL     := https://github.com/plougher/squashfs-tools/archive/refs/tags/$(SQ_VERSION).tar.gz
SQ_SRC     := squashfs-tools-$(SQ_VERSION)
SELF       := $(abspath .)

UNSQUASHFS := $(SELF)/unsquashfs

.PHONY: all clean distclean
all: $(UNSQUASHFS)

$(SQ_TARBALL):
	@echo "[squashfs] downloading $(SQ_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(SQ_URL) || wget -q -O "$$tmp" $(SQ_URL); \
	mv "$$tmp" "$@"

$(SQ_SRC)/squashfs-tools/Makefile: $(SQ_TARBALL)
	@echo "[squashfs] extracting..."
	@rm -rf $(SQ_SRC); tar -xzf $(SQ_TARBALL); touch $@

# Build with all three codecs; point CFLAGS at our static codec sysroots and link static.
$(UNSQUASHFS): $(SQ_SRC)/squashfs-tools/Makefile
	@echo "[squashfs] building unsquashfs (musl static, gzip+xz+zstd)..."
	@$(MAKE) -C $(SQ_SRC)/squashfs-tools unsquashfs \
	  CC="$(MUSL_CC)" \
	  GZIP_SUPPORT=1 XZ_SUPPORT=1 ZSTD_SUPPORT=1 \
	  LZO_SUPPORT=0 LZ4_SUPPORT=0 XATTR_SUPPORT=0 \
	  EXTRA_CFLAGS="-D_GNU_SOURCE -I$(XZ_SYSROOT)/include -I$(ZSTD_SYSROOT)/include -I$(ZLIB_SYSROOT)/include" \
	  EXTRA_LDFLAGS="-static -L$(XZ_SYSROOT)/lib -L$(ZSTD_SYSROOT)/lib -L$(ZLIB_SYSROOT)/lib"
	@cp $(SQ_SRC)/squashfs-tools/unsquashfs $(UNSQUASHFS)
	@echo "[squashfs] built $(UNSQUASHFS)"; file $(UNSQUASHFS)

clean:
	rm -f $(UNSQUASHFS); $(MAKE) -C $(SQ_SRC)/squashfs-tools clean 2>/dev/null || true
distclean:
	rm -f $(SQ_TARBALL) $(UNSQUASHFS); rm -rf $(SQ_SRC)
