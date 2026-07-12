# deps/e2fsprogs — musl-static mke2fs for the DECOY_DISTRO runtime ISO→ext4 pipeline (D8).
# The installer runs `mke2fs -d <rootfs-dir> <img.ext4>` on USB #2 to turn an extracted
# distro rootfs into a populated ext4, which the VeraCrypt decoy path then encrypts.
# Built like busybox: musl-clang, fully static, staged into the installer ISO.
PROJECT_ROOT ?= $(abspath ../..)

MUSL_INSTALL := $(abspath ../musl/install)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang

E2_VERSION := 1.47.0
E2_TARBALL := e2fsprogs-$(E2_VERSION).tar.gz
E2_URL     := https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$(E2_VERSION)/$(E2_TARBALL)
E2_SRC     := e2fsprogs-$(E2_VERSION)
SELF       := $(abspath .)
BLD        := $(SELF)/build

# Final artifact the ISO staging copies in.
MKE2FS_BIN := $(SELF)/mke2fs

.PHONY: all clean distclean
all: $(MKE2FS_BIN)

$(E2_TARBALL):
	@echo "[e2fsprogs] downloading $(E2_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(E2_URL) || wget -q -O "$$tmp" $(E2_URL); \
	mv "$$tmp" "$@"

$(E2_SRC)/configure: $(E2_TARBALL)
	@echo "[e2fsprogs] extracting..."
	@rm -rf $(E2_SRC); tar -xzf $(E2_TARBALL); touch $@
	@# musl fix: in lib/blkid/llseek.c the (!HAVE_LLSEEK && long==long long) branch
	@# defines `llseek` but leaves `my_llseek` undefined → clang errors on the (dead,
	@# size-guarded) my_llseek call. Define my_llseek=lseek there. See DECOY_DISTRO D8.
	@sed -i 's/^#define llseek lseek$$/#define my_llseek lseek/' $(E2_SRC)/lib/blkid/llseek.c

# Configure for a static musl build. Trim to what mke2fs needs: no NLS, no fuse2fs, no
# blkid daemon; use the BUNDLED libuuid/libblkid so there are no external deps. The
# cross cache vars keep configure from running host-only link probes wrongly.
$(BLD)/Makefile: $(E2_SRC)/configure
	@echo "[e2fsprogs] configuring (musl static)..."
	@mkdir -p $(BLD)
	@cd $(BLD) && \
	  CC="$(MUSL_CC)" CFLAGS="-O2 -static -D_LARGEFILE64_SOURCE" LDFLAGS="-static" \
	  $(SELF)/$(E2_SRC)/configure \
	    --disable-nls --disable-fuse2fs --disable-defrag \
	    --disable-testio-debug --enable-libuuid \
	    ac_cv_func_getpwnam=yes ac_cv_func_getgrnam=yes >/dev/null

$(MKE2FS_BIN): $(BLD)/Makefile
	@echo "[e2fsprogs] building static libs..."
	@$(MAKE) -C $(BLD) libs
	@echo "[e2fsprogs] building mke2fs..."
	@$(MAKE) -C $(BLD)/misc mke2fs
	@cp $(BLD)/misc/mke2fs $(MKE2FS_BIN)
	@echo "[e2fsprogs] built $(MKE2FS_BIN)"; file $(MKE2FS_BIN)

clean:
	rm -rf $(BLD) $(MKE2FS_BIN)
distclean: clean
	rm -f $(E2_TARBALL); rm -rf $(E2_SRC)
