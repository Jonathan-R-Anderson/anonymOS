PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang

BB_VERSION    := 1.36.1
BB_TARBALL    := busybox-$(BB_VERSION).tar.bz2
BB_URL        := https://busybox.net/downloads/$(BB_TARBALL)
BB_SRC        := busybox-$(BB_VERSION)
BB_OUT        := $(abspath .)

# Final output placed where the Makefile can copy it into the ISO
BUSYBOX_ELF   := $(BB_OUT)/busybox

.PHONY: all clean distclean

all: $(BUSYBOX_ELF)

# ── Download ──────────────────────────────────────────────────────────────────
$(BB_TARBALL):
	@echo "[busybox] Downloading $(BB_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(BB_URL) || wget -q -O "$$tmp" $(BB_URL); \
	mv "$$tmp" "$@"

# ── Extract ───────────────────────────────────────────────────────────────────
$(BB_SRC)/Makefile: $(BB_TARBALL)
	@echo "[busybox] Extracting..."
	tar xf $(BB_TARBALL)
	touch $@

# ── Configure ─────────────────────────────────────────────────────────────────
$(BB_SRC)/.config: $(BB_SRC)/Makefile busybox.config merge_config.sh
	@echo "[busybox] Applying config..."
	rm -f $(BB_SRC)/.config
	$(MAKE) -C $(BB_SRC) allnoconfig CC=$(MUSL_CC) HOSTCC=gcc
	./merge_config.sh $(BB_SRC)/.config busybox.config
	cd $(BB_SRC) && yes '' | $(MAKE) oldconfig CC=$(MUSL_CC) HOSTCC=gcc

# ── Build ─────────────────────────────────────────────────────────────────────
$(BB_SRC)/busybox: $(BB_SRC)/.config $(MUSL_CC)
	@echo "[busybox] Building (static, musl)..."
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(BB_SRC) \
	  CC=$(MUSL_CC) \
	  HOSTCC=gcc \
	  CONFIG_STATIC=y \
	  LDFLAGS="--static"

$(BUSYBOX_ELF): $(BB_SRC)/busybox
	cp $< $@
	@echo "[busybox] Static binary ready: $(BUSYBOX_ELF)"

clean:
	[ -d $(BB_SRC) ] && $(MAKE) -C $(BB_SRC) clean || true
	rm -f $(BUSYBOX_ELF)

distclean: clean
	rm -rf $(BB_SRC) $(BB_TARBALL)
