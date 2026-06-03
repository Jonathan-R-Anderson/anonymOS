PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang

HOST_TOOLS_SRC := $(HOST_TOOLS_ROOT)/src
HOST_TOOLS_DIST := $(HOST_TOOLS_ROOT)/dist

# ── host gperf (required by elogind meson) ──────────────────────────────────
HOST_GPERF_VERSION := 3.1
HOST_GPERF_TARBALL := $(HOST_TOOLS_DIST)/gperf-$(HOST_GPERF_VERSION).tar.gz
HOST_GPERF_URL     := https://ftp.gnu.org/pub/gnu/gperf/gperf-$(HOST_GPERF_VERSION).tar.gz
HOST_GPERF_SRC     := $(HOST_TOOLS_SRC)/gperf-$(HOST_GPERF_VERSION)
HOST_GPERF_BIN     := $(HOST_TOOLS_BIN)/gperf

# ── libcap (required by elogind for capability checks) ────────────────────────
LIBCAP_VERSION := 2.70
LIBCAP_TARBALL := libcap-$(LIBCAP_VERSION).tar.xz
LIBCAP_URL     := https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/$(LIBCAP_TARBALL)
LIBCAP_SRC     := libcap-$(LIBCAP_VERSION)
LIBCAP_INSTALL := $(abspath libcap-install)
LIBCAP_A       := $(LIBCAP_INSTALL)/lib/libcap.a

# ── elogind ───────────────────────────────────────────────────────────────────
ELOGIND_VERSION := 255.4
ELOGIND_TARBALL := elogind-$(ELOGIND_VERSION).tar.gz
ELOGIND_URL     := https://github.com/elogind/elogind/archive/v$(ELOGIND_VERSION).tar.gz
ELOGIND_SRC     := elogind-$(ELOGIND_VERSION)
ELOGIND_INSTALL := $(abspath install)
ELOGIND_PKG_CONFIG_ENV = \
	PKG_CONFIG_LIBDIR="$(LIBCAP_INSTALL)/lib/pkgconfig" \
	PKG_CONFIG_PATH=""

ELOGIND_BIN     := $(ELOGIND_INSTALL)/lib/elogind/elogind
ELOGIND_OUT     := $(abspath .)/elogind

.PHONY: all libcap elogind clean distclean

all: $(ELOGIND_OUT)

# ── host gperf bootstrap ─────────────────────────────────────────────────────
$(HOST_GPERF_TARBALL):
	@echo "[host-gperf] Downloading gperf $(HOST_GPERF_VERSION)..."
	@mkdir -p $(HOST_TOOLS_DIST)
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(HOST_GPERF_URL) || wget -q -O "$$tmp" $(HOST_GPERF_URL); \
	mv "$$tmp" "$@"

$(HOST_GPERF_SRC)/configure: $(HOST_GPERF_TARBALL)
	@echo "[host-gperf] Extracting..."
	@mkdir -p $(HOST_TOOLS_SRC)
	@tar -C $(HOST_TOOLS_SRC) -xf $<

$(HOST_GPERF_BIN): $(HOST_GPERF_SRC)/configure
	@echo "[host-gperf] Building..."
	@mkdir -p $(HOST_TOOLS_ROOT)
	cd $(HOST_GPERF_SRC) && ./configure --prefix=$(HOST_TOOLS_ROOT)
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(HOST_GPERF_SRC)
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(HOST_GPERF_SRC) install
	@echo "[host-gperf] Installed: $(HOST_GPERF_BIN)"

# ── libcap: download, build, install ─────────────────────────────────────────
$(LIBCAP_TARBALL):
	@echo "[libcap] Downloading $(LIBCAP_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(LIBCAP_URL) || wget -q -O "$$tmp" $(LIBCAP_URL); \
	mv "$$tmp" "$@"

$(LIBCAP_SRC)/Make.Rules: $(LIBCAP_TARBALL)
	@echo "[libcap] Extracting..."
	tar xf $(LIBCAP_TARBALL)
	touch $@

$(LIBCAP_A): $(LIBCAP_SRC)/Make.Rules
	@echo "[libcap] Building (static, musl)..."
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(LIBCAP_SRC) \
	  CC="$(MUSL_CC)" \
	  COPTS="-O2 -static -I$(MUSL_INSTALL)/include" \
	  lib=lib \
	  GOLANG=no \
	  TESTS=no \
	  prefix=$(LIBCAP_INSTALL) \
	  install
	@echo "[libcap] Done."

libcap: $(LIBCAP_A)

# ── elogind meson cross-file ──────────────────────────────────────────────────
elogind-cross.ini: $(MUSL_CC)
	@echo "[elogind] Generating meson cross file..."
	@printf '[binaries]\n'                                      >  $@
	@printf "c = '%s'\n"       "$(MUSL_CC)"                    >> $@
	@printf "ar = 'ar'\n"                                        >> $@
	@printf "strip = 'strip'\n"                                  >> $@
	@printf "pkg-config = 'pkg-config'\n"                         >> $@
	@printf '\n[built-in options]\n'                            >> $@
	@printf "c_args = ['-static', '-I%s/include', '-I%s/include']\n" \
	  "$(MUSL_INSTALL)" "$(LIBCAP_INSTALL)"                     >> $@
	@printf "c_link_args = ['-static', '-L%s/lib', '-L%s/lib']\n" \
	  "$(MUSL_INSTALL)" "$(LIBCAP_INSTALL)"                     >> $@
	@printf '\n[host_machine]\n'                                >> $@
	@printf "system = 'linux'\n"                                 >> $@
	@printf "cpu_family = 'x86_64'\n"                            >> $@
	@printf "cpu = 'x86_64'\n"                                   >> $@
	@printf "endian = 'little'\n"                                >> $@

# ── elogind: download ─────────────────────────────────────────────────────────
$(ELOGIND_TARBALL):
	@echo "[elogind] Downloading $(ELOGIND_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -L -o "$$tmp" $(ELOGIND_URL) || wget -q -O "$$tmp" $(ELOGIND_URL); \
	mv "$$tmp" "$@"

$(ELOGIND_SRC)/meson.build: $(ELOGIND_TARBALL)
	@echo "[elogind] Extracting..."
	tar xf $(ELOGIND_TARBALL)
	touch $@

# ── elogind: configure ────────────────────────────────────────────────────────
$(ELOGIND_SRC)/build/build.ninja: $(ELOGIND_SRC)/meson.build elogind-cross.ini $(LIBCAP_A) $(HOST_GPERF_BIN)
	@echo "[elogind] Configuring with meson..."
	$(ELOGIND_PKG_CONFIG_ENV) meson setup $(ELOGIND_SRC)/build $(ELOGIND_SRC) \
	  --cross-file elogind-cross.ini \
	  --prefix=$(ELOGIND_INSTALL) \
	  --buildtype=release \
	  --default-library=static \
	  -Dmode=release \
	  -Dstatic-libelogind=true \
	  -Dpam=disabled \
	  -Dacl=disabled \
	  -Dselinux=disabled \
	  -Dsmack=false \
	  -Dman=disabled \
	  -Dhtml=disabled \
	  -Dtranslations=false \
	  -Dpolkit=disabled \
	  -Ddbus=disabled \
	  -Ddefault-hierarchy=unified \
	  -Dutmp=false \
	  -Daudit=disabled \
	  -Dxenctrl=disabled \
	  -Defi=false \
	  -Dtests=false \
	  -Dinstall-tests=false

# ── elogind: build + install ──────────────────────────────────────────────────
$(ELOGIND_BIN): $(ELOGIND_SRC)/build/build.ninja
	@echo "[elogind] Building..."
	$(NINJA) -C $(ELOGIND_SRC)/build $(NINJA_BUILD_FLAGS)
	@echo "[elogind] Installing to $(ELOGIND_INSTALL)..."
	$(NINJA) -C $(ELOGIND_SRC)/build install

$(ELOGIND_OUT): $(ELOGIND_BIN)
	cp $(ELOGIND_BIN) $@
	@echo "[elogind] Binary ready: $(ELOGIND_OUT)"

clean:
	rm -rf $(ELOGIND_SRC)/build elogind-cross.ini
	[ -d $(LIBCAP_SRC) ] && $(MAKE) -C $(LIBCAP_SRC) clean || true

distclean: clean
	rm -rf $(ELOGIND_SRC) $(ELOGIND_TARBALL) $(ELOGIND_INSTALL) $(ELOGIND_OUT)
	rm -rf $(LIBCAP_SRC) $(LIBCAP_TARBALL) $(LIBCAP_INSTALL)
