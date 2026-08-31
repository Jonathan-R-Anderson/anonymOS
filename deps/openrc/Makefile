PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CFLAGS   := -static -I$(MUSL_INSTALL)/include
MUSL_LDFLAGS  := -static -L$(MUSL_INSTALL)/lib

OPENRC_VERSION := 0.54
OPENRC_TARBALL := openrc-$(OPENRC_VERSION).tar.gz
OPENRC_URL     := https://github.com/OpenRC/openrc/archive/refs/tags/$(OPENRC_VERSION).tar.gz
OPENRC_SRC     := openrc-$(OPENRC_VERSION)
OPENRC_INSTALL := $(abspath install)

# Outputs we copy into the ISO
OPENRC_BIN     := $(OPENRC_INSTALL)/sbin/openrc
OPENRC_OUT     := $(abspath .)/rc

.PHONY: all clean distclean

all: $(OPENRC_OUT)

# ── Download ───────────────────────────────────────────────────────────────────
$(OPENRC_TARBALL):
	@echo "[openrc] Downloading $(OPENRC_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -L -o "$$tmp" $(OPENRC_URL) || wget -q -O "$$tmp" $(OPENRC_URL); \
	mv "$$tmp" "$@"

# ── Extract ───────────────────────────────────────────────────────────────────
$(OPENRC_SRC)/meson.build: $(OPENRC_TARBALL)
	@echo "[openrc] Extracting..."
	tar xf $(OPENRC_TARBALL)
	touch $@

# ── Meson cross-file ──────────────────────────────────────────────────────────
openrc-cross.ini: $(MUSL_CC)
	@echo "[openrc] Generating meson cross file..."
	@printf '[binaries]\n'                                     >  $@
	@printf "c = '%s'\n"      "$(MUSL_CC)"                    >> $@
	@printf "ar = 'ar'\n"                                       >> $@
	@printf "strip = 'strip'\n"                                 >> $@
	@printf "pkg-config = 'false'\n"                             >> $@
	@printf '\n[host_machine]\n'                               >> $@
	@printf "system = 'linux'\n"                                >> $@
	@printf "cpu_family = 'x86_64'\n"                           >> $@
	@printf "cpu = 'x86_64'\n"                                  >> $@
	@printf "endian = 'little'\n"                               >> $@
	@printf '\n[properties]\n'                                 >> $@
	@printf "c_args = ['-static', '-I%s/include']\n"   "$(MUSL_INSTALL)" >> $@
	@printf "c_link_args = ['-static', '-L%s/lib']\n"  "$(MUSL_INSTALL)" >> $@

# --sysconfdir MUST be absolute.  meson.build:221 hands get_option('sysconfdir') straight to
# tools/meson_runlevels.sh, and that script ends with
#     ln -snf "${rc_libexecdir}"/sh/functions.sh "${DESTDIR}/${init_d_dir}"
# -- note the slash between DESTDIR and init_d_dir, which the rest of the script does
# NOT have.  With meson defaulting sysconfdir to the RELATIVE "etc" and the install
# rule below forcing DESTDIR= (empty), that expands to the real host /etc/init.d and
# the install dies with "ln: failed to create symbolic link '/etc/init.d/functions.sh':
# Permission denied" (and would silently scribble on the host if run as root).
# ── Configure ─────────────────────────────────────────────────────────────────
$(OPENRC_SRC)/build/build.ninja: $(OPENRC_SRC)/meson.build openrc-cross.ini Makefile
	@echo "[openrc] Configuring with meson..."
	rm -rf $(OPENRC_SRC)/build
	meson setup $(OPENRC_SRC)/build $(OPENRC_SRC) \
	  --cross-file openrc-cross.ini \
	  --prefix=$(OPENRC_INSTALL) \
	  --sbindir=sbin \
	  --sysconfdir=$(OPENRC_INSTALL)/etc \
	  --buildtype=release \
	  --default-library=static \
	  -Drootprefix=$(OPENRC_INSTALL) \
	  -Dpam=false \
	  -Dselinux=disabled \
	  -Daudit=disabled \
	  -Dcapabilities=disabled \
	  -Dsysvinit=false \
	  -Dnewnet=false \
	  -Dbash-completions=false \
	  -Dzsh-completions=false \
	  -Dpkgconfig=false

# ── Build + install ───────────────────────────────────────────────────────────
$(OPENRC_BIN): $(OPENRC_SRC)/build/build.ninja
	@echo "[openrc] Building..."
	$(NINJA) -C $(OPENRC_SRC)/build $(NINJA_BUILD_FLAGS)
	@echo "[openrc] Installing to $(OPENRC_INSTALL)..."
	DESTDIR= $(NINJA) -C $(OPENRC_SRC)/build install

$(OPENRC_OUT): $(OPENRC_BIN)
	cp $(OPENRC_BIN) $@
	@echo "[openrc] Static binary ready: $(OPENRC_OUT)"

clean:
	rm -rf $(OPENRC_SRC)/build openrc-cross.ini

distclean: clean
	rm -rf $(OPENRC_SRC) $(OPENRC_TARBALL) $(OPENRC_INSTALL) $(OPENRC_OUT)
