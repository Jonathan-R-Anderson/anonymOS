PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

MUSL_CC ?= $(PROJECT_ROOT)/deps/musl/install/bin/musl-clang

DROPBEAR_VERSION ?= 2024.86
DROPBEAR_TARBALL := dropbear-$(DROPBEAR_VERSION).tar.bz2
DROPBEAR_URL := https://matt.ucc.asn.au/dropbear/releases/$(DROPBEAR_TARBALL)
DROPBEAR_SRC := dropbear-$(DROPBEAR_VERSION)
INSTALL_DIR := $(abspath install)
DBCLIENT_BIN := $(INSTALL_DIR)/bin/dbclient
SCP_BIN := $(INSTALL_DIR)/bin/scp
DROPBEARKEY_BIN := $(INSTALL_DIR)/bin/dropbearkey

.PHONY: all clean distclean

all: $(DBCLIENT_BIN) $(SCP_BIN) $(DROPBEARKEY_BIN)

$(DROPBEAR_TARBALL):
	@echo "[dropbear] Downloading $(DROPBEAR_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -LfsS -o "$$tmp" $(DROPBEAR_URL); \
	mv "$$tmp" "$@"

$(DROPBEAR_SRC)/configure: $(DROPBEAR_TARBALL)
	@echo "[dropbear] Extracting $(DROPBEAR_TARBALL)..."
	tar xf $(DROPBEAR_TARBALL)
	touch $@

# DYNAMIC on purpose: the guest routes AF_INET through LD_PRELOAD=/libnshim.so (the LKL
# net-provider shim, same as NM/wpa/nmcli).  A static dbclient/scp ignores LD_PRELOAD
# entirely, its socket(AF_INET) hits the EpinAnonymOS kernel (AF_UNIX-only -> EAFNOSUPPORT)
# and every transfer dies as dropbear's "Connect failed: unexpected failure".  The kernel
# maps any PT_INTERP to the staged ld-musl boot module (findInterpModule), so the host
# build-path interpreter in the ELF is fine.
$(DROPBEAR_SRC)/config.status: $(DROPBEAR_SRC)/configure $(MUSL_CC) Makefile
	@echo "[dropbear] Configuring dynamic musl client build (LD_PRELOAD shim must load)..."
	cd $(DROPBEAR_SRC) && ./configure \
		--host=x86_64-linux-musl \
		--prefix=/ \
		--enable-bundled-libtom \
		--disable-zlib \
		--disable-pam \
		--disable-syslog \
		--disable-shadow \
		--disable-lastlog \
		--disable-utmp \
		--disable-utmpx \
		--disable-wtmp \
		--disable-wtmpx \
		--disable-loginfunc \
		--disable-pututline \
		--disable-pututxline \
		CC=$(MUSL_CC) \
		CFLAGS="-Os -Wno-undef"

$(DROPBEAR_SRC)/dbclient $(DROPBEAR_SRC)/scp $(DROPBEAR_SRC)/dropbearkey: $(DROPBEAR_SRC)/config.status
	@echo "[dropbear] Building dbclient + scp + dropbearkey..."
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(DROPBEAR_SRC) PROGRAMS="dbclient scp dropbearkey" MULTI=0 SCPPROGRESS=0

$(DBCLIENT_BIN): $(DROPBEAR_SRC)/dbclient
	mkdir -p $(INSTALL_DIR)/bin
	cp $< $@
	strip $@

$(SCP_BIN): $(DROPBEAR_SRC)/scp
	mkdir -p $(INSTALL_DIR)/bin
	cp $< $@
	strip $@

$(DROPBEARKEY_BIN): $(DROPBEAR_SRC)/dropbearkey
	mkdir -p $(INSTALL_DIR)/bin
	cp $< $@
	strip $@

clean:
	[ -d $(DROPBEAR_SRC) ] && $(MAKE) -C $(DROPBEAR_SRC) clean || true
	rm -rf $(INSTALL_DIR)

distclean: clean
	rm -rf $(DROPBEAR_SRC) $(DROPBEAR_TARBALL)
