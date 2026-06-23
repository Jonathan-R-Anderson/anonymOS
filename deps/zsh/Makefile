# ZSH_INTEGRATION_ROADMAP Z0 — build upstream zsh as a static musl binary for the
# AnonymOS Linux personality, against a musl-built ncursesw whose terminal entries are
# COMPILED IN (--with-fallbacks), so no terminfo database is needed on the OS.
#
# Reproducible + offline: the upstream tarballs are vendored next to this Makefile and
# verified by SHA256; nothing is fetched if they are already present.  `make` here only
# *builds* zsh — it is NOT staged into the OS image yet (that is Z1).  Toolchain = the
# same musl-clang that builds the Wayland clients; x86-64 musl runs on the x86-64 build
# host, so zsh's configure runs its test programs natively (no cross-compile cache).

ROOT     := $(abspath $(CURDIR)/../..)
MUSL_CC  := $(ROOT)/deps/musl/install/bin/musl-clang
SYSROOT  := $(CURDIR)/sysroot

ZSH_VER  := 5.9
NC_VER   := 6.4
ZSH_SHA  := 9b8d1ecedd5b5e81fbf1918e876752a7dd948e05c1a0dba10ab863842d45acd5
NC_SHA   := 6931283d9ac87c5073f30b6290c4c75f21632bb4fc3603ac8100812bed248159
ZSH_URL  := https://sourceforge.net/projects/zsh/files/zsh/$(ZSH_VER)/zsh-$(ZSH_VER).tar.xz/download
NC_URL   := https://ftp.gnu.org/gnu/ncurses/ncurses-$(NC_VER).tar.gz

ZSH_TAR  := zsh-$(ZSH_VER).tar.xz
NC_TAR   := ncurses-$(NC_VER).tar.gz
NC_LIB   := $(SYSROOT)/lib/libncursesw.a
ZSH_BIN  := $(CURDIR)/zsh

all: $(ZSH_BIN)

# --- fetch (only if the vendored tarball is missing) + verify checksum ---
$(ZSH_TAR):
	curl -fsSL -o $@ "$(ZSH_URL)"
	echo "$(ZSH_SHA)  $@" | sha256sum -c -
$(NC_TAR):
	curl -fsSL -o $@ "$(NC_URL)"
	echo "$(NC_SHA)  $@" | sha256sum -c -

# --- ncursesw: static, widechar, terminal-info compiled in (no DB) ---
$(NC_LIB): $(NC_TAR)
	echo "$(NC_SHA)  $(NC_TAR)" | sha256sum -c -
	rm -rf ncurses-$(NC_VER) && tar xf $(NC_TAR)
	cd ncurses-$(NC_VER) && \
	  CC="$(MUSL_CC)" BUILD_CC="clang" BUILD_CFLAGS="-O2" CFLAGS="-O2 -fPIC" \
	  ./configure --host=x86_64-pc-linux-musl --prefix="$(SYSROOT)" \
	    --without-progs --without-tests --without-manpages \
	    --without-cxx --without-cxx-binding --without-ada \
	    --enable-widec --with-termlib --enable-static --disable-shared \
	    --without-debug --without-pthread \
	    --with-fallbacks=linux,xterm,xterm-256color,vt100,vt220,screen,screen-256color,ansi
	$(MAKE) -C ncurses-$(NC_VER) libs
	$(MAKE) -C ncurses-$(NC_VER) install.libs

# --- zsh: static musl, modules linked in (--disable-dynamic), against musl ncursesw ---
$(ZSH_BIN): $(ZSH_TAR) $(NC_LIB)
	echo "$(ZSH_SHA)  $(ZSH_TAR)" | sha256sum -c -
	rm -rf zsh-$(ZSH_VER) && tar xf $(ZSH_TAR)
	cd zsh-$(ZSH_VER) && \
	  CC="$(MUSL_CC)" \
	  CPPFLAGS="-I$(SYSROOT)/include -I$(SYSROOT)/include/ncursesw" \
	  LDFLAGS="-static -L$(SYSROOT)/lib" LIBS="-lncursesw -ltinfow" \
	  ./configure --host=x86_64-pc-linux-musl --prefix=/system/shell/zsh \
	    --disable-dynamic --disable-dynamic-nss --without-tcsetpgrp
	$(MAKE) -C zsh-$(ZSH_VER)
	cp zsh-$(ZSH_VER)/Src/zsh $@ && strip $@
	@echo "Z0 OK: built static musl zsh -> $@"

clean:
	rm -rf zsh-$(ZSH_VER) ncurses-$(NC_VER) sysroot zsh

.PHONY: all clean
