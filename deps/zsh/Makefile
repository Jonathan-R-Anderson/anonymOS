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

# --- zsh: DYNAMIC musl (Z2), against musl ncursesw ---
# Z2 (ZSH_INTEGRATION_ROADMAP): build zsh dynamically (--enable-dynamic) so the zmodules
# become dlopen-able .so files loaded over the kernel's dynamic linker (PT_INTERP=ld-musl,
# .so basename->boot-module resolution).  Two cross-build gotchas, both handled here:
#   * configure can't RUN its musl-dynamic probe programs on the glibc build host, so the
#     dynamic-loading capabilities are supplied as zsh_cv_* cache vars (they're true for
#     ELF/musl).  (Z1's static build sidestepped this — static binaries run anywhere.)
#   * the rdynamic flag that exports the zsh exe's symbols to its dlopen'd modules is only
#     applied inside configure's (skipped, because cached) rdynamic test — so force it via
#     EXTRA_LDFLAGS=-Wl,--export-dynamic.  Without it modules fail: "hashgetfn: not found".
# The exe is NOT stripped (keep .dynsym so modules resolve the core symbols); modules are.
ZMODDIR := $(CURDIR)/modules
$(ZSH_BIN): $(ZSH_TAR) $(NC_LIB) anon.c
	echo "$(ZSH_SHA)  $(ZSH_TAR)" | sha256sum -c -
	rm -rf zsh-$(ZSH_VER) && tar xf $(ZSH_TAR)
	# Z4a.3: the platform/anonymos/ host hooks (native-personality FS dispatch).  Built as
	# libanon.a and linked into zsh via --wrap so zsh's open/read/write/close/lseek route
	# through the native ABI when native (transparent for the Linux-personality default).
	$(MUSL_CC) -O2 -fPIC -c anon.c -o anon.o
	ar rcs $(SYSROOT)/lib/libanon.a anon.o
	cd zsh-$(ZSH_VER) && \
	  CC="$(MUSL_CC)" \
	  CPPFLAGS="-I$(SYSROOT)/include -I$(SYSROOT)/include/ncursesw" \
	  LDFLAGS="-L$(SYSROOT)/lib" \
	  EXTRA_LDFLAGS="-Wl,--export-dynamic -Wl,--wrap=open -Wl,--wrap=read -Wl,--wrap=write -Wl,--wrap=execve -Wl,--wrap=wait3 -Wl,--wrap=waitpid" \
	  LIBS="-lncursesw -ltinfow -lanon" \
	  zsh_cv_func_dlsym_needs_underscore=no \
	  zsh_cv_shared_environ=yes zsh_cv_shared_tgetent=yes zsh_cv_shared_tigetstr=yes \
	  zsh_cv_sys_dynamic_clash_ok=yes zsh_cv_sys_dynamic_execsyms=yes \
	  zsh_cv_sys_dynamic_rtld_global=yes \
	  zsh_cv_sys_dynamic_strip_exe=no zsh_cv_sys_dynamic_strip_lib=no \
	  ./configure --prefix=/system/shell/zsh \
	    --enable-dynamic --disable-dynamic-nss --without-tcsetpgrp
	$(MAKE) -C zsh-$(ZSH_VER)
	cp zsh-$(ZSH_VER)/Src/zsh $@
	# collect the dlopen-able zmodules (zsh/<name>.so), stripped, for the OS to stage
	rm -rf $(ZMODDIR) && mkdir -p $(ZMODDIR)
	cp zsh-$(ZSH_VER)/Src/Modules/*.so zsh-$(ZSH_VER)/Src/Zle/*.so \
	   zsh-$(ZSH_VER)/Src/Builtins/*.so $(ZMODDIR)/
	strip $(ZMODDIR)/*.so
	@echo "Z2 OK: built dynamic musl zsh + $$(ls $(ZMODDIR)/*.so | wc -l) zmodules -> $@"

clean:
	rm -rf zsh-$(ZSH_VER) zsh-$(ZSH_VER)-dyn ncurses-$(NC_VER) sysroot zsh modules

.PHONY: all clean
