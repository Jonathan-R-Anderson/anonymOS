PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF := $(abspath .)

MUSL_VERSION  := 1.2.5
MUSL_TARBALL  := musl-$(MUSL_VERSION).tar.gz
MUSL_URL      := https://musl.libc.org/releases/$(MUSL_TARBALL)
MUSL_SRC      := musl-$(MUSL_VERSION)
MUSL_INSTALL  := $(abspath install)
MUSL_SYSROOT  := $(MUSL_INSTALL)
MUSL_AR       ?= llvm-ar
MUSL_RANLIB   ?= llvm-ranlib
MUSL_CXX_BOOT ?= clang++

# The musl-clang wrapper ends up in $(MUSL_INSTALL)/bin/musl-clang
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CXX      := $(MUSL_INSTALL)/bin/musl-clang++
MUSL_UAPI_STAMP := $(MUSL_INSTALL)/include/.linux-uapi-synced

.PHONY: all clean distclean

all: $(MUSL_UAPI_STAMP)

# ── Download ──────────────────────────────────────────────────────────────────
$(MUSL_TARBALL):
	@echo "[musl] Downloading $(MUSL_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(MUSL_URL) || wget -q -O "$$tmp" $(MUSL_URL); \
	mv "$$tmp" "$@"

# ── Extract ───────────────────────────────────────────────────────────────────
$(MUSL_SRC)/configure: $(MUSL_TARBALL)
	@echo "[musl] Extracting..."
	tar xf $(MUSL_TARBALL)
	touch $@

# ── Configure + build + install ───────────────────────────────────────────────
$(MUSL_CC): $(MUSL_SRC)/configure $(SELF)/Makefile
	@echo "[musl] Configuring..."
	mkdir -p $(MUSL_SRC)/build
	cd $(MUSL_SRC)/build && \
	  ../configure \
	    --prefix=$(MUSL_INSTALL) \
	    --syslibdir=$(MUSL_INSTALL)/lib \
	    --target=x86_64-linux-musl \
	    --enable-shared \
	    CC=$(CROSSCOMPILE_CLANG) \
	    AR=$(MUSL_AR) \
	    RANLIB=$(MUSL_RANLIB) \
	    CFLAGS="-O2 -pipe" \
	    LDFLAGS=""
	@echo "[musl] Building..."
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(MUSL_SRC)/build
	@echo "[musl] Installing to $(MUSL_INSTALL)..."
	$(MAKE) $(MAKE_BUILD_FLAGS) -C $(MUSL_SRC)/build install
	@echo "[musl] Rewriting musl-clang wrappers with explicit musl sysroot support..."
	@{ \
		printf '%s\n' '#!/bin/sh'; \
		printf '%s\n' 'cc="$(CROSSCOMPILE_CLANG)"'; \
		printf '%s\n' 'libc="$(MUSL_INSTALL)"'; \
		printf '%s\n' 'libc_inc="$(MUSL_INSTALL)/include"'; \
		printf '%s\n' 'libc_lib="$(MUSL_INSTALL)/lib"'; \
		printf '%s\n' 'thisdir="`cd "$$(dirname "$$0")"; pwd`"'; \
		printf '%s\n' 'clang_resource_dir=`"$$cc" -print-resource-dir 2>/dev/null`'; \
		printf '%s\n' 'clang_resource_flags='; \
		printf '%s\n' 'if test -n "$$clang_resource_dir" ; then'; \
		printf '%s\n' '    clang_resource_flags="-isystem $$clang_resource_dir/include"'; \
		printf '%s\n' 'fi'; \
		printf '%s\n' ''; \
		printf '%s\n' '# Skip linker-only flags for compile/preprocess-only invocations. Meson and'; \
		printf '%s\n' '# similar build systems probe the compiler with -c/-E under -Werror, and clang'; \
		printf '%s\n' '# treats linker flags as unused arguments in that mode.'; \
		printf '%s\n' 'linking=1'; \
		printf '%s\n' 'sflags='; \
		printf '%s\n' 'eflags='; \
		printf '%s\n' 'for x ; do'; \
		printf '%s\n' '    case "$$x" in'; \
		printf '%s\n' '        -c|-E|-S|-M|-MM|-MD|-MMD) linking= ;;'; \
		printf '%s\n' '        -l*) input=1 ;;'; \
		printf '%s\n' '        *) input= ;;'; \
		printf '%s\n' '    esac'; \
		printf '%s\n' '    if test "$$linking" && test "$$input" ; then'; \
		printf '%s\n' '        sflags="-l-user-start"'; \
		printf '%s\n' '        eflags="-l-user-end"'; \
		printf '%s\n' '        break'; \
		printf '%s\n' '    fi'; \
		printf '%s\n' 'done'; \
		printf '%s\n' ''; \
		printf '%s\n' 'if test "$$linking" ; then'; \
		printf '%s\n' '    exec "$$cc" \'; \
		printf '%s\n' '        -B"$$thisdir" \'; \
		printf '%s\n' '        -fuse-ld=musl-clang \'; \
		printf '%s\n' '        -static-libgcc \'; \
		printf '%s\n' '        -nostdinc \'; \
		printf '%s\n' '        --sysroot "$$libc" \'; \
		printf '%s\n' '        -isystem "$$libc_inc" \'; \
		printf '%s\n' '        $$clang_resource_flags \'; \
		printf '%s\n' '        -L-user-start \'; \
		printf '%s\n' '        $$sflags \'; \
		printf '%s\n' '        "$$@" \'; \
		printf '%s\n' '        $$eflags \'; \
		printf '%s\n' '        -L"$$libc_lib" \'; \
		printf '%s\n' '        -L-user-end'; \
		printf '%s\n' 'fi'; \
		printf '%s\n' ''; \
		printf '%s\n' 'exec "$$cc" \'; \
		printf '%s\n' '    -B"$$thisdir" \'; \
		printf '%s\n' '    -nostdinc \'; \
		printf '%s\n' '    --sysroot "$$libc" \'; \
		printf '%s\n' '    -isystem "$$libc_inc" \'; \
		printf '%s\n' '    $$clang_resource_flags \'; \
		printf '%s\n' '    "$$@"'; \
	} > $(MUSL_CC)
	@{ \
		printf '%s\n' '#!/bin/sh'; \
		printf '%s\n' 'cxx="$(MUSL_CXX_BOOT)"'; \
		printf '%s\n' 'libc="$(MUSL_INSTALL)"'; \
		printf '%s\n' 'libc_inc="$(MUSL_INSTALL)/include"'; \
		printf '%s\n' 'libc_lib="$(MUSL_INSTALL)/lib"'; \
		printf '%s\n' 'thisdir="`cd "$$(dirname "$$0")"; pwd`"'; \
		printf '%s\n' 'clang_resource_dir=`"$$cxx" -print-resource-dir 2>/dev/null`'; \
		printf '%s\n' 'clang_resource_flags='; \
		printf '%s\n' 'cxx_header_flags="-nostdinc++"'; \
		printf '%s\n' 'cxx_link_flags='; \
		printf '%s\n' 'use_installed_cxxrt=1'; \
		printf '%s\n' 'if test -n "$$MUSL_NO_CXX_RUNTIME" ; then'; \
		printf '%s\n' '    use_installed_cxxrt='; \
		printf '%s\n' 'fi'; \
		printf '%s\n' 'if test -n "$$clang_resource_dir" ; then'; \
		printf '%s\n' '    clang_resource_flags="-isystem $$clang_resource_dir/include"'; \
		printf '%s\n' 'fi'; \
		printf '%s\n' 'if test "$$use_installed_cxxrt" && test -d "$$libc_inc/c++/v1" ; then'; \
		printf '%s\n' '    cxx_header_flags="$$cxx_header_flags -isystem $$libc_inc/c++/v1"'; \
		printf '%s\n' 'fi'; \
		printf '%s\n' 'if test "$$use_installed_cxxrt" && test -f "$$libc_lib/libc++.a" ; then'; \
		printf '%s\n' '    cxx_link_flags="-l-user-start -lc++ -lc++abi -lunwind -l-user-end"'; \
		printf '%s\n' 'fi'; \
		printf '%s\n' ''; \
		printf '%s\n' '# Skip linker-only flags for compile/preprocess-only invocations. Meson and'; \
		printf '%s\n' '# similar build systems probe the compiler with -c/-E under -Werror, and clang'; \
		printf '%s\n' '# treats linker flags as unused arguments in that mode.'; \
		printf '%s\n' 'linking=1'; \
		printf '%s\n' 'sflags='; \
		printf '%s\n' 'eflags='; \
		printf '%s\n' 'for x ; do'; \
		printf '%s\n' '    case "$$x" in'; \
		printf '%s\n' '        -c|-E|-S|-M|-MM|-MD|-MMD) linking= ;;'; \
		printf '%s\n' '        -l*) input=1 ;;'; \
		printf '%s\n' '        *) input= ;;'; \
		printf '%s\n' '    esac'; \
		printf '%s\n' '    if test "$$linking" && test "$$input" ; then'; \
		printf '%s\n' '        sflags="-l-user-start"'; \
		printf '%s\n' '        eflags="-l-user-end"'; \
		printf '%s\n' '        break'; \
		printf '%s\n' '    fi'; \
		printf '%s\n' 'done'; \
		printf '%s\n' ''; \
		printf '%s\n' 'if test "$$linking" ; then'; \
		printf '%s\n' '    exec "$$cxx" \'; \
		printf '%s\n' '        -B"$$thisdir" \'; \
		printf '%s\n' '        -fuse-ld=musl-clang \'; \
		printf '%s\n' '        -nostdlib++ \'; \
		printf '%s\n' '        -rtlib=compiler-rt \'; \
		printf '%s\n' '        -unwindlib=none \'; \
		printf '%s\n' '        -nostdinc \'; \
		printf '%s\n' '        --sysroot "$$libc" \'; \
		printf '%s\n' '        $$cxx_header_flags \'; \
		printf '%s\n' '        $$clang_resource_flags \'; \
		printf '%s\n' '        -isystem "$$libc_inc" \'; \
		printf '%s\n' '        -L-user-start \'; \
		printf '%s\n' '        $$sflags \'; \
		printf '%s\n' '        "$$@" \'; \
		printf '%s\n' '        $$eflags \'; \
		printf '%s\n' '        $$cxx_link_flags \'; \
		printf '%s\n' '        -L"$$libc_lib" \'; \
		printf '%s\n' '        -L-user-end'; \
		printf '%s\n' 'fi'; \
		printf '%s\n' ''; \
		printf '%s\n' 'exec "$$cxx" \'; \
		printf '%s\n' '    -B"$$thisdir" \'; \
		printf '%s\n' '    -nostdinc \'; \
		printf '%s\n' '    --sysroot "$$libc" \'; \
		printf '%s\n' '    $$cxx_header_flags \'; \
		printf '%s\n' '    $$clang_resource_flags \'; \
		printf '%s\n' '    -isystem "$$libc_inc" \'; \
		printf '%s\n' '    "$$@"'; \
	} > $(MUSL_CXX)
	@chmod +x $(MUSL_CC) $(MUSL_CXX)
	@echo "[musl] Build complete. wrappers: $(MUSL_CC) $(MUSL_CXX)"

$(MUSL_CXX): $(MUSL_CC)
	@test -x $@

$(MUSL_UAPI_STAMP): $(MUSL_CC) $(MUSL_CXX)
	@echo "[musl] Syncing Linux UAPI headers into musl sysroot..."
	rm -rf $(MUSL_INSTALL)/include/linux $(MUSL_INSTALL)/include/asm $(MUSL_INSTALL)/include/asm-generic
	cp -a /usr/include/linux $(MUSL_INSTALL)/include/linux
	cp -a /usr/include/asm-generic $(MUSL_INSTALL)/include/asm-generic
	cp -a /usr/include/x86_64-linux-gnu/asm $(MUSL_INSTALL)/include/asm
	touch $@

clean:
	rm -rf $(MUSL_SRC)/build

distclean: clean
	rm -rf $(MUSL_SRC) $(MUSL_TARBALL) $(MUSL_INSTALL)
