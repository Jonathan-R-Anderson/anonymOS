PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF          := $(abspath .)
MUSL_INSTALL  := $(abspath ../musl/install)
MUSL_CC       := $(MUSL_INSTALL)/bin/musl-clang
MUSL_CXX      := $(MUSL_INSTALL)/bin/musl-clang++
STAMPS        := $(SELF)/stamps
DLDIR         := $(SELF)/downloads
SRCDIR        := $(SELF)/src
BLDDIR        := $(SELF)/build

LLVM_VER      := 18.1.8
LLVM_TARBALL  := llvm-project-$(LLVM_VER).src.tar.xz
LLVM_URL      := https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VER)/$(LLVM_TARBALL)
LLVM_SRC      := $(SRCDIR)/llvm-project-$(LLVM_VER).src
LLVM_SRC_STAMP:= $(STAMPS)/llvm-src-$(LLVM_VER).done
RUNTIMES_BLD  := $(BLDDIR)/runtimes
STAMP         := $(STAMPS)/libcxx.done
LLVM_AR       := $(shell command -v llvm-ar 2>/dev/null || printf '%s' llvm-ar)
LLVM_RANLIB   := $(shell command -v llvm-ranlib 2>/dev/null || printf '%s' llvm-ranlib)
LLVM_NM       := $(shell command -v llvm-nm 2>/dev/null || printf '%s' llvm-nm)

# These static runtimes are later archived into shared Mesa objects, so they
# must be built as PIC even though we only install .a files.
COMMON_CFLAGS := -O2 -fPIC
COMMON_EXE_LDFLAGS := -static -no-pie -L$(MUSL_INSTALL)/lib
COMMON_SHARED_LDFLAGS := -L$(MUSL_INSTALL)/lib

.PHONY: all clean distclean

all: $(STAMP)

$(STAMPS) $(DLDIR) $(SRCDIR) $(BLDDIR):
	mkdir -p $@

$(DLDIR)/$(LLVM_TARBALL): | $(DLDIR)
	@echo "[cxxrt] Downloading $(LLVM_TARBALL)..."
	@set -e; tmp="$@.tmp"; rm -f "$$tmp" "$@"; \
	curl -fsSL -o "$$tmp" $(LLVM_URL) || wget -q -O "$$tmp" $(LLVM_URL); \
	mv "$$tmp" "$@"

$(LLVM_SRC_STAMP): $(DLDIR)/$(LLVM_TARBALL) | $(STAMPS) $(SRCDIR)
	@echo "[cxxrt] Extracting llvm-project $(LLVM_VER)..."
	rm -rf $(LLVM_SRC)
	tar -C $(SRCDIR) -xf $<
	touch $@

$(STAMP): $(LLVM_SRC_STAMP) $(MUSL_CC) $(MUSL_CXX) $(SELF)/Makefile | $(STAMPS) $(BLDDIR)
	@echo "[cxxrt] Building libunwind + libc++abi + libc++ for musl..."
	rm -rf $(RUNTIMES_BLD)
	MUSL_NO_CXX_RUNTIME=1 cmake -G Ninja \
	    -S $(LLVM_SRC)/runtimes \
	    -B $(RUNTIMES_BLD) \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DCMAKE_SYSTEM_NAME=Linux \
	    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	    -DCMAKE_INSTALL_PREFIX=$(MUSL_INSTALL) \
	    -DCMAKE_SYSROOT=$(MUSL_INSTALL) \
	    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
	    -DCMAKE_C_COMPILER=$(MUSL_CC) \
	    -DCMAKE_CXX_COMPILER=$(MUSL_CXX) \
	    -DCMAKE_ASM_COMPILER=$(MUSL_CC) \
	    -DCMAKE_AR=$(LLVM_AR) \
	    -DCMAKE_RANLIB=$(LLVM_RANLIB) \
	    -DCMAKE_NM=$(LLVM_NM) \
	    -DCMAKE_C_COMPILER_WORKS=ON \
	    -DCMAKE_CXX_COMPILER_WORKS=ON \
	    -DCMAKE_C_FLAGS="$(COMMON_CFLAGS)" \
	    -DCMAKE_CXX_FLAGS="$(COMMON_CFLAGS)" \
	    -DCMAKE_EXE_LINKER_FLAGS="$(COMMON_EXE_LDFLAGS)" \
	    -DCMAKE_SHARED_LINKER_FLAGS="$(COMMON_SHARED_LDFLAGS)" \
	    -DLLVM_ENABLE_RUNTIMES="libunwind;libcxxabi;libcxx" \
	    -DLLVM_INCLUDE_TESTS=OFF \
	    -DLIBCXX_ENABLE_SHARED=OFF \
	    -DLIBCXX_ENABLE_STATIC=ON \
	    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
	    -DLIBCXX_CXX_ABI=libcxxabi \
	    -DLIBCXX_ENABLE_EXCEPTIONS=ON \
	    -DLIBCXX_ENABLE_RTTI=ON \
	    -DLIBCXX_ENABLE_THREADS=ON \
	    -DLIBCXX_HAS_MUSL_LIBC=ON \
	    -DLIBCXX_HAS_PTHREAD_API=ON \
	    -DLIBCXX_INCLUDE_TESTS=OFF \
	    -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
	    -DLIBCXX_ENABLE_TIME_ZONE_DATABASE=OFF \
	    -DLIBCXXABI_ENABLE_SHARED=OFF \
	    -DLIBCXXABI_ENABLE_STATIC_UNWINDER=ON \
	    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
	    -DLIBCXXABI_ENABLE_EXCEPTIONS=ON \
	    -DLIBCXXABI_ENABLE_THREADS=ON \
	    -DLIBCXXABI_INCLUDE_TESTS=OFF \
	    -DLIBUNWIND_ENABLE_SHARED=OFF \
	    -DLIBUNWIND_ENABLE_THREADS=ON \
	    -DLIBUNWIND_ENABLE_ASSERTIONS=OFF \
	    -DLIBUNWIND_INCLUDE_TESTS=OFF
	MUSL_NO_CXX_RUNTIME=1 $(NINJA) -C $(RUNTIMES_BLD) $(NINJA_BUILD_FLAGS) cxxabi cxx unwind
	MUSL_NO_CXX_RUNTIME=1 $(NINJA) -C $(RUNTIMES_BLD) $(NINJA_BUILD_FLAGS) install-cxxabi install-cxx install-unwind
	touch $@

clean:
	rm -rf $(RUNTIMES_BLD)
	rm -f $(STAMP)

distclean: clean
	rm -rf $(DLDIR) $(SRCDIR) $(BLDDIR) $(STAMPS)
