# ==========================================================================
# deps/calamares/Makefile
#
# Cross-build of the Calamares installer (roadmap/INSTALLER.md §D3) and its C++
# dependencies, against the static Qt 6 from deps/qt-stack — musl-clang + libc++,
# -static -no-pie, single static ELF boot module.  Mirrors deps/qt-stack: the
# shared CMake cross toolchain (qt-cross.cmake), output into sysroot/.
#
# Dependency order:
#   yaml-cpp  →  (KPMcore + deps/parted-stack, §D2)  →  calamares
#
# Targets:   yaml-cpp   — Calamares' YAML settings/config parser (foundation dep)
#            calamares  — the installer ELF (needs §D2 backend; recipe staged below)
# Output:    sysroot/   — static libs, headers, cmake configs
#            calamares  — the final static ELF (staged into cd/ by the hos.iso target)
# ==========================================================================
PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF           := $(abspath .)
MUSL_INSTALL   := $(abspath ../musl/install)
CXXRT_STAMP    := $(abspath ../cxxrt/stamps/libcxx.done)
QT_SYSROOT     := $(abspath ../qt-stack/sysroot)
GTK_SYSROOT    := $(abspath ../gtk-stack/sysroot)
PARTED_SYSROOT := $(abspath ../parted-stack/sysroot)
SYSROOT        := $(SELF)/sysroot
STAMPS         := $(SELF)/stamps
DLDIR          := $(SELF)/downloads
BLDDIR         := $(SELF)/build
# Reuse the shared cross toolchain (deps/qt-stack/qt-cross.cmake): musl-clang{,++},
# libc++, -static -no-pie, and a CMAKE_FIND_ROOT_PATH that includes deps/calamares/sysroot.
TOOLCHAIN      := $(abspath ../qt-stack/qt-cross.cmake)

RUN := $(BUILD_RESOURCE_RUN)
export EPIN_ROOT := $(PROJECT_ROOT)

YAML_CPP_VER  ?= 0.8.0
CALAMARES_VER ?= 3.3.14

# CMake configure shorthand for a CMake-based dep:
#   $(1) = name (source already unpacked into build/$(1)-src) → installs into SYSROOT.
CMAKE_CROSS = cmake -G Ninja -S $(BLDDIR)/$(1)-src -B $(BLDDIR)/$(1)-build \
    -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
    -DCMAKE_INSTALL_PREFIX=$(SYSROOT) \
    -DCMAKE_PREFIX_PATH="$(SYSROOT);$(QT_SYSROOT);$(GTK_SYSROOT);$(PARTED_SYSROOT)" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF

.PHONY: all yaml-cpp calamares clean
all: yaml-cpp

dirs:
	@mkdir -p $(SYSROOT) $(STAMPS) $(DLDIR) $(BLDDIR)

# ── yaml-cpp ─────────────────────────────────────────────────────────────────
# Calamares parses its settings.conf / *.conf modules with yaml-cpp.  Pure, portable
# C++11 → a clean static cross-build that also proves the non-Qt C++ dependency
# pipeline (libc++ + musl + qt-cross.cmake) before the heavier KPMcore/Calamares work.
yaml-cpp: $(STAMPS)/yaml-cpp
$(STAMPS)/yaml-cpp: $(CXXRT_STAMP) $(TOOLCHAIN) $(SELF)/Makefile | dirs
	@if [ ! -f $(DLDIR)/yaml-cpp-$(YAML_CPP_VER).tar.gz ]; then \
	  echo "[calamares] fetching yaml-cpp $(YAML_CPP_VER)"; \
	  curl -fSL --retry 3 -o $(DLDIR)/yaml-cpp-$(YAML_CPP_VER).tar.gz \
	     https://github.com/jbeder/yaml-cpp/archive/refs/tags/$(YAML_CPP_VER).tar.gz; \
	fi
	@rm -rf $(BLDDIR)/yaml-cpp-src $(BLDDIR)/yaml-cpp-build; mkdir -p $(BLDDIR)/yaml-cpp-src
	tar -xf $(DLDIR)/yaml-cpp-$(YAML_CPP_VER).tar.gz -C $(BLDDIR)/yaml-cpp-src --strip-components=1
	$(RUN) $(call CMAKE_CROSS,yaml-cpp) \
	    -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF -DYAML_CPP_BUILD_CONTRIB=OFF \
	    -DYAML_CPP_INSTALL=ON
	$(RUN) cmake --build $(BLDDIR)/yaml-cpp-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/yaml-cpp-build
	@touch $@

# ── calamares (the installer ELF) ────────────────────────────────────────────
# PREREQUISITES (not yet complete): §D2 partitioning backend (deps/parted-stack +
# KPMcore) and the static-QML/Widgets module set.  This target is the build recipe;
# it cross-configures Calamares against deps/qt-stack + yaml-cpp.  Until KPMcore and
# the §D2 backend land it is expected to fail at configure on the missing pieces —
# run `make -C deps/calamares yaml-cpp` for the foundation that IS ready today.
calamares: $(STAMPS)/calamares
$(STAMPS)/calamares: $(STAMPS)/yaml-cpp
	@if [ ! -f $(DLDIR)/calamares-$(CALAMARES_VER).tar.gz ]; then \
	  echo "[calamares] fetching Calamares $(CALAMARES_VER)"; \
	  curl -fSL --retry 3 -o $(DLDIR)/calamares-$(CALAMARES_VER).tar.gz \
	     https://github.com/calamares/calamares/releases/download/v$(CALAMARES_VER)/calamares-$(CALAMARES_VER).tar.gz; \
	fi
	@rm -rf $(BLDDIR)/calamares-src $(BLDDIR)/calamares-build; mkdir -p $(BLDDIR)/calamares-src
	tar -xf $(DLDIR)/calamares-$(CALAMARES_VER).tar.gz -C $(BLDDIR)/calamares-src --strip-components=1
	# Widgets-only (no QML), no Python module support, build against the static Qt.
	$(RUN) $(call CMAKE_CROSS,calamares) \
	    -DWITH_QML=OFF -DWITH_PYTHON=OFF -DWITH_PYTHONQT=OFF \
	    -DBUILD_TESTING=OFF -DINSTALL_CONFIG=OFF -DWITH_KF6Crash=OFF
	$(RUN) cmake --build $(BLDDIR)/calamares-build $(NINJA_BUILD_FLAGS)
	$(RUN) cmake --install $(BLDDIR)/calamares-build
	@touch $@

clean:
	rm -rf $(BLDDIR) $(STAMPS) $(SYSROOT)
