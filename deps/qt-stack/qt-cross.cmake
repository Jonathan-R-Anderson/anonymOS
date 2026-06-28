# ─────────────────────────────────────────────────────────────────────────────
# CMake cross-toolchain for EpinAnonymOS — musl-clang + libc++, STATIC, no-pie.
# Shared by deps/qt-stack, deps/parted-stack, deps/calamares (mirrors the role of
# deps/gtk-stack/stamps/meson-cross.ini for CMake-based packages).
#
# Pass the repo root in the EPIN_ROOT environment variable (the Makefiles do this).
# ─────────────────────────────────────────────────────────────────────────────
set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

if(NOT DEFINED ENV{EPIN_ROOT})
  message(FATAL_ERROR "EPIN_ROOT not set (expected the repo root)")
endif()
set(EPIN_ROOT   "$ENV{EPIN_ROOT}")
set(MUSL        "${EPIN_ROOT}/deps/musl/install")
set(GTK_SYSROOT "${EPIN_ROOT}/deps/gtk-stack/sysroot")
set(QT_SYSROOT  "${EPIN_ROOT}/deps/qt-stack/sysroot")
set(PARTED_SYSROOT "${EPIN_ROOT}/deps/parted-stack/sysroot")
set(CALAMARES_SYSROOT "${EPIN_ROOT}/deps/calamares/sysroot")

# Cross compilers (the musl-clang wrappers default to libc++, as the gtk-stack uses them).
set(CMAKE_C_COMPILER   "${MUSL}/bin/musl-clang")
set(CMAKE_CXX_COMPILER "${MUSL}/bin/musl-clang++")
set(CMAKE_AR      llvm-ar      CACHE FILEPATH "")
set(CMAKE_RANLIB  llvm-ranlib  CACHE FILEPATH "")
set(CMAKE_STRIP   llvm-strip   CACHE FILEPATH "")
set(CMAKE_NM      llvm-nm      CACHE FILEPATH "")
set(CMAKE_OBJCOPY llvm-objcopy CACHE FILEPATH "")

# Sysroot search order: this stack → the shared GTK/Wayland sysroot → musl.
set(CMAKE_SYSROOT "${MUSL}")
set(CMAKE_FIND_ROOT_PATH "${CALAMARES_SYSROOT};${QT_SYSROOT};${PARTED_SYSROOT};${GTK_SYSROOT};${MUSL}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)   # host tools (moc/cmake) come from the host
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)

# Static, position-dependent (matches deps/gtk-stack BASE_LDFLAGS: -static -no-pie).
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_compile_options(-fPIC -isystem ${MUSL}/include)
add_link_options(-static -no-pie -Wl,--allow-multiple-definition
                 -L${QT_SYSROOT}/lib -L${GTK_SYSROOT}/lib -L${MUSL}/lib)
include_directories(SYSTEM
  ${GTK_SYSROOT}/include ${GTK_SYSROOT}/include/freetype2 ${QT_SYSROOT}/include)

# Force static-library lookups (no accidental host .so pickup).
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
