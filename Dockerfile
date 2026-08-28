# syntax=docker/dockerfile:1.7
# =============================================================================
# anonymOS — containerized build.  `docker build` runs the ENTIRE make and hands
# back the installer ISO, so a host needs nothing but Docker: no make, no clang,
# no ldc2, no musl toolchain.
#
#     ./build-in-docker.sh                    # -> dist/hos-install.iso
#     docker build --target artifacts --output type=local,dest=dist .   # same thing
#
# Stages
#   toolchain — Ubuntu 24.04 + every host tool this tree's makefiles reach for.
#   deps      — deps/ ONLY (musl, libc++, the GTK stack, weston, mutter, zsh, the
#               VeraCrypt/preboot EFI apps, the H1 decoy Linux image).  It is a
#               separate layer keyed on deps/ so editing src/ does not re-run the
#               multi-hour dependency build.
#   build     — the rest of the tree: anonymos-config, the D kernel, the boot
#               tree, and hos-install.iso.
#   artifacts — a scratch image holding just the ISO (+ kernel.elf), so
#               `--output` drops them straight onto the host filesystem.  This is
#               the DEFAULT stage: a plain `docker build .` yields an image whose
#               entire content is the ISO.
#
# Ubuntu 24.04 is not incidental.  deps/gtk-stack hardcodes the clang **18**
# resource directory ($(LLVM_PREFIX)/lib/clang/18/include), and deps/musl copies
# the host's Debian-layout UAPI headers (/usr/include/x86_64-linux-gnu/asm) into
# the musl sysroot — 24.04 is the distro that ships exactly that pair.
#
# The old Ubuntu 18.04 + GHC/JHC image survives as Dockerfile.haskell-legacy: it
# existed for `make progs-haskell` (the legacy JHC userspace), which is not part
# of `make all` and cannot be built by a modern GHC.
# =============================================================================

ARG UBUNTU_VERSION=24.04

# -----------------------------------------------------------------------------
# 1. toolchain — the host side of the cross-build
# -----------------------------------------------------------------------------
FROM ubuntu:${UBUNTU_VERSION} AS toolchain

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Grouped by what needs them, because a missing one of these usually surfaces
# thousands of lines deep in someone else's configure script:
#   * clang/lld/llvm 18 + ldc  — the kernel (D, -betterC) and every musl target
#   * libclang-rt-18-dev — clang's compiler-rt builtins.  It is only a Recommends of
#     clang-18, so --no-install-recommends drops it, and then every C++ link through
#     deps/musl's musl-clang++ wrapper (it passes -rtlib=compiler-rt -unwindlib=none)
#     dies on "cannot find .../libclang_rt.builtins-x86_64.a"
#   * meson/ninja/cmake/autotools/gperf/flex/bison — the dependency tarballs
#   * libwayland-bin, libglib2.0-*-bin — HOST codegen (wayland-scanner,
#     glib-compile-resources, gdbus-codegen) used by cross-built gtk/weston/mutter
#   * libegl-dev/libgl-dev/libgles-dev — deps/gtk-stack's gl-headers step stages the
#     Khronos headers by copying /usr/include/{EGL,GL,GLES,GLES2,GLES3,KHR} out of the
#     host; without them libepoxy compiles with no KHR/khrplatform.h and dies
#   * xorriso/mtools/dosfstools/gdisk/parted/e2fsprogs/fakeroot — the ISO, the
#     FAT32 ESP images (scripts/mk-install-iso.sh) and the decoy ext4 rootfs
#   * fonts-noto-{core,mono}/dmz-cursor-theme — `make build-gui-assets` copies
#     these straight out of /usr/share and hard-fails if any of the four faces is
#     missing; on 24.04 the two NotoSansMono faces are in fonts-noto-MONO, not core
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        bc \
        bison \
        build-essential \
        bzip2 \
        ca-certificates \
        cmake \
        clang \
        cpio \
        curl \
        dmz-cursor-theme \
        dosfstools \
        e2fsprogs \
        fakeroot \
        file \
        flex \
        fonts-noto-core \
        fonts-noto-mono \
        gdisk \
        gettext \
        git \
        gperf \
        ldc \
        libegl-dev \
        libgl-dev \
        libgles-dev \
        libclang-rt-18-dev \
        libglib2.0-bin \
        libglib2.0-dev-bin \
        libtool \
        libwayland-bin \
        lld \
        llvm \
        m4 \
        meson \
        mtools \
        ninja-build \
        openssl \
        parted \
        patch \
        pkg-config \
        python3 \
        python3-packaging \
        python3-pip \
        python3-setuptools \
        rsync \
        squashfs-tools \
        texinfo \
        unzip \
        wget \
        xorriso \
        xsltproc \
        xz-utils \
        zstd \
    && rm -rf /var/lib/apt/lists/*

# deps/gtk-stack and deps/cxxrt call llvm-ar/llvm-nm/llvm-ranlib/llvm-strip/
# llvm-objcopy unversioned.  Ubuntu's llvm package has shipped both versioned and
# unversioned names over the years; link whatever is missing so the build does not
# depend on which of the two this image happened to get.
RUN set -eux; \
    for t in ar nm ranlib strip objcopy config; do \
        command -v "llvm-$t" >/dev/null 2>&1 && continue; \
        ln -sf "/usr/lib/llvm-18/bin/llvm-$t" "/usr/local/bin/llvm-$t"; \
    done; \
    llvm-config --version; clang --version | head -1; ldc2 --version | head -1

# R0/R1: two boot modules (hello-wl, hos-term) are Rust->musl.  The Makefile stages
# them only `if [ -x $(RUSTC) ]` with RUSTC = $(HOME)/.cargo/bin/rustc, so this is
# what turns them from "skipped" into "included".
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --no-modify-path \
        --default-toolchain stable --target x86_64-unknown-linux-musl
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build

# Serial by default, exactly like build.opts: several dependency builds (libc++,
# mutter, weston) are memory-hungry enough to OOM a container that fans out to
# every core.  Raise it on a big machine: --build-arg BUILD_JOBS=8.
ARG BUILD_JOBS=1
ENV BUILD_JOBS=${BUILD_JOBS}

# -----------------------------------------------------------------------------
# 2. deps — the dependency stack, in its own cacheable layer
# -----------------------------------------------------------------------------
FROM toolchain AS deps

# Only what deps/ itself reads: build.opts (included by every dep makefile) and
# the low-resource wrapper it points BUILD_RESOURCE_RUN at.  Deliberately NOT the
# top-level Makefile — editing it must not invalidate this layer.
COPY build.opts ./build.opts
COPY src/util/bin ./src/util/bin
COPY scripts ./scripts
COPY deps ./deps

# deps/gtk-stack, deps/mutter and deps/hyprland-hos want $(HOST_TOOLS_BIN)/python3
# (build.opts: deps/.host-tools/bin).  Nothing in the tree creates it — on a
# developer's machine it is set up by hand — so create it here; the other host
# tools that live under deps/.host-tools (bison, gperf, meson) are built/installed
# into it by the dep makefiles themselves.
RUN mkdir -p deps/.host-tools/bin && ln -sfn /usr/bin/python3 deps/.host-tools/bin/python3

# deps/{gtk-stack,cxxrt,mutter,hyprland-hos}/stamps/* are tracked in git, but the
# static libraries they certify are not (.gitignore drops *.a).  A checkout would
# therefore look "already built" and fail much later at link time on a missing
# -lgtk-3.  .dockerignore already keeps them out of the context; this is the same
# guarantee for anyone driving `docker build` with a context of their own.
RUN rm -f deps/*/stamps/*

# Same class of trap, one level down: ten of the vendored source trees under deps/
# were committed incomplete (openrc has the headers but none of the .c files,
# elogind is missing 353 of 955 files), and each dep makefile keys extraction on a
# file that IS present, so it never re-extracts.  Fill the gaps from the tarball
# vendored next to each tree, without touching anything the repo does ship.
RUN ./scripts/fill-vendored-sources.sh

# musl on its own, then probe the wrapper with the EXACT snippet meson uses for its
# builtin `iconv` check — glib 2.80 does `libiconv = dependency('iconv')`, which
# compiles and links this and nothing else, and that is what the GTK stack died on.
# Later probes repeat it with the cross-file's own args, through BOTH wrappers: meson
# ran that check with musl-clang++, and the C++ wrapper is the one with its own runtime
# flags, so a C-only probe would have called this toolchain healthy.  Diagnostic
# only: it never fails the build, so its output lands next to the real error.
RUN scripts/docker-build-step.sh make -C deps musl
RUN set -x; \
    CC="$PWD/deps/musl/install/bin/musl-clang"; \
    SYSROOT="$PWD/deps/gtk-stack/sysroot"; \
    MUSL="$PWD/deps/musl/install"; \
    RES="$(clang -print-resource-dir)"; \
    printf '#include <iconv.h>\nint main() {\n    iconv_open("","");\n}\n' > /tmp/ic.c; \
    ls -l "$CC" "$MUSL/bin/ld.musl-clang" "$MUSL/include/iconv.h" "$MUSL/lib/libc.a" || true; \
    nm "$MUSL/lib/libc.a" 2>/dev/null | grep -c 'T iconv_open' || true; \
    "$CC" -c /tmp/ic.c -o /tmp/ic.o; echo "PROBE compile-only rc=$?"; \
    "$CC" /tmp/ic.c -o /tmp/ic; echo "PROBE plain link rc=$?"; \
    "$CC" -O2 -fPIC -isystem "$RES/include" -I"$SYSROOT/include" -I"$MUSL/include" \
        -Wl,--allow-multiple-definition -no-pie -L"$SYSROOT/lib" -L"$MUSL/lib" \
        /tmp/ic.c -o /tmp/ic2; echo "PROBE cross-file-flags link (C) rc=$?"; \
    cp /tmp/ic.c /tmp/ic.cpp; \
    "$MUSL/bin/musl-clang++" -O2 -fPIC -isystem "$RES/include" -I"$SYSROOT/include" -I"$MUSL/include" \
        -Wl,--allow-multiple-definition -no-pie -L"$SYSROOT/lib" -L"$MUSL/lib" \
        /tmp/ic.cpp -o /tmp/ic3; echo "PROBE cross-file-flags link (C++) rc=$?"; \
    true

# The dependency stack, one RUN per phase instead of one for the lot.  Docker keeps
# every completed step as a layer, so a failure deep in the GTK stack resumes from the
# last good phase rather than rebuilding musl and libc++ from scratch each attempt.
# Each step runs through scripts/docker-build-step.sh, which on failure repeats the
# last 150 lines of that step plus the newest meson-log.txt at the END of the output,
# where the real error is otherwise hidden hundreds of lines up.
RUN scripts/docker-build-step.sh make -C deps cxxrt
RUN scripts/docker-build-step.sh make -C deps busybox openrc
RUN scripts/docker-build-step.sh make -C deps dbus dconf networkmanager \
        elogind logind pipewire pipewire-pulse wireplumber
# Split at glib: it is the single longest package in the GTK chain, and everything
# after it (cairo, pango, gdk-pixbuf, atk, epoxy, gtk3) is where the cross-build
# breakages actually turn up.
RUN scripts/docker-build-step.sh make -C deps/gtk-stack glib
RUN scripts/docker-build-step.sh make -C deps gtk-stack
RUN scripts/docker-build-step.sh make -C deps staged-desktop
RUN scripts/docker-build-step.sh make -C deps mutter
RUN scripts/docker-build-step.sh make -C deps weston
# Assertion, not work: with every phase above done this is a no-op, and it fails loudly
# if the split above ever drifts from what `desktop` actually pulls in.
RUN scripts/docker-build-step.sh make -C deps desktop

# Z2: upstream zsh 5.9 as dynamic musl + its 37 zmodules.
RUN scripts/docker-build-step.sh make -C deps/zsh

# INSTALLER E5/H1: the UEFI pre-boot loader + stage2, and the decoy Alpine ext4.
# Both are stage-iso-tree prerequisites, and both are pure deps/ work.
RUN scripts/docker-build-step.sh make -C deps/veracrypt efi
RUN scripts/docker-build-step.sh make -C deps/decoy-os image verify

# -----------------------------------------------------------------------------
# 3. build — kernel, boot tree, installer ISO
# -----------------------------------------------------------------------------
FROM deps AS build

COPY . /build

# `make all` in three steps, minus the dependency phase the deps stage already
# did.  Split so a failure says which half broke and a re-run resumes near it.
RUN scripts/docker-build-step.sh make anonymos-config
RUN scripts/docker-build-step.sh make build/libkernel_d.a kernel.elf

# The LKL WiFi module (build/lkl-boot-musl) links against a liblkl.a built from an
# LKL tree that lives OUTSIDE this repo (src/lkl/README.md), so by default it is
# absent and stage-iso-tree skips it — the ISO boots, without WiFi.  To include it,
# put the prebuilt tree in the build context and point at it:
#     docker build --build-arg LKL_BUILD_DIR=/build/lkl-build ...
ARG LKL_BUILD_DIR=""
RUN scripts/docker-build-step.sh make ${LKL_BUILD_DIR:+LKL_BUILD_DIR="$LKL_BUILD_DIR"} iso

RUN test -f hos-install.iso && ls -l hos-install.iso

# -----------------------------------------------------------------------------
# 4. artifacts — what leaves the container (default stage)
# -----------------------------------------------------------------------------
FROM scratch AS artifacts
COPY --from=build /build/hos-install.iso /
COPY --from=build /build/kernel.elf /
