# POSIX utilities embedding workflow

This repository now treats POSIX utilities as build artifacts that are imported
directly into the kernel image. The workflow has three stages:

1. **Toolchain integration** – `toolchain_builder.py` exposes the
   `--build-posixutils` flag so that the `tools/build_posixutils.py` helper can be
   invoked alongside the runtime/Phobos build. The flag accepts optional
   overrides for the source directory, output directory, compiler, and extra
   flags, making it easy to keep the manifest in sync whenever the toolchain is
   rebuilt.
2. **Guest build staging** – `buildscript.sh` copies the generated binaries into
   `$OUT_DIR/kernel-posixutils/bin` immediately after they are compiled and keeps
   a copy of `objects.tsv` next to them. This directory mirrors the
   `/kernel/posixutils` hierarchy that the kernel probes at boot.
3. **ISO packaging** – the ISO creation step mirrors both the build manifest
   (`build/posixutils`) and the staged `/kernel/posixutils` tree into the image
   so that `defaultEmbeddedPosixUtilitiesRoot` resolves to files that exist on
   the guest filesystem even in bare-metal mode.

With these steps in place, the kernel always sees a consistent manifest and a
well-known directory of binaries regardless of whether the utilities were
compiled on the host or inside the guest.
