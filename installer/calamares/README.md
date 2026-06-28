# installer/calamares — the in-OS Calamares installer

Configuration, branding, and custom modules for the EpinAnonymOS Calamares installer.
See [`roadmap/INSTALLER.md`](../../roadmap/INSTALLER.md) for the full plan and
[`installer/ARCHITECTURE.md`](../ARCHITECTURE.md) for the Phase 1 analysis.

## Layout
```
settings.conf                     install sequence (show/exec, dont-chroot)
branding/epinanonymos/
    branding.desc                 product name, logos, slideshow, palette (Phase 4)
modules/
    identitymanager/              custom: Administrator + Identity profiles (Phase 6)
        module.desc CMakeLists.txt IdentityManagerViewStep.{h,cpp} identitymanager.conf
    epinpartition/                native object-FS disk module (§D2(b)) — TODO
    epincopy/ epinbootloader/ epinconfig/   post-install jobs (Phases 8–10) — TODO
```

## How it builds (depends on the Qt runtime + Calamares, §D1/§D3)
1. `make -C deps/qt-stack`      → static Qt 6.4.2 (musl + libc++) into `deps/qt-stack/sysroot`.
2. `make -C deps/parted-stack`  → libblkid + libparted + KPMcore (§D2) — for the standard
   `partition` module; the native `epinpartition` module is the rootless default.
3. `make -C deps/calamares`     → cross-builds Calamares + these custom modules into one static
   ELF, against qt-stack + parted-stack.
4. `make hos.iso`               → stages the `calamares` ELF as a boot module + autostarts it on
   the Weston desktop (live session).

## Design notes
- **Static, Wayland, rootless.** Qt is built static (no runtime plugin loading) → the `qwayland`
  platform plugin is statically imported; `QT_QPA_PLATFORM=wayland`. Raster paint engine + Wayland
  `wl_shm` (Qt built `-no-opengl` — the installer needs no GPU, matching the software desktop).
- **Identities, not users.** `identitymanager` writes selected profiles to GlobalStorage; the
  `epinconfig` job folds them into one declarative `install.json` consumed at first boot, which
  materialises each as a Domain object (`core/domain.d`). No imperative `useradd`, no root.
- **Disk = object FS.** `epinpartition` drives the OS's own AHCI/NVMe + GPT/ESP path (the same
  one the ISO build uses) under a one-shot, capability-gated block-write grant — not pkexec.

## Status
Scaffolded (settings, branding, the Identity module). The Qt runtime build (`deps/qt-stack`)
is proven to configure + compile static against musl; Calamares + the partitioning backend
build on top of it. See the roadmap's honest-status section for what remains.
