# Installer integration — Phase 1 repository analysis

How EpinAnonymOS installs, boots, and configures today, and where Calamares plugs in.
(Companion to [`roadmap/INSTALLER.md`](../roadmap/INSTALLER.md).)

## How it boots / "installs" today
- **Boot medium:** `make hos.iso` builds a `cd/` tree (kernel + boot modules + `limine.conf`)
  and wraps it with `xorriso` into an **isohybrid** ISO (MBR + GPT/ESP; El Torito BIOS + UEFI),
  so it boots on CD, USB, BIOS, and UEFI. **limine** is the bootloader.
- **No persistent install exists yet.** The ISO is a live image; the only on-disk persistence
  is the AHCI object store (`hos-disk.img`, a 32 MiB SATA disk created on first run). There is
  no tool that lays the OS down onto a target disk — that gap is what Calamares fills.
- **Kernel load:** limine (`protocol: limine`) loads `boot()/boot/kernel.elf` + every
  `module_path:` module into memory; the D kernel (`src/kernel/d`) takes over.

## Rootfs / userland
- Userland binaries are **statically linked musl ELFs** shipped as **boot modules** in `cd/`
  (busybox, zsh, the Weston stack, the Wayland clients). They are loaded by limine and spawned
  via `spawnWaylandProgram` — there is no separate rootfs image; the "filesystem" is the
  kernel's **object filesystem** with Linux-path **compat views** (`/objects`, `/config`,
  `/system`, `/linux`, a hardened ramfs for `/etc`, `/proc`, …).
- Cross-build convention (`deps/<name>/`): musl-clang + **libc++** (`deps/cxxrt`), `-static
  -no-pie`, output into a per-dep `sysroot/`. `deps/gtk-stack` is the GTK/Wayland reference.
  **Calamares + Qt must follow this** (static, boot module) — §D1/§D3 of the roadmap.

## Identities / users (NOT POSIX-only)
- Identity is **object/capability-based** (`src/kernel/d/core/identity.d`): `NetPolicy`,
  device-class gates, per-domain caps. There is a thin POSIX compat (`/etc/passwd` uid-1000,
  `EPIN_*` env) so shells show `user@namespace`, but the source of truth is the **Domain**
  objects (`core/domain.d`, `/config/domains.json`, 11 seeded domains). The installer's
  **Identity Manager** page (Phase 6) writes *domain/identity definitions*, not `useradd`.

## Configuration system
- **Declarative + object-based.** `/config/*.json` (e.g. `domains.json`, `packages.json`,
  `templates.json`, `shell.json`) is the live config surface; the Domain Manager + first boot
  consume it. The installer's `install.json` (Phase 7) is the same idea, one level up: it
  *describes* the whole system; first boot *realises* it. **No imperative config sprawl.**

## Packages
- `core/pkgrepo.d` (DM7) is a capability-gated package manager over `/config/packages.json`;
  busybox provides the base applet userland; per-domain distro/pkg-mgr profiles exist (DM11).
  Phase 9 "init package database" maps onto this, not apt/dnf.

## Bootloader + first boot
- **limine** is installed on the boot path; the ISO build already produces **GPT + an ESP**.
  Phase 8/9 reuse this: the partition module lays GPT+ESP+rootfs and drops the limine UEFI/BIOS
  files + a generated `limine.conf` (the same one the ISO uses, retargeted to the disk).
- "First boot" = the kernel's `init = Weston module` path (`kernel_main`) bringing up the
  desktop; the installer adds a first-boot consumer of `install.json` before the desktop.

## Integration points (where Calamares attaches)
| Calamares needs | EpinAnonymOS provides | Action |
|---|---|---|
| a Qt runtime | nothing yet | **build `deps/qt-stack`** (static Qt6, §D1) |
| a partitioning backend | object FS + AHCI/NVMe + GPT; **no udev/sys** | **`deps/parted-stack` + native module** (§D2) |
| run as root | **rootless**, capability-gated | one-shot block-write cap, not pkexec (§D2.2, Phase 11) |
| user creation | Domain/identity objects | custom **Identity** module → `install.json` (Phase 6/7) |
| bootloader install | limine + GPT/ESP already on the boot path | reuse it (Phase 8/9) |
| autostart on desktop | Weston + the Domain Manager autostart hook | autostart Calamares the same way (§D3) |
| GUI platform | **Weston/Wayland only** (no X11) | `qwayland` platform plugin, static (§D1.4) |

## Leave untouched
The kernel/ABI, the object FS, the identity/capability model, limine + the existing boot path,
and the desktop bring-up. Calamares is an **app on top** + a first-boot config consumer; it must
not modify the kernel or the boot protocol. All installer code stays under `installer/`.

## Required modifications (summary)
1. New `deps/qt-stack`, `deps/parted-stack`, `deps/calamares` (cross-build, §D1–D3).
2. `installer/calamares/` (branding, settings, custom Identity + object-FS partition modules).
3. Top `Makefile`: gated `qt-stack`/`parted-stack`/`calamares` targets; `hos.iso` stages the
   `calamares` boot module + autostart hook.
4. A first-boot `install.json` consumer (small, in the existing init path).
