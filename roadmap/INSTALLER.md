# EpinAnonymOS Installer Roadmap — Calamares, integrated as a first-class component

Integrate the **Calamares** installer into EpinAnonymOS as a first-class, in-OS component
— **not** a standalone Linux distro bolted on. Preserve the design philosophy throughout:
immutable kernel · rootless security · object-oriented OS architecture · declarative
configuration · BusyBox userland · Linux compatibility layer · identity-based security ·
minimal, auditable, modular code. Never duplicate functionality that already exists.

The original 14-phase plan is preserved below (Phases 1–14). Two things the plan previously
hand-waved are now first-class, because they are the load-bearing prerequisites: the **Qt
runtime** Calamares needs (§D1) and the **partitioning backend** it drives (§D2). Both are
specified against *this OS's actual build system*, not a generic Linux host.

---

## North star

Boot the live ISO → a branded Calamares launches on the Weston desktop → the user picks a
disk, a hostname, and a set of **Identity profiles** → Calamares writes ONE declarative
`install.json`, copies the OS to the disk, installs limine, and reboots → first boot consumes
`install.json` and materialises the object tree, identities, and permissions. No imperative
sprawl; the installer *describes*, first boot *realises*.

---

## Target-environment reality (read this before writing any build code)

Calamares is C++/Qt and builds fine against musl (Alpine ships it). The cost here is not the
libc — it is that **none of the Qt/KPMcore dependency stack is built in this repo yet**, and
this is not a normal Linux target. The existing cross-build convention (`deps/<name>/`) is the
template; mirror it exactly.

- **Toolchain.** `deps/musl/install/bin/musl-clang{,++}` (clang-18), `llvm-ar/ranlib/strip`.
  C++ runtime is **libc++** from `deps/cxxrt` (`stamps/libcxx.done`), *not* libstdc++.
- **Linking convention is STATIC.** Every `deps/*/sysroot` is built `-static -no-pie`
  (see `deps/gtk-stack/Makefile` `BASE_LDFLAGS`). GUI apps (`gtk-hello`, `wl-term`, the
  Wayland clients) ship as **single static ELF boot modules** in `cd/`, listed in
  `src/boot/limine.conf` as `module_path:`. Qt + Calamares must follow suit: a **static Qt**
  with the Wayland platform plugin **statically imported**, linked into one Calamares binary.
- **Display server is Weston/Wayland.** There is no X11. The only viable Qt platform plugin is
  **`qwayland`**; `xcb` is out. Input/output go through the same Weston the desktop uses.
- **No udev, no systemd, no polkit, no /sys PCI tree.** Storage is the kernel's **object
  filesystem** + an AHCI/NVMe block layer with **GPT** already understood by the boot path.
  The system is **rootless** (identity-based caps), so Calamares's usual "run partitioning as
  root via pkexec" model does not apply — see §D2.
- **Build orchestration.** Top-level `Makefile` builds `deps/*` via their sub-Makefiles into
  sysroots, then the `hos.iso` target stages binaries/blobs into `cd/`. Cross files live at
  `deps/<name>/stamps/meson-cross.ini` (meson) — CMake needs an analogous toolchain file.

---

## §D1 — Qt runtime (`deps/qt-stack`)

A **static Qt 6** cross-built with musl-clang + libc++, the minimum module set Calamares
needs, with `qwayland` as a static plugin. New tree `deps/qt-stack/` mirroring
`deps/gtk-stack/` (`Makefile`, `downloads/`, `build/`, `stamps/`, `sysroot/`).

### D1.1 — Host Qt tools (two-stage cross-build)
Qt 6's CMake build needs **host** `moc`/`rcc`/`uic`/`qmlcachegen`/`syncqt` of the *same
version* to cross-compile the target. Either install distro `qt6-base-dev-tools` or build a
minimal **host** `qtbase` (`-DQT_BUILD_TOOLS_ONLY`-style) once. Record its path; pass
`-DQT_HOST_PATH=<host-qt>` to every target build. Pin one Qt version (6.8 LTS) for all modules.

### D1.2 — Prerequisite libraries (into the qt-stack sysroot)
Reuse what `deps/gtk-stack/sysroot` already provides where possible (zlib, libpng, freetype,
fontconfig, harfbuzz, pcre2, glib, **wayland + wayland-protocols**, libxkbcommon). Add what Qt
additionally wants, built static against musl: **double-conversion**, **zstd**, optional
**OpenSSL** (for `qtnetwork` TLS — can defer; the installer is offline), **libb2**. xkbcommon
+ wayland are mandatory for `qwayland`.

### D1.3 — qtbase (static, musl, libc++)
Configure target qtbase with CMake + a Qt toolchain file (analogue of `meson-cross.ini`:
`CMAKE_C/CXX_COMPILER` = musl-clang{,++}, `CMAKE_SYSROOT` = the qt-stack sysroot,
`-stdlib=libc++`, `-static -no-pie`). Key flags:
`-DBUILD_SHARED_LIBS=OFF -DQT_HOST_PATH=… -DQT_FEATURE_xcb=OFF -DQT_FEATURE_dbus=OFF`
(no dbus daemon here) `-DQT_FEATURE_glib=ON -DQT_FEATURE_widgets=ON -DINPUT_opengl=es2`
(Mesa GLES2/virgl is what the desktop uses) `-DFEATURE_system_*` for the libs from D1.2.
Expect **musl patches** (port the ones Alpine carries): `__GLIBC__` guards, `execinfo`/
`backtrace` → libexecinfo or stub, `getauxval`, `pthread_getname`, `qt_safe_*` signal bits,
`iconv`. Stage `Core/Gui/Widgets/Network` static libs + headers into `sysroot`.

### D1.4 — qtwayland (the platform plugin, static)
Build `qtwayland` static against qtbase. Output is `libqwayland-integration.a` +
`libQt6WaylandClient.a`. Because Qt is static, the plugin cannot be discovered at runtime —
Calamares's `main()` (or a thin launcher) must `Q_IMPORT_PLUGIN(QWaylandIntegrationPlugin)`
and link the plugin lib. Set `QT_QPA_PLATFORM=wayland` at runtime via the Calamares wrapper.

### D1.5 — qtdeclarative + qtsvg + qttools
`qtdeclarative` (QML — Calamares branding/slideshow + several view modules use Quick);
`qtsvg` (SVG icons/branding); `qttools` host side for `lupdate/lrelease` (translations, Phase
13). QML with **static** Qt needs `qmlimportscanner` + `qmlcachegen` (host tools) and
`qt_import_qml_plugins()` so the QML modules are linked in. If QML proves too heavy on musl,
fall back to **Widgets-only** Calamares pages (Calamares supports both; lose only the fancy
slideshow).

### D1.6 — package + stage
Like Mesa drivers in the `hos.iso` target: there are no runtime `.so`s (static), so staging is
just the final Calamares ELF (§Phase 3) plus Qt **runtime data** that is read at startup —
`plugins/platforms` is linked-in, but **fonts** (already seeded), **QML modules** (if linked,
none external), and the **i18n `.qm`** files go into the rootfs the installer process sees.

---

## §D2 — Partitioning backend (`deps/parted-stack`) + the rootless adaptation

Calamares partitions through **KPMcore**, which wraps a backend (libparted or sfdisk) and
discovers devices via libblkid + udev. This OS has **no udev and no /sys block tree**, and is
**rootless** — so the backend needs real work, not just a build.

### D2.1 — Build the backend libraries (static, musl)
New `deps/parted-stack/` (mirror gtk-stack). Cross-build static against musl:
- **util-linux** → `libblkid` (fs/partition probing) + `libsmartcols` + `libuuid`,
  `--disable-all-programs --enable-libblkid --enable-libuuid`. (Heavy musl porting; Alpine
  patches exist.)
- **libparted** (GNU parted) → GPT/MBR table manipulation. Disable device-mapper, NLS, readline:
  `--disable-device-mapper --without-readline --disable-nls`. libparted does direct block-device
  I/O via `ioctl`/`BLKxxx` — see D2.3 for how those reach the kernel's block layer.
- optional **libatasmart** (KPMcore wants it; can stub).

### D2.2 — KPMcore (static, against Qt + the backend)
Build KPMcore with CMake against `deps/qt-stack` (Qt6 Core/Gui) + `deps/parted-stack`
(libparted/libblkid). KPMcore normally runs its partition operations through a privileged
helper (`kpmcore_externalcommand` via pkexec/`SUID`). **Rootless replacement:** build
KPMcore's **"sfdisk"/external** backend OR patch its `ExternalCommand` to invoke operations
through EpinAnonymOS's **capability-gated device syscall** instead of pkexec — the installer
identity is granted a one-shot block-write capability for the target disk only (mirrors the
DM8 device-class gate / the L4 LKL per-device cap). No SUID, no root.

### D2.3 — Device discovery + I/O against the object FS (the real adaptation)
KPMcore/libblkid enumerate disks from `/sys/block` + udev. EpinAnonymOS exposes block devices
as **objects** (`/objects/devices/…`) and through the AHCI/NVMe drivers, not `/sys`. Two
acceptable paths, pick per effort:
- **(a) Shim:** a thin compat layer that synthesises the few `/sys/block/<dev>/{size,…}` nodes
  + `/dev/<dev>` block files KPMcore reads, backed by the object FS — least KPMcore patching.
- **(b) Native module (preferred, fits Phase 12):** a custom Calamares C++ partition module
  that talks to the OS's block/object layer + the existing **GPT** support directly, bypassing
  KPMcore. The OS already creates GPT + an ESP on the boot path, so the primitives exist; this
  module just exposes "pick disk → lay down GPT+ESP+rootfs → mark bootable" to the UI. This is
  the rootless, udev-free, object-FS-honest design and avoids the util-linux/udev musl swamp.

The plan **builds D2.1+D2.2 (the literal KPMcore/libparted backend)** so the standard Calamares
`partition` module compiles and runs, **and** keeps **(b)** as the shippable default for this
OS. Disk Installation (Phase 8) consumes whichever is enabled via `modules.conf`.

---

## §D3 — Build integration (wiring D1/D2 into the tree)
- `deps/qt-stack/Makefile` and `deps/parted-stack/Makefile` follow the `deps/gtk-stack`
  stamp/sysroot pattern; add `qt-stack` / `parted-stack` / `calamares` targets to the top-level
  `Makefile`, gated like the GPU/GTK pieces so a normal build is unaffected if they're absent.
- `deps/calamares/Makefile` cross-builds Calamares (CMake, against qt-stack + parted-stack +
  yaml-cpp static), producing one static `calamares` ELF + its `.qm`/branding assets.
- `hos.iso` stages the `calamares` ELF as a boot module + appends `module_path: boot():/calamares`
  to `limine.conf` (conditional, like `gl-term`/`wl-files`), and seeds the branding/settings into
  the installer's runtime view.
- A live-session hook autostarts Calamares on the Weston desktop (reuse the Domain Manager
  autostart path: `wet_client_start` / the boot-module autostart already used for the desktop).

---

## PHASE 1 — Repository analysis
Determine, and write up in `installer/ARCHITECTURE.md`: how install/live-boot works today; where
the rootfs is generated; how packages install; how users/identities are created; how the
bootloader + config are generated; how first boot initialises. Report: existing architecture,
integration points, required modifications, components to leave untouched.

## PHASE 2 — Add Calamares
Vendor Calamares + the §D1/§D2 deps under `deps/`; put **all installer-specific** content under
`installer/calamares/` (`branding/ modules/ settings.conf modules.conf branding.desc scripts/
assets/ translations/ slides/`). Builds alongside the project. **Prereq: §D1 Qt runtime +
§D2 backend exist.**

## PHASE 3 — Build integration
Per §D3: Calamares + branding build automatically, assets land in the live image, no manual
copying.

## PHASE 4 — Branding
Replace ALL Calamares branding — logos, icons, backgrounds, slideshow, window title, distro
name, installer name, version strings, copyright, default colours — with EpinAnonymOS branding.
No upstream branding remains visible.

## PHASE 5 — Installation flow
Pages: Welcome · Language · Keyboard · Timezone · Disk Selection · Filesystem · Encryption ·
Hostname · Administrator · **Identities** · Summary · Installation · Finish. Feels like a
professional OS installer.

## PHASE 6 — Identity Manager page (custom module)
A bespoke Calamares C++/QML module replacing plain Linux user creation: an **Identity Manager**
(Administrator account + toggleable profiles: Personal · Work · Banking · Research · Disposable ·
Anonymous). Do **not** create every identity immediately — emit *configuration* describing them
(consumed at first boot). Each becomes a declarative **object** in the installed system.

## PHASE 7 — Declarative configuration
The installer performs minimal imperative work; it generates ONE declarative file
(`install.json`): hostname, locale, timezone, filesystem, encryption, bootloader, users,
administrator, identity definitions, desktop options, Linux-compat options, security options,
package selections, network configuration. First boot consumes it.

## PHASE 8 — Disk installation
Support GPT/MBR, EFI/BIOS, ext4/Btrfs/XFS, LUKS, swapfile/partition; automatic **and** manual
partitioning; respect immutable layouts. Driven by §D2 — KPMcore/libparted where built, the
native object-FS module by default. Bootloader = **limine** (the OS already installs limine on
GPT/ESP); the module lays down GPT + ESP + rootfs and installs limine UEFI/BIOS.

## PHASE 9 — Post-install scripts (modular)
Generate declarative config · install bootloader (limine) · copy kernel + modules · generate
initramfs/rootfs · create administrator · create initial object tree · generate identity
metadata · init package database · install Linux-compat layer · prepare first boot.

## PHASE 10 — First-boot integration
Installer → generate config → copy OS → reboot → first boot: init system, generate object tree,
create identities, init permissions, enable services, finalise. (Not all config during install.)

## PHASE 11 — Security
No plaintext passwords; password hashing; secure temp files; least privilege; installer runs with
the **minimal capability set** (a one-shot block-write cap for the chosen disk — §D2.2), not root;
validate input; verify copied files; verify package integrity; Secure Boot if available; encrypted
installs.

## PHASE 12 — Project integration
Integrate with the object model, identity manager, package manager, filesystem, Linux-compat
layer, security manager, kernel config, init system, configuration manager. **Do not hardcode
Linux assumptions the project already abstracts** (this is why §D2(b) is preferred).

## PHASE 13 — Documentation
Architecture doc, installer developer guide, directory structure, module docs, branding guide,
configuration reference, build instructions, flow diagrams, first-boot sequence, extension guide.

## PHASE 14 — Validation
✓ installer builds ✓ live ISO boots ✓ installer auto-launches ✓ install succeeds ✓ bootloader
installs ✓ system boots ✓ first boot consumes `install.json` ✓ identities init ✓ object tree init
✓ Linux-compat works ✓ security applied ✓ declarative config preserved.

---

## General requirements
Favour modularity over monoliths · reuse Calamares modules, write custom ones only for what is
unique here (Identity, the object-FS partition module) · keep installer code under `installer/` ·
document every modification + why · extend/integrate rather than replace where the repo already
provides the function · end with a checklist of done / remaining / risks / next steps.

## Honest status + risk
The dominant cost and risk is **§D1/§D2**, not the Calamares glue: static **Qt 6 on musl/libc++**
(porting patches, two-stage host-tools build, static-QML plugin import) and the **udev-free,
rootless partitioning backend** are each multi-day efforts with real chance of upstream friction.
Mitigation/order: (1) `deps/qt-stack` qtbase+qwayland static "hello world" on Weston FIRST — prove
Qt runs here before any Calamares code; (2) scaffold `installer/calamares/` + branding + the
custom modules against that; (3) bring up partitioning via §D2(b) (native module) to sidestep the
util-linux/udev swamp, building D2.1/D2.2 in parallel for the standard module. Each step boots the
live ISO and is checkpointed; nothing lands that breaks the desktop.

## Build status (live)
- **§D1 qtbase ✅ DONE + verified.** `deps/qt-stack` cross-builds **static Qt 6.4.2** with musl-clang
  + libc++, reusing the gtk-stack sysroot for shared prereqs. `qtbase` configures clean and builds
  **[1013/1013], 0 errors** → `libQt6{Core,Gui,Widgets,Network,Concurrent,Xml,PrintSupport}.a` +
  platform-support libs in `sysroot`. The plan's dominant risk (does Qt build here at all?) is
  retired. Config keys that mattered: bundled md4c/b2 (`-DINPUT_libmd4c=qt`), and
  `-DINPUT_opengl=no -DFEATURE_egl=OFF` (raster + `wl_shm`, Widgets-only — D1.5).
- **§D1 qtwayland ◑ blocked on the HOST toolchain (two-stage, D1.1).** The cross recipe is fine; it
  needs the **host** `qtwaylandscanner` + Qt **private** headers (`Qt::CorePrivate`). Debian's
  `qt6-base-dev` ships neither, and `qt6-base-private-dev` / `qt6-wayland-dev` aren't installed (no
  sudo). **Next:** build a host qtbase (native, with private headers) + host qtwayland tools, point
  `HOST_QT_PREFIX` at it, then `make -C deps/qt-stack qtwayland`. (Same two-stage Qt cross-build
  pattern; just host-side.)
- **§D2 / Calamares: scaffolded, not built.** `installer/calamares/` has the sequence, branding, and
  the custom `identitymanager` view module; `deps/parted-stack` + `deps/calamares` recipes are
  specified (D2/D3) and build once qtwayland lands. Phase-1 analysis: `installer/ARCHITECTURE.md`.
