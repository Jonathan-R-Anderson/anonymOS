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

Boot the live ISO → the Weston desktop comes up carrying an **"Install EpinAnonymOS to Disk"
desktop entry** (panel launcher + keybind, and a first-run auto-launch on live media) → the
user opens it → a branded Calamares lets them pick a disk, a hostname, and a set of **Identity
profiles** → Calamares writes ONE declarative `install.json`, copies the OS to the disk,
installs limine, and reboots → first boot consumes `install.json`, materialises the object
tree, identities, and permissions, and **sets `system.installed = true`**. From then on the
installer desktop entry is **gone from every startup** — declaratively, because it is gated on
that one flag, not torn down by hand. No imperative sprawl; the installer *describes*, first
boot *realises*, and the install surface *retires itself*.

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

## §D4 — Live "Install to Disk" desktop entry + post-install self-removal

The installer must be reachable from the running live desktop as a first-class **desktop entry**
("Install EpinAnonymOS to Disk"), and that entry must **disappear from every future startup once
the OS is installed to disk** — declaratively (gated on one flag), never by deleting files.

Grounding in this OS's real mechanisms: the desktop is **Weston + the desktop-shell panel + the
Domain Manager**, configured by the single file **`cd/desktop.conf`** that the shell reads at boot
(`autostart = <module>`, `bind = MODIFIERS, KEY, exec, <module>`, panel launchers). Persistence is
the **AHCI object store** (F4, `objstoreMounted()`) + the declarative **`/config/system.json`**
(rendered by the kernel; see `core/hoscall.d`). D4 wires the entry into the former and gates it on
a flag in the latter.

### D4.1 — The entry (live desktop surface)
A branded launcher **"Install EpinAnonymOS to Disk"** (icon + label) that launches the Calamares
boot module (`/calamares`, §D3). Surfaced three complementary ways, all driven by
`desktop.conf` / the shell so no new launch machinery is invented:
- a **panel launcher** in the desktop-shell panel — the always-visible primary entry;
- a **keybind** (e.g. `bind = SUPER, I, exec, /calamares`);
- on live media only, an optional **first-run auto-launch** (`autostart = /calamares`) so a fresh
  boot opens the installer directly (the North-Star flow).
The **Domain Manager** (the default autostart client) also grows an "Install to Disk" toolbar
action. Every one of these routes through the single visibility gate in D4.3.

### D4.2 — The `installed` state flag (single source of truth)
One persistent boolean — **`system.installed`** in `/config/system.json`, backed by an object in
the on-disk object store — is the authority. It is **false/absent on live media** and set **true
exactly once**, at first boot of the installed system (Phase 10, when `install.json` is consumed).
It is never written by a live session. The kernel exposes it as a read-only userspace signal
(e.g. `/system/state/installed`, alongside the existing `/config` render path) so the shell can
consult it cheaply without parsing JSON.

### D4.3 — Conditional visibility (the self-removal)
At desktop startup the shell consults the `installed` signal and **includes the installer entry
iff not installed**. "Disappears after install" is therefore declarative and idempotent:
- live / not-yet-installed (`installed != true`) → entry shown in the panel + keybind, and
  optionally auto-launched;
- installed (`installed == true`) → entry **omitted** from the panel launcher, the keybind table,
  the `autostart` list, and the DM toolbar — on this boot and every future one.
Nothing is deleted and no imperative teardown runs; flipping the one flag retires the entry
everywhere at once. (Same pattern the DM device-class gate / `/config` render already use to drive
UI purely from declarative state.) Implementation seam: have the desktop-shell's `desktop.conf`
reader skip any entry tagged `live-only` (a new `installer = /calamares` directive, or a
`live-only` flag on a `bind`/`autostart`/launcher line) when the `installed` signal is true.

### D4.4 — Live-vs-installed detection (how the flag gets its initial value)
The **live ISO** boots from **read-only media** with an **ephemeral object store** and **no
install-complete marker**; the **installed system** boots from the **on-disk object store**
carrying the marker that `install.json` + first boot left. The kernel derives `installed` from
"booted off the persistent on-disk store **AND** the install-complete marker is present", then
renders it into `system.json` / the `/system/state/installed` signal. A blank or half-written
target disk seen *during* a live session (object store freshly formatted, no marker) still reads
`installed = false`, so the entry correctly stays until a real install finishes and reboots.

### D4.5 — Incremental delivery (decouple from the heavy Calamares build)
The entry + gate are independently testable and can land **before** Calamares fully builds: ship a
tiny placeholder `/calamares` (or point the entry at a stub that prints "installer not yet built")
so D4.1–D4.4 — appears on live, hidden after `system.installed=true` — can be validated on the
existing desktop now, then swapped for the real installer when §D1–§D3 complete.

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
copying. **Also stage the §D4 desktop entry**: the "Install EpinAnonymOS to Disk" launcher
icon/label asset, and the `desktop.conf` lines that surface it (panel launcher + keybind +
live-only `autostart`), authored as `live-only` so the D4.3 gate can hide them post-install.

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
package selections, network configuration. First boot consumes it. **`install.json` is also the
install-complete marker (§D4.2/D4.4)**: its presence on the on-disk object store is what first
boot keys off to set `system.installed = true` and retire the installer entry.

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
**First boot of the installed system sets `system.installed = true`** (§D4.2) after consuming
`install.json` — the single, idempotent act that makes the §D4.3 gate hide the "Install to Disk"
desktop entry on this and all future startups. Setting it must be crash-safe/idempotent (re-runs
on a partial first boot converge, never resurrecting the entry once install truly completed).

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
✓ installer builds ✓ live ISO boots ✓ **"Install to Disk" desktop entry present on the live
desktop** (panel + keybind) ✓ entry launches Calamares ✓ installer auto-launches (live first-run)
✓ install succeeds ✓ bootloader installs ✓ system boots ✓ first boot consumes `install.json`
✓ **first boot sets `system.installed = true`** ✓ **installer desktop entry ABSENT after
install + reboot, and on every subsequent startup** ✓ identities init ✓ object tree init
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
live ISO and is checkpointed; nothing lands that breaks the desktop. **§D4 (the live "Install to
Disk" entry + self-removal) is low-risk and decoupled** — it touches only `desktop.conf` / the
desktop-shell gate + one persistent `system.installed` flag, so it can land early against a stub
`/calamares` (D4.5) and be validated on the current desktop before the heavy Qt/KPMcore work
finishes.

## Build status (live)
- **§D1 qtbase ✅ DONE + verified.** `deps/qt-stack` cross-builds **static Qt 6.4.2** with musl-clang
  + libc++, reusing the gtk-stack sysroot for shared prereqs. `qtbase` configures clean and builds
  **[1013/1013], 0 errors** → `libQt6{Core,Gui,Widgets,Network,Concurrent,Xml,PrintSupport}.a` +
  platform-support libs in `sysroot`. The plan's dominant risk (does Qt build here at all?) is
  retired. Config keys that mattered: bundled md4c/b2 (`-DINPUT_libmd4c=qt`), and
  `-DINPUT_opengl=no -DFEATURE_egl=OFF` (raster + `wl_shm`, Widgets-only — D1.5).
- **§D1 qtwayland ✅ DONE (host-toolchain blocker resolved).** `make -C deps/qt-stack qtwayland`
  cross-builds the **static `qwayland` platform plugin**: `sysroot/lib/libQt6WaylandClient.a` (2.1 MB),
  `sysroot/plugins/platforms/libqwayland-generic.a` (the QPA plugin for `Q_IMPORT_PLUGIN`), the shell
  integrations (`xdg-shell`/`wl-shell`/`ivi-shell`/`qt-shell`/`fullscreen-shell-v1`), the `bradient`
  client-side-decoration plugin, and the `Qt6WaylandClient` CMake package. **The two-stage host
  toolchain (D1.1) is now a real, self-contained target:** `make -C deps/qt-stack host-qt` builds a
  **native** host Qt (host qtbase + host qtwayland) into `deps/qt-stack/host-qt`, providing
  `moc/rcc/uic/syncqt` **and** `qtwaylandscanner` (+ its `Qt6WaylandScannerTools` CMake export) — so
  the cross build imports `Qt6::qtwaylandscanner` from there instead of Debian's `/usr` Qt (which ships
  no scanner + no private headers). The whole cross stack now uses `host-qt` as `QT_HOST_PATH`, fully
  decoupled from Debian. ★★ TRAPS (all fixed in the Makefile):
  (1) **`CMAKE_FIND_PACKAGE_TARGETS_GLOBAL=ON`** on the host build — Qt 6.4.2 + CMake ≥ 3.28 otherwise
  dies promoting `Threads::Threads` to `IMPORTED_GLOBAL` from `src/corelib` (cross-directory scope is
  forbidden); the flag makes `find_package` create targets global inline so Qt's manual promotion is
  skipped. The cross qtbase dodges this via its toolchain-file scoping; the native host build needs it.
  (2) **`-DFEATURE_xkbcommon=OFF` on the host build** — Ubuntu's system `xkbcommon-keysyms.h` (1.6.0)
  predates the `XKB_KEY_dead_*` keysyms Qt 6.4.2 references, so `qxkbcommon.cpp` won't compile on the
  host; a tool-only host Qt needs no keyboard, and the cross build gets real xkbcommon (1.7.0, with
  those keysyms) from `deps/gtk-stack/sysroot`.
  (3) **Cross qtbase MUST be rebuilt against `host-qt`, not Debian** — the cross qtbase *bakes*
  `initial_qt_host_path[_cmake_dir]` into `sysroot/lib/cmake/Qt6/Qt6Dependencies.cmake`, and cross
  qtwayland reads them. If they point at Debian, `find_package(Qt6HostInfo)` resolves Debian's
  `QT6_HOST_INFO_LIBEXECDIR=lib/qt6/libexec`, so syncqt is sought at `host-qt/lib/qt6/libexec/syncqt.pl`
  (doesn't exist; ours is `host-qt/libexec/syncqt.pl`) → "Can't open perl script … syncqt.pl". Building
  cross qtbase against `host-qt` bakes the correct `./libexec`.
  (4) **`unpack` now wipes the `-build` dir too** — a stale Qt CMake build dir caches
  `QT_HOST_PATH`/`QT_HOST_PATH_CMAKE_DIR`, so reconfiguring with changed `-D` flags left a *split*
  host-path state (`QT_HOST_PATH=host-qt` but `_CMAKE_DIR=/usr`). A clean build dir per configure
  prevents it.
  **Remaining for roadmap-order step (1):** runtime proof — a static qtbase+qwayland "hello world"
  rendered on Weston (boot the live ISO). The build artifacts are all present; only the on-Weston
  validation is left.
- **§D3 build infrastructure ◑ BEGUN.** The Calamares cross-build tree exists:
  `deps/calamares/Makefile` (CMake cross via the shared `deps/qt-stack/qt-cross.cmake`, now with a
  `CALAMARES_SYSROOT` in its find path) builds Calamares' C++ deps + the installer ELF into
  `deps/calamares/sysroot`. **yaml-cpp ✅ built** (static `libyaml-cpp.a`, musl + libc++) — proving
  the non-Qt C++ dependency pipeline works. `deps/parted-stack/Makefile` (§D2.1 util-linux
  libuuid/libblkid + libparted, autotools-cross like gtk-stack) is **scaffolded** (the recipe; the
  musl-porting long-pole is next). Opt-in top-level targets added (NOT in the default build):
  `make qt-stack | calamares-deps | parted-stack | calamares | installer-deps`.
- **§D2 / Calamares core: not built yet.** Remaining: build §D2 (util-linux/libparted + KPMcore, or
  the §D2(b) native object-FS module) → then the `calamares` ELF (recipe staged in
  `deps/calamares/Makefile`, Widgets-only/no-QML/no-Python) → wire `installer/calamares/` (sequence,
  branding, the custom `identitymanager` module). Phase-1 analysis: `installer/ARCHITECTURE.md`.
- **§D4.1 ✅ DONE — the "Install to Disk" entry exists + verified in VBox.** Launch target = a
  **§D4.5 stub** (`src/util/wl-installer.c`, a Cairo/FreeType Wayland client): a welcome — "Install
  EpinAnonymOS to a disk, or try the live session" — with two working buttons, **Install to Disk**
  and **Try Live Session**. *Try Live Session* closes the installer to the live desktop; *Install to
  Disk* shows a clear "Calamares disk-install is being integrated (§D1–D3), not in this build yet"
  screen (the stub genuinely can't partition/copy/persist — no fake install; no text-entry box).
  Built via `INSTALLER_BIN`, staged as `cd/calamares` + `module_path: boot():/calamares`; the real
  Calamares (§D1–D3) drops in at the same path later. All button actions verified via QMP in
  software QEMU (Install→info, Back→welcome, Try-Live→close).
- **§D4.2 / D4.3 / D4.4 ✅ DONE — installer AUTO-LAUNCHES on a live boot and self-removes once
  installed (verified both ways, 0 faults).** No key combo: on a live boot the installer **appears
  automatically, front-and-centre**. Mechanics in `deps/weston-14.0.0/desktop-shell/shell.c`:
  `epin_load_config` checks `access("/install.json")` once (the install marker = the one declarative
  file Calamares writes, Phase 7; presence = "installed") and recognises two LIVE-MEDIA-ONLY
  directives, **`autostart-live`** and `bind-live`, which are honoured while live and **skipped once
  installed**. `autostart-live` entries launch on a **+3000 ms `wl_event_loop` timer** so they map
  *after* the desktop and come up as the focused, on-top window (fixes the earlier occlusion behind
  the maximized Domain Manager). `src/desktop.conf` now has `autostart-live = /calamares` (no
  keybind). Verified in VBox (x2APIC on): live boot → `install state = live`, `scheduled 1 live-only
  autostart … (+3000ms, on top)`, installer renders on top with no input; with `/install.json`
  present → `install state = INSTALLED (live-only entries HIDDEN)`, **nothing scheduled, no installer**
  — gone on this and every future startup. (D4.2's richer `system.installed` field in
  `/config/system.json` + a kernel `/system/state/installed` render can replace the raw `access()`
  signal later without touching the gate.)
- **§D4 remaining:** the **real install→marker write** — Calamares (§D1–D3) + first boot (Phase
  7/10) must actually drop `/install.json` on the persistent on-disk root so a truly-installed
  system trips the gate (today the gate is proven; the thing that *creates* the marker for real is
  the Calamares build).
