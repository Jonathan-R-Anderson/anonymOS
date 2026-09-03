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

## Current implementation audit (2026-06-29)

The repository does **not** yet implement every facet of this roadmap in full. The native
installer path is real and now drives a **full, Ubuntu-like guided page sequence** end-to-end; the
heavy Qt/Calamares stack (§D1–§D3) remains the only roadmap-incomplete delivery vehicle, and the
native installer is the shippable one.

Implemented now:
- Native Wayland installer UI at `/calamares` (`src/util/wl-installer.c`, Cairo/FreeType) now spans
  the **full Phase-5 page sequence**: Welcome · Language · Keyboard · Time zone · Network · Disk ·
  Filesystem · Encryption · (Decoy) · Boot integrity · Account · Identities · Summary · Install. It
  has a left step rail, scrollable single-choice option lists (mouse wheel + arrow keys), a
  toggleable identity-profile page (Phase 6: Personal/Work/Banking/Research/Disposable/Anonymous),
  per-page validation (password match, required fields gate the Continue button), and a slideshow on
  the progress page. It sends the captured JSON to `/config/install.action` before triggering install.
- **Real disk enumeration.** The kernel renders the live AHCI block devices as declarative JSON at
  **`/config/disks.json`** (`core/hoscall.d` CFG_DISKS — index + size + role hint). The installer's
  Disk-Selection page reads it and lists real targets (or "Automatic" when none are enumerated);
  choosing a specific disk sends `install <idx>` to the backend, otherwise `install` (auto-target).
- **All wizard choices are declarative.** The GUI serialises locale, keymap, timezone, network,
  filesystem, target disk, boot-integrity mode, and the enabled identity profiles into the captured
  config; the kernel backend (`drivers/veracrypt_impl.d installBuildPersistedConfig`) carries those
  non-secret fields verbatim into the persisted `/install.json`, and first boot
  (`core/install_config.d`) consumes + logs them alongside the account/hostname it already applies.
- Kernel install backend (`src/kernel/d/drivers/veracrypt_impl.d`) accepts `config <json>` and
  `install [diskidx]`, writes a GPT + ESP from the staged `esp-image` (or `esp-hidden-image` for
  Hidden OS), persists the captured config into the installed ESP as `/install.json`, and fails instead
  of reporting 100% if config persistence fails.
- First boot consumes installed `/install.json` (`src/kernel/d/core/install_config.d`) and applies the
  OS account name + hostname into the kernel-owned user/hostname views. It also records decoy metadata
  and password-hash presence for later decoy/encryption integration.
- Plaintext installer passwords are not persisted. The install backend stores SHA-512 hex fields in
  `install.json` (`userPasswordSha512`, `decoyPasswordSha512`, `hiddenPasswordSha512`,
  `outerPasswordSha512`, `decoyBootPasswordSha512`).
- When **Hidden OS** is selected, the installer ISO carries both `esp-hidden-image` (preboot EFI +
  stage2) and the built §H1 Alpine decoy disk image as `decoy-linux.ext4`; the kernel install backend
  refuses to silently fall back to a plain install, writes the encrypted ESP/system/outer GPT, streams
  the preboot ESP, random-fills the decoy system partition and the full outer partition, XTS-encrypts
  the decoy Linux image into the decoy system partition, XTS-encrypts the normal installed
  EpinAnonymOS image into the hidden volume area, and writes decoy/outer/hidden VeraCrypt headers from
  the selected boot passwords.
- Installed-state is exposed both in `/config/system.json` as `installed` and as the read-only
  `/system/state/installed` signal. Today this is derived from whether the installed `/install.json`
  boot module was loaded.
- Live-only installer autostart/gating exists through `desktop.conf` `autostart-live = /calamares`
  and the desktop shell's install-state check.

Not implemented in full:
- The Calamares (Qt) installer binary and its page sequence are scaffolded, not complete — the
  native UI above is the shippable flow that already covers the Ubuntu-like sequence.
- The locale/keymap/timezone/network/filesystem/boot-integrity selections are **captured,
  persisted, and consumed (logged) at first boot**, but the kernel does not yet *act* on all of them
  (e.g. it does not re-map the live keymap or set a system timezone offset from the value). Manual
  partitioning is still automatic single-ESP only (no custom partition layout UI).
- Identity profiles chosen on the Identities page are captured + persisted as a declarative list;
  materialising each as a first-boot identity **object** (Phase 6/10) is not yet wired.
- Real login password enforcement is not modeled by the kernel user system yet. Usernames/hostnames
  are applied; password hashes are persisted for future auth/encryption consumers.
- Decoy OS account/password values are captured and persisted, and the staged decoy Linux image plus
  hidden EpinAnonymOS payload are now encrypted into the target disk when Hidden OS is selected.
  Remaining gaps: per-install regeneration of the decoy image with the user-entered decoy account
  values, and replacing the EFI `stage2.efi` handoff stub with the real decoy/hidden OS bootloader.
- The zkSync boot-attestation option is specified only.
- Full validation from Phase 14 still needs to be rerun on a freshly built install ISO by the operator.

---

## Target-environment reality (read this before writing any build code)

Calamares is C++/Qt and builds fine against musl (Alpine ships it). The cost here is not the
libc — it is that this is not a normal Linux target, and the Qt/partitioning stack has to be built
and adapted inside this repo. Qt base + qtwayland are now built; KPMcore/libparted remain scaffolded
and the native backend is the shippable path. The existing cross-build convention (`deps/<name>/`) is
the template; mirror it exactly.

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

Current native-installer implementation: the signal is derived from the installed `/install.json`
boot module that the backend writes into the installed ESP. `/config/system.json` and
`/system/state/installed` expose that state now; backing the flag with the persistent object store is
still the planned stronger form.

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

### D6 — Native in-OS installer (**works today**, no Calamares dependency)

A self-contained installer that installs the running OS to a disk and boots it — independent of the
heavy §D1–§D3 Qt/Calamares stack. This is what the "Install to Disk" button drives now.

**Approach (prebuilt ESP image).** Building a FAT32 filesystem host-side (`mkfs.fat`/`mcopy`) is far
simpler and more robust than an in-kernel FAT writer, so:
- `scripts/mk-install-iso.sh` builds an **`esp-image`** boot module = a FAT32 EFI System Partition
  containing the whole boot tree (limine `BOOTX64.EFI` + `kernel.elf` + modules + `limine.conf`),
  and stages it into **`hos-install.iso`** (`make hos-install.iso`).
- In the OS, `installBootableToDisk()` (`drivers/veracrypt_impl.d`) writes a **single-ESP GPT**
  (`core/diskpart.d gptWriteBootableEsp`) to a target disk, then streams the `esp-image` payload into
  the ESP — cap-gated (`core/install_cap.d`). UEFI firmware then boots the installed disk directly.
- The desktop **"Install to Disk"** button writes `install` to **`/config/install.action`**, a
  write-only kernel control file (`FD_INSTALL_CTL` in `posix.d`, mirroring `/config/domain.action`),
  which routes to `installControlWrite()`. Grammar: `config <install.json>` followed by
  `install [diskidx]`.
- **Robustness:** the install targets a spare disk distinct from the object store, and
  `objstoreMount()` refuses to claim a **GPT-partitioned** disk (`disk.d diskFirstSectorIsGpt`), so an
  installed disk's boot GPT is never clobbered by the object store — it boots repeatedly.

The native path is implemented, but every change to this area must be revalidated from a freshly
built install ISO: install → target gets a valid single-ESP GPT → booting the installed disk alone
reaches the desktop → `/config/system.json` reports `installed: true` and `/system/state/installed`
prints `true`.

#### Testing the installer in VirtualBox
```
make hos-install.iso                 # boot tree + esp-image + esp-hidden-image + decoy-linux.ext4
scripts/vbox-install-test.sh         # create a UEFI/x2APIC VM: store + 8G system disks + installer DVD
scripts/vbox-install-test.sh --start # boot it
  # → desktop → "Install to Disk" → Install; tail the VM serial.log for "[install] DONE"; power off
scripts/vbox-install-test.sh --boot-disk   # detach the DVD + boot the installed system disk
```
The VM has two SATA disks: **port 0 `store`** (live object store, scratch) and **port 1 `system`**
(the install target you boot afterward). UEFI + x2APIC are required (the kernel needs x2APIC; the
installed disk is UEFI/limine-only — no BIOS bootloader is installed).

> Future: when §D1–§D3 land, Calamares becomes the richer guided installer (partitioning choices,
> the §E encrypted decoy/hidden-OS option); D6 is the minimal always-available path it builds on.

---

## §E — VeraCrypt-derived decoy/hidden-OS disk encryption (stripped to plausible deniability)

An **optional installer step** (one page in the Phase-5 flow, off by default) offering
**plausible-deniability full-disk encryption with a hidden OS**: a second EpinAnonymOS installed in
a *different layer of the disk encryption* than the visible one. Built by **refactoring the vendored
`deps/VeraCrypt` down to ONLY this feature** — strip everything else. Reuses the §D2(b) partition
engine (the kernel owns block I/O + the GPT/ESP layout) and the crypto already seeded in the kernel
(`src/kernel/d/drivers/veracrypt_impl.d`: XTS-AES, PBKDF2-HMAC-SHA512, VeraCrypt volume header).

### E0 — The deniability model (what "decoy OS" means here)
Two operating systems, two passwords, on one disk:
- **Decoy OS** — a normal-looking, fully-encrypted EpinAnonymOS on the system partition. Booting it
  proves the disk is encrypted (nothing suspicious about that), so the **decoy password** is the one
  you reveal under coercion.
- **Hidden OS** — the *real* EpinAnonymOS, living inside a **hidden volume** in the free space of a
  second ("outer") volume. Its existence is **cryptographically undetectable**: the hidden volume is
  indistinguishable from the random data that fills the outer volume's free space. The **hidden
  password** boots it; without it there is no evidence it exists.
The outer volume itself is a third, decoy-sensitive container (with plausible-but-fake files) the
user can also reveal — so revealing *a* password never proves it was the only one. This is
VeraCrypt's hidden-OS construction, adapted; the security claim is *plausible deniability*, and §E7
treats it as security-critical, not a checkbox.

### E1 — Strip VeraCrypt to the decoy/hidden-OS subset (`deps/veracrypt`)
Refactor the 76 MB vendored tree to a minimal cross-buildable library — KEEP only what the feature
needs, DELETE the rest:
- **KEEP** — `Crypto/` ciphers (AES + Serpent + Twofish + the cascades) and hashes
  (SHA-512/Whirlpool/Streebog/BLAKE2s) + the KDF; the **volume-header format** (primary + the hidden
  header at the second offset); the system-encryption + **hidden-OS layout logic** distilled from
  `Common/BootEncryption.cpp`; and the **EFI pre-boot loader** (`Boot/EFI`).
- **STRIP** — the wxWidgets GUI (`Main/`, `Mount/`, `Resources/`), file-container volumes (the
  non-system use case), the Windows kernel driver (`Driver/`), `Format/`, `ExpandVolume/`, `Setup/`,
  `COMReg/`, `PKCS11`/smartcard, language packs, and all non-target-OS code. The result is a tiny,
  auditable encryption core — no daemon, no mount service, no Windows.
- Cross-build it the repo way (`deps/veracrypt/Makefile`, musl-clang, `-static -no-pie`), and **fold
  it into the kernel's existing `veracrypt_impl.d`** rather than duplicating — that file is the seed.

**Crypto core ✅ DONE — cross-builds + KAT-validated.** `deps/veracrypt/Makefile` (opt-in:
`make veracrypt`) compiles ONLY a curated, software-only C subset of `../VeraCrypt/src/Crypto` into
`sysroot/lib/libvc_crypto.a` (37 symbols): AES (Aescrypt/Aeskey/Aestab), Serpent, Twofish,
Kuznyechik, SHA-512, Whirlpool, Streebog. `-DCRYPTOPP_DISABLE_ASM` selects the pure-C transforms (no
hw-asm/SSE/AVX/NEON variants, no CPU-feature dispatch, no `cpu.c` — nothing but the math compiles;
VeraCrypt's `_UEFI` mode is avoided as it pulls in EDK2 `<Uefi.h>`). `make veracrypt` links a NIST
known-answer test (`test/kat.c`, musl-static, runs on the build host): **AES-256 KAT PASS** (FIPS-197)
+ **SHA-512 KAT PASS** — the strip kept a *correct* core, not just a linkable one. (Camellia/blake2s
have minor include quirks; PBKDF2/`Pkcs5.c` pulls in Argon2 — both folded into E2.)
**Volume-header + hidden-volume layout ✅ DISTILLED** → `deps/veracrypt/VOLUME_FORMAT.md`. The
upstream `Common/` encryption C (`Volumes.c`/`Xts.c`/`Crypto.c`) is MSVC/Windows-tangled (`__int64`
intrinsics, `<strsafe.h>`/`<io.h>`, an `EncryptionThreadPool`, the EFI `_UEFI`+`<Uefi.h>` path) — and
its only clean cross-build is the `_UEFI` mode, which needs the EDK2 headers. Porting it recreates the
"musl swamp" §D2 deliberately rejected. So §E keeps the split the architecture already implies:
**the portable crypto core stays C (`libvc_crypto.a`, done), and the XTS mode + volume header + the
hidden-volume layout are implemented NATIVELY in the kernel's `veracrypt_impl.d`** (which already seeds
`xts_encrypt_sector`/`pbkdf2_sha512`/`create_veracrypt_header`; the kernel owns block I/O per §D2(b),
so it owns the on-disk encryption). `VOLUME_FORMAT.md` is the byte-exact spec it implements in E2 —
header geometry, every field offset, the `HIDDEN_VOLUME_SIZE` tell + the second hidden header at
`TC_VOLUME_HEADER_SIZE`, the random-fill deniability requirement, and the KDF/cipher set.
**"Strip" = build only the Crypto/ subset; the rest of the vendored tree is reference** (kept on
purpose — other VeraCrypt features may be wanted later), not compiled or shipped.
**E1 remaining → folded into E5:** the `Boot/EFI` pre-boot loader is its own UEFI-toolchain build.

### E2 — Crypto core (extend `veracrypt_impl.d` to VeraCrypt parity)
Bring the kernel/installer crypto to header-compatible parity with the stripped subset: the full
cipher set + cascades, the exact PBKDF2 iteration counts + header KDF, the **hidden-volume header**
(a second encrypted header at the standard backup offset that only the hidden password decrypts), and
XTS over the whole system partition. Header-compat means a stripped VeraCrypt could in principle open
our volumes — a strong correctness check, not a runtime dependency.

**E2a — header engine + deniability ✅ DONE on the KAT'd crypto** (`deps/veracrypt/vcheader.{c,h}`,
`make veracrypt` → `header-test`). Implements the full `VOLUME_FORMAT.md` layout — AES-256-XTS header
(data unit 0), PBKDF2-HMAC-SHA512 header KDF, big-endian fields at every documented offset, key-area +
header CRCs — as `vc_create_header` / `vc_open_header` over `libvc_crypto.a`. The 8/8 test proves the
**hidden-volume deniability mechanism end-to-end**: create a decoy + a hidden header, each opens with
*only* its own password, wrong passwords are rejected, and the `"VERA"` magic is encrypted (no
plaintext tell). The XTS + PBKDF2 here deliberately mirror `veracrypt_impl.d`'s algorithms so it is
the byte-exact reference for E2b.
**E2b — kernel native-D header ✅ DONE + byte-identical to the C reference.** Done in two steps:
- **E2b-1 — real kernel crypto** (`drivers/veracrypt_crypto.d`): pure-D AES-256 + SHA-512 replace the
  former do-nothing `core/stubs.d` stubs (`sha512_hash` used to just klog "STUB"). `vcCryptoKat()` runs
  at boot → `[vc-crypto] KAT PASS (AES-256 FIPS-197 + SHA-512 NIST)`.
- **E2b-2 — the header port** (`veracrypt_impl.d` rewritten to `VOLUME_FORMAT.md`: absolute big-endian
  offsets, XTS unit 0, PBKDF2 matched). `vcHeaderProof()` writes a header (fixed inputs) to a spare
  disk; the host `make veracrypt parity-check` → `vc-parity <image>` cross-checks it the §D2(b) way:
  **"kernel header is byte-identical to vcheader.c reference" + "vc_open_header opens it + recovers the
  master key"** — both PASS. Two independent implementations (kernel D, host VeraCrypt-derived C)
  produce the *same bytes*. Header parity proven.

### E3 — On-disk layout (built on the §D2(b) GPT engine)
The Phase-8 partitioner (`core/diskpart.d`) lays the GPT down; §E adds the encrypted layout:
- **ESP** (unencrypted, FAT32 — already done in §D2(b)): holds *only* the §E5 pre-boot loader. No
  plaintext OS leaks here.
- **System partition** (after the ESP): the **decoy OS**, system-encrypted (XTS-AES); its VeraCrypt
  header sits at the partition start.
- **Outer-volume partition**: a normal encrypted volume (decoy-sensitive fake files) whose free
  space holds the **hidden volume** → the **hidden OS**. Outer header at the front, hidden header at
  the backup offset.

**✅ DONE — the encrypted layout is written + host-validated.** `veracrypt_impl.d
vcEncryptedLayoutProof()` writes the three headers (decoy-system, outer, hidden) at fixed LBAs
modelling the partitions, plus one XTS-encrypted decoy-OS data block, to a spare disk via
`diskWriteSectorsOn` (SKIPs without one). The host `make veracrypt layout-check` → `vc-layout
<image>` validates **8/8**: each header opens with **only its own password**; no password opens
another volume (deniability); the **decoy data block decrypts** with the recovered decoy master key
(real data encryption, not just headers); the hidden header shows no plaintext magic. This is the
multi-header decoy/hidden scheme on disk — E4 turns it into a real partition+rootfs install.

### E4 — Encryption + hidden-OS install engine (kernel-side, on §D2(b) block I/O)
Layered on `diskWriteSectorsOn` / the cap-gated install op: (1) write the decoy OS to the system
partition and XTS-encrypt it under the decoy password; (2) write the outer volume + its header; (3)
clone-install the *real* EpinAnonymOS into the hidden volume and encrypt it under the hidden
password; (4) fill all unused space with indistinguishable-from-ciphertext random so the hidden
volume can't be located by entropy analysis. All three headers PBKDF2-derived; the hidden one is
findable only with its password.

**E4a — volume data-encryption engine ✅ DONE + host-validated.** `veracrypt_impl.d
vcVolumeDataProof()` does the two data primitives behind (1)/(4): XTS-encrypts a **multi-sector**
region (each 512-byte sector as its own XTS data unit — the real "XTS over the whole partition", not
E3's single block) and **random-fills free space**. Host `make veracrypt volume-check` → `vc-volume
<image>`: **all 16 rootfs sectors decrypt at their per-sector units**, and the free-fill measures
**7.975 bits/byte** Shannon entropy (≈ perfect → indistinguishable from ciphertext, so the hidden
volume can hide in it). (Proof uses a deterministic PRNG for the fill; a real install swaps in a
CSPRNG.)

**E4b — encrypted layout on a REAL 3-partition GPT ✅ DONE.** `core/diskpart.d gptBuildEncrypted` /
`gptWriteEncryptedToDisk` extend the §D2(b) engine to **ESP + system (decoy) + outer-volume**
partitions (the two encrypted ones use the Microsoft Basic Data type — no FS signature, more
deniable). `veracrypt_impl.d vcEncryptedInstallProof()` writes that GPT, formats the ESP FAT32, and
places the decoy header at the **system-partition start** (a real boundary, not an arbitrary LBA).
Host-validated: `sgdisk` shows the 3 partitions (ESP EF00 + 2× 0700), and `vc-parity <img> 131106`
opens the decoy header at `sysFirst`.

**E4c — one-shot block-write capability (Phase 11) ✅ DONE.** `core/install_cap.d`: the installer is
not root — it mints an `InstallWriteCap` scoped to ONE target disk and revokes it when the install
finishes, so writes go through `gatedDiskWrite` (no cap → refuse; cap for disk A can't write disk B;
a revoked cap is dead). `vcEncryptedInstallProof` now routes its header write through the gate (mint →
gated writes → revoke). `installCapProof()` proves all four cases at boot: **PASS (no-cap=refuse,
minted=allow, wrong-disk=refuse, revoked=refuse)**.

**E4c — encrypt a REAL rootfs ✅ DONE.** `make veracrypt cryptdisk` (`test/cryptdisk.c`) drives the
§E4a engine over the **actual §H1 decoy Alpine rootfs** (3.7 MB / 7281 sectors): header (PBKDF2 from
the decoy password + master key) + every rootfs sector XTS-encrypted under the master key. 4/4:
ciphertext ≠ plaintext, the decoy password opens the header + recovers the master key, the
**decrypted rootfs is byte-identical to the original**, and a wrong password can't open it. This is
the installer's data path over a real multi-MB OS image — so the full chain is real: **§H1 decoy
distro → §E4c encrypt → §E5 loader decrypts + chain-loads.** The kernel performs the same writes
in-VM, cap-gated (above); a future increment streams a multi-MB rootfs through the in-kernel engine.

### E5 — Pre-boot authentication (the EFI loader, decoy vs hidden)
The stripped `Boot/EFI` loader is installed to the ESP and runs *before* the kernel: it prompts for a
password, tries to decrypt the system-partition header (→ decoy) and the hidden header (→ hidden),
and on a match decrypts that system's first sectors and **chain-loads it** (which then hands off to
limine/the EpinAnonymOS kernel for that OS). A wrong password reveals nothing; no prompt text hints
that a hidden OS could exist. (For BIOS targets, the equivalent VeraCrypt MBR bootstrap; EFI is the
primary path.)

**E5a — the decision core ✅ DONE + validated on the real layout.** The security-critical heart —
which OS does a password boot, and "reveal nothing on a wrong one" — is factored into
`deps/veracrypt/preboot_auth.{c,h}` (`preboot_authenticate(password, decoyHeader, hiddenHeader) →
DECOY | HIDDEN | REJECT`, reusing `libvc_crypto`). It always tries BOTH headers (constant-shape, no
early-out) so timing can't betray which matched. The install (`vcEncryptedInstallProof`) now writes
the decoy/outer/hidden headers at their **real partition boundaries** (decoy @ `sysFirst`, outer @
`outerFirst`, hidden @ `outerFirst`+64 KiB), all cap-gated. Host `make veracrypt preboot-check` →
`vc-preboot <image>` validates **4/4**: decoy pw→DECOY, hidden pw→HIDDEN, wrong pw→REJECT, outer pw→
REJECT-for-boot. This is reused *verbatim* by the `.efi`.
**E5b — the loader as a real UEFI `.efi` ✅ DONE + OVMF-validated.** Built with clang's
`x86_64-unknown-windows` PE target + `lld-link` → a PE32+ EFI app (no gnu-efi needed; it's absent).
`deps/veracrypt/efi/efi_vc.c` is self-contained crypto for the EFI/PE target (no libc, no VeraCrypt
headers — both unavailable there): AES-256 enc+**dec** (decrypt added for the open path), SHA-512,
HMAC/PBKDF2, XTS-decrypt, `vc_open_header`, `preboot_authenticate` — cross-checked natively against
the kernel-written headers first. `efi_main.c` enumerates `EFI_BLOCK_IO`, finds the install disk,
reads the headers, routes, and emits over COM1. `efi/ovmf-test.sh` boots it under real UEFI firmware
(OVMF) against the install disk: **`decoy-password→DECOY`, `hidden-password→HIDDEN`,
`wrong-password→REJECT`**. `make veracrypt efi`.

**E5c — interactive console password prompt ✅ DONE + OVMF-validated.** `efi_main.c` reads the
password from the EFI keyboard (`ConIn->ReadKeyStroke`, masked `*` echo, backspace, retry-limit); the
prompt and the wrong-password message are identical whether or not a hidden OS exists.
`efi/qmp-interactive-test.py` drives it in OVMF with **real keystrokes injected via QMP**: typing
`decoy-password` → `unlocked; BOOTING DECOY OS`; a wrong password → `access denied` (REJECT). So the
full user-facing pre-boot flow runs in real firmware.
**G2.2 typo tolerance wired in:** `preboot_authenticate` (host `preboot_auth.c` + the EFI `efi_vc.c`,
kept in lock-step) fuzzes the INPUT with the §G2.2 correction model (caps-lock/first-char/
transposition/single-deletion) and tries every candidate against the decoy + hidden headers with
**no early-out** (the VeraCrypt header is the exact verifier; the headers reveal nothing, so the
honey/chaff is inherent). OVMF-validated: a **transposition typo `dceoy-password` unlocks the decoy**,
while `wrong-pass` and far-off typos are rejected. (The 8 KB candidate buffer is `static` to avoid the
freestanding `__chkstk` stack-probe.)

**E5d — chain-load ✅ DONE + OVMF-validated.** After unlock the loader reads the matched OS's loader
off the boot volume (`EFI_LOADED_IMAGE` → `EFI_SIMPLE_FILE_SYSTEM` → open `\EFI\anonymos\stage2.efi`
→ read) and hands off via `LoadImage`/`StartImage`. Proven end-to-end in OVMF — typing
`decoy-password` runs the whole chain: prompt → unlock → *"chain-loading the OS bootloader…"* →
**`[stage2] … STAGE2 RUNNING`**. `efi_stage2.c` is still a stand-in for the real decrypted decoy/hidden
bootloader. The installer now writes the hidden preboot ESP, encrypted decoy Linux image, and encrypted
hidden EpinAnonymOS payload, but a real stage2 bootloader remains the E5/H1 handoff gap.

### E6 — Installer integration: an OPTIONAL step
In the Phase-5 flow, the **Encryption** page is one **optional** step the user can skip. It offers:
**None** · **Full-disk encryption** (single password) · **Hidden OS (plausible deniability)**. Picking
the hidden-OS option collects the decoy + outer + hidden passwords (with clear deniability guidance),
and the installer then runs §E3–E5 instead of a plain copy. It writes its choice into the declarative
`install.json` (encryption mode + which-OS-is-which), so first boot and the §E5 loader are configured
declaratively — no imperative branching. Defaults to **None**; nothing about §E touches a normal
unencrypted or single-password install.

**The decoy OS is configured in the SAME flow, not a separate install.** When "Hidden OS" is chosen,
the hidden-OS sub-step collects the **decoy OS's own account settings** — username, full name, login
password, hostname — *alongside* the decoy passphrase, exactly like the normal Administrator/Hostname
pages do for the real OS. The installer passes those to the §H1 decoy build, which is already fully
parameterized (`make decoy-os DECOY_USER=… DECOY_HOSTNAME=… DECOY_USER_FULLNAME=… DECOY_USER_PASSWORD=…`
→ a real `/etc/passwd`+SHA-512-`/etc/shadow` account, hostname, `/home/<user>`, and §G/§H2 fake history
that **references that same user + hostname**). Verified: building with `DECOY_USER=alice
DECOY_HOSTNAME=thinkpad` yields an `alice` login account, `thinkpad` hostname, 702 `alice`-referencing
log lines, and **zero leakage of the `decoyuser`/`helix` defaults**. So the user ends an install owning
*two* configured systems (real + decoy), each with credentials they set — the decoy is theirs, not a
generic template.

### E7 — Deniability security review (security-critical)
Treat plausible deniability as a threat model, not a feature flag: the hidden volume must be
**entropy-indistinguishable** from free space (no headers, no FS signatures, no size tells); the
decoy OS must be a *believable* daily-driver (real use, plausible timestamps) or its emptiness
betrays the hidden one; **no leaks** — the ESP, logs, `install.json`, swap, hibernation, or the
decoy OS's own state must never reference the hidden OS or its password. Document the residual risks
honestly (this is hard, and weak operational use defeats the math).

---

## §F — Blockchain-anchored boot integrity (zkSync anti-rootkit attestation)

An **optional installer step** that anchors the hashes of the immutable system files to a
**smart contract on the zkSync Era network** (an Ethereum L2), so that **at boot the system verifies
its own files against an external, tamper-evident source of truth** — a rootkit that rewrites local
files (and the local manifest) still can't rewrite the public chain, so the mismatch is detected.
This layers an *off-machine* root of trust on top of the existing in-machine `manifest.blob`
(HMAC-signed, verified-config boot). The contract is **yet to be written**; this section is its plan.

### F0 — Model + why a chain
The immutable `/system` store (already A/B-updated + rollback-capable) has a well-defined content set.
Compute a **Merkle root over all `/system` file hashes** and publish that 32-byte root on-chain.
- **Boot check:** recompute the local `/system` Merkle root and compare it to the on-chain root. Equal
  → untampered; different → tamper/rootkit → tamper response (warn, refuse to mount RW, or drop to a
  recovery/known-good image). The check must run from an **early, trusted stage** (kernel, before any
  userland) or a boot-stage rootkit could fake it — anchoring is only as strong as the verifier's
  own integrity (Secure Boot / measured boot still matter underneath).
- **Why zkSync Era:** EVM-compatible but L2 — gas is cents not dollars, so frequent hash updates on
  every system update are affordable; finality is fast. (`zksolc` compiler + the zkSync RPC.)
- **⚠ Honest tensions (carried into F7), not afterthoughts:** (1) publishing your exact system-file
  hashes is a **public fingerprint** — in direct tension with this OS's anonymity goals; mitigations
  (publish only a salted root, or a per-install commitment) must be designed in, not bolted on.
  (2) Boot-time verification needs **working internet at boot** — and the network stack's **RX is
  currently blocked on real hardware** (see the network roadmap), so this feature is **gated on that
  landing first.** (3) The update key is a live attack surface (F7).

### F1 — Network bring-up (the hard prerequisite)
Deploying the contract (install time) and reading it (boot time) both need connectivity, so the
installer gains a **Network** step:
- **Ethernet:** DHCP over the existing e1000 driver (TX proven; **RX is the open blocker** — N-roadmap).
- **Wi-Fi:** bring up a wifi NIC + `wpa_supplicant`/`iwd`-style association (SSID + passphrase from the
  installer UI). EpinAnonymOS has no wifi driver yet → either a native driver or the LKL bridge
  (the bare-metal roadmap already drives Linux drivers via LKL — the same path can carry `mac80211`).
- **Verify connectivity** (DNS + a zkSync RPC reachability probe) before offering F3, and **fail
  gracefully** when offline: F-features become unavailable, the install still completes without them.
- This step is genuinely **blocked on the 🚧 network stack** (RX) + a wifi path; F1 is where that work
  surfaces in the installer.

### F2 — The smart contract (Solidity, to be written → `installer/contracts/`)
A minimal owner-gated registry:
- **Storage:** `bytes32 systemRoot` (the current Merkle root), `uint64 version`, `address owner`.
- **`updateRoot(bytes32 newRoot, uint64 newVersion)`** — `onlyOwner`; emits `RootUpdated(newRoot,
  version, block.timestamp)` for an auditable history (every legitimate system state is on record).
- **`currentRoot() view returns (bytes32, uint64)`** — public; what the boot check reads.
- Optional: a small ring of recent roots so an in-flight A/B update (old root still valid briefly)
  doesn't trip the check. Owner is ideally a **multisig / hardware-key**, not a hot key (F7).
- Compile with `zksolc`; keep the source + ABI in-repo so the build is reproducible + auditable.

### F3 — Deploy flow (install time)
After F1 connectivity: compile the contract, deploy it to zkSync Era from the user's funded account
(gas), and record the **contract address + chain ID + RPC endpoint** into the declarative
`install.json` / system config so boot and updates know where to look. The signing/deploy key is
collected securely and **never written to disk in the clear** (F7). Offline → skip, install proceeds.

### F4 — Seed the hashes
At install, compute the `/system` Merkle root over the freshly-laid rootfs and call `updateRoot()`
with version 1, so the chain reflects the as-installed system from first boot.

### F5 — Boot-time verification
Early in boot (kernel stage, post-network-init), read `currentRoot()` over JSON-RPC, recompute the
local `/system` root, compare:
- **match** → continue.
- **mismatch** → tamper response: loud warning + a configurable policy (audit-only · block RW mount ·
  boot the last known-good A/B image · halt). Policy is declarative.
- **offline / RPC unreachable** → **cached-last-known-good** fallback (the last verified root, stored
  signed locally): fail-secure to a degraded "could not attest" state rather than silently fail-open.
- Harden the read against a lying RPC (F7): query **multiple endpoints**, or verify a light-client
  proof, so one malicious node can't forge `currentRoot()`.

### F6 — Update integration (keep the chain == the legit system)
Hook the **A/B system update** path: after staging a new `/system`, recompute its Merkle root and call
`updateRoot(newRoot, version+1)` **as part of committing the update**, so the on-chain truth always
tracks the current legitimate system and the next boot verifies clean. A rollback re-publishes the
prior root (or selects it from the recent-roots ring). Updates while offline queue the publish.

### F7 — Security review (security-critical)
- **Verifier integrity:** on-chain anchoring detects file tampering but not a verifier that's already
  subverted — pair with Secure Boot / measured boot so the kernel doing the check is itself trusted.
- **Update-key custody:** the `owner` key can rewrite "truth"; if stolen, an attacker legitimizes a
  rootkit. Multisig / hardware-backed key; never a plaintext on-disk hot key.
- **RPC trust:** don't trust a single node's `currentRoot()` — multi-endpoint agreement or a proof.
- **Privacy:** public hashes fingerprint the install — publish a **salted/committed** root, reconcile
  with the OS's anonymity model, and treat the wallet/tx history as linkable metadata.
- **Availability:** define the offline policy deliberately (fail-secure vs usable-offline) — a check
  that bricks the machine when the RPC is down is its own denial of service.

---

## §G — Perlin-noise decoy activity generator (deterministic fake histories; required for boot)

A track **separate from §F**, integrated with the §E decoy/hidden-OS feature. It synthesizes
believable, deterministic fake system histories — logs, processes, users, services, network, object
access, security events, filesystem/object-tree activity — so a decoy environment looks *lived-in*.
An empty, pristine decoy is the single biggest tell that a hidden OS exists; §G removes that tell.
**Boot-required:** every boot passes through the §G honey-hashed, typo-tolerant matcher (§G Phase 2),
which both gates entry and derives the fake-universe seed.

### 1. Executive Summary
The fake universe is a **pure, lazily-evaluated function** `U(seed, subsystem, t₀…t₁) → events` that is
**never materialized or stored** — each read (e.g. "tail `/var/log/auth.log` around a date") is answered
on the fly by sampling a seeded coherent-noise field over the queried window. That one decision
discharges most requirements simultaneously: deterministic + reboot-stable + snapshot-trivial (persist
only the seed), scales to years (cost is O(window), not O(history)), different password → different
universe (seed = KDF(password)), and rootless/immutable (a cap-gated *read-only* generator; nothing
mutable to write). §G is **not** a log writer bolted onto the OS — it is a new *generated object view*
(the same mechanism that already renders Linux-path compat views and the Domain-Manager `RuntimeView`),
selected by the boot authentication context.

### 2. Architecture Review (what fits, what fights)
- **Fits:** the object model already produces **generated views** (`core/namespace.d` RuntimeView; the
  Linux-path compat views) — a decoy is just another deterministic view subtree. The **immutable +
  A/B** model is *ideal*: a deterministic generator needs no mutable state, so there is nothing to
  diverge across reboots. The **capability/rootless** model gives the generator a least-privilege
  mint-decoy-objects capability. **§E** already turns a boot password into a decrypted decoy OS; §G
  hangs the matching fake history off the *same* password.
- **Fights (architectural problems to fix first):**
  1. **No virtual clock.** Time today is raw `rdtsc`/RTC (`core/random.d`, `diskpart.d`). Fake history
     read against the real wall clock will be internally inconsistent (uptime, "now", mtimes). §G needs
     a **seed-anchored virtual clock** (a decoy "install epoch" derived from the seed; history generated
     backward from it; "now" tracks real time but offset) and a rule that **no decoy artifact may ever
     read the real RTC directly**.
  2. **No logging/audit subsystem exists** (`grep` finds none). Good news (clean slate, no real-log
     format to fake against) and a task (define the canonical log/object-event schema the generator and
     any *real* logging will share, so real and fake are format-identical).
  3. **Float nondeterminism.** Classic Perlin uses floats — IEEE-754 + compiler reordering can differ
     across builds/arches, **breaking determinism (req 1/2)**. Mandate **integer/fixed-point coherent
     noise** (seeded permutation table, integer gradients) — justified by determinism over "true" Perlin.
  4. **Real entropy leakage.** Any real PID/inode/UUID/MAC/hash that reaches a decoy object breaks
     determinism *and* can leak. Every id in a decoy view must be **derived from the seed**, never minted
     from real counters.

### 3. Missing Components (must build)
Virtual clock; canonical event/log schema; deterministic integer coherent-noise lib; KDF→universe seed
derivation; the honey-hashed typo-tolerant boot matcher; the timeline/event engine; the cross-subsystem
correlation engine; the decoy view-provider that maps generated events onto the object tree; per-subsystem
generators (proc/user/service/net/security/audit/fs); a statistical "realism" shaper; and a forensic
self-audit harness that tries to *distinguish* generated from real.

### 4. Detailed Implementation To-Do List
Format per task: *Purpose · New/Files · Deps · Security · Complexity (S/M/L) · Order.*

**PHASE 1 — Core architecture, object & storage model, snapshot integration**
- **G1.1 Virtual clock.** *Purpose:* one seed-anchored time source for all decoy artifacts; ban direct
  RTC reads in decoy context. *New:* `core/decoy_clock.d`. *Files:* `core/random.d`, time call-sites.
  *Deps:* G2 seed. *Security:* a single real-timestamp leak dates the decoy → high. *Cx:* M. *Order:* 1.
- **G1.2 Canonical event schema.** *Purpose:* one TLV/object schema for events (ts, subsystem, actor,
  object-ref, severity, corr-id) shared by real + fake so they're indistinguishable. *New:*
  `core/event_schema.d`. *Deps:* object model. *Security:* schema drift = tell → med. *Cx:* M. *Order:* 1.
- **G1.3 Decoy view provider.** *Purpose:* a generated object subtree (`/var/log`, `/proc`, object
  access histories) backed by the generator, materialized on traversal. *New:* `core/decoy_view.d`.
  *Files:* `core/namespace.d` (RuntimeView hook), object FS. *Deps:* G3/G4. *Cx:* L. *Order:* 3.
- **G1.4 Snapshot = seed only.** *Purpose:* persist just `{seed, params, install-epoch}` in the decoy's
  config object; regenerate everything. *Files:* `core/store.d`, `core/configboot.d`. *Cx:* S. *Order:* 2.

**PHASE 2 — Seed generation, password-derived universe, noise subsystem, the boot gate**
- **G2.1 Password → universe seed (honey).** *Purpose:* seed = slow-KDF(canonical matched secret); every
  password yields *a* plausible universe, none stored. *New:* `core/decoy_seed.d`. *Deps:* §E2b KDF
  (`pbkdf2_sha512`/AES). *Security:* the seed is as sensitive as the password → high. *Cx:* M. *Order:* 1.
- **G2.2 Honey-hashed, typo-tolerant boot matcher (REQUIRED FOR BOOT).** *Purpose:* accept a typed
  password, decide if it's "close enough" to a registered decoy, boot that decoy's universe; reject
  everything else. *Design (security-engineered):* **fuzz the *input*, not the storage** — from the typed
  password generate a *bounded* candidate set (case/layout/edit-distance ≤ t corrections) and check each
  against **exact, per-decoy slow salted verifiers**; storage stays strong exact hashes (no similarity
  data about the secret on disk). Snap a fuzzy hit to the **canonical** decoy so the seed (and thus the
  whole history) is identical for the decoy and its typos (req 2). A pool of **honey/chaff verifiers**
  pads the real decoys so the stored count never reveals how many decoys exist; a typed password matching
  **no** real verifier **does not boot** (per spec). *New:* `core/decoy_match.d`; wire into the §E5
  pre-boot auth. *Deps:* G2.1, §E. *Security:* ⚠ **explicit usability↔security trade-off — fuzzy
  acceptance widens the accept set and lowers effective entropy; keep t small, require strong base
  decoy passwords, rate-limit, and never persist similarity data.** *Cx:* L. *Order:* 2.
- **G2.3 Deterministic integer coherent-noise lib.** *Purpose:* reproducible bursty noise (value/simplex,
  seeded permutation, fixed-point), multi-octave. *New:* `core/coherent_noise.d` (+ KAT vectors). *Deps:*
  G2.1. *Security:* a noise spectral fingerprint is a tell (§G risk) → shape in G4. *Cx:* M. *Order:* 3.

**PHASE 3 — Timeline engine, event engine, correlated subsystem activity**
- **G3.1 Rate-to-events (bursty).** *Purpose:* turn noise N(t) into an event **rate** λ(t), place events
  by a *deterministic* Poisson/Hawkes process → natural bursts + heavy tails, not smooth noise (req 4,5).
  *New:* `core/decoy_timeline.d`. *Deps:* G2.3. *Cx:* M. *Order:* 1.
- **G3.2 Correlation engine.** *Purpose:* one shared "intensity" field drives all subsystems through
  per-subsystem transfer functions + lags, so a busy hour shows correlated login+process+net+log spikes,
  and one event deterministically spawns its consequences (login → session → process tree → net flows).
  *New:* `core/decoy_correlate.d`. *Deps:* G3.1. *Security:* uncorrelated subsystems = the #1 forensic
  tell → high. *Cx:* L. *Order:* 2.
- **G3.3 Realism shaper.** *Purpose:* map raw event stats onto real-world distributions (diurnal/weekly/
  seasonal cycles, holidays, log-message templates, port/protocol mixes). *New:* `core/decoy_realism.d`.
  *Cx:* L. *Order:* 3.

**PHASE 4 — Object-tree integration: process/user/service histories**
- **G4.1 proc/G4.2 user/G4.3 service generators.** *Purpose:* deterministic `/proc`, login/session, and
  service-restart histories as objects, all ids seed-derived, all consistent with G3.2's events. *New:*
  `core/decoy_proc.d`, `decoy_user.d`, `decoy_service.d`. *Deps:* G1.3, G3.2. *Cx:* M each. *Order:* 1–3.

**PHASE 5 — Security history, network history, audit trails**
- **G5.1 security/G5.2 network/G5.3 audit generators.** *Purpose:* plausible auth failures/alerts, flow
  records + DNS/connection logs, and a coherent audit trail — all correlated with G3.2 and each other.
  *New:* `core/decoy_security.d`, `decoy_net.d`, `decoy_audit.d`. *Security:* a fake "successful root
  login" contradicting the rootless model is a tell → keep events in-model. *Cx:* M each. *Order:* 1–3.

**PHASE 6 — Snapshot persistence, distributed, performance**
- **G6.1 Distributed coherence.** *Purpose:* the seed *is* the sync unit — another node regenerates the
  same universe for free; align only the "live" epoch via the ORG distributed clock. *Files:*
  `core/org_dist.d`. *Cx:* M. *Order:* 2.
- **G6.2 Windowed cache + latency parity.** *Purpose:* cache hot windows; make generated-read latency
  match real-read latency so **timing can't distinguish fake from real** (a real side-channel). *New:*
  `core/decoy_cache.d`. *Security:* high (timing leak). *Cx:* M. *Order:* 1.
- **G6.3 Forensic self-audit.** *Purpose:* a harness that *tries* to distinguish generated vs real
  (spectral, correlation, distribution, timing tests) — failures become work. *New:* `tests/decoy/`.
  *Cx:* M. *Order:* 3.

### 5. Dependency Graph
`§E (decoy OS + KDF)` → `G2.1 seed` → {`G2.2 boot matcher` (also → §E5), `G2.3 noise`} → `G3.1 timeline`
→ `G3.2 correlation` → `G3.3 realism` → Phase-4/5 generators → `G6` (cache/distributed/audit).
`G1.1 clock`, `G1.2 schema`, `G1.4 snapshot` underpin everything (build first). `G1.3 view` needs G3/G4.

### 6. Risk Analysis
- **Determinism breakers:** float noise; real RTC reads; real PIDs/inodes/UUIDs/MACs; non-canonical
  ordering (map iteration, concurrency); KDF/endianness drift across arches; locale/timezone in rendering.
- **Decoy-existence leaks:** an *empty/too-clean* decoy; uncorrelated subsystems; a noise spectral
  fingerprint; **timing** (computed reads slower than stored reads); free-space entropy that says "hidden
  volume here"; fake events that violate OS invariants (a root login under a rootless model); identical
  universes across two "different" installs (seed reuse).
- **Metadata consistency:** file mtimes must equal the events that touched them; log sequence numbers
  monotonic; process start<exit; session spans contain their child processes; uptime = now − boot;
  package "installed" dates precede their first "use".
- **Timestamp requirements:** one virtual clock; monotonic per subsystem; consistent offsets; no future
  timestamps; DST/timezone handled deterministically.
- **Resource/scaling:** never generate history you don't read (lazy); bound candidate-fuzzing in G2.2;
  cap cache; keep noise sampling O(1) table lookups; years-of-history must stay O(query window).

### 7. Recommended Order of Development
G1.1 clock + G1.2 schema + G1.4 snapshot → G2.1 seed → **G2.2 boot matcher (gates boot — land early,
behind a flag)** → G2.3 noise → G3.1 timeline → G3.2 correlation → G3.3 realism → G1.3 view → Phase-4
then Phase-5 generators → G6 cache/distributed/forensic-audit.

### 8. Final Validation Checklist
☐ same decoy password → byte-identical history across two cold boots and two machines · ☐ different
password → fully uncorrelated history · ☐ a typo within threshold boots the *same* universe; outside →
**no boot** · ☐ no decoy artifact ever reads the real RTC · ☐ no real PID/inode/UUID/MAC in any decoy
object · ☐ cross-subsystem events correlate (login↔session↔proc↔net↔log) · ☐ all metadata invariants
hold (mtimes, monotonic seq, span containment, uptime) · ☐ generated-vs-real reads are
timing-indistinguishable · ☐ generated stats pass the forensic self-audit · ☐ storage reveals neither
the decoy count nor which entries are real (honey/chaff) · ☐ snapshot persists only the seed/params · ☐
years of history with O(window) cost.

---

## §H — Linux decoy OS + concealed activity synthesis

**The decoy OS is a real Linux distribution**, not a synthetic view — a genuine, daily-usable distro is
the most believable decoy (real binaries, real package manager, real journald/syslog). §G's synthetic
history is realized *inside* that Linux by a concealed component, so an examiner who unlocks the decoy
under coercion sees a normal, lived-in Linux and finds **no evidence** that (a) it is a decoy or (b) a
hidden OS exists. Builds on §E (encrypted decoy/hidden layout) and §G (the deterministic generator);
the decoy rootfs is written by §E4c.

> **Authorization & intent.** §H is plausible-deniability / anti-coercion concealment on the user's
> *own* decoy environment — the same threat model as VeraCrypt's Hidden OS. It is not for accessing or
> hiding from third-party systems. The §H4 concealment is dual-use, so the security review (§H5) is
> mandatory and treats *detectability of the concealment itself* as the primary risk.

### H1 — The decoy Linux distribution
*Purpose:* a real, believable decoy OS. *Tasks:* select a base distro (Debian/Arch-class); the installer
images its rootfs into the **encrypted system partition** (§E4b) and registers it with the §E5 pre-boot
loader (decoy password → chainload this Linux). *Critical:* it must be a *believable daily driver* —
real installed packages, a plausible home dir, browser/app state — because an empty, pristine decoy is
the single biggest tell that a hidden OS exists (E7/§G). *Deps:* §E4b/c, §E5. *Files:* `installer/`,
`installer/decoy/`. *Cx:* M. *Order:* 1.

### H2 — The Linux fake-log generator program
*Purpose:* a program inside the decoy Linux that backfills + maintains realistic fake history (logs,
`wtmp`/`btmp`, journald, `~/.bash_history`, package/update history, process/session traces) — the
**Linux-userland incarnation of §G**, seeded by the decoy password so the same decoy → identical history
(deterministic, reboot-stable). *Tasks:* port the §G integer coherent-noise + timeline/correlation
engine to a Linux build; on first decoy boot, backfill years of history from the seed; thereafter run as
a low-rate daemon maintaining live, correlated activity. *Deps:* §G (engine), H1. *Security:* the
generator must never write a timestamp/PID/path that contradicts the rest of the decoy (the §G metadata
invariants apply verbatim). *New:* `installer/decoy/fakelog/`. *Cx:* L. *Order:* 2.

### H3 — Full-disk illusion driver (hide the hidden volume's space)
*Purpose:* make the decoy Linux believe it owns the **entire disk**, so neither the hidden volume's
reserved space nor the partition geometry that brackets it is visible (unaccounted space, or a too-small
"disk", is a tell). *Tasks:* a Linux **block shim / device-mapper target** that (a) reports the full disk
geometry to the decoy, and (b) **protects the hidden volume's sectors** — reads return indistinguishable-
from-free random (the §E4a free-fill), writes into that region are redirected or refused (VeraCrypt's
"protect hidden volume" mode) so the decoy can use "its" disk freely without ever reading, corrupting, or
*detecting* the hidden OS. *Deps:* §E (layout), §E4a (entropy fill), H1. *Security:* the protection map
must not itself be discoverable from inside the decoy. *New:* a kernel module
`installer/decoy/dm-fulldisk/`. *Cx:* L. *Order:* 3.

### H4 — Conceal the generator (kernel-embedded, hidden from the process table)
*Purpose:* hide H2's existence so an examiner with the decoy password **and root** cannot find the
fake-history machinery — because finding it proves the decoy is a decoy, which defeats deniability.
*Tasks (as requested):* compile the generator into the decoy **Linux kernel** (built-in, not a loadable
module listed in `lsmod`); hide its process from `/proc` (cross-view PID filtering), its files, its open
sockets, and its CPU/scheduler footprint. *Deps:* H2, H3. *New:* a kernel patch in
`installer/decoy/conceal/`. *Cx:* XL. *Order:* 4.
> **⚠ This is the riskiest part of the whole feature — flagged, not glossed.** Kernel-level
> process/module hiding is *itself a forensic red flag*: anti-rootkit tooling routinely detects hidden
> PIDs (cross-view `/proc` vs syscall/`/proc/PID` enumeration), hidden modules, and kernel-text
> integrity violations — and a **detected rootkit on an otherwise-normal decoy screams "this machine is
> hiding something,"** which is *worse* for deniability than no concealment at all. **Recommended primary
> strategy: hide in plain sight** — disguise the generator as an ordinary, expected system daemon
> (telemetry/log-rotation/indexing) whose activity is *indistinguishable from legitimate*, so there is
> nothing to detect. Treat kernel-embedded hiding as defense-in-depth *only if* it provably evades the
> known detectors; otherwise it is a liability. §H5 must adjudicate this.

### H5 — Security review (mandatory; detectability is the threat)
- **Concealment detectability (the #1 risk):** run the decoy against real anti-rootkit / live-forensics
  tooling (cross-view process scans, kernel-integrity/`kallsyms` checks, module-hiding detectors, timing
  analysis). If the concealment is detectable, prefer H4's *hide-in-plain-sight* path. A concealment that
  trips a detector is a deniability *failure*.
- **Internal consistency:** H2's fake history must satisfy every §G invariant (timestamps, monotonic seq,
  span containment, cross-subsystem correlation); a fake "root login" under a Linux that otherwise shows
  none, or logs referencing absent files, are tells.
- **Disk-illusion leaks:** the H3 protection map, the size mismatch vs SMART/`hdparm`, and write-latency
  differences over the protected region must not reveal the hidden volume.
- **Determinism:** H2 inherits §G's float-noise / real-RTC / real-id determinism rules verbatim.
- **Blast radius:** H3/H4 are kernel code in the *decoy* only — they must never touch the real
  EpinAnonymOS kernel or the hidden OS, and must fail safe (a bug must not corrupt the hidden volume).

### Dependency & order
`§E (layout) + §G (engine)` → `H1 distro` → `H2 generator` → `H3 disk-illusion` → `H4 conceal` → `H5
review`. H4 is gated on H5 deciding kernel-hiding vs hide-in-plain-sight.

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
Pages: Welcome · Language · Keyboard · Timezone · **Network (optional)** · Disk Selection · Filesystem
· **Encryption (optional)** · **Boot integrity (optional)** · Hostname · Administrator · **Identities**
· Summary · Installation · Finish. Feels like a professional OS installer. Two *optional, skippable*
steps: the **Encryption** page (default **None**) offers None · Full-disk encryption · **Hidden OS
(plausible deniability)** — the §E VeraCrypt-derived decoy/hidden-OS feature; the **Boot integrity**
page offers the §F zkSync blockchain-anchored anti-rootkit attestation (which needs the **Network**
step's connectivity to deploy its contract).

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
Support GPT/MBR, EFI/BIOS, ext4/Btrfs/XFS, swapfile/partition; automatic **and** manual
partitioning; respect immutable layouts. Driven by §D2 — KPMcore/libparted where built, the
native object-FS module (§D2(b)) by default. Bootloader = **limine** (the OS already installs limine
on GPT/ESP); the module lays down GPT + ESP + rootfs and installs limine UEFI/BIOS. **Encryption is
the §E VeraCrypt-derived path** (XTS-AES system encryption, optionally the **hidden/decoy OS**) — not
LUKS — chosen so it can carry the plausible-deniability feature; when the §E Encryption step is
enabled, the §E5 pre-boot loader fronts limine on the ESP.

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
the **minimal capability set** (a one-shot block-write cap for the chosen disk — §D2.2/§D2(b)), not
root; validate input; verify copied files; verify package integrity; Secure Boot if available;
**encrypted installs via §E** (XTS-AES + the optional **hidden/decoy OS** for plausible deniability).
The §E path carries its own security review (§E7): the hidden OS must be entropy-indistinguishable
from free space and leak-free across the ESP, logs, `install.json`, swap, and the decoy OS's state.

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
  + libc++, reusing the gtk-stack sysroot for shared prereqs. `qtbase` configures clean and builds
  **[1013/1013], 0 errors** → `libQt6{Core,Gui,Widgets,Network,Concurrent,Xml,PrintSupport}.a` +
  platform-support libs in `sysroot`. The plan's dominant risk (does Qt build here at all?) is
  retired. Config keys that mattered: bundled md4c/b2 (`-DINPUT_libmd4c=qt`), and
  `-DINPUT_opengl=no -DFEATURE_egl=OFF` (raster + `wl_shm`, Widgets-only — D1.5).
- **§D3 build infrastructure ◑ BEGUN.** The Calamares cross-build tree exists:
  `deps/calamares/Makefile` (CMake cross via the shared `deps/qt-stack/qt-cross.cmake`, now with a
  `CALAMARES_SYSROOT` in its find path) builds Calamares' C++ deps + the installer ELF into
  `deps/calamares/sysroot`. **yaml-cpp ✅ built** (static `libyaml-cpp.a`, musl + libc++) — proving
  the non-Qt C++ dependency pipeline works. `deps/parted-stack/Makefile` (§D2.1 util-linux
  libuuid/libblkid + libparted, autotools-cross like gtk-stack) is **scaffolded** (the recipe; the
  musl-porting long-pole is next). Opt-in top-level targets added (NOT in the default build):
  `make qt-stack | calamares-deps | parted-stack | calamares | installer-deps`.
- **§D2(b) native object-FS partition engine ◑ BEGUN (chosen over util-linux/libparted).** The
  rootless, udev-free backend: the kernel owns block I/O (`drivers.block.disk`
  `diskRead/WriteSectors`) + caps, so the installer asks it to "lay down GPT+ESP+rootfs" rather than
  touching raw devices. **GPT layout primitive ✅ DONE** — `src/kernel/d/core/diskpart.d` builds a
  spec-valid GPT (protective MBR + GPT header + 128-entry array with an EFI System Partition + a
  Linux-root partition, all CRC32-checked, type GUIDs + per-partition GUIDs) and validates one back.
  Boot proof (`gptPartProof`, wired after `diskSelfTest` in `kernel_main.d`) builds a GPT for an 8 GiB
  disk in-memory (no disk write → live object store safe) + validates + corruption-checks: serial
  shows `[diskpart] GPT proof PASS (esp_lba=0x22 root_lba=0x100022 …; corruption rejected)`.
  **GPT-to-disk write ✅ DONE + externally validated.** `gptWriteToDisk()` commits a full GPT
  (protective MBR + primary header/entries at the front; backup entry array + backup header at the
  disk tail) to a TARGET disk, addressed by per-disk block I/O added to `drivers.block.disk`
  (`diskFindTarget` / `diskRead/WriteSectorsOn` — a chosen disk, never the live object-store disk).
  `gptWriteProof()` (boot, SKIPs when no spare disk) writes a real GPT to a spare target + rereads +
  validates. Verified in QEMU with a 2nd disk: `[diskpart] GPT-write proof PASS (… target idx=0x1 …
  primary validated, backup-hdr-sig=0x1)`, the object store on disk0 untouched — and host **`sgdisk
  -p`** reads the result as a clean GPT with **part 1 = ESP (EF00) 256 MiB + part 2 = Linux root
  (8304)**, no backup-GPT errors.
  **ESP FAT32 format ✅ DONE + externally validated.** `fatFormatEsp()` writes a valid empty FAT32
  onto the ESP partition (boot/BPB + FSInfo + backup boot + the head of each FAT; Microsoft fatgen
  FAT-size formula; on a zeroed target the rest reads as free → valid empty FS). The write proof now
  formats the just-laid ESP and reports `esp-fat32=0x1`. Cross-validated on the host: `file` →
  *"FAT (32 bit)", label "EPIN ESP", sectors/FAT 4064*; `fsck.fat` parses it cleanly (512 B/cluster,
  2 FATs 32-bit, 516128 data clusters).
  **Native plain-install backend ✅ IMPLEMENTED via §D6.** The shippable native path now uses the
  prebuilt `esp-image` payload rather than a separate rootfs partition: `installBootableToDisk()`
  writes a single-ESP GPT to the selected target disk, streams the staged ESP image, and exposes the
  operation through `/config/install.action`. The GUI sends `config <json>` first; the backend hashes
  password fields, writes the resulting `/install.json` into the installed ESP, and refuses to report
  completion if that persistence fails. Remaining §D2(b) work is the richer Calamares/native-module
  partitioner: root partition/rootfs choices, manual partitioning, BIOS support, and direct UI-driven
  filesystem selection.
- **§D2 / Calamares core: not built yet.** After the native-module partitioner is complete: build the `calamares` ELF (recipe staged in
  `deps/calamares/Makefile`, Widgets-only/no-QML/no-Python, no KPMcore — the native module replaces
  it) → wire `installer/calamares/` (sequence, branding, the custom `identitymanager` module) +
  the partition page driving the §D2(b) engine. Phase-1 analysis: `installer/ARCHITECTURE.md`.
- **§F Blockchain-anchored boot integrity (zkSync anti-rootkit): SPECIFIED (F0–F7), not built.** An
  *optional* step: publish a Merkle root of the `/system` hashes to a (yet-to-be-written) zkSync Era
  smart contract and verify it at boot. **Gated on the 🚧 network stack (RX) + a Wi-Fi path** (F1),
  which is its hard prerequisite. Carries real, documented tensions: the public-hash fingerprint vs
  the OS's anonymity goals, update-key custody, and RPC trust (F7). Contract source will live in
  `installer/contracts/` (`zksolc`, ABI in-repo).
  + notes, an apk package `world`), and **seeds a year of deterministic, password-keyed fake `/var/log`
  history via §H2** → `make image` produces `decoy.ext4`, staged in the installer ISO as
  `decoy-linux.ext4`, for the installer to encrypt into the decoy system partition (E4c).
  Verify PASS: Alpine os-release, busybox+apk, 24 k seeded syslog + 3.4 k auth lines, user, history; the
  seed is reproducible (rootfs `/var/log` == `fakelogd(decoy-password)`).
  **H2 — the Linux fake-log generator BUILT** (`deps/decoy/h2/fakelogd.c`, `make -C deps/decoy h2`):
  drives the §G engine+renderer and backfills deterministic, password-keyed history into `/var/log`,
  routing each subsystem to the right file (auth/sudo → `auth.log`, audit → `audit.log`, the rest →
  `syslog`), time-ordered. 5/5 self-test: same password → byte-identical `/var/log`, different password →
  different, correct routing, no auth-content leak into syslog. Remaining: the full-disk-illusion block
  driver hides the hidden volume's space from the decoy (H3), and the generator is concealed from the decoy's root user (H4: kernel-embedded + hidden
  from the process table). ⚠ Security review (H5) is mandatory and treats **detectability of the
  concealment itself** as the primary risk — a *detected* rootkit is worse for deniability than none, so
  the recommended primary is **hide-in-plain-sight** (disguise as an ordinary daemon), with kernel-hiding
  only as defense-in-depth if it provably evades anti-rootkit tooling. Plausible-deniability/anti-coercion
  on the user's own decoy (VeraCrypt-Hidden-OS threat model). Builds on §E + §G.
- **§D4 remaining:** persistent object-store backing for `system.installed` and desktop-shell
  consumption of `/system/state/installed` instead of raw `/install.json` access. The native installer
  creates the marker by persisting `/install.json` into the installed ESP; Calamares still needs to
  produce the same config once the full GUI lands.
