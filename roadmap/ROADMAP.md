# anonymOS — Master Roadmap

One ordered list, condensed from the 34 roadmaps in this directory. Ordered by **importance
first** (does the OS work; can someone actually use it), then by **feasibility** within each
tier (cheap and unblocked before expensive and blocked).

Each item names its source roadmap. Those files keep the detail; this file decides the order.

**The single rule:** do not start a tier until the one above it is green. Most of the pain in
this project's history came from deep platform work landing while the desktop could not boot.

---


## Tier 1 — ✅ COMPLETE (2026-09-05)

**Exit criterion met:** a person can install anonymOS to a disk and reboot into it. Confirmed
working on VirtualBox (UEFI + SATA/AHCI, `scripts/vbox-install-test.sh`), with the installer
driven from the desktop and the installed system booting afterwards.

Delivered: `wl-sysmon` tabs (1.1), persistent storage (1.2 — the object store in the disk's free
tail plus `persist =` subtrees in `/desktop.conf`, proven across reboots on an installer-written
disk), the busybox applet set (1.3), the domain manager's Users/Services/Startup views (1.5), and
`wl-files` File Search (1.6).

**Carried forward, not done:** `wl-quicksettings`' Keyboard / Mouse / Touchpad / Appearance
panels (was 1.4). They are blocked on an input and theme configuration backend that does not
exist, and shipping them without one would mean four panels of controls that change nothing.
Tracked in Tier 3 as a desktop-quality item, which is what it actually is.

**Known platform gap found while confirming this:** the kernel has AHCI and NVMe block drivers
and no VirtIO. Proxmox defaults to VirtIO SCSI, so an install there fails with "no disk to
install to". Either configure SATA, or add a virtio-blk driver — the latter is the honest fix
and is listed in Tier 5.


---

## Tier 2 — The application runtime (the multiplier)

Everything in Tier 3+ and 54 of the 124 apps sit behind this. It is the highest-leverage
work in the project, and it is *not* speculative: GTK 3 with the Wayland backend is already
built for musl in `deps/gtk-stack/sysroot`, and `gtk-hello` already runs.

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 2.1 | **`/compat/linux` + `/proc` + `/sys` + `/etc`** | Most monitor-type apps read `/proc` and nothing else. Also what SHELL A1/A5 need | APPS A2 · OBJECT_FS F0 | M |
| 2.2 | **Syscall audit** — inotify, eventfd, signalfd, timerfd, memfd_create, ppoll | Record what is missing once, rather than discovering it one crash at a time | APPS A3 · syscalls | M |
| 2.3 | **One real upstream GTK app end-to-end** (suggest `gnome-calculator`) | The gate. Until one runs, every Stage C estimate is speculation | APPS A4 | M |
| 2.4 | **Font / icon / theme resolution inside a GTK process** | Blobs are staged; confirm fontconfig and the icon theme actually resolve | APPS A5 | S |
| 2.5 | ✅ **D-Bus system bus** — DONE 2026-09-05 | A real upstream `dbus-daemon` 1.14.10 serves the bus; `dbus-send --system GetId` completes a round-trip in 33 ms, proving EXTERNAL auth over `SO_PEERCRED`. | APPS A7 | S |
| 2.6 | **Stage C1** — `/proc` readers: Hardware Info, System Info, USB/PCI, Sensors, Battery, Routes | Falls out of 2.1 almost free. ~8 more apps | APPS C1 | M |

**Exit criterion:** an upstream GTK application, not written for this OS, runs on the desktop.

### Notes from 2.5 (D-Bus), 2026-09-05

Four separate faults, none of which announced itself. Worth recording because each one
*reported success* and the damage only showed up much later:

- `deps/dbus-build/build-dbus.sh` still had `ROOT=/home/bruns/Documents/EpinAnonymOS`, a path
  that died when the project was renamed. dbus had therefore never built at all. The Makefile
  gates its staging on `install/bin/dbus-daemon` existing, so it silently emitted no
  `module_path` line and the kernel could not load the launcher.
- Grepping the ISO for `hos-dbus-launch` found six hits and *looked* like proof it was staged.
  It was not — the kernel binary names the program in a spawn call. **Grepping an image for a
  filename proves nothing about whether that file is in it.**
- The build script piped everything to `tail`, and a pipeline's status is the last command's, so
  `set -e` never saw a failure. Now `set -o pipefail`.
- `gschemas.compiled` was staged, logged as "Included", and genuinely present in the ISO, yet
  never reached the guest: `pack-assets.py` sorted it into category `misc`, which had no blob,
  and the kernel reads the aggregate `assets.blob` only as a fallback that never triggers. Fixed
  generally with a `misc.blob` rather than special-casing glib.

Also: waiting a fixed number of scheduler polls for a daemon to be ready is not a timeout —
it measures nothing physical. Both a 40-poll and a 400-poll guess fired early. The gate now
waits on `unixListenerReady()` (is the socket actually in the listener state?) bounded by
`pitMs()` wall clock.

**Feeds 2.2:** `dbus-daemon` logs `Cannot initialize inotify: Function not implemented`. It
degrades gracefully — it just stops watching its config for changes — but this is a confirmed
missing syscall for the audit, found without having to go looking.

---

## Tier 3 — Desktop quality

Usable is not the same as good. Ordered cheap-first deliberately: R5 is explicitly "cheap
present wins" and buys most of the perceived responsiveness.

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 3.0b | **`wl-quicksettings` panels** — Keyboard, Mouse, Touchpad, Appearance. **Blocked:** no input/theme configuration backend exists, so these would be four panels of controls that change nothing. Was roadmap 1.4; it is a desktop-quality item, not a prerequisite for installing | APPS B2 · GUI G18 | M |
| 3.1 | **Damage-tracked KMS blit + fast copy** | The roadmap's own "cheap present wins". Biggest felt improvement per hour | DESKTOP_RESP R5 | S |
| 3.2 | **Multi-window and workspace experience** — **BLOCKED on client resize support.** Windows visibly overlap instead of tiling because six clients (`wl-overview`, `wl-logview`, `wl-quicksettings`, `wl-calendar`, `wl-wifi-menu`, `wl-domain-manager`) call `xdg_toplevel_set_max_size` equal to their min size, and Hyprland floats any toplevel where min == max. That is not the layout failing — those windows opt out of it. **Dropping `set_max_size` is NOT the fix:** none of the five has a resize path (checked), so tiling them reproduces the domain manager regression its own source documents (collapses to a 562x181 sliver). Each needs a reflowing layout first, i.e. the `resize_buffer()` treatment `wl-installer` and `wl-cairo-demo` already got | Hyprland provides the mechanism; this is the desktop actually using it | GUI G20 | M |
| 3.3 | **Visual QA + screenshot regression tests** — ◑ PARTIAL. `scripts/screen-check.sh` captures the framebuffer via the HMP monitor and asserts the desktop is rendering (distinct-colour count + dominant-colour share); it found the swapchain bug within minutes of existing. **Not done:** golden-image comparison per app. | Marked Critical in GUI_ROADMAP, and this session showed why: a two-month-old binary shipped unnoticed | GUI G21 | M |
| 3.4 | **Kernel-mode interrupt handling** | Real fix for input latency, but a genuine kernel change | DESKTOP_RESP R4 | L |
| 3.5 | **Preemptive scheduling** | Depends on 3.4 | DESKTOP_RESP R6 | L |
| 3.6 | **quickshell (Qt6/QML) port** | The only route to true host parity — the host's bar, sidebars, overview and launcher are all one `qs` process. Needs 2.x and a working GL path | APPS E6 | XL |

---

## Tier 4 — Platform depth

Valuable, coherent, and **not** on the path to a usable desktop. Deliberately after Tier 3.

| # | Item | Source |
|---|---|---|
| 4.1 | Identity brokers, disposable identities, policy engine (Phases 7–9) | IDENTITY_DOMAIN |
| 4.2 | Immutable-rootless foundation (Phase 0 invariants) | IMMUTABLE_ROOTLESS |
| 4.3 | Declarative config compiler (Phases 1–9) | DECLARATIVE_CONFIG_SPEC |
| 4.4 | Whole-image A/B update unit | SYSTEM_UPDATE D1 |
| 4.5 | Native object shell `-sh` (B0–B5) | SHELL_AND_COMMANDS |
| 4.6 | Marketplace / I2P template distribution | NETWORK_AND_MARKETPLACE |

---

## Tier 5 — Hardware

Only matters when leaving the VM. Nothing above depends on it.

| # | Item | Source |
|---|---|---|
| 5.0 | **VirtIO block driver (`virtio-blk` / `virtio-scsi`)** — the kernel has AHCI + NVMe only, so an install on Proxmox fails at "no disk to install to" because VirtIO SCSI is its default bus. Confirmed 2026-09-05. VirtIO NET is already handled; the disk side is the gap | — |
| 5.1 | LKL hardware bridge (`lkl_dev_pci_ops`), per-device isolation | BARE_METAL L3, L4 |
| 5.2 | USB HID via LKL — "the usable-desktop unlock" on real hardware | BARE_METAL L5 |
| 5.3 | WiFi association hardening | WIFI_AUTODRIVER |
| 5.4 | Audio driver + PipeWire → Audio Mixer, Volume, Players, Recorder, Screen Reader, TTS | APPS D1 |
| 5.5 | GPU via LKL | BARE_METAL L6 |

---

## Tier 6 — Deferred by design

Each is a project. Listed so the estimate is honest, not to be scheduled.

| # | Item | Source |
|---|---|---|
| 6.1 | Web Browser — an order of magnitude beyond anything else here | APPS E1 |
| 6.2 | Office Suite, IDE, CAD, Email | APPS E2, E3, E5 |
| 6.3 | Decoy distro pipeline (X1–X7) | DECOY_DISTRO |
| 6.4 | VeraCrypt hidden-OS install (E1–E7) | INSTALLER |
| 6.5 | Blockchain boot attestation (F0–F7) | INSTALLER |
| 6.6 | Fake-log generator / full-disk illusion (H1–H5) | INSTALLER |
| 6.7 | Calamares/Qt installer (D1.x) — **the native installer already works** (INSTALLER D6) | INSTALLER |
| 6.8 | Foveated display, UML program generation, Rust/ratty terminal | foveated_display, uml_*, SHELL C2–C5 |

---

## Corrections to carry forward

- **Do not boot with `GPU=1`.** It selects `gtk,gl=on`, which `qemu-run.sh`'s own comment warns
  "gives a BLACK SCREEN on many hosts (the GL display path does not present the firmware-VGA
  framebuffer the desktop renders to)". Confirmed here. To exercise virgl use `GPU=1 HEADLESS=1`
  and read `serial.log`.
- **Verifying a build reached the ISO:** `make verify`. It greps the image for string literals
  and compares the baked-in build manifest against `git HEAD`. Two other approaches were tried
  and both failed — C/D **comments do not survive compilation**, and a `__DATE__`/`__TIME__`
  build stamp is frozen by this project's reproducible build (two ISOs 13 minutes apart, with
  demonstrably different kernels, both stamped `18:09:00`).
- **Counting anything in `serial.log`:** every Hyprland/aquamarine line appears **twice** (bursty
  replay, not adjacent duplication). Kernel lines appear once. Halve compositor-side counts.
- **`serial.log` contains NUL bytes** — plain `grep` says "binary file matches". Use `grep -a`.

Two stale claims in the roadmaps will mislead whoever reads them next:

- **`GUI_ROADMAP` still leads with "ARCHITECTURE PIVOT — Weston + Pixman instead of Hyprland."**
  That pivot has been reversed; the desktop is Hyprland. GW4 ("re-express the shell on Weston")
  should be struck.
- **`domain_manager.md` lists DM0–DM12 as if open.** The boot log shows `[domain] lifecycle
  proof PASS`, `[tpl] bundle proof PASS`, `DM2.4 RuntimeView` and `[domain] inherit proof PASS`
  — DM0–DM9 are largely done and simply never marked. It uses no status markers, which is why
  the cleanup could not strip it.
- **`DESKTOP_TILING_PLAN` §A** (the `/wl-quicksettings` popover bug) is in
  `clients/desktop-shell.c` — the **Weston** panel. It does not affect Hyprland, where
  `wl-overview` spawns via its own `launch_and_exit()`. Only relevant if Weston is revived.

---

