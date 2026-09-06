# anonymOS — Master Roadmap

One ordered list, condensed from the 34 roadmaps in this directory. Ordered by **importance
first** (does the OS work; can someone actually use it), then by **feasibility** within each
tier (cheap and unblocked before expensive and blocked).

Each item names its source roadmap. Those files keep the detail; this file decides the order.

**The single rule:** do not start a tier until the one above it is green. Most of the pain in
this project's history came from deep platform work landing while the desktop could not boot.

---


**Tier 1 — installable OS — ✅ complete 2026-09-05.** Removed; see git history. Its two
carried-forward items live on as 3.0b (`wl-quicksettings` panels) and 5.0 (virtio-blk).

---

## Tier 2 — ✅ exit criterion MET (2026-09-05); three items still open

**Exit criterion met:** upstream `gtk3-widget-factory` runs on the desktop, and a GTK app renders
Pango text and theme icons. 2.3 (upstream GTK app) and 2.4 (font/icon/theme resolution +
installable packs) are **complete and removed** — see git history.

What remains is real but no longer blocking, so Tier 3 can start:

| # | Item | State | Source |
|---|---|---|---|
| 2.1 | **`/proc` + `/sys` + `/etc`** | `/proc` reports real data. `/sys` and `/etc` are still largely synthetic | APPS A2 · OBJECT_FS F0 |
| 2.2 | **inotify** | Audit done: of 14 syscalls probed, **only the 4 inotify calls are missing**. GIO file monitors are the visible casualty. Remaining work is implementing it, not surveying | APPS A3 |
| 2.6 | **Stage C1 readers** | The `/proc` data they consume is real and verified; the apps themselves are unbuilt. Unblocked by 2.3 | APPS C1 |

Two follow-ups the audit surfaced, both cheap: `nr 254` routed to `inotify_init()` while `253` was
unrouted (fixed — **the rest of the syscall table is worth sweeping for the same pattern**), and
`signalfd` accepts `0xFFFF_FFFF` as a descriptor instead of returning EBADF.

**Constraint that outlives Tier 2:** `librsvg` is a stub and gdk-pixbuf is built
`-Dbuiltin_loaders=png` in a fully static stack, so **SVG cannot be decoded at all** — icons must be
PNG. Theme icons are rasterised at build time by `scripts/stage-gui-assets.py`; a user-installed
SVG-only pack will silently resolve to nothing.

---

## Tier 3 — Desktop quality

Usable is not the same as good. Ordered cheap-first deliberately: R5 is explicitly "cheap
present wins" and buys most of the perceived responsiveness.

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 3.0b | **`wl-quicksettings` panels** — Keyboard, Mouse, Touchpad, Appearance. **Blocked:** no input/theme configuration backend exists, so these would be four panels of controls that change nothing. Was roadmap 1.4; it is a desktop-quality item, not a prerequisite for installing | APPS B2 · GUI G18 | M |
| 3.1 | ✅ **Damage-tracked KMS blit + fast copy** — DONE 2026-09-05. **8% of scanlines written** (was 100%) and **stores 5.3x faster** (22070 -> 4178 cycles/row). Blit loop 83256 -> 64988 cycles/row; screen pixel-identical, `boot-test: PASS` | The roadmap's own "cheap present wins". Biggest felt improvement per hour | DESKTOP_RESP R5 | S |
| 3.2 | ◑ **Multi-window and workspace experience** — **UNBLOCKED 2026-09-06**: `wl-calendar` and `wl-logview` reflow and tile — **verified**: 4 windows tiled, no overlap, both re-reflowing at a second width. `wl-wifi-menu` is converted and builds but is **unverified at runtime** (its `SUPER+W` bind did not fire in the test). 2 left (`wl-overview`, `wl-quicksettings`) plus `wl-domain-manager`, each needing its own layout reflow before `set_max_size` can go | Hyprland provides the mechanism; this is the desktop actually using it | GUI G20 | M |
| 3.3 | ✅ **Visual QA + screenshot regression tests** — DONE 2026-09-06. `scripts/golden-check.sh` (`make golden`) masks the clock, compares the rest pixel-exactly, and passes with **0 differing pixels across separate boots**; a corrupted golden fails with 180847. One golden recorded (`installer`); more are one `make golden-update GOLDEN=<name>` each | Marked Critical in GUI_ROADMAP, and this session showed why: a two-month-old binary shipped unnoticed | GUI G21 | M |
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
- **`make all` builds Weston, not Hyprland.** `Makefile:172` has `WESTON ?= 1`, and that staging
  step overrides Hyprland as init. The symptom is not a build error but a boot that looks like a
  severe regression: `tests/desktop-smoke.txt` requires `init = Hyprland module`, `[bar]
  wl-layer-bar launched` and `[g5] windows=`, and against a Weston ISO all three are ABSENT.
  **Build `make WESTON=0 all`**; on a surprise failure check `grep -a 'init = ' serial.log` before
  suspecting your own change.
- **Grepping an ISO for a *filename* proves nothing about whether that file is in it.** Searching
  for `hos-dbus-launch` returned six hits while the binary was not staged at all — the hits were
  the kernel's own spawn call naming the program. Grep for the `module_path:` line, or list the
  staged tree. (Grepping for a new *string literal* is still valid — see `make verify` above.)
- **`pitMs()` is 1:1 with real time once the system is up.** Measured 2026-09-05 against three
  independent NTP server timestamps in one soak: Δ`pitMs` 4000 ↔ 4 s, and Δ`pitMs` 60000 ↔ 60 s.
  A clock set by SNTP held to within 1 second over a full minute. (Wall time *before* the periodic
  loop starts ticking is not counted — a 150 s soak reached `pitMs` 75000 because the ISO spends
  the first ~75 s in firmware and kernel init, so don't read boot-relative `pitMs` as uptime.)
- **"The clock must be running slow" is usually a scheduling bug, not a slow clock.** A re-sync
  timer that never fired twice looked exactly like `pitMs` advancing at 1/30 of real time, and was
  nearly written into this file as that. The real fault was a re-arming deadline: the retry round
  pushed its own next-attempt time forward before ever sending, so the following pass re-gated on
  the deadline it had just moved. **Measure the clock before concluding anything about it** — a
  heartbeat at a fixed `pitMs` interval, counted against a soak of known length, settles it in one
  run.
- **`scripts/boot-test.sh` kills QEMU the moment every `require` marker has appeared** — `TIMEOUT`
  is a ceiling, not a duration. Anything that needs the guest to keep running (a periodic timer, a
  re-sync, a soak) will never be observed through it. Run `qemu-run.sh` directly for those.
- **A keybinding can only launch a single-word command, and there is no `/bin/sh`.** A command with
  arguments is routed through a shell and execs an empty program name (`[exec] not found: /bin/`).
  This is why `SUPER+B` (top-bar toggle) has never worked. Anything needing arguments or an
  environment variable needs a small launcher binary — see `hos-wl-trace`.
- **A process Hyprland forked inherits no console, so anything it prints is discarded.** This looks
  exactly like a feature being disabled rather than its output being lost, and invalidated three
  separate conclusions before it was spotted. `hos-wl-trace` dup2's `/dev/console` onto fd 1/2.
- **`busybox-dyn` is not in the ISO** despite the Makefile having a `module_path` line for it; its
  staging block never runs. `/busybox` is the one that exists.
- **A fixed poll count is not a timeout.** Anything polled from the main scheduler loop runs at no
  defined wall rate, so "wait N polls for the daemon" measures nothing physical. Both a 40-poll
  and a 400-poll wait for the D-Bus socket fired early. Wait on the condition itself and bound it
  with `pitMs()`.
- **A build step that reports success can still have built nothing.** `build-dbus.sh` piped every
  command to `tail`, and a pipeline's exit status is the last command's, so `set -e` never saw
  configure or make fail and the script printed its "RESULT" banner regardless. Any wrapper script
  here that pipes to `tail`/`head` needs `set -o pipefail`.
- **Staged, logged, and present in the ISO still does not mean the guest can open it.** Assets
  only reach the runtime overlay through a *category blob* the kernel unpacks; `pack-assets.py`
  sorts unknown paths into `misc`, and the aggregate `assets.blob` is a fallback that never fires
  while any named blob yields files. Confirm with `grep -a '\[assets\].*unpacked' serial.log`.

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

