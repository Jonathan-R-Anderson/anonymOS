# anonymOS — Master Roadmap

One ordered list, condensed from the 34 roadmaps in this directory. Ordered by **importance
first** (does the OS work; can someone actually use it), then by **feasibility** within each
tier (cheap and unblocked before expensive and blocked).

Each item names its source roadmap. Those files keep the detail; this file decides the order.

**The single rule:** do not start a tier until the one above it is green. Most of the pain in
this project's history came from deep platform work landing while the desktop could not boot.

---

## Tier 0 — Verify what is already written but unproven

Five commits changed the boot path and none has been booted. Everything below is guesswork
until this is done, because a broken desktop invalidates every measurement.

| # | Item | Source | Effort |
|---|---|---|---|
| 0.1 | Boot current `main`. Confirm no `COMPOSITOR DIED`, `[dm] wl-domain-manager launched`, `[assets] /apps.blob unpacked` | — | minutes |
| 0.2 | Confirm the launcher shows 20 tiles incl. **Software**, **Task Manager**, **CPU Monitor**, and that each launches (arg-bearing Exec lines included) | GUI A6 | minutes |
| 0.3 | Boot once with `GPU=1` — confirm virgl, not softpipe, and that host blur/shadow/animations return | — | minutes |

---

## Tier 1 — Minimal usable installation

The target: install to disk, boot it, get a terminal, edit a file, browse the filesystem,
install more software, and see what the system is doing. Most of this already exists; the
work is reach and polish, not new subsystems.

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 1.1 | **`wl-sysmon` tabs** — ✅ DONE. Task Manager, Process Viewer, System Monitor, CPU, Memory, Disk Usage — 6 launcher entries, one binary, via `--view=`. **Network Monitor NOT shipped**: `/proc/net/dev` is a static stub (posix.d:6490) and the driver keeps no counters, so a view over it would display fiction. Unblock by adding rx/tx counters to `drivers/network`. Disk I/O rates likewise need a `/proc/diskstats` that does not exist — the Disk view reports mounts and is named accordingly | APPS B1 | S |
| 1.2 | **Persistent storage** — installed system survives reboot | "Installation" is meaningless without it. Gates any judgement of daily usability | SHELL A5 | M |
| 1.3 | ~~Full busybox applet set~~ — **ALREADY DONE**, my listing was stale. `deps/busybox/Makefile:37` builds from `defconfig`, and SHELL A1 records 117 → 381 applets. The DONE marker sat in the section body, not the header, so the roadmap cleanup did not strip it | SHELL A1 | — |
| 1.4 | **`wl-quicksettings`** — ◑ PARTIAL. Date & Time row added (real); the fake volume slider removed and the battery row made truthful; "Settings" button renamed "Domains" to match the launcher. **Still blocked:** Keyboard, Mouse, Touchpad and Appearance panels have no backend to change anything — they would be fake controls, so they are not shipped. Needs an input/theme config path first | APPS B2 · GUI G18 · QUICKSETTINGS | M |
| 1.5 | **`wl-domain-manager` views** — User Manager, Service Manager, Startup Applications | Adjacent views on objects the kernel already exposes and proves at boot | APPS B3 | S |
| 1.6 | **`wl-files` / `wl-editor` extensions** — File Search, Disk Usage, Hex/Code editing | Rounds out the core four apps a person actually uses | APPS B5, B6 | M |

**Exit criterion:** a person can install anonymOS, reboot into it, and do a day's basic work
without the serial console.

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
| 2.5 | **D-Bus session bus** | Some GTK apps hard-fail without it; establish which | APPS A7 | S |
| 2.6 | **Stage C1** — `/proc` readers: Hardware Info, System Info, USB/PCI, Sensors, Battery, Routes | Falls out of 2.1 almost free. ~8 more apps | APPS C1 | M |

**Exit criterion:** an upstream GTK application, not written for this OS, runs on the desktop.

---

## Tier 3 — Desktop quality

Usable is not the same as good. Ordered cheap-first deliberately: R5 is explicitly "cheap
present wins" and buys most of the perceived responsiveness.

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 3.1 | **Damage-tracked KMS blit + fast copy** | The roadmap's own "cheap present wins". Biggest felt improvement per hour | DESKTOP_RESP R5 | S |
| 3.2 | **Multi-window and workspace experience** | Hyprland provides the mechanism; this is the desktop actually using it | GUI G20 | M |
| 3.3 | **Visual QA + screenshot regression tests** | Marked Critical in GUI_ROADMAP, and this session showed why: a two-month-old binary shipped unnoticed | GUI G21 | M |
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
