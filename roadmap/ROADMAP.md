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

## Tier 2 — The application runtime (the multiplier)

Everything in Tier 3+ and 54 of the 124 apps sit behind this. It is the highest-leverage
work in the project, and it is *not* speculative: GTK 3 with the Wayland backend is already
built for musl in `deps/gtk-stack/sysroot`, and GTK clients launch and talk to the compositor.
They do not yet map a window (2.3).

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 2.1 | ◑ **`/compat/linux` + `/proc` + `/sys` + `/etc`** — `/proc` now reports real data (2026-09-05); `/sys` and `/etc` still largely synthetic | Most monitor-type apps read `/proc` and nothing else. Also what SHELL A1/A5 need | APPS A2 · OBJECT_FS F0 | M |
| 2.2 | ◑ **Syscall audit** — done as a survey: **only the 4 inotify calls are missing**. Remaining work is implementing inotify | Record what is missing once, rather than one crash at a time | APPS A3 · syscalls | M |
| 2.3 | ◑ **One real upstream GTK app end-to-end** — upstream demos build, launch and talk to the compositor; none maps a window yet. Three kernel bugs fixed so far | The gate. Until one runs, every Stage C estimate is speculation | APPS A4 | M |
| 2.4 | **Font / icon / theme resolution inside a GTK process** | Blobs are staged; confirm fontconfig and the icon theme actually resolve | APPS A5 | S |
| 2.6 | ◑ **Stage C1** — the `/proc` data is real and verified; the **apps** are gated on 2.3 by definition | Falls out of 2.1 almost free. ~8 more apps | APPS C1 | M |

**Exit criterion:** an upstream GTK application, not written for this OS, runs on the desktop.

### 2.3 — where it stands (2026-09-05)

Upstream `gtk3-widget-factory`, `gtk3-demo` and our `gtk-hello` all build, launch, and talk to the
compositor. **None maps a window yet.** Three kernel bugs found and fixed on the way, each hiding
the next:

1. **memfd size lost across `SCM_RIGHTS`.** `fstat` reported the per-fd `File.fileSize`, and fd
   passing hands the receiver a *copy*, so a client that grew its shm pool after passing the fd
   left the compositor stat-ing the old size. Hyprland answered
   `wl_shm: "The size of the file is not big enough for the shm pool"` and libwayland tore the
   connection down. Length now lives on the memfd (`MemFdRec.exactLen`).
2. **Missing file under a synthetic-dir prefix returned a directory, not ENOENT.** GTK got
   "Is a directory" for `gtk.css` and `/etc/gtk-3.0/Compose`, which it does not handle; ENOENT it
   handles by falling back to its built-in theme.
3. **…which then broke file *creation*** under those prefixes, because the ENOENT check sat above
   the `O_CREAT` path. `O_CREAT` is now exempt.

**Current state.** `gtk_hello.c` prints `create window`, builds its widgets, calls
`gtk_widget_show_all()`, then prints `window shown -- G11 COMMIT`. The first marker appears, the
second never does — so it stops during widget construction or realize, before GDK creates a
surface. Consistent with the wire trace: no `wl_compositor.create_surface`, and `xdg_wm_base` never
bound (GDK binds it lazily at first toplevel). It is a **hang, not slowness** — six minutes, window
count never moved, process alive. **The compositor is not at fault**: it advertises 70 globals
including everything GTK needs.

**Last logged activity before the stall is fontconfig**, reached via Pango — but that lead is now
weaker, not stronger. An `[openfail]` log (path + errno for every failed open) shows **no
fontconfig failure at all**: its cache files, including `<hash>.cache-9.TMP-XXXXXX`, are created
successfully. The only failures in the whole boot are 19 benign ENOENT probes by Hyprland (`drirc`,
an optional `libglapi.so.0`, `uevent` files).

So "fontconfig is last in the log" may only mean **`[open]` is the most verbose trace we have** —
the client could be stalling in something unlogged (a `write`, `rename`, `mmap`, or a futex wait).

**Next:** trace `write`/`rename`/`futex` the same way, rather than assuming the last visible
syscall is the relevant one — that assumption has already been wrong twice this investigation
(the `HOG:` counters, and "last traced syscall" being `TIOCGWINSZ` only because writes are
untraced). **`G11 COMMIT` is the exact success signal.**

**Tooling built for this, worth keeping:** the kernel decodes the Wayland wire protocol
(`[wl]` lines — object ids resolved to interface names via `wl_registry.bind`, `wl_display.error`
payloads, and the globals list from `wl_registry.global`), and `hos-wl-trace` gives a client a
console so its own messages are readable at all.

### 2.6 — the `/proc` data is real; the C1 apps are gated on 2.3

`GRAPHICAL_APPLICATIONS_ROADMAP` defines C1 as *"cross-build an existing GTK app, not write an
app"* and gates it on A4, so the app half cannot finish before 2.3.

The data every C1 reader consumes is done and verified on a real boot: `/proc/cpuinfo` reports
CPUID vendor and brand with the SMP CPU count (was a hardcoded 1 CPU at 2000 MHz);
`/proc/bus/pci/devices` exists for the first time (walks bus 0, first entry `8086:1237`); and
`meminfo`, `stat`, `loadavg`, `uptime`, `diskstats`, `net/dev` are real from 2.1. `wl-sysmon`
reads five of those already, so it went from an invented 512 MB to the machine's real memory with
no change to the app.

Deliberately absent rather than faked: `cpu MHz`, PCI BAR sizes, Sensors/Battery (need ACPI).

If 2.3 stays blocked, the fallback is to surface this through the native `wl-*` clients, which do
map — C1's outcome without its method, and a deviation from the roadmap worth naming as one.

### 2.2 — audit result: only inotify is missing

Of the 14 syscalls probed **through the real dispatcher** at boot (`[audit]` lines), only the four
inotify calls return ENOSYS. `eventfd`, `eventfd2`, `signalfd`, `signalfd4`, `timerfd_create`,
`memfd_create`, `ppoll`, `epoll_create1`, `dup3` and `pipe2` all work. So 2.2 is no longer a
survey — the remaining work is **implementing inotify**. GIO's file monitors are the visible
casualty (`Unable to find default local file monitor type`).

Probing beats reading the switch table: `inotify_init1` has a `case` arm *and* an ENOSYS stub, so
grepping `case <nr>:` would have scored it present. Two follow-ups it surfaced: `nr 254` routed to
`inotify_init()` while `253` was unrouted (fixed; **the rest of the table is worth sweeping for
this**), and `signalfd` accepts `0xFFFF_FFFF` as a descriptor instead of returning EBADF.

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

