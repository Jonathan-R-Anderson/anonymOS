# anonymOS — Master Roadmap

One ordered list, condensed from the 34 roadmaps in this directory. Ordered by **importance
first** (does the OS work; can someone actually use it), then by **feasibility** within each
tier (cheap and unblocked before expensive and blocked).

Each item names its source roadmap. Those files keep the detail; this file decides the order.

**The single rule:** do not start a tier until the one above it is green. Most of the pain in
this project's history came from deep platform work landing while the desktop could not boot.

---


**Tier 1 — installable OS — ✅ complete 2026-09-05.** Removed; see git history. Its two
carried-forward items live on as 5.0 (virtio-blk).

---

## Tier 2 — ✅ exit criterion MET (2026-09-05); three items still open

**Exit criterion met:** upstream `gtk3-widget-factory` runs on the desktop, and a GTK app renders
Pango text and theme icons. 2.3 (upstream GTK app) and 2.4 (font/icon/theme resolution +
installable packs) are **complete and removed** — see git history.

**2.1 `/proc` + `/sys` + `/etc` — ✅ complete 2026-09-06.** Entries that describe the MACHINE now read
live state: `/sys` DRM identity (`vendor`/`device`/`revision`/`uevent`/`subsystem_*`, both path
families) and `/sys/bus/pci/devices` from the PCI bus; `/etc/machine-id` per-install;
`/etc/resolv.conf` from the DHCP lease. This corrected a constant wrong on the dev VM itself —
`/sys` claimed virtio-gpu `1af4:1050` at `0000:00:04.0`, the machine has stdvga `1234:1111` at
`0000:00:02.0`. Entries that are BROADCAST stay uniform on purpose (`hostname`, `timezone`): they
are announced to the network, so a per-install value would shrink the anonymity set to one — the
reasoning is recorded at the constants. Config files (dbus/pipewire/NM) stay constants because that
is what they are. Not done, and deliberately: `/sys/class/net` (fixed `lo`/`wlan0` — gating it risks
NetworkManager not finding the device), `/sys/block/*` (absent), DRM `status`/`enabled`/`dpms`.

What remains is real but no longer blocking, so Tier 3 can start:

| # | Item | State | Source |
|---|---|---|---|
| 2.7 | **zsh syntax-highlighting fails on `/dev/null`** — every prompt prints `_zsh_highlight__function_callable_p:13: no such file or directory: /dev/null`. NOT a missing device: the kernel logs successful `[open] /dev/null`, and the message predates the 4.0 identity change (present in pre-change logs), so it is not a device-mask regression from apps moving System -> Personal. The plugin tests whether a command is callable, and that probe -- an `execve`/`stat`/`access` shape rather than a plain open -- gets an answer the plugin reads as ENOENT. Same class as the 2.2 audit finding: a syscall that exists but does not behave as the caller expects. Was invisible until the mirrored-font fix made terminal text readable | APPS A3 |
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

Usable is not the same as good.

**3.5 preemptive scheduling — resolved by measurement 2026-09-06, no code change.** R6 asks to add
time-slice preemption because "a task that doesn't yield can monopolize the core". It cannot: the
APIC tick reaches `scheduleNext()` at 1 kHz and takes a non-yielding ring-3 task off the core in
~1ms. Four `/hog` tasks (`src/util/hog.c`, never makes a syscall, `SUPER+SHIFT+Y`) confirmed it --
the desktop kept presenting and repainting throughout. Share is not the limit either: giving the
compositor a guaranteed alternating turn was measured A/B at **71 vs 70 frames in 75s** and
reverted. Under load the ceiling is softpipe frame cost, not the scheduler.

**Done and removed 2026-09-06** (see git history): 3.4 kernel-mode interrupt handling (the BSP now
`sti;hlt`s when idle instead of running a ring-3 PAUSE-spinner; 200/200 halts woken by a
kernel-handled APIC tick, golden PASS 0 differing pixels), 3.0b `wl-quicksettings` settings panels
(Keyboard/Mouse/Touchpad/Appearance, live over Hyprland IPC and persisted under `/home`),
3.1 damage-tracked KMS blit (8% of scanlines written, stores 5.3x faster), 3.2 multi-window
reflow (all five floating clients now tile), 3.3 screenshot regression tests (`make golden`,
0 differing pixels across boots).

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 3.6 | **quickshell (Qt6/QML) port** | The only route to true host parity — the host's bar, sidebars, overview and launcher are all one `qs` process. Needs 2.x and a working GL path | APPS E6 | XL |

---

## Tier 4 — Platform depth

Valuable, coherent, and **not** on the path to a usable desktop. Deliberately after Tier 3.

| # | Item | Source |
|---|---|---|
| 4.6 | 🚧 **TBD — marketplace / template distribution, transport undecided.** Held deliberately, not merely unstarted: the I2P design in `NETWORK_AND_MARKETPLACE_ROADMAP` is **being reconsidered in favour of an alternative**, and nothing here starts until that choice is made. Building on the wrong transport would repeat this project.'.s most expensive pattern — code that self-tests and no live path ever reaches. **Whatever transport wins still needs the layer under it:** `SYSTEM_UPDATE` records TCP **RX host-blocked in QEMU** (N2), so plain receive is unproven in the test environment. **Order when it resumes:** decide the transport → finish N2 → bring up that transport → discovery → template distribution, which is mostly packaging on top. Shares U5/U6 with `SYSTEM_UPDATE`, so it gets built once and serves both updates and the marketplace | NETWORK_AND_MARKETPLACE (TBD) |
| 4.11 | ◑ **Host paths are gone; the row's second premise turned out to be wrong.** ✅ **Deniability + reproducibility: DONE.** `grep -ac "/home/bruns" hos-install.iso` = **0**, and the sanitiser now maps each dependency sysroot to `/usr` rather than a placeholder, so `<root>/deps/gtk-stack/sysroot/share/drirc.d` becomes a path POSIX collapses to `/usr/share/drirc.d` — where this OS would stage such a file — instead of `/build/…`, where nothing could ever be. ⚠ **The row claimed a rebuild would let "the guest's own path probes actually resolve instead of failing ENOENT". Measured: it would not.** Those files are **not staged in the ISO at all** — `/usr/lib/ld-musl-x86_64.so.1`, `/usr/share/drirc.d`, `/usr/lib/dri` are all absent — so baking a guest-relative prefix changes the *string* without putting a *file* there. Most are optional lookups that correctly fail: the binaries are **statically linked**, so a dynamic loader path is not needed. Resolving them is a separate decision about what to SHIP, not about prefixes. **One known wart:** a single prefix substitution cannot be right for the whole sysroot — its top level holds both `etc/` and `share/`, which the guest wants at `/etc` and `/usr/share`. Mapping to `/usr` is correct for the 17 `share/` and `lib/` probes and wrong for the 12 `etc/` ones (`/usr/etc/drirc`). **What genuinely remains** is the cleanliness refactor: build deps with `--prefix=/usr` + `DESTDIR` so nothing is baked in to begin with. That relocates every installed file in a **722 MB** tree and every staging path that reads it — worth doing deliberately, and not worth starting half-done on a machine in daily use | DECOY_SECURITY |

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


---

## Tier 7 — Administrator documentation

An admin cannot manage what is not written down, and this kernel deviates from Linux in ways that
are invisible until something fails oddly. The reference has to be GENERATED from the kernel
source: `docs/SYSCALL_ABI.md` was hand-written and already claimed "160 syscalls" against 177
dispatch arms, and a reference that drifts is worse than none because nobody can tell which half
is lying.

| # | Item | State | Source |
|---|---|---|---|
| 7.2 | **Ship the pages on the system** — the pages exist in the repo but are not staged into the ISO, so an admin on the running OS cannot read them. Needs a `man` binary (or a minimal pager) plus staging under `/usr/share/man` | GUI · INSTALLER |
| 7.3 | **Fill the 20 undocumented calls** — where neither the implementation nor the dispatch site records anything. These are the calls whose behaviour is least known, which is exactly why they should be written up rather than left to the reader | — |
| 7.4 | **Document the native object ABI per verb** — 25 `HOSQ_*` verbs. `docs/NATIVE_OBJECT_ABI.md` (752 lines) covers the surface in prose; the per-verb pages do not exist | `docs/NATIVE_OBJECT_ABI.md` |
| 7.5 | **Admin runbook for the deviations** — the ABI differences that have each cost real debugging time (AF_UNIX read returning EAGAIN, namespace-resolved opens, cross-identity connect refusal, overlay-only inotify) belong in one place an admin reads BEFORE debugging, not after | — |



---

## The backlog — every unimplemented item, by source roadmap

The tiers above are the *ordered* plan. This is the *complete* one: the named, still-open
milestones from all 37 other roadmaps in this directory, so work can continue down the list
without re-reading each file. **Items already delivered are omitted** — each roadmap keeps its own
record of what it claimed.

Where a milestone is partly done, the remaining part is what is listed.

### Hardware enablement — `BARE_METAL_ROADMAP`, `WIFI_AUTODRIVER_ROADMAP`
- **BM0** — boot + software desktop on real hardware (verify; no LKL)
- **L3** — the hardware bridge: a custom `lkl_dev_pci_ops` backend *(the core piece)*
- **L4** — per-device LKL isolation (cap-gating) + bridge LKL's devices to the OS
- **L5** — USB HID via LKL *("the usable-desktop unlock" on real hardware)*
- **L6** — GPU via LKL *(research frontier)*
- **W1/W1-pre** — LKL wireless rebuild + toolchain · **W2** firmware provisioning
- **W3** — WPA/WPA2/WPA3 association *(the hard part)* · **W4** IP + connectivity
- **W5** — installer network page · **W6** auto-driver detection + provisioning

### Graphics + desktop — `VIRGL_BLOB_ROADMAP`, `DESKTOP_RESPONSIVENESS_ROADMAP`, `GUI_ROADMAP`
- **B1–B8** — host-visible `RESOURCE_CREATE_BLOB` for cross-process virgl sharing: cap-walk the SHM
  region, negotiate the feature, fix the hardcoded `fence_id`, kernel transport, GETPARAM, the DRM
  ioctl, cross-process import *(the payoff)*, lifecycle
- **R5** — cheap present wins (damage-tracked KMS blit + fast copy)
- **R6** — preemptive scheduling · **R7** multi-core · **R8** GPU-accelerated compositing
- **G18** settings app · **G19** animation/effects · **G20** multi-window + workspaces ·
  **G21** visual QA + screenshot regression tests
- *(**GW4** "re-express the shell on Weston" is **obsolete** — the desktop is Hyprland now)*
- **`LLVMPIPE=1`** — implemented, off by default; the largest desktop-performance win available

### Update + distribution — `SYSTEM_UPDATE_ROADMAP`
- **U2** — signed `.hosupd` staging over a transport *(the unit and its verification are done)*
- **U3** — updater UI + offline medium (USB) · **U5** I2P transport · **U6** Kademlia DHT
- **U7** — end-to-end decentralized upgrade + rollback *(the north-star demo)*
- **U8** efficiency/scope · **U9** hardening tail
- **D4/D5/D5a/D6** — the zkSync, I2P-router and updater-daemon design decisions
- *All of the transport half is gated on 4.6's TBD decision.*

### Domains + templates — `domain_manager`, `DECOY_DISTRO_ROADMAP`
- **DM6** templates/overlay tail · **DM9** template inheritance + least-privilege merge
- **DM11** multi-distro / package-manager shims · **DM12** signed downloadable templates *(TBD, 4.6)*
- Per-domain terminal — reverted once; design in git history
- **X1–X7** — runtime network install of a real distro ISO: download/verify/extract → ext4,
  feed it to the VeraCrypt decoy path, wizard picker, squashfs-live distros (Mint/Fedora),
  non-live distros (Debian/Alpine/NixOS), resumable download + mirror failover, hardening

### Installer + deniability — `INSTALLER`, `DECOY_SECURITY_REVIEW`
- **F6** — update integration (keep the boot-integrity chain equal to the legit system)
- **F7** — boot-integrity security review · **H5** hidden-OS detectability review *(both flagged
  security-critical, and neither has been done)*
- **H3** — full-disk illusion driver (hide the hidden volume's space)
- **H4** — conceal the fake-log generator (kernel-embedded, hidden from the process table)
- Unaddressed findings in `DECOY_SECURITY_REVIEW`
- **GUI installer throughput** — one 4 MiB batch per compositor round-trip, so a large install is
  bounded by frame rate rather than disk

### Shell + userland — `SHELL_AND_COMMANDS_ROADMAP`, `expand_busybox_roadmap`
- **Track A** — the remaining busybox/coreutils coverage
- **C2** — Rust toolchain targeting the OS *(no rustc on host)* · **C3** winit/Wayland client ·
  **C4** GPU stack for wgpu *(the hard gate)* · **C5** `ratty` bring-up
- Account database + the wider identity/command model (`expand_busybox_roadmap`)

### Kernel + platform — `SMP_ROADMAP`, `OBJECT_*`, `SECURITY_ROADMAP`
- **SMP** — more than one AP online; work-stealing. *(Needs x2APIC: absent → PIT fallback.)*
- **Object FS F5+** and the service-extraction tail (§5.2) — move FS/net/display out of the kernel
- **Memory hardening** — ASLR, NX stack, guard pages, stack canaries, SMAP/SMEP
- **Physical `/var` separation** — the last piece of the immutable story

### Documentation — `DOCUMENTATION_ROADMAP` (all deliverables verified missing)
- **D4** `docs/IDENTITY_AND_CAPABILITIES.md` · **D5** `docs/OBJECT_MODEL.md` ·
  **D6** `docs/IPC_AND_SERVICES.md` · **D7** `docs/BOOT_MEMORY_SCHED.md` ·
  **D8** `docs/PERSISTENCE.md` · **D9** `docs/DRIVERS_AND_DISPLAY.md` · **D10** `docs/BUILD_AND_TEST.md`
- *(Tier 7's syscall pages are done: 150 `man2` + `anonymos-syscalls(7)`.)*

### Design documents — not scheduled work
`syscalls_roadmap` (Plan 9 + capability semantics), `ORG_ARCHITECTURE`, `foveated_display`
(foveated/parallax compositor), and **`uml_program_generation_roadmap`** — generate programs from a
UML model. That last one is unrelated to the declarative config compiler despite the surface
similarity: different input, output and consumer. None of these have ever been scheduled, and they
should not be read as planned work.

## Corrections to carry forward

- **The identity border is real now — this note used to say the opposite.** It read "no task carries
  an identity, so the border is decorative… stamping tasks with identities is the actual work, and it
  is unstarted". That was true when written and is not any more: 4.0 made per-process identity live,
  and 4.1 put three identities on screen at once, measured at the pixel — Personal `ff2e7d32`,
  Banking `ffffd600`, Disposable `ffff6d00`, each drawn from the owning task's real `identityObjId`.
  The pid-hash fallback (`HOS_ID_PALETTE[pid % 8]`) that made a border change when inotify shifted
  pids is gone; `IDENTITY_BORDER_NEUTRAL` is the single fallback. **Kept as a correction because the
  lesson outlived the bug:** a mechanism that is written, self-tested and never reached by the live
  path reads exactly like a working feature, and this tier found that same shape five more times —
  `idwinStamp`, `domainBindTaskNs`, the `applications` config field, `brokerAuthorizePair`, and
  `g_idIpcRules`. Check what the live path actually calls before believing a subsystem works.

- **An IRQ taken in the kernel used to be unsurvivable**, and that shaped a lot of this system.
  `serviceISR` assumes userspace was interrupted: it saves registers into `curUserSpaceState` and
  returns from `x64SwitchToUserspace`. From kernel mode that corrupts the task's state and unwinds
  the kernel's stack — so the kernel ran with IF=0, could not `hlt`, and "idle" was a ring-3
  PAUSE-spinner burning a core. 3.4 fixed it: `serviceIRQ` branches on the iret frame's CS.
  **A kernel-mode ISR here is a TOP HALF only** — EOI plus the i8042 drain (that buffer is one byte
  deep) — because it interrupts arbitrary kernel code, so anything walking a shared structure is
  deferred to `kernelIrqDrainBottomHalf()` under the BKL.
- **`make golden` compares against a RUNNING guest.** With none up it fails with "no monitor socket";
  worse, with a *stale* guest still running it silently compares the wrong build. Boot the build
  under test first, then run `scripts/golden-check.sh installer`.
- **The desktop's configuration backend is Hyprland's IPC socket**, not a config file. Input and
  theme settings live in `system/hypr/custom/*.lua`, baked in at build time, so a running desktop
  could not change them — that is what blocked 3.0b. `hypr_ipc()` in `wl-quicksettings.c` writes a
  bare command (no framing) to `/run/user/1000/hypr/<sig>/.socket.sock`. The command is
  **`eval hl.config{...}`, not `keyword`** — keyword only drives the old hyprlang parser, and this
  desktop's config is Lua (`HyprCtl.cpp:1143`). Three traps, all paid for:
  the kernel does not export `HYPRLAND_INSTANCE_SIGNATURE`, so the code enumerates that directory
  and assumes a single instance; **AF_UNIX reads return `EAGAIN` on an empty socket instead of
  blocking** (`localSocketRead`), so a client MUST poll rather than read once — Hyprland does not
  `accept()` until its event loop next runs, then polls for 5s and closes without replying
  (`HyprCtl.cpp:2243`), so an impatient client silently applies nothing; and a Hyprland-forked
  child has no console, so the reply must be shown in the UI to be read at all.
- **Do not judge a pixel change by eye.** `general:border_size 8` was reported as proving the IPC
  path worked; measured with `compare -metric AE` it was **0 differing pixels**. The test could not
  have worked either way: in this desktop the window borders are painted by the KERNEL
  (`drmSetHosWindows`), not the compositor. Use a setting the compositor genuinely owns, and
  measure it.

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

