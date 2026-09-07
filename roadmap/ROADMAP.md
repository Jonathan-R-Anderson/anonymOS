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
| 2.2 | ✅ **inotify — DONE 2026-09-06.** Real watches over the rtfs overlay, keyed on node index; events posted from the three overlay mutation points (create/unlink/write); `read()` returns `struct inotify_event` 4-byte padded; poll/epoll see it via `fdReadable`. Verified 8/8 from userspace (`src/util/inotify-test.c`), and dbus-daemon's "Cannot initialize inotify" is gone. Only the writable overlay generates events — a watch on an image file or synthetic `/proc` succeeds and never fires | APPS A3 |
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
| 3.5b | ✅ **Idle wake churn — DONE 2026-09-06.** `wakePollers()` un-parked **every** poll-blocked task on every PIT tick without asking whether anything was ready, so idle tasks cycled wake/rescan/park at 1 kHz. Measured **~7000 -> ~705 wakes/sec (10x)** on an idle desktop, golden PASS 0 differing pixels, frames 68 -> 79. Two mechanisms, because one does not fit both: epoll waiters are **filtered** (kernel owns the watch set, so `fdIsReadable(epfd)` answers exactly what `epoll_wait` would) -> ~1000 to 32-42; poll() waiters are **rate-limited** to every 8th tick -> ~1000 to ~127. Filtering poll() was tried and reverted (d37fb65e90): its fd array is in userspace, and the blanket wake turned out to be a system-wide safety net whose removal stranded a futex waiter forever. Slowing the net bounds a missed wakeup at ~8ms instead. `POLL_BACKSTOP_TICKS` is the tuning knob | DESKTOP_RESP | M |
| 3.6 | **quickshell (Qt6/QML) port** | The only route to true host parity — the host's bar, sidebars, overview and launcher are all one `qs` process. Needs 2.x and a working GL path | APPS E6 | XL |

---

## Tier 4 — Platform depth

Valuable, coherent, and **not** on the path to a usable desktop. Deliberately after Tier 3.

| # | Item | Source |
|---|---|---|
| 4.0 | ✅ **Per-process identity is live — DONE 2026-09-06.** `spawnWaylandProgram` copied user/namespace/untyped from task 0 but omitted `identityObjId`, so every desktop process ran unlabelled (`ident=0`) — and that is why the border could be a `pid % 8` hash unnoticed: with nothing to show, a decorative fallback looked identical to working code. Apps now inherit the **session domain's** identity (first non-template, non-system-trust domain), not the kernel's. Measured end to end: `ident=0` -> `0x33`, border `0xFF2E7D32` Personal, distinct from task 0's System `0x31`; desktop up, 0 faults, golden re-recorded and PASS. Two wrong rules were caught by printing values first: inheriting task 0 labelled apps *System*, and "first non-template domain" selected the *System domain* | IDENTITY_DOMAIN |
| 4.0b | ✅ **Namespace confinement — DONE 2026-09-06.** Confinement decided in `execveTask`, the choke point BOTH launch paths share (`spawnWaylandProgram` calls it; so does the `execve` syscall Hyprland uses for keybinds), keyed on the program just loaded. Verified per-exec: `wl-quicksettings CONFINED ns=0x1451` (a Hyprland-forked user app — the case the earlier `spawnWaylandProgram`-only hook missed entirely), `calamares`/`wl-domain-manager`/`wl-layer-bar`/`hos-*` SYSTEM(unconfined); 0 `/config` openfails, desktop up, 0 faults. System split is an **allowlist** (`isSystemProgram`) so unknown programs fail safe as unconfined. Enforces **read-mostly, write-confined, explicit denies** — full read isolation still needs a filesystem-layout change (`allowTraversalOutsideMounts` grants read-only `/` because binaries live at the root). Note: `dbus-daemon` ends up confined (the `hos-*` rule exempts its launcher, not the daemon); it works, since the policy allows `/etc`, `/run`, `/var/lib` | IDENTITY_DOMAIN |
| 4.0c | ✅ **Identity border — resolved 2026-09-06.** Question was which of two border paths is authoritative. **Measured: the kernel's.** On the shipped Hyprland configuration the in-kernel compositor never runs — its identity self-test fires 0 times and it allocates 0 surfaces, while `[g5] BORDER` does — so `drmSetHosWindows` -> `fbDrawBorder` is what paints. That is also **stronger** than what IDENTITY_DOMAIN §56 describes: the kernel is the TCB, so a border it draws cannot be raced or spoofed by the compositor, let alone an app. `compositor.d borderColorFor()` is therefore **kept, not deleted** — it is the Weston path, which `make all` still builds. The real defect was that the two disagreed: both fall back to a neutral colour for an unlabelled window and used **different** ones (`0xFF8FBF5F` vs `0xFF505050`), so the indicator's meaning depended on which compositor shipped. `IDENTITY_BORDER_NEUTRAL` (identity.d) is now the single definition | IDENTITY_DOMAIN |
| 4.1 | ✅ **Identity brokers, disposable identities, policy engine (Phases 7–9) — DONE 2026-09-07.** All three existed as code only a SELF-TEST had ever reached. (a) **Two, then three identities run concurrently** — `domainSpawnInto` puts `wl-calc` in BankVault (Banking, yellow) and `wl-clocks` in the new Throwaway domain (Disposable, orange) beside the Personal session (green); all three borders are on screen at once and each is drawn from the owning task's real identity. (b) **Cross-identity IPC gate is live and proven in both directions** — `idipcMayConnect()` is consulted on every AF_UNIX connect, the first non-self-test caller of `g_idIpcRules`; `xid-test` gets `EACCES` reaching out of BankVault while `calamares(Personal) -> Hyprland(System)` still connects. **Rule derived from measurement:** every real cross-identity connect is app -> compositor, and there is **no** app-to-app crossing, so a system-trust peer is a **hub** any identity may reach (refusing it would cut every app off its display) and app-to-app is `EACCES` without a broker pair rule. (c) **Disposable identities work without unfreezing the registry.** `identityCreate()` refuses once `g_idFrozen`, which `configboot` sets after loading policy — a security property, not an oversight: privilege cannot be minted at runtime. The Disposable identity was already declared at boot; what was missing was a domain referencing it, so nothing could ever run as one. (d) **`brokerRequestSession()` has a real caller** — `sys_connect` mints a signed, expiring descriptor once per identity pair, stamped with two real identities instead of the self-test's `0x100`/`0x200` fixtures. Minting required writing the compositor hub down as explicit broker rules, so the connect path and the broker agree instead of the hub living only as a trust comparison. **Proof:** `tests/disposable-identity.txt` — 5 require / 2 forbid, PASS, asserting the painted colour `ffff6d00` rather than the registry. **Not done, and out of this row's scope:** Phase 9's *runtime* signed policy transactions (`policyEpoch` bump, `CAP_RIGHT_ADMIN_IDENTITY`); boot-time signed policy load is live (`configboot` verifies the manifest HMAC via `cryptoVerify` before applying) | IDENTITY_DOMAIN |
| 4.2 | Immutable-rootless foundation (Phase 0 invariants) | IMMUTABLE_ROOTLESS |
| 4.3 | Declarative config compiler (Phases 1–9) | DECLARATIVE_CONFIG_SPEC |
| 4.4 | Whole-image A/B update unit | SYSTEM_UPDATE D1 |
| 4.5 | Native object shell `-sh` (B0–B5) | SHELL_AND_COMMANDS |
| 4.6 | Marketplace / I2P template distribution | NETWORK_AND_MARKETPLACE |
| 4.7 | ⚠ **The shipped ISO names the person who built it.** `grep -ac "/home/bruns/Documents/anonymOS" hos-install.iso` = **396**, across **34 binaries** in `cd/`. Compile-time prefixes baked into the vendored stack: musl's `ld-musl-x86_64.path`, Mesa's DRI/GBM driver search, glib's gio modules, libinput's data dir, `drirc`. The guest probes 9 of them at runtime and every one fails `ENOENT`, so nothing is broken functionally — but an image whose premise is deniability embeds its builder's username and source-tree layout, which is a fingerprint of exactly the kind this OS exists to avoid, and it also makes the build non-reproducible across machines. Fix is a deps rebuild with guest-relative prefixes (`--prefix`/sysroot), not a kernel change | DECOY_SECURITY · IMMUTABLE_ROOTLESS |

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
| 7.1 | ✅ **Generated syscall man pages** — DONE 2026-09-06. `scripts/gen-syscall-man.sh` parses the dispatch table and the implementations, emitting **150 section-2 pages** plus `anonymos-syscalls(7)`. Descriptions come from the source comments at the implementation AND the dispatch site: **130 of 150 carry real notes**, 20 are honest placeholders where the source records none. Regeneration is the only update path, so it cannot drift | `scripts/gen-syscall-man.sh`, `docs/man2/`, `docs/man7/` |
| 7.2 | **Ship the pages on the system** — the pages exist in the repo but are not staged into the ISO, so an admin on the running OS cannot read them. Needs a `man` binary (or a minimal pager) plus staging under `/usr/share/man` | GUI · INSTALLER |
| 7.3 | **Fill the 20 undocumented calls** — where neither the implementation nor the dispatch site records anything. These are the calls whose behaviour is least known, which is exactly why they should be written up rather than left to the reader | — |
| 7.4 | **Document the native object ABI per verb** — 25 `HOSQ_*` verbs. `docs/NATIVE_OBJECT_ABI.md` (752 lines) covers the surface in prose; the per-verb pages do not exist | `docs/NATIVE_OBJECT_ABI.md` |
| 7.5 | **Admin runbook for the deviations** — the ABI differences that have each cost real debugging time (AF_UNIX read returning EAGAIN, namespace-resolved opens, cross-identity connect refusal, overlay-only inotify) belong in one place an admin reads BEFORE debugging, not after | — |

## Corrections to carry forward

- **No task carries an identity, so the "identity border" is decorative.** `identity.d` states that
  windows "are bordered with the identity's color by the trusted compositor", and `idwin.d`
  implements exactly that — but nothing on the live path stamps a task: the installer, the bar and
  every desktop app run with `identityObjId == 0`. `hosIdentityColor()` therefore always took its
  fallback, which was `HOS_ID_PALETTE[pid % 8]` — a pid hash presented as a domain indicator. Found
  when implementing inotify shifted pids and the 3.3 golden check failed on a border that had no
  business changing. The fallback is now one fixed colour (honest, and stable across boots) and the
  real-identity path takes over the moment `identityObjId` is non-zero. **Stamping tasks with
  identities is the actual work, and it is unstarted** — until then, per-window domain separation is
  not visible to the user. Note the original intent was per-client colours; if wanted back, key them
  on the exec name (stable) rather than the pid (shifts every boot).
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

