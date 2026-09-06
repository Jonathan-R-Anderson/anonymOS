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
built for musl in `deps/gtk-stack/sysroot`, and `gtk-hello` already runs.

| # | Item | Why here | Source | Effort |
|---|---|---|---|---|
| 2.1 | **`/compat/linux` + `/proc` + `/sys` + `/etc`** | Most monitor-type apps read `/proc` and nothing else. Also what SHELL A1/A5 need | APPS A2 · OBJECT_FS F0 | M |
| 2.2 | ◑ **Syscall audit** — *measured 2026-09-05, see below.* Of the 14 probed, **only the 4 inotify calls are missing**; eventfd, eventfd2, signalfd, signalfd4, timerfd_create, memfd_create, ppoll, epoll_create1, dup3 and pipe2 are all implemented. Remaining work is **implementing inotify**, not surveying | Record what is missing once, rather than discovering it one crash at a time | APPS A3 · syscalls | M |
| 2.3 | ◑ **One real upstream GTK app end-to-end** — `gtk3-widget-factory` and `gtk3-demo` now build from the upstream tree and are staged + bound (`SUPER+SHIFT+W` / `+G`). widget-factory **launches and gets deep into GTK startup but never maps a window** — see below. No need for `gnome-calculator`; the gate is now a debugging problem, not a packaging one | The gate. Until one runs, every Stage C estimate is speculation | APPS A4 | M |
| 2.4 | **Font / icon / theme resolution inside a GTK process** | Blobs are staged; confirm fontconfig and the icon theme actually resolve | APPS A5 | S |
| 2.6 | ◑ **Stage C1** — the *data* is now real (see below). The **apps** are blocked: `GRAPHICAL_APPLICATIONS_ROADMAP` defines C1 as "cross-build an existing GTK app, not write an app" and gates it on A4 — i.e. on 2.3 | Falls out of 2.1 almost free. ~8 more apps | APPS C1 | M |

**Exit criterion:** an upstream GTK application, not written for this OS, runs on the desktop.

### 2.3 status — upstream GTK app launches but never maps — 2026-09-05

`-Ddemos=true` was added to the gtk-stack build, so GTK's own `gtk3-widget-factory` (22.6 MB),
`gtk3-demo`, `gtk3-icon-browser` and `gtk3-demo-application` now build against musl exactly as
`gtk-hello` does. widget-factory is staged as a boot module and bound to `SUPER+SHIFT+W`.

**What happens when it is launched** (driven through the real keybinding via the HMP monitor, twice,
the second time waiting a full 4 minutes):

- It execs and runs — three tasks appear, doing `poll`/`sendmsg` on Wayland fds.
- It gets **deep into GTK startup**: reads `/usr/share/glib-2.0/schemas/gschemas.compiled` (so the
  `misc.blob` fix is doing its job), loads gio modules, then enumerates the cursor theme, opening
  dozens of hashed names under `/usr/share/icons/Epin/cursors/`.
- **No `Gtk-WARNING`, no `Gtk-CRITICAL`, no assertion, no crash, no exit.**
- **`[g5] windows=` never leaves 1.** It never maps a toplevel.
- Throughout, the compositor stalls: `[freeze] stalled 6s…29s` with `flipQ`/`flipRd` frozen and
  `HOG: <tid>:gtk3-widget-factory`.

**It is NOT the missing preemptive scheduler.** That was the first hypothesis, from the freeze
watchdog naming widget-factory as the hog while presentation was frozen. Reading the log properly
killed it, and the two pieces of evidence are worth keeping because both look like starvation and
neither is:

- **After the cursor load, widget-factory issues 2 `recvmsg` and 1 `sendmsg` and then nothing.**
  It is not CPU-bound; it is *blocked*.
- **The `HOG:` figures are near-identical across every task** — `15:gtk3-widget-factory=619
  0:Hyprland=618 2:dbus-daemon=618`. That counter is close to uniform, so "HOG" names the top
  three of a near-flat distribution. **It is not evidence that anything is hogging.**

The cursor enumeration is also innocent: 88 opens, 88 *distinct* names, each exactly once — a
normal one-time theme load, not a livelock.

So the real shape is: widget-factory sends a Wayland request and waits for a reply that never
comes, while Hyprland sits idle with `flipQ == flipRd` (nothing pending). **Two processes each
waiting on the other** — a lost wakeup or a request never dispatched, not a CPU shortage.

**The control fails identically.** `gtk-hello` was bound to `SUPER+SHIFT+H` and launched in the
same boot: it also never maps (`windows=` stays 1 after 120 s). So it is **not** the application,
and not application weight — it is something common to GTK clients here. That also means the
roadmap's long-standing "`gtk-hello` already runs" is **not true in this configuration** and should
not be relied on as evidence the toolkit works end-to-end.

**Two further theories tested and killed, both by direct observation:**

- *"Clients are pointed at the wrong wayland socket."* An `[conn]` log of every AF_UNIX connect
  settles it: `gtk-hello` connects to `/run/user/1000/wayland-1` and **succeeds** — the very same
  socket `calamares` and `wl-layer-bar` use, both of which map fine.
- *"The compositor never accepts them."* It does. gtk-hello's main task then runs an active
  `sendmsg`/`recvmsg` conversation on that fd and **receives replies**.

**So the failure is at the protocol level, after a working connection** — a GTK client talks to
Hyprland, gets answers, and still never gets a mapped toplevel, while a Qt client (calamares) and a
layer-shell client (`wl-layer-bar`) on the identical socket both do.

**A non-GTK client launched the same way works fine.** `wl-calendar`, bound to `SUPER+C`, launched
post-boot through the identical keybinding path onto the identical socket, maps in **6 seconds**
(`windows` 1 → 2). This closes the last alternative explanation: it is not the launch path, not
post-boot spawning, not the socket, not the compositor, not load. **It is specific to GTK clients.**

**Blocked on tooling, not on ideas.** The obvious next move is `WAYLAND_DEBUG=1`, which makes
libwayland print every request and event, and there is currently **no way to set an environment
variable for a keybinding-launched app**:

- Putting it in the kernel's env block (`exports.d`) produces nothing — a keybinding launch is
  Hyprland forking a child, so the child inherits *Hyprland's* environment, not the one the kernel
  builds for programs it execs itself. (This also explains why `gtk-hello` picked up the correct
  `wayland-1` socket while the kernel block still said `wayland-0`: it was never reading it.)
- Wrapping in a shell fails because **Hyprland execs the command directly, with no shell**, and
  **there is no `/bin/sh` on this system** at all.
- `system/hypr/custom/env.lua` is an empty stub and the Lua config exposes no env API.

**The launcher was built (`hos-wl-trace`, `SUPER+SHIFT+J`) and the trace still could not be
captured.** Eight build/boot cycles, each failing for a *different* environment reason. The
failures are the useful part, because each is a real property of this system that was not written
down anywhere:

1. **Keybinding commands cannot take arguments.** Every binding that works is a single word. A
   command with arguments is routed through a shell; there is no `/bin/sh`, so it execs an empty
   program name (`[exec] not found: /bin/`). This is also why `SUPER+B` has never worked — and why
   swapping its `sh -c` for `/busybox sh -c` does **not** fix it.
2. **`busybox-dyn` is not in the ISO** despite having a `module_path` line; its staging block never
   runs. `/busybox` is the one that exists.
3. **A Hyprland-forked child inherits no console.** The launcher exec'd its target correctly
   (gtk-hello appeared as 22 tasks) while not one of its own log lines, written to fd 2 just
   before the exec, reached `serial.log`. Anything a client prints — including a protocol trace —
   is written and discarded. Fixed in the launcher by `dup2`-ing `/dev/console` onto fd 1/2.
4. **`setenv()` in the launcher does not reach the array `execv` passes.** Proven by having it
   print its own `environ` immediately after setting the variable: it listed nothing at all, not
   even what it had just set.
5. **Capability denials were silent for every task except init.** The `[fdcap] deny-cap`
   diagnostic was gated on `task == 0`. With that widened, `gtk-hello` shows denials —
   `fd=1`/`fd=2`, `want=0x10` = `CAP_RIGHT_IOCTL`, i.e. `isatty()`. Benign in itself (writes are
   not denied), but it means **a client can be refused things and nobody is told**.

**That tactic worked: instrument the kernel, not the guest.** Decoding the Wayland wire header
(`[u32 object][u16 opcode][u16 size]`) in the AF_UNIX send/recv path needs nothing from the
client's environment. The conversation did not trail off — it **ended on a `wl_display.error`**,
and decoding the payload named the fault outright:

> `wl_shm: "The size of the file is not big enough for the shm pool"`

**FIXED — first root cause.** `fstat` reported `File.fileSize`, which is *per-fd*, and `SCM_RIGHTS`
hands the receiver a **copy** of the sender's `File`. A client that passed its shm fd and then grew
the pool left the compositor stat-ing the size as of the hand-off. Hyprland saw a file smaller than
the declared pool, raised the error, and libwayland tore the connection down — so GTK apps died
mid-startup, printed nothing (no console), and never mapped. A length belongs to the *object*:
`MemFdRec.exactLen` is now set on every `ftruncate` path and reported by `fstat` for `FD_MEMFD`.

That also explains the asymmetry that drove the whole investigation: our `wl-*` clients never
resize a pool after passing its fd, so they were untouched while both GTK apps failed identically.

**Still not mapping — a second blocker behind the first.** Measured after the fix:

| | before | after |
|---|---|---|
| `wl_display.error` | 1 (shm) | **0** |
| wire messages | 125 | 256 |
| gtk-hello tasks | 22 | 158 |
| widget-factory tasks | 20 | 231 |
| windows mapped | 1 | 1 |

The clients now get much further and stop cleanly, waiting on the compositor rather than being
killed by it. The trace ends on inbound events around objects 19 and 25 with the client sending
nothing more.

**The decoder now names objects and interfaces** (from `wl_registry.bind`) and lists what the
compositor advertises (from `wl_registry.global`). With `hos-wl-trace` giving the client a console,
its own messages are readable for the first time. What that shows:

- **The compositor is fine.** It advertises 70 globals including `xdg_wm_base`, `wl_compositor`,
  `wl_shm`, `zwlr_layer_shell_v1` and `zwp_linux_dmabuf_v1`. Nothing is missing.
- **The client reaches its own "create window" marker** and then sends **zero** further Wayland
  messages. It binds `wl_compositor`, `wl_shm`, `wl_seat`, `wl_output`, `wl_data_device_manager`,
  `zwp_primary_selection`, `org_kde_kwin_server_dec` — never `xdg_wm_base`, which GDK binds lazily
  when the first toplevel is created, i.e. it never gets that far.
- **It hangs rather than dying** — no exit, no crash. Final syscalls are repeated
  `ioctl(fd=2, 0x5413)` = `TIOCGWINSZ` from two tasks, which is the ioctl the capability layer
  denies (`want=0x10` = `CAP_RIGHT_IOCTL`). It stops after icon-theme loading.

**Second bug, found here, not yet fixed: a missing file under a synthetic-directory prefix is
reported as a DIRECTORY instead of ENOENT.** `isVirtualDirectoryPath()` matches on *prefixes*
(`/etc/gtk-3.0/`, `/usr/share/themes/`, …), so every path beneath one — including leaf files — is
fabricated as a directory. GTK sees:

```
Theme parsing error: Failed to import: Error opening file
  /usr/share/themes/Epin/gtk-3.24/gtk.css: Is a directory
Failed to parse .../settings.ini: Not a regular file
Error reading file "/etc/gtk-3.0/Compose": Is a directory
```

Note the theme genuinely does not exist (the Epin asset ships only `settings.ini` and
`index.theme`; there is no `gtk.css` anywhere in the tree, and GTK 3.24 looks in `gtk-3.24/` while
the asset provides `gtk-3.0/`). The correct answer is ENOENT, which GTK handles by falling back to
its built-in theme. "Is a directory" is a different thing and it does not.

**FIXED — second bug.** A non-`O_DIRECTORY` open of a path that only matched a prefix rule now
returns ENOENT. Scoped narrowly: `O_DIRECTORY` opens still get their directory (so `opendir` on an
empty `/etc/dbus-1` is unaffected) and the exact base directories come from the non-prefix rules.
`boot-test: PASS` afterwards, so nothing that relies on synthetic directories regressed.

The messages are now the right ones — GTK's ordinary fallback path:

```
Theme parsing error: ... Error opening file .../gtk-3.24/gtk.css: No such file or directory
Failed to open file "/etc/gtk-3.0/Compose": No such file or directory
```

**Still hangs — third blocker, now located: fontconfig.** After its own "create window" marker the
client's last activity is font setup, and then it stops:

```
[open] /etc/fonts/fonts.conf
[open] /usr/share/fonts
[open] /var/cache/fontconfig//3830…cache-9
[open] /var/cache/fontconfig//3830…cache-9.TMP-lPEcK      <- writing a cache
```

then nothing but repeated `ioctl(fd=2, TIOCGWINSZ)`, which the capability layer denies. It never
sends another Wayland message and never binds `xdg_wm_base`. The process stays alive — this is a
hang, not a crash.

**FIXED — third bug (a regression in the second).** The ENOENT check sat ~200 lines above the rtfs
`O_CREAT` path, so `open(path, O_CREAT|O_WRONLY)` under one of these prefixes returned ENOENT
instead of *creating* the file — swapping one failure for another. `O_CREAT` is now exempt.
Fontconfig visibly got further: it writes several cache files (`3830…TMP-KIEMph`, `TMP-mknHBC`,
`4c599…TMP-KMFJBi`) where before it managed one.

**Where it hangs, precisely.** `gtk_hello.c` prints two markers:

```c
g_print("G11GTK: create window -- G11 GTK\n");   // seen
...   gtk_window_new, gtk_image_new_from_icon_name, labels+markup, entry, button
gtk_widget_show_all(window);
g_print("G11GTK: window shown -- G11 COMMIT\n"); // NEVER seen
```

So it stops inside widget construction or `gtk_widget_show_all`, before GDK ever creates a
surface — which is consistent with no `wl_compositor.create_surface` on the wire and
`xdg_wm_base` never being bound (GDK binds it lazily at first toplevel).

**It is a hang, not slowness.** Waited a full **6 minutes** after launch: still `windows=1`. The
process stays alive.

**Last activity is fontconfig**, reached via Pango during label/markup setup. That is the strongest
remaining lead.

**Next, in order:** (1) check whether the fontconfig cache write actually completes — does the
`.TMP-` file get created, written and renamed, or does one of those return an error the library
retries forever? (2) if it is the cache, the cheap workaround is to ship a prebuilt fontconfig
cache in the assets so no write is needed at startup; (3) confirm by watching for the
`G11 COMMIT` marker, which is the exact success signal.

**Real bugs found while building the harness** (all fixed, none related to 2.3):

- **`SUPER+B` (top-bar toggle) has never worked.** It uses `sh -c`, and there is no `/bin/sh` —
  it fails silently as `[exec] not found: /usr/bin/sh`, because nothing surfaces an exec failure.
- **`busybox-dyn` is not in the ISO.** The Makefile has a `module_path` line for it, but its
  staging block does not run: the image has 0 occurrences against 5 for `busybox`.

**Found on the way (real, unrelated to 2.3):** `maybeSpawnWaylandClient()` gated the kernel's GUI
autostart on a listener at `wayland-0`. Hyprland probes `wayland-0`, gets ECONNREFUSED, and binds
`wayland-1` — so that listener never appears and the gate could never open. Both that gate and the
hardcoded `WAYLAND_DISPLAY=wayland-0` now probe for the socket that actually exists.

### 2.6 status — the data is real, the apps are gated on 2.3 — 2026-09-05

Worth stating plainly: **C1 as written cannot be finished before 2.3.**
`GRAPHICAL_APPLICATIONS_ROADMAP` defines it as *"cross-build an existing GTK app, not write an
app"* and gates it on A4. GTK apps do not map windows here, so the app half is blocked.

What *is* done is everything those apps would read. Verified on a real boot through the
`open`/`read` path (`[proc]` proof lines):

| file | before | now |
|---|---|---|
| `/proc/cpuinfo` | hardcoded `GenuineIntel`, `cpu MHz: 2000.000`, 1 CPU | CPUID vendor + brand, count from `g_smpCpuCount` — reports `QEMU Virtual CPU version 2.5+` |
| `/proc/bus/pci/devices` | **did not exist** (ENOENT) | walks bus 0 via `pciConfigRead32`; first entry reads `8086:1237`, the 440FX host bridge |
| `/proc/meminfo`, `stat`, `loadavg`, `uptime`, `diskstats`, `net/dev` | constants | real (2.1) |
| `/proc/net/route` | — | already dynamic |

`wl-sysmon` already reads `loadavg`, `meminfo`, `mounts`, `stat` and `uptime`, so it went from
displaying an invented 512 MB to the machine's actual memory with no change to the app.

**Deliberately still absent rather than faked:** `cpu MHz` (no core-frequency measurement exists —
the old 2000.000 was invented), PCI BAR *sizes* (probing them means writing all-ones into a live
device's BAR), and Sensors/Battery, which need ACPI the kernel does not have.

**If 2.3 stays blocked**, the useful fallback is to surface this data through the native `wl-*`
clients, which do map — that delivers C1's outcome without its method. Flagged as a deviation from
the roadmap's stated approach, not slipped in as if it were the same thing.

### 2.2 audit result — 2026-09-05

`maybeSyscallAudit()` probes each candidate **through `dispatchLinuxSyscall`** at boot and prints
`[audit]` lines. It probes rather than reads the switch table because *routed* and *implemented*
are different things: `inotify_init1` has a case arm **and** returns ENOSYS from a stub, so
grepping `case <nr>:` would have scored it present.

| syscall | nr | result |
|---|---|---|
| `inotify_init` / `_init1` / `_add_watch` / `_rm_watch` | 253, 294, 254, 255 | **MISSING (ENOSYS)** |
| `eventfd`, `eventfd2`, `timerfd_create`, `memfd_create`, `epoll_create1` | 284, 290, 283, 319, 291 | present — returned live fds |
| `ppoll` | 271 | present |
| `signalfd`, `signalfd4` | 282, 289 | present |
| `dup3`, `pipe2` | 292, 293 | present — correctly rejected bad args (EBADF, EFAULT) |

**So the only gap is inotify.** `dbus-daemon` degrades gracefully (stops watching its config);
GTK/GIO file monitoring is the caller that will care.

Two follow-ups this turned up:

- **`nr 254` routed to `inotify_init()` and `nr 253` was not routed at all.** Invisible while every
  inotify call is an ENOSYS stub, and a silently wrong call the moment one is implemented — the
  same fault `case 233` carries a "was mis-routed to `epoll_create`" note about. Each number now
  has its own handler. **Worth sweeping the rest of the table for this pattern.**
- **`signalfd` accepted `0xFFFF_FFFF` as a descriptor and echoed it back** instead of returning
  EBADF. Found by accident — the probe should have sign-extended `-1` to 64 bits. Unconfirmed as a
  defect, but it should reject a descriptor that high.

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

