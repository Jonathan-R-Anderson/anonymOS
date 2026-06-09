# Shell & System Commands Roadmap

Goal: three parallel deliverables, each independently shippable and verifiable so we
can go straight down the list.

- **Track A — Linux command set (busybox):** the full set of Linux system commands
  (`ls`, `cp`, `find`, `vi`, …) working in the busybox shell, on a real filesystem.
- **Track B — Native object shell (`-sh` / dash):** a from-scratch shell *written in D*
  for EpinAnonymOS whose "system commands for the actual OS" drive the kernel's **own**
  object/capability/namespace/identity/service primitives — the thing busybox
  fundamentally cannot do. Talks to the kernel through a **native object syscall ABI**,
  not the Linux compat layer.
- **Track C — Groundwork for the `ratty` GPU terminal emulator** (orhun/ratty): a
  Rust, GPU-rendered (wgpu + Bevy + Ratatui + Parley/Vello) terminal. Lay the
  prerequisites (solid PTY, Rust toolchain, Wayland-client path, GPU stack) so ratty
  can eventually be the desktop terminal.

Legend: **P** priority · **E** effort (1 = hrs … 5 = weeks) · **R** risk · deps.

## Current state (measured 2026-06-08)

- **busybox 1.36.1**, static/musl, built from source ([deps/busybox/](../deps/busybox/),
  `busybox.config`): **117 applets enabled** including `ls cat cp mv rm mkdir find grep
  ps kill vi less ash`. `/-sh` is just a copy of busybox (login shell), launched by
  [wl-term.c](../src/util/wl-term.c) when `EPIN_SHELL=linux`.
- **Filesystem:** the kernel has a static read-only VFS (`g_vfs` in
  [posix.d](../src/kernel/d/core/syscalls/posix.d): `/proc`, `/sys`, `/etc`) **plus a
  writable in-memory ramfs** (`g_rt`, `RT_MAX_NODES = 1024`, `RT_NAME_MAX = 96`, growable
  file data) with `rtCreate`/`rtResolve`/read/write/`getdents64`/`stat`/`unlink`/`rename`/
  `mkdir` wired and a boot-seeded skeleton (`rtInit`: `/run`, `/tmp`, …). So `ls`/`mkdir`/
  `cat`/`touch` **already work** on the ramfs — but the root tree is sparse, the ramfs
  leaks on grow (`rtEnsureCap`: "old pages leak"), has no symlinks, no real mode/owner
  persistence, and a 1024-node cap.
- **PTY:** `/dev/ptmx` + `/dev/pts/N` exist (`FD_PTY_MASTER`/`SLAVE`, `g_ptys[]` rings,
  ioctls `TIOCGPTN`/`TIOCSPTLCK`/`TCGETS`/`TCSETS`/`TIOCGWINSZ`/`TIOCSWINSZ`) — but
  `TCSETS` "stores nothing": no real canonical/raw mode switch, no echo control, no
  signal generation (`^C`/`^Z`). Interactive apps (`vi`, `top`, line editing) are
  therefore fragile.
- **Native object shell:** does not exist — `EPIN_SHELL=native` shows
  *"native object-shell is not yet available."* There is **no native syscall surface**
  for userspace; unknown syscall numbers just return `ENOSYS`.
- **Rust / GPU:** no Rust toolchain in-tree. The display stack has `vulkan.d`,
  `gpu_accel.d`, `virtio_gpu.d`, `drm.d` and freetype/harfbuzz bindings, but compositing
  is software (Pixman). ratty needs a real GPU path (see
  [[DESKTOP_RESPONSIVENESS_ROADMAP]] R8).

---

# Track A — Full Linux command set (busybox)

## A1 — Enable the full busybox applet set · P: High · E: 1 · R: low · deps: —

Go from the curated 117 applets to the full useful set (~300–400).

- Expand `deps/busybox/busybox.config`: coreutils (`ln rmdir head tail cut sort uniq wc
  tr sed awk od hexdump du df stat readlink realpath basename dirname seq yes tee sleep
  env printf test [ true false expr`), file tools (`xargs diff patch tar gzip gunzip
  bzip2 xz cpio cmp md5sum sha256sum`), proc (`top free pkill pgrep uptime nproc pidof
  watch`), term (`clear reset stty tty which whoami id date cal dmesg mount umount chmod
  chown mknod dd`), editors (`vi`, `awk`, `sed`), net (`wget nslookup ping nc telnet` —
  gate on the network stack). Keep `ash` (+ optionally `hush`) as the shell.
- Rebuild busybox; confirm `busybox --list` count and that every applet at least
  *launches* without an immediate missing-syscall abort.
- *Verify:* a smoke script in the terminal exercises one applet per category; record any
  applet that aborts with `ENOSYS <n>` → feeds A4.

## A2 — Harden the runtime ramfs into a real tmpfs · P: High · E: 2 · R: med · deps: —

`g_rt` is a "minimal tmpfs"; make it production-grade so coreutils round-trip.

- Fix the grow-leak in `rtEnsureCap` (currently leaks the old buffer) — realloc/copy+free
  or a page list; track and cap total tmpfs bytes (wire to the Domain Manager memory/disk
  control — see [[desktop-autostart-client]] / IDENTITY_DOMAIN).
- Raise/parametrise limits: node count, name length, per-file size.
- Add symlinks (`RT_LNK` kind) + `symlinkat`/`readlinkat` over `g_rt`; hardlinks optional.
- Persist real `mode`/`uid`/`gid`/`mtime` and honour `chmod`/`chown`/`utimensat` (today
  `chmod` is a no-op and `stat` synthesises owner).
- *Verify:* `cp -a` a tree, `find`, `tar -c | tar -x`, `chmod`+`stat`, symlink + `readlink`
  all round-trip; node/byte caps enforced.

## A3 — Populate a realistic root filesystem · P: High · E: 2 · R: med · deps: A2

Today `ls /` is nearly empty. Give the shell a real FHS tree.

- Seed an FHS layout (`/bin /sbin /usr/bin /etc /home/user /root /tmp /var /dev`), either
  in `rtInit` or — cleaner and scalable — by unpacking a **cpio initramfs** boot module at
  startup.
- Install busybox as `/bin/busybox` + an applet symlink per command (`/bin/ls` → busybox,
  …) so `ls /bin` shows the command set and `PATH` resolution + `which` work.
- Provide `/etc` defaults (`profile`, `passwd`, `group`, `hostname`) and a writable
  `/home/user` as the shell's cwd.
- *Verify:* `ls -la /bin`, `which ls`, `cd /home/user && pwd`, `echo $PATH`, ash
  tab-completion resolve real entries.

## A4 — Fill the termios / signal / syscall gaps · P: High · E: 3 · R: med · deps: A3

The gap between "applet launches" and "applet is usable interactively".

- **termios:** implement real canonical vs raw mode + echo (today `TCSETS` stores
  nothing) so line editing, `vi`, `less`, `top` work.
- **Signals + job control:** generate `SIGINT`/`SIGTSTP`/`SIGQUIT` from the PTY line
  discipline (`^C`/`^Z`/`^\`), `TIOCSPGRP`/`tcsetpgrp`, process groups, `SIGWINCH` on
  resize; correct `waitpid` semantics.
- **Missing fs/proc syscalls** surfaced by A1's smoke run: `utimensat fchmodat fchownat
  linkat symlinkat statvfs sync fsync sendfile copy_file_range`, real `/proc/<pid>` and
  `/proc/self` listings for `ps`/`top`.
- *Verify:* `vi` edits + saves a file, `top` refreshes and quits, `^C` interrupts a
  `sleep`, `sort < big | uniq | wc -l` pipeline completes, `dd`/`tar` finish.

## A5 — Persistent disk-backed storage (optional) · P: Med · E: 4 · R: high · deps: A2

Make files survive reboot; backs the Domain Manager "disk operations" control.

- Mount part of the tree on a real disk via the existing AHCI driver
  ([drivers/block/ahci.d](../src/kernel/d/drivers/block/ahci.d)) + a simple FS (ext2 read,
  or a small log-structured FS for read/write).
- *Verify:* write a file, reboot, read it back; `df` shows the disk.

---

# Track B — Native object-capability shell (`-sh` / dash, in D)

Decision (confirmed with user): the native shell's commands operate on the **object/
capability model**, and it is written in **D calling native object syscalls** — a truly
native binary, not the Linux compat layer.

## B0 — Native object syscall ABI · P: High · E: 3 · R: high · deps: —

The kernel manipulates objects internally but exposes nothing to userspace. Add a native,
capability-checked syscall surface.

- Define a native syscall region distinct from the Linux-compat range (e.g. numbers
  ≥ `0x4000`, or a dedicated `hoscall` entry vector) dispatched in
  [kernel_main.d](../src/kernel/d/core/kernel_main.d) before the Linux table.
- Expose the existing subsystems, each **deny-by-default + cap-gated** (reuse the
  identity-domain ceilings — IDENTITY_DOMAIN P4/P5): `objmgr` (enumerate/describe),
  `cap` (list/grant/revoke/derive/attenuate), `namespace` (create/clone/share/list),
  `identity` (list/create/freeze/ceilings/stamp), `service` (list/start/stop/status),
  `secipc` (channels/sessions), `untyped`/memory (allocations + caps).
- *Verify:* a tiny D probe enumerates the object table and prints it; a cap-less call is
  denied; matches the kernel's `objStats`/`capStats` dumps.

## B1 — D userspace runtime (freestanding -betterC) · P: High · E: 3 · R: med · deps: B0, A4

First-ever D *userspace* binary on this OS.

- Minimal D `crt0` + syscall shims for the native ABI plus a handful of Linux calls
  (`read`/`write`/`exit`/`mmap`) so it runs as a normal process; build with
  `ldc2 -betterC -O0 @nogc nothrow` like the kernel. New Makefile target + boot module.
- A no-GC line editor (history, cursor, completion) over the PTY in raw mode (needs A4).
- *Verify:* `-sh` boots, prints a prompt, echoes/edits input, exits cleanly.

## B2 — Shell core: parser + REPL · P: High · E: 3 · R: med · deps: B1

- Tokeniser + parser: builtins, args, quoting, **pipes between native commands**,
  variables, simple control flow (`if`/`for`/`while`). Grammar leans object-oriented
  (e.g. `objects | where type=Identity | freeze`) while staying scriptable.
- Job table, exit codes, environment, `source`/script execution.
- *Verify:* pipelines, conditionals, and a multi-line script run.

## B3 — Native command suite (the OS's own system commands) · P: High · E: 4 · R: med · deps: B2

Builtins (no fork) or tiny native binaries resolved from a native `/sbin`:

- `obj` — ls/inspect/create/destroy objects (type, refs, owner, caps).
- `cap` — ls/grant/revoke/derive/attenuate; print the capability graph.
- `ns` — ls/create/clone/share/enter namespaces.
- `id` — identity domains: ls/create/freeze/thaw/set-ceiling/stamp (integrates with the
  Domain Manager).
- `svc` — ls/start/stop/status services.
- `ipc` — ls channels/sessions, open/send/inspect secure IPC.
- `mem` — show untyped/memory allocations + caps; enforce per-domain caps.
- `sys` — census/audit/validator + present/sched/perf stats (reuse the kernel stat dumps).
- *Verify:* each command round-trips against the live kernel and agrees with the
  corresponding `*Stats` dump; destructive ops require confirmation.

## B4 — Wire `-sh` into the desktop · P: High · E: 2 · R: low · deps: B3

- Replace the `EPIN_SHELL=native` notice in [wl-term.c](../src/util/wl-term.c) with a real
  launch of `-sh` on a PTY. The boot module `/-sh` becomes the **native** shell; the
  busybox login shell moves to `/bin/sh` for the `linux` flavor.
- The Domain Manager "Native" option launches `-sh` **scoped to the selected identity
  domain**, so its `obj`/`cap`/`ns` view is restricted to that domain.
- *Verify:* pick *Native* in the Domain Manager → terminal drops into `-sh`; `obj ls` /
  `ns ls` reflect that domain's scope, denied outside the ceiling.

## B5 — Safety + polish · P: Med · E: 2 · R: low · deps: B4

- Confirmations + `--dry-run` for destructive ops; **audit-log every privileged action**
  (reuse `auditStats`); `help`/`man` builtins; tab-completion of object/cap/ns names.

---

# Track C — Groundwork for the `ratty` GPU terminal emulator

ratty (orhun/ratty) is Rust + GPU (wgpu/Bevy/Ratatui/Parley/Vello), requires a
Bevy/wgpu-supported GPU, Wayland, fontconfig, a Rust toolchain, and a PTY-hosted shell.
Heavy — lay groundwork in order; the GPU step is the real gate and overlaps
[[DESKTOP_RESPONSIVENESS_ROADMAP]] R8.

## C1 — Solid PTY + terminal semantics · P: High · E: 3 · R: med · deps: — (shared with A4)

Any emulator hosts a shell on a PTY; make ours robust.

- Real termios (raw mode, echo, winsize, signals, flow control) on `/dev/ptmx`+`/dev/pts`;
  ratty drives the master, the shell runs on the slave.
- *Verify:* a headless VT loop (read master / echo) hosts busybox **and** `-sh` correctly;
  `TIOCSWINSZ` propagates `SIGWINCH`.

## C2 — Rust toolchain targeting EpinAnonymOS · P: High · E: 3 · R: high · deps: A3

- Bring up `rustc` + `cargo` cross-compiling to the musl/Linux-compat target (x86_64,
  static), reusing the musl sysroot the C utils use; a `deps/rust` build mirroring
  `deps/busybox`.
- Prove it with a hello-world Rust **Wayland** client (smithay-client-toolkit, or raw
  libwayland via FFI) that paints a buffer.
- *Verify:* a Rust wl client shows a window like `wl-shm-demo`.

## C3 — winit + Wayland client path (CPU first) · P: Med · E: 4 · R: high · deps: C2

- Get **winit** (Bevy's windowing) running on our Wayland: implement/stub the protocols
  it needs beyond xdg-shell + pointer/keyboard (e.g. relative-pointer, fractional-scale,
  `wl_seat` versions).
- fontconfig + freetype sysroot for Parley shaping (freetype/harfbuzz bindings already
  exist in the display stack).
- *Verify:* a winit hello window; a **Ratatui-over-CPU** text demo renders (no GPU yet).

## C4 — GPU stack for wgpu (the hard gate) · P: Med · E: 5 · R: high · deps: C3, [[DESKTOP_RESPONSIVENESS_ROADMAP]] R8

- Provide a wgpu-supported backend: software Vulkan (lavapipe/llvmpipe-Vulkan) **or** real
  virtio-gpu (VIRGL/Vulkan) in QEMU + a guest driver. Build out the existing `vulkan.d` /
  `gpu_accel.d` / `virtio_gpu.d` stubs.
- wgpu → Vulkan → our driver; Bevy renders offscreen → present via Wayland.
- *Verify:* a wgpu triangle; then Bevy clears a frame at a stable rate.

## C5 — ratty bring-up · P: Low · E: 4 · R: high · deps: C1, C4

- `cargo build` ratty for the target; supply its font/asset deps; spawn a shell (busybox
  or `-sh`) on the PTY; map ratty's window onto the desktop; optionally make it the default
  terminal (replacing/augmenting `wl-term`) and a Domain-Manager shell host.
- 2D mode first; the Ratty Graphics Protocol (RGP) inline-3D is a stretch.
- *Verify:* ratty opens, runs `ls`, shows output; 2D mode stable; resize works.

---

## Milestones

- **M-A — Linux complete.** A1–A4: the full busybox command set on a real, hardened FHS
  filesystem; interactive apps (`vi`/`top`) and pipelines work.
- **M-B — Native shell.** B0–B4: `-sh` drives objects/caps/namespaces/identity/services,
  domain-scoped from the Domain Manager.
- **M-C1 — Terminal substrate.** C1 (+A4): a robust PTY hosts any shell or emulator.
- **M-C — Rust + GPU.** C2–C4: Rust toolchain and a wgpu/Bevy frame run on the OS.
- **M-ratty — Desktop terminal.** C5: ratty is a working terminal on EpinAnonymOS.

## Suggested order

A1 → A2 → A3 → A4/C1 (shared termios+signals) → B0 → B1 → B2 → B3 → B4 → C2 → C3 → C4 →
C5. Track A delivers the felt win fastest (real `ls` on a real tree); the shared
PTY/termios work (A4/C1) unblocks both the native shell and ratty; B is mostly
independent of C until the desktop wiring.
