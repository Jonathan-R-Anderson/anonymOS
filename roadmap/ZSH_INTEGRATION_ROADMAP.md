# Z Shell (zsh) Integration Roadmap

Goal: make the **real upstream Z Shell** the standard interactive shell across AnonymOS —
running both inside the Linux compatibility personality (the upstream `zsh` binary) and
**natively** (the same zsh source over an AnonymOS platform-abstraction layer) — while
preserving the object model, capability security, namespace isolation, identity domains,
and Linux compatibility. **Do not fork zsh.** All AnonymOS changes are isolated to a
platform layer.

> **Status & honesty.** This is a staged plan. Today the OS ships two *custom* shells:
> busybox `ash` (the Linux personality) and the native object shell `/hos-sh` (Track B,
> the AnonymOS personality, [NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md)). Both now
> carry the rich prompt (username · permissions · namespace · path) this roadmap calls for
> (Z6 milestone, already landed). The remaining work replaces them with real zsh in two
> stages: **Linux zsh first** (low risk — it's just another musl binary), **native zsh
> second** (the platform layer). zsh is large autoconf C; each phase keeps the shell
> functional.

Legend: **P** priority · **E** effort (1=hrs … 5=weeks) · status.

---

## Architecture (target)

```
/system/shell/zsh/{src,platform,modules,themes,plugins,completion,configs}
/etc/zsh/{zshenv,zprofile,zshrc,zlogin,zlogout}
/system/config/shell.json          # declarative config (a /config object-FS view)
/users/<user>/{.zshrc,.zprofile,.zlogin}
```

zsh compiled as shared libraries — `libzsh.so`, `libzshmodules.so`, `libzshcompletion.so` —
loaded by the existing dynamic linker. The **parser/expander/job-control core is upstream
and unchanged**; only the platform `#ifdef` surface is AnonymOS-specific.

### The platform abstraction layer (the only AnonymOS code in the zsh tree)

A single `platform/anonymos/` shim that zsh's configure selects, implementing the host
hooks zsh needs against AnonymOS primitives:

| zsh needs | Linux personality | Native personality |
|---|---|---|
| filesystem (`open/read/stat/readdir`) | Linux ABI ([SYSCALL_ABI.md](../docs/SYSCALL_ABI.md)) | `object_open/Stream/Container` ([NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md) §10) |
| terminal I/O + PTY | `/dev/ptmx`, termios ioctls (live) | `Device`/`Channel` PTY object (§12) |
| signals | `rt_sigaction`/`tgkill` (live, SIGINT/SIGQUIT) | `object_subscribe` to a signal channel (§13) |
| processes (`fork/exec/wait`) | clone/execve/wait4 (live) | `spawn_process`/`process_wait` (§4) |
| environment | the Linux env block | identity/namespace-bound env object |
| **capabilities** | read-only (Linux can't reach the native ABI) | `cap_*` (§7) — the prompt's permission flags |
| **namespaces** | read EPIN_DOMAIN env | `namespace_lookup` (§11) — the prompt's namespace |
| **object manager** | n/a | `object_*` (§6) — `objctl`, object-path completion |
| **IPC** | AF_UNIX sockets (live) | `channel_*` (§8) |
| dynamic loader / threads / malloc | musl + the kernel dynamic linker (live) | same (native userspace uses musl too) |

The two personalities share **one** zsh source; they differ only in which platform backend
the shim dispatches to (chosen at process start from the task personality, the same flag
that gates the native ABI).

---

## Z0 — Toolchain + upstream fetch · ✅ DONE · P: High · E: 2

- **Vendored** the upstream `zsh-5.9.tar.xz` under `deps/zsh/`, pinned + SHA256-verified
  (`9b8d1ec…`), mirroring how `deps/busybox` vendors its tarball (offline-cached; the
  build never fetches if the tarball is present).
- **Term-lib prerequisite:** zsh needs a curses/termcap library, which the musl sysroot
  lacks, so the build also vendors + builds **ncurses-6.4** (`6931283…`) against musl —
  `libncursesw.a`/`libtinfow.a`, widechar, **with the terminal entries compiled in**
  (`--with-fallbacks=linux,xterm,xterm-256color,vt100,…`) so **no terminfo DB is needed**
  on the OS (TERM=linux, which wl-term sets, is built in).
- **Wired into the Makefile** (`deps/zsh/Makefile` + top-level `make zsh`): configures with
  the existing `musl-clang` toolchain (x86-64 musl runs on the x86-64 build host, so
  configure's test programs run natively — no cross-compile cache) and builds a **static**
  zsh with `--disable-dynamic` (modules linked in) + `--disable-dynamic-nss`. (The
  `--enable-shared`/dynamically-loaded-module split is Z2; static is the correct first
  build for musl and for Z1.)
- *Deliverable 5 (build), 1 (source tree).* **No OS behaviour change** — zsh is built but
  **not** staged into `hos.iso` yet (that's Z1).
- *Verified:* a clean `make zsh` produces a 1.8 MB static x86-64 musl ELF that runs —
  `zsh --version` = 5.9; arrays, associative arrays, and globbing/modifiers all work.

## Z1 — Linux-personality zsh · ✅ DONE · P: High · E: 3 · deps: Z0

- **Staged** the static-musl zsh (Z0) as a limine **boot module `/zsh`** + rtfs symlinks
  `/bin/zsh` and `/system/shell/zsh/zsh` → it (`rtInit`); the iso build copies it (`make`
  wired `$(ZSH_BIN)` into the `hos.iso` prereqs + `cd/zsh`).
- `exec("/bin/zsh")` runs upstream **zsh 5.9** as the default Linux shell — wl-term's
  `linux` flavour launches `/zsh` (argv0 `-zsh`, a login shell); busybox stays as `/bin/sh`
  and as the coreutils zsh execs. `/etc/passwd` shell for `user`/`root` is now `/bin/zsh`.
- *Verified live in the GUI:* prompt with all four fields (`[domain] user [perms]:cwd%`),
  builtins (`echo`, `for` loops, arrays), **external commands** (`whoami`, `uname`, `ls`,
  `id`, `tr`), **pipes** (`echo … | cat`), command sequences (`;`), `$var` expansion —
  all run, each returning cleanly to the prompt.
- **Three kernel fixes were required** (the syscall gaps the risk note predicted, plus two
  deeper ones), all in `posix.d`/`kernel_main.d`/`task.d`:
  1. **Blocking pipe reads** — zsh's `execcmd_fork` does a blocking `read_loop` on a
     `pipe()` to sync with the forked child; the kernel returned EAGAIN. Added
     `pipeBlockingReadFd` so the dispatcher rewinds+yields (like a PTY) until the child
     writes — the cooperative-scheduler blocking-read path now covers pipes.
  2. **Userspace SIGCHLD handler delivery** — zsh waits for jobs via SIGCHLD (it picked
     `BROKEN_POSIX_SIGSUSPEND`, so really `sigprocmask`+`pause`), but the kernel had no
     handler invocation at all (only default-terminate). Built x86-64 rt_sigframe delivery
     (`deliverUserSignal` + `rt_sigreturn`/`case 15`, handler/restorer stored by
     `rt_sigaction`), delivered from the `pause`/`sigsuspend` wait point (`case 34/130`)
     where SIGCHLD is unblocked. **General signal-handler delivery — benefits the whole OS.**
  3. **pid stability across exit** — `linuxPidForTask = processLeaderTid+1`, and exit
     cleanup zeroes `processLeaderTid`, so `wait4` returned pid 1 instead of the pid `fork`
     gave the parent; zsh matches reaped pids to its job table, so the job never went DONE.
     Snapshot the pid at `exitTask` entry (`g_childExitLinuxPid`) and return it from wait4.
  - Plus 3 already-implemented handlers wired into dispatch (98 `getrusage`, 138 `fstatfs`,
    439 `faccessat2`), and `unsetopt MONITOR` in `/etc/zshrc` (job control needs process
    groups the cooperative kernel doesn't fully model; `^Z`/`bg`/`fg` are a later item).
- *Deliverable 4 (Linux integration), 18 (regression vs upstream).* Remaining nuance:
  full job control (process groups + `tcsetpgrp`) and the upstream test-suite run are
  follow-ups; the interactive shell is fully usable.

## Z2 — Dynamic linking · ✅ DONE · P: Med · E: 3 · deps: Z1

- zsh is now built **dynamically** (`deps/zsh/Makefile`: `--enable-dynamic`, replacing Z1's
  static `--disable-dynamic`): a PIE `zsh` with `PT_INTERP=ld-musl` + `NEEDED libc.so`, plus
  **36 dlopen-able zmodule `.so`** (`zle`, `complete`, `compctl`, `computil`, `zutil`,
  `parameter`, `terminfo`, …).  (zsh keeps its core in the exe rather than a separate
  `libzsh.so`; the modules resolve the core symbols from the exe — see the export-dynamic
  note below.)
- **Loaded over the existing kernel dynamic linker:** the OS execs `/zsh` → ld-musl
  (PT_INTERP) loads `libc.so`; zsh then dlopens `/system/shell/zsh/lib/zsh/5.9/zsh/<m>.so`,
  which the kernel resolves by **basename → boot module** (the same `.so` path the GUI stack
  uses; [posix.d](../src/kernel/d/core/syscalls/posix.d) `isSharedObject`/basename resolve).
  The 36 modules + ld-musl are staged as boot modules by the iso build.
- *Verified live in the OS:* the serial shows zsh dlopening `zle.so`/`complete.so`/`compctl.so`
  from the module path; `zmodload` lists `zsh/zle zsh/complete zsh/compctl zsh/main` loaded;
  the shell is fully functional (prompt rendered by the dlopen'd zle, builtins, external
  commands, pipes) — no relocation failures.
- **Two cross-build gotchas** (recorded for Z4+ and any future dynamic dep):
  1. configure can't *run* its musl-dynamic probe programs on the glibc build host, so the
     dynamic-loading capabilities are passed as `zsh_cv_*` cache vars (true for ELF/musl);
     Z1's static build sidestepped this because static binaries run anywhere.
  2. the rdynamic flag that exports the exe's symbols to its modules is set only inside
     configure's (cache-skipped) rdynamic test, so it must be forced via
     `EXTRA_LDFLAGS=-Wl,--export-dynamic` — without it modules fail `hashgetfn: not found`.
- *Deliverable 6 (dynamic linking).* **Validates the kernel loader against a second large
  dynamic program besides the GUI stack** (zsh + 36 dlopen'd modules), as intended.

## Z3 — PTY / terminal split · ✅ DONE · P: High · E: 2 · deps: Z1

- **wl-term is a pure terminal** — `spawn_shell` only opens `/dev/ptmx`, forks, and
  `execve`s the shell on the slave (no parsing/builtins/command logic).  Its default
  Linux shell is now the canonical **`/bin/zsh`** (the rtfs symlink → the `/zsh` boot
  module).  It keeps keyboard/pointer/PTY/Unicode/rendering/window-decoration duties;
  everything line-editing is zsh.
- **termios line discipline** (kernel PTY, `posix.d` `ptyIoctl`/`ptyInputByte`) is complete
  for ZLE: `TCSETS` *applies* the termios so zsh's raw mode (ICANON/ECHO off) takes effect;
  raw passthrough, canonical VERASE/VKILL editing, ISIG (^C/^\), `TIOCGWINSZ/SWINSZ`, and
  `TIOC[GS]PGRP` all work.
- **The coverage check found + fixed two real gaps** (wl-term, both verified live):
  1. *Input:* `key_to_pty` didn't emit escape sequences for navigation keys — so Up/Down
     (history), Left/Right (cursor), Home/End/Del/PgUp/PgDn did nothing.  Added the
     linux-console sequences (`\E[A..D`, `\E[N~`).
  2. *Output:* the VT interpreter merely **swallowed** CSI sequences, so ZLE's line-redraw
     (cursor addressing + erase) was lost — recalling history over an existing line printed
     `second-cmdfirst-cmd`.  Added a real CSI interpreter (`vt_exec_csi`): cursor move
     (`A/B/C/D/G/H`), erase line/display (`K/J`), insert/delete chars (`@/P`).
- **^C** now aborts the line and interrupts a running foreground command.  This needed
  extending Z1's signal delivery to **SIGINT**: `deliverSignalToGroup` no longer skips a
  handler-bearing task (zsh), the run loop leaves a handler-signal pending so it is
  delivered at the next blocking read as an **EINTR** (POSIX), and zsh's own SIGINT handler
  then aborts ZLE.  A foreground command (default disposition) is still terminated.  (The
  fg-group is `lastReader`-scoped, so ^C hits the running command, not the shell behind it.)
- *Verified live:* history (Up/Down) with clean redraw, in-line cursor editing
  (`echo abcde` → Left×2 → insert → `echo abcXde`), **tab completion** (`ls /et`<Tab> →
  `/etc`), and ^C (aborts the line; interrupts `sleep 9` instantly) — external commands /
  pipes unregressed.
- *Deliverable 7 (PTY/terminal).*  Remaining job-control items (`^Z`/`bg`/`fg`, process
  groups + `tcsetpgrp`) stay deferred per Z1.

## Z4 — Native platform layer · ✅ DONE · P: High · E: 5 · deps: Z1, Z2

**Complete.** Z4a (FS+TTY+process → interactive native prompt), Z4b (signals + IPC: object_wait
/ object_subscribe / object_send/recv), and Z4c (env + the cap_grant/namespace_clone/enter
mutation verbs + the in-process `zsh/anonymos` builtin module) all DONE and verified live.  Native
zsh's filesystem, terminal, process spawn, child-wait, event subscription, channel IPC, and the
object-model commands all flow through the native object ABI — and the new cap/namespace mutations
are non-escalating by construction (attenuation-only grants; owned-only namespace entry).

The big one: port zsh to native userspace via `platform/anonymos/`.

- Implement the host hooks (table above) dispatching to native ABI verbs when the process
  is native personality, Linux syscalls otherwise. **No change to zsh's parser/expander.**
- Native zsh gets its filesystem through `object_open` over namespaces (§10/§11), its PTY
  through a `Device` object (§12), processes through `spawn_process` (§4).
- *Deliverable 2 (platform design), 3 (native port).* Staged: (Z4a) FS+TTY+process hooks to
  reach an interactive prompt; (Z4b) signals/IPC; (Z4c) env/cap/namespace/object hooks.
- **Honest constraint:** this is multi-week C porting; until Z4 completes, the native
  personality keeps using `/hos-sh` (which already drives the object model and carries the
  rich prompt). zsh becomes the native shell when Z4a lands; `/hos-sh`'s object commands
  (`obj/id/ns/svc/sys`) survive as zsh builtins/plugins (Z9).

**Decision (this pass): begin the true native-ABI port — start with the FS path.** Not the
pragmatic "zsh-in-native-personality-over-the-Linux-ABI" shortcut; the real platform layer.
The native ABI today is read-only `HOSQ_*` queries, so each phase below first adds the
needed kernel verbs, then the zsh host-hook that uses them. Tracked sub-steps:

### Z4a — FS + TTY + process hooks → interactive native prompt · ✅ DONE

- **Z4a.1 — Kernel native FS verbs** · ✅ DONE · `object_open`/`read`/`write`/`close`/`lseek`
  as `HOS_SYS_QUERY` ops (`HOSQ_OPEN`=7…`FSTAT`=12) in `hoscall.d`; the path resolves through
  the object FS (namespace-gated) and the returned handle **is the real backing VFS fd** (see
  Z4a.5 — a separate handle space broke the shell). The *surface* is still pure native ABI: a
  native task opens via `object_open`, never Linux `open`.
- **Z4a.2 — Native FS test** · ✅ DONE · added a native `cat <path>` to `hos-sh` (already a
  native-personality task) that drives `object_open`+`object_read`+`object_close`. Verified
  live: `cat /etc/passwd` printed the file through the native ABI — proves the verbs +
  handle lifecycle end-to-end.
- **Z4a.3 — zsh `platform/anonymos/` host-hooks layer** · ✅ DONE · `deps/zsh/anon.c` provides
  `__wrap_open`, linked into zsh via `-Wl,--wrap=open` (no call-site patching). When native
  (one-time `HOSQ_SYS` probe) a read-only `open` goes through `object_open` (which returns a
  real fd, so read/write/close/… need no wrapping); otherwise it falls straight through to
  `__real_open`. Verified: the **Linux** zsh (default shell) is fully unregressed with the
  layer linked in (`is_native()=0` ⇒ transparent) — builtins, external commands, pipes work.
- **Z4a.4 — Wire zsh FS ops through the hooks** · ✅ DONE · the `--wrap` interposition (Z4a.3)
  *is* the wiring — no parser/expander change, only the host I/O calls. **Verified live:** a
  native zsh reads its startup files (`/etc/zshenv`, `/etc/zshrc`, `/root/.zshenv`) through
  `object_open`/`object_read` (the kernel logged each native open) — zsh's filesystem flows
  through the native object ABI. Added `object_fstat` (`HOSQ_FSTAT`=12) too.
- **Z4a.5 — Native zsh launch** · ✅ DONE · **the Domain Manager's "Native OS" shell flavor now
  launches a fully interactive native zsh.** `EPIN_SHELL=native` → wl-term execs `/hos-zsh`
  (an rtfs symlink to the *shared* zsh boot module); `execveTask` marks the task native by the
  request-path basename `hos-zsh` (same activation model as `/hos-sh`, no binary duplication).
  zsh reaches the filesystem through `object_open` and runs with the rich 4-field prompt.
  **The OOM was the handle design:** a separate high handle space (fd ≥ `0x40000000`) made zsh
  grow its fd-indexed tables to ~1e9 entries → `alloc_phys_page` OOM. Fixed by having
  `object_open` return the **real backing fd as the handle** — so every other fd op
  (dup/fcntl/fstat/mmap) keeps working and there's no blowup; the handle table + the
  read/write/close/lseek/fstat wrappers are gone (only `--wrap=open` remains). Verified live:
  `echo`, `print -l`, and `whoami` (external fork/exec) all work; no OOM, no faults. `/hos-sh`
  stays a boot module — its object commands (`obj/id/ns/svc/sys`) move into native zsh in Z9.
- **Z4a.6 — Native TTY (Device-object PTY)** · ✅ DONE · `device_read`/`device_write` verbs
  (`HOSQ_DEV_READ`=13/`WRITE`=14) over the PTY, and native zsh's terminal I/O routed through
  them via `__wrap_read`/`__wrap_write` (`-Wl,--wrap=read,write`).  The kernel gives
  `device_read` the **same cooperative blocking + ^C→EINTR** a Linux terminal read gets
  (`ptyBlockingReadFd`/`pipeBlockingReadFd`/`isConsoleFd` on `rsi`).  Verified live: native
  zsh's prompt/output/input flow through the Device verbs (`[dev-io]` fired), commands and
  **^C** (aborts the line) work; the Linux zsh is unregressed (`is_native()=0` ⇒ transparent).
  *Note:* the routing currently covers **all** of native zsh's wrapped read/write, not just the
  tty — `isatty` can't single out the terminal because the kernel mishandles `ioctl(TCGETS)`
  on a **dup'd** PTY fd (zsh moves its terminal to a high fd via `movefd`), and zsh's stdio
  output bypasses the wrapper anyway.  A finer file/device split + that dup-PTY `ioctl` fix
  are refinements.
- **Z4a.7 — Native process spawn** · ✅ DONE · `spawn_process` verb (`HOSQ_SPAWN`=15) — native
  zsh's external-command exec routes through it via `__wrap_execve` (`-Wl,--wrap=execve`).  zsh
  forks, the child sets up its fds, then `execve`s the command; when native that becomes
  `spawn_process(path, argv, envp)`, which the kernel turns into `execveTask` — loading the
  image into the forked caller through its process-creation machinery (Process object,
  F4.2 cap-gate, identity binding, personality reset).  Handled in the **outer** dispatcher so
  it re-enters userspace like `execve` (regs reset, no RAX write).  Verified live: native zsh's
  `whoami`, `uname -a`, `echo … | tr` (pipes too) all run through `spawn_process` (`[spawn]`
  logged `/bin/whoami` etc.), no faults; Linux zsh unregressed (`is_native()=0` ⇒ `__real_execve`).
  *Note:* this is the fork+exec idiom's exec leg routed native (the child becomes the image);
  the §4 parent-driven *create-a-child-and-return-a-handle* form, plus explicit ns/identity
  args on the manifest, are a later refinement (zsh inherits both via fork today).
- **Z4a.8 — Interactive native-ABI prompt** · ✅ DONE · **FS + TTY + process spawn all native.**
  An interactive native zsh whose *filesystem* (`object_open`), *terminal I/O*
  (`device_read`/`device_write`), and *external-command spawn* (`spawn_process`) all flow
  through the native object ABI, at a working prompt with ^C, pipes, and external commands.
  The "all core I/O native" milestone — **Z4a complete.** (Refinements remain: Z4b signals/IPC,
  Z4c env/cap/ns, and the noted dup-PTY `ioctl` + §4 spawn-handle items.)

### Z4b — signals + IPC · ✅ DONE · deps: Z4a

Route native zsh's job-wait / signal / IPC surfaces onto the native object ABI (§6 event
subscription + §8 message-passing), reusing the kernel's existing signal + child-exit
machinery — the same "re-surface, don't rewrite" pattern as Z4a.  Tracked sub-steps:

- **Z4b.1 — Kernel native wait verb (`object_wait`, §6)** · ✅ DONE · `object_wait(pid,
  statusbuf, options)` (`HOSQ_WAIT`=16) over the existing `wait4Task`, with the **same**
  rewind-RIP + `scheduleNext` cooperative blocking the Linux `wait4` (case 61) uses; handled in
  the **outer** dispatcher (like `spawn_process`) so it can yield-and-re-run — its block path is
  byte-for-byte the Linux wait path's.
- **Z4b.2 — Route zsh's child-reaping through `object_wait`** · ✅ DONE · `__wrap_wait3` /
  `__wrap_waitpid` (`-Wl,--wrap=wait3,waitpid`) send zsh's reaps (`wait3` ×3, `waitpid` ×1) to
  `object_wait` when native; `WNOHANG` reaps return immediately, foreground waits yield (same
  `wait4Task` semantics).  Verified live: native `whoami`/`uname`/`cat /dev/null` and pipes all
  reap their children through `object_wait` (one-shot `[obj-wait]` confirmed), shell fully
  functional; Linux zsh unregressed (`is_native()=0` ⇒ `__real_wait3`/`__real_waitpid`).  (Can't
  demo a *multi-second* block because `nanosleep` is a kernel no-op OS-wide — `sleep N` exits
  instantly for both flavors, so no child ever takes wall-clock time; the block *logic* is
  identical to the working Linux `wait4`.)
- **Z4b.3 — Native async-event surface (`object_subscribe`, §6) for SIGCHLD + SIGINT** · ✅ DONE ·
  the kernel already delivers these to native zsh — SIGCHLD as an rt_sigframe (Z1) and ^C as
  an EINTR at a blocking `device_read` (Z3/Z4a.6) — so native job-notify + interrupt already
  *work*; this step adds the explicit native subscription registration, a formalization of the
  already-functional delivery.  **`object_subscribe(events)` = `HOSQ_SUBSCRIBE`=17**, recording a
  per-task event bitmask (`g_taskSubscriptions[]`, hoscall.d).  Verified live: a native task ran
  `object_subscribe(SIGCHLD|SIGINT)` → `0` and the kernel logged `[obj-subscribe events=0x20004]`.
- **Z4b.4 — Native IPC message-passing (§8) behind coproc / `zsh/zselect`** · ✅ DONE · zsh's coproc
  and `zsh/zselect` already move their bytes through `device_read`/`device_write` (Z4a.6 routes
  all native read/write), so the *data* path is native today; this adds the explicit native
  endpoint.  **`object_send`/`object_recv` = `HOSQ_SEND`=18 / `HOSQ_RECV`=19** over a channel fd
  (the same verified VFS path as the device verbs).  Verified live: a native task created a pipe
  and round-tripped 7 bytes — `object_send/recv over a channel -> sent 7, recv 7: "hos-ipc"`.
- **Z4b.5 — Verify** · ✅ DONE · foreground *and* **background** job-wait work native (reap via
  `object_wait`, `[obj-wait]` confirmed, shell functional, Linux unregressed).  Closing the bg
  path took three fixes, all landed: (1) **`FD_NULL`** — `/dev/null` is now a real device (opens,
  reads EOF, discards writes); (2) **`open` POSIX lowest-free-fd** — the scan starts at 0 (not 3),
  so zsh's `zclose(0); open("/dev/null", O_RDWR)` bg-stdin idiom lands on fd 0 as it expects
  (only reuses 0/1/2 when explicitly closed; normal tasks still get ≥3 — desktop + Linux shell
  verified unregressed); (3) **`setpriority`/`getpriority` (140/141) wired** — were defined but
  not dispatched, so zsh's `nice()` of a bg job warned `function not implemented`.  Verified:
  `echo X &` prints `X` cleanly (no `/dev/null` error, no nice warning), `wait` returns, both
  flavors; full Weston desktop renders and runs.

### Z4c — env + cap + namespace + object hooks · ✅ DONE · deps: Z4a

Give the native zsh prompt the distinctly-native surface — the kernel object model as
commands, plus env/cap/namespace passing on spawn.  Tracked sub-steps:

- **Z4c.1 — Object commands at the zsh prompt (`obj/id/ns/svc/sys`)** · ✅ DONE · the HOSQ
  enumeration verbs surfaced as native-shell commands.  Added a **non-interactive mode** to the
  native object shell — `/hos-sh <verb> [args]` runs one command and exits (refactored its
  dispatch into `runCommand`, reused by both the interactive loop and `main(argc, argv)`) — and
  seeded **native-flavor** zsh functions (`obj`/`id`/`ns`/`svc`/`sys` + an `hos` dispatcher) that
  spawn it.  `/hos-sh` self-gates to the native ABI **by name** (`execName=="hos-sh"`), so the N0
  gate holds — zsh never calls HOSQ itself; the gated helper does.  Gated on `EPIN_SHELL==native`
  (and wl-term now sets `EPIN_SHELL` to match the shell it actually launches), so the Linux shell
  stays clean.  Verified live: native `sys`/`obj`/`id`/`ns`/`hos sys` print the live object model
  (1128 objects, 7 identities, 17 namespaces, …); Linux flavor → `command not found: obj`.
  (`id` shadows coreutils `id` in the native shell on purpose; `command id` / `/bin/id` still reach it.)
- **Z4c.2 — Environment passing on spawn** · ✅ DONE · native zsh's `spawn_process` forwards
  `envp` to `execveTask` (Z4a.7), so exported vars reach spawned children — verified
  `export FOO=z4cbar; printenv FOO` → `z4cbar`.
- **Z4c.3 — Capability + namespace inheritance / hooks** · ✅ DONE · a spawned child inherits its
  caps and namespace via fork/exec today, and `id`/`ns` (Z4c.1) read them back; this adds the
  explicit native **mutation** verbs, deny-by-default and **non-escalating by construction**:
  - **`cap_grant(srcHandle, wantRights)` = `HOSQ_CAP_GRANT`=20** — derives a NEW handle in the
    caller's cap table from one it already holds, attenuation-only: `newRights = want ∩
    source.rights ∩ identity-ceiling`.  Cannot grant more than held; nothing left ⇒ EPERM.
  - **`namespace_clone()` = `HOSQ_NS_CLONE`=21** — a private copy of the caller's namespace
    (`nsClone`, fork semantics), recorded per-task (`g_taskOwnedNs[]`).
  - **`namespace_enter(nsObjId)` = `HOSQ_NS_ENTER`=22** — switch to a namespace the caller OWNS
    (created via clone); entering anything else is denied (would breach isolation).

  Verified live (native `/hos-sh z4`): `cap_grant(h1, READ) -> new handle 35 (attenuated)`,
  `namespace_clone() -> 1578`, `namespace_enter(1578) -> 0` (own clone), `namespace_enter(5820)
  -> -1 EPERM` (not mine — gate holds); kernel logged `[cap-grant … rights=0x1]`, `[ns-clone]`,
  `[ns-enter]` (and **no** `[ns-enter]` for the denied id).
- **Z4c.4 — Real in-process zsh-module builtins** (overlaps Z9) · ✅ DONE · the object commands as
  a zsh C module (builtin table calling HOSQ in-process) rather than the helper+functions of
  Z4c.1.  **`zsh/anonymos`** (`deps/zsh/anonymos.c` + `.mdd`, a standard dynamic zmodule modelled
  on `example`) defines **obj/id/ns/svc/sys as native-ABI builtins** that issue `HOS_SYS_QUERY`
  directly from the zsh process — no `/hos-sh` subprocess per command.  The Makefile drops the
  module into `Src/Modules/` before `configure` (auto-detected → `anonymos.so`), it is staged as
  a boot module by basename like every other zmodule, and the native zshrc `zmodload zsh/anonymos`
  (falling back to the Z4c.1 helper functions if absent).  Safe by personality: the builtins call
  the gated native ABI, so they only function inside native zsh (the N0 grant); a Linux-personality
  zsh would get `-ENOSYS` and the builtin reports the ABI unavailable.  Verified live in a native
  terminal: `whence -w obj id ns svc sys` → **all `builtin`** (not the fallback functions), and
  `obj | head -4` prints the live object table in-process through a real builtin pipeline.

## Z5 — Configuration system · ✅ DONE · P: Med · E: 3 · deps: Z1

Make the declarative `shell.json` the **source of truth** for the user-facing shell config —
today it is seeded at `/etc/shell.json` but nothing reads it (the zshrc settings are
hardcoded).  A translator reads it at shell startup and applies the settings, layered system
→ user.  Tracked sub-steps:

- **Z5.1 — `shell.json` schema** · ✅ DONE · the declarative config (theme/prompt/history/
  completion/autosuggestions/highlighting/plugins/aliases) seeded at `/etc/shell.json`; aliases
  tidied to real commands + a `z5demo` marker.  (Surfacing it as a `/config` object-FS view +
  `/system/config/shell.json` path is a later cross-link — refinement.)
- **Z5.2 — JSON→zsh translator (Deliverable 9)** · ✅ DONE · `__hos_apply_shell_json <file>` in
  `/etc/zshrc` maps `shell.json` keys to zsh: `history.size`→`HISTSIZE`/`SAVEHIST`,
  `history.shared`→`SHARE_HISTORY`, `history.saveDuplicates:false`→`HIST_IGNORE_DUPS`,
  `completion.menu`→`zstyle … menu select`, `completion.caseInsensitive`→`matcher-list`, and the
  `aliases` block→`alias`.  **Pure zsh** (reads with `read`, matches with `[[ … =~ … ]]`/`$match`/
  glob), so no external tool — runs in both flavors (native reads the file via `object_open`).
  (A native C/D JSON-parser binary is the fuller Deliverable-9 form — refinement.)
- **Z5.3 — Wire into startup + resolution priority** · ✅ DONE · `/etc/zshrc` applies the **system**
  `/etc/shell.json` then the **user** `~/.shell.json` (user overrides system); zsh sources
  `~/.zshrc` last, so an explicit user rc stays the final word.  (The brief's exact *user JSON >
  user `.zshrc`* ordering would need a one-shot `precmd` hook — refinement.)
- **Z5.4 — Verify** · ✅ DONE · both flavors: `z5demo`→`Z5-CONFIG-LIVE` (JSON alias),
  `$HISTSIZE`=100000 (JSON `history.size`), `setopt|grep share`→`sharehistory` (JSON
  `history.shared`); resolution priority — wrote `{"history":{"size":42}}` to `~/.shell.json`,
  re-sourced, `$HISTSIZE`=42 (user JSON overrode system); hardcoded defaults unregressed, no faults.

## Z6 — Prompt: identity / namespace / capabilities / path · ✅ DONE (current shells; carries to zsh) · P: High · E: 2

The prompt the brief asks for — **username, permissions, namespace, file path** — is **live
in both current shells today**, and the same data feeds the zsh theme later:

- **Linux shell (busybox):** wl-term builds `PS1="[<domain>] \u [<perms>]:\w\$ "` from the
  per-domain policy the Domain Manager passes (`EPIN_DOMAIN`/`EPIN_DISK`/`EPIN_NET`/
  `EPIN_SECURE_IPC`); `\u`/`\w` expand live (added the uid-1000 `/etc/passwd` entry so `\u`
  resolves). Example: `[System] user [fs:rw net:nat ipc]:/`.
- **Native shell (hos-sh):** `HOSQ_WHOAMI` now returns `user@namespace [perms]`, perms
  derived from the task identity's rights ceiling + net policy + brokered devices
  (`fs:rw net:nat ipc exec admin`); the prompt is `user@namespace [perms]:/path` and the
  path updates live on `cd`. Example: `user@System [fs:rw net:nat ipc exec admin]:/objects/identities`.
- **For zsh (Z7):** the same fields become a `prompt_anonymos_setup` theme function that
  reads the identity/namespace/caps via the platform layer (native) or the `EPIN_*` env
  (Linux), so the multi-line `╭─ user@machine … ├─ Identity … ├─ Namespace … ╰─ λ` layout
  from the brief is a theme, not hardcoded shell logic.

- **Z6.1 — Native zsh prompt from the kernel identity** · ✅ DONE · native *zsh* now shows the
  **full native identity** — `user@namespace [<full rights ceiling>]` — instead of the Linux-style
  `PS1`.  Added a `whoami` verb to `/hos-sh` (prints the `HOSQ_WHOAMI` string), and in `/etc/zshrc`
  under the `EPIN_SHELL==native` gate set `PROMPT` from it.  Verified live: the native prompt reads
  `user@System [fs:rw net:nat ipc exec admin]:/%` (note `user@namespace` + the `exec admin` rights
  the Linux flavor omits); Linux flavor keeps `[System] user [fs:rw net:nat ipc]:/%` (gate holds).
  zsh can't issue the syscall itself, and `$(/hos-sh whoami)` would hit the bug below, so the value
  is routed through a temp file + the `read` builtin (no capture pipe).  Computed once; `%~`/`%#`
  update live.  A foretaste of the Z7 theme reading identity natively.

> **RESOLVED (commit 54c370e77) — command substitution `$(cmd)` hang.** Capturing a forked
> child's output — `X=$(whoami)` — wedged the shell after the child was reaped.  The original
> "pipe never sees EOF" hypothesis was **wrong**: the pipe closed fine.  Live kernel syscall
> tracing (caller-tid + return value on `kill`/`sigsuspend`) showed zsh spinning in
> `waitforpid()` (jobs.c), whose loop `while (kill(pid,0) >= 0 || errno != ESRCH) signal_suspend(...)`
> is meant to exit once the reaped child makes `kill(pid,0)` return ESRCH.  **Two-part root cause:**
> (1) the kernel's `linux_sys_kill` was a stub returning 0 for *any* pid, so the probe never saw
> ESRCH; (2) more subtly, when zsh was first cross-compiled against *that* stub, its configure
> probe `zsh_cv_sys_killesrch` set `BROKEN_KILL_ESRCH=1`, hardcoding `#define ESRCH EINVAL` (22) —
> so even after the kernel was fixed to return real `-ESRCH` (3), zsh compared `errno != 22` and
> the guard `3 != 22` was always true → infinite `signal_suspend()`/`pause()` spin (~150k EINTR/s),
> ZLE never re-engaged, terminal stuck cooked.  **Fix:** `linux_sys_kill` now reports real liveness
> (`-ESRCH` for a reaped/dead pid; `syscalls/posix.d`), AND zsh is rebuilt without
> `BROKEN_KILL_ESRCH` (`deps/zsh/Makefile zsh_cv_sys_killesrch=yes`) so its ESRCH is the real 3.
> Verified live: `echo A=$(whoami) B=$(echo hi)` → `A=user B=hi`, pipes + external commands work,
> fresh prompt.  **Z7/Z8/Z9 (themes/completion/plugins, all of which use `$()`) are now unblocked.**

## Z7 — Theme engine · ✅ DONE · P: Med · E: 3 · deps: Z5, Z6

- Oh-My-Zsh-style themes under `themes/`; ship `themes/anonymos.zsh-theme` with the
  multi-line layout (identity/namespace/capabilities/git/object/exit-status/exec-time).
- Nerd-Font glyphs when the terminal advertises them (an env/termcap probe), ASCII fallback.
- Window border color already matches the namespace (the unspoofable domain border in
  wl-term); the theme reads the same `EPIN_DOMAIN_COLOR`. *Deliverable 8 (theme engine).*

**Sub-steps:**
- ✅ **Z7.1 — wl-term ANSI color (the enabler).** wl-term was monochrome: its `char grid[ROWS][COLS]`
  stored chars only and rendered every cell with a fixed `COL_FG`; SGR (`m`) was parsed-and-dropped.
  Add per-cell `fgc/bgc` + a pen, parse SGR `m` (reset 0, bold/reverse, 30–37/90–97 fg, 40–47/100–107
  bg, `38;5;N`/`48;5;N` 256-color, `38;2;R;G;B`/`48;2` truecolor, defaults 39/49), and render glyph
  with the per-cell fg over a per-cell bg rect. Without this every theme is invisible (and Z9b
  Powerlevel + Z9 syntax-highlighting are impossible).
- ✅ **Z7.2 — `anonymos.zsh-theme`.** Colored multi-line prompt: line 1 = identity(user) · namespace
  (in the truecolor domain color) · capabilities · object/path · git; line 2 = exit-status-tinted
  prompt char. `RPROMPT` = exec-time (preexec/precmd timer, shown past a threshold) + clock. Works in
  both flavors (native reads the kernel identity it already cached in `~/.hos_id` via Z6.1; Linux
  reads `EPIN_*`). A glyph set vs ASCII set switched by an advertise probe (`EPIN_NERDFONT`), ASCII
  active — actual Nerd glyph *rendering* needs terminal UTF-8 + a Nerd font (the grid is single-byte,
  bytes ≥0x7f dropped) → tracked as a follow-up, the probe-branch lands now.
- ✅ **Z7.3 — loader + seeding.** Seed `themes/anonymos.zsh-theme` to `/etc/zsh/themes/` (rtSeedShellConfig,
  like /etc/zshrc); `/etc/zshrc` sets `ZSH_THEME=anonymos` + sources `$ZSH_THEMES_DIR/$ZSH_THEME.zsh-theme`
  (user `~/.zsh/themes/` overrides). The theme reads `EPIN_DOMAIN_COLOR` (0xAARRGGBB → `\e[38;2;R;G;Bm`)
  so the namespace text matches the unspoofable window border.

## Z8 — Completion engine · ✅ DONE · P: Med · E: 3 · deps: Z2, Z5

- Upstream zsh completion + AnonymOS extensions (`_objctl`, `_identityctl`, `_nsctl`,
  `_capctl`, `_servicectl`, `_packagectl`): complete objects, capabilities, namespaces,
  services, packages, identities, permissions — driven by `object_enumerate`/`service_lookup`
  (native) or the `/objects` FS views (Linux). *Deliverable 11 (completion).*

**Sub-steps:**
- ✅ **Z8.1 — stage zsh's function/completion tree + enable compinit (the foundation).** Until now
  zsh's autoloadable functions weren't staged at all — `$fpath` pointed at an empty
  `/system/shell/zsh/share/zsh/5.9/functions` (zsh's compiled-in default), so neither `compinit`
  nor `add-zsh-hook` (Z7) existed and TAB did nothing. Pack `deps/zsh/zsh-5.9/{Functions,Completion}`
  (flattened by basename, OS-specific completion dirs pruned) into a `zshfns.blob` (the same flat
  `[u32 pathLen][path][u32 dataLen][data]` archive as xkb.blob/fonts.blob) staged at that default
  fpath dir; the kernel unpacks it at boot via the existing `rtUnpackAssetBlob`. `/etc/zshrc` then
  runs `autoload -Uz compinit && compinit -C` so the full completion system loads. Bump
  `RT_MAX_NODES` + add an `rtAllocNode` free-slot hint for the extra ~900 nodes.
- ✅ **Z8.2 — AnonymOS completion extensions.** A `#compdef`-tagged `_hos` (covering `hos`/`obj`/
  `id`/`ns`/`svc`/`sys`) seeded into the fpath dir; compinit registers it (`$_comps[hos]` → `_hos`,
  verified). It `_describe`s the object-model verbs. Refinements: the verbs are currently flat
  queries (no entity args), so live object/namespace *enumeration* lands when the commands grow
  entity arguments; live triggering is on the native shell (the obj/ns/svc functions are
  native-only) — the Linux flavour registers it but `hos` isn't a command there.

**Kernel fixes Z8 required (surfaced by the completion's depth — broader than zsh):**
- The user stack was a fixed **128 KB (32 pages)**; zsh's completion recursion (deep, esp. inside
  a forked `$()` subshell) overflowed it → faulted below the stack region. Bumped to **1 MB
  (256 pages)**.
- The fatal-page-fault path logged the user return address by dereferencing `rsp` — but on a stack
  overflow `rsp` is itself unmapped, so the kernel deref escalated to a **fatal nested KERNEL
  FAULT** (any deep-stack forked command could crash the OS). Now guarded by `userPageMapped`.
- `RT_MAX_NODES` 8192 → 12288 + an `rtAllocNode` free-slot hint for the +1018 function nodes.
- *Deferred:* automatic stack growth (vs the fixed 1 MB); `rename`/`renameat` is ENOSYS so
  compinit can't cache its dump (`~/.zcompdump`) — harmless (the ramfs cache is lost each boot
  anyway, and per-completion autoload is the real first-use cost), tracked separately.

## Z9 — Plugin system · ✅ DONE · P: Med · E: 3 · deps: Z2

- Standard zsh plugins (`git`, `history`, `fzf`, `extract`) load unchanged. Native plugins
  (`objects`, `identity`, `namespace`, `capabilities`, `security`, `process`, `package`,
  `services`) wrap the object/native-ABI commands — the `/hos-sh` builtins reborn as zsh
  plugins. Integrate `zsh-autosuggestions` (history-driven) and `zsh-syntax-highlighting`
  (grammar extended for `objctl/identityctl/nsctl/servicectl/packagectl`).
- *Deliverable 10 (plugin architecture).* Plugins dynamically loaded (Z2).

**Sub-steps:**
- ✅ **Z9.1 — plugin loader (the architecture).** An Oh-My-Zsh-compatible loader in `/etc/zshrc`:
  a `plugins=(…)` array + a loop that sources `$ZSH_PLUGINS_DIR/<name>/<name>.plugin.zsh`
  (fallback `<name>.zsh`). zsh-syntax-highlighting is always sourced **last** (it wraps ZLE
  widgets). `ZSH_PLUGINS_DIR=/system/shell/zsh/plugins`, staged from a `zshplugins.blob`.
- ✅ **Z9.2 — native AnonymOS plugin.** `anonymos.plugin.zsh`: the object-model commands as a
  plugin — on Linux it defines `obj/svc/sys` + `objects/identities/services/sysinfo` reading
  the `/objects` store + `/config/*.json` views; native already has them as `/hos-sh` builtins.
  Wires the Z8.2 `_hos` completion via `compdef`. Makes the object model reachable + completable
  in **both** flavours.
- ✅ **Z9.3 — zsh-syntax-highlighting (vendored 0.8.0).** The big visible win now that wl-term has
  ANSI colour (Z7): commands/paths/options/strings coloured live as you type. Vendored tarball
  + the ~8 runtime highlighter files packed (tests/docs excluded).
- ✅ **Z9.4 — zsh-autosuggestions (vendored 0.7.1).** History-driven inline suggestion (grey) that
  Right-arrow/End accepts. Vendored tarball, packed.
- Staging: `pack-zshplugins.py` reads the vendored tarballs (+ the native plugin), filters to
  runtime files, packs to `/system/shell/zsh/plugins/<plugin>/…` (paths preserved, unlike the
  flattened Z8 functions) → `zshplugins.blob`, unpacked at boot by `rtUnpackAssetBlob`.

## Z9b — Oh My Zsh + Powerlevel ("over 9000") · ✅ DONE · P: Med · E: 3 · deps: Z5, Z7, Z9

**Sub-steps (in progress):**
- **Z9b.1 — vendor Oh My Zsh (subset) + Powerlevel9k.** Fetch + pin OMZ (master) and Powerlevel9k
  0.6.7; pack a *functional subset* (oh-my-zsh.sh + lib/ + plugins/git + P9k theme/functions +
  the Z9 plugins under custom/plugins/) into `omz.blob`, staged at `/system/shell/zsh/omz/`
  (`$ZSH`), `$ZSH_CUSTOM=$ZSH/custom`. **Powerlevel9k, not 10k** — pure-zsh (no `gitstatusd`
  binary, no terminal-probe/instant-prompt gymnastics the minimal VT can't answer), and it
  showcases Z7's background-colour support.
- **Z9b.2 — AnonymOS custom segments + ready profile.** A `~/.zshrc` (`zshrc.omz`) that sources
  `$ZSH/oh-my-zsh.sh`, `ZSH_THEME=powerlevel9k/powerlevel9k`, `plugins=(git zsh-autosuggestions
  zsh-syntax-highlighting)`, ASCII mode (the grid is single-byte — Nerd glyphs need terminal
  UTF-8, tracked), gitstatus disabled. Three P9k `custom_anonymos_*` segments — identity,
  namespace (domain colour), capabilities — read `EPIN_*` (Linux) / the kernel identity (native).
- **Z9b.3 — `omz-setup` installer.** The offline, idempotent analogue of the gist's
  `install-zsh.sh`: copies the profile to `~/.zshrc` (backing up any existing rc) so "set up my
  shell like everyone's" is one command — fully vendored, no network, capability-respecting. The
  Z7 anonymos theme stays the default; OMZ+P9k is opt-in via `omz-setup`.
- *Nerd Fonts + nerdfont-mode glyphs are deferred to terminal UTF-8 support (the Z7 follow-up).*

The popular customization stack (cf. the `ni-c/install-zsh.sh` gist — oh-my-zsh +
powerlevel9k + zsh-autosuggestions + zsh-syntax-highlighting + Nerd Fonts), made
**available so anyone can customize their shell** the way they already know how. We vendor
the frameworks (no network at runtime) and wire them to the AnonymOS prompt data.

- **Oh My Zsh** — vendor the framework under `/system/shell/zsh/omz/` (cached, pinned). A
  default `~/.zshrc` sources `$ZSH/oh-my-zsh.sh`, sets `plugins=(…)` and `ZSH_THEME=…`. Users
  customize by editing `~/.zshrc` exactly as upstream — the whole point.
- **Powerlevel9k / Powerlevel10k** — vendor as a custom theme
  (`$ZSH/custom/themes/powerlevel10k`). The brief's segment layout maps cleanly to AnonymOS:
  ```
  POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(anonymos_identity anonymos_namespace dir vcs)
  POWERLEVEL9K_RIGHT_PROMPT_ELEMENTS=(anonymos_caps status background_jobs time)
  POWERLEVEL9K_MODE="nerdfont-complete"
  ```
  We add three **custom prompt segments** (a tiny `prompt_anonymos_*` each) that surface the
  same fields the live prompt already shows (Z6): `anonymos_identity` (the security domain),
  `anonymos_namespace` (with the domain color as the segment background), and `anonymos_caps`
  (the capability flags `fs:rw net:nat ipc …`). On native zsh they read the identity/namespace/
  caps via the platform layer (`object_query`/`namespace_lookup`/`cap_rights`); on Linux zsh
  they read the `EPIN_*` env. The `custom_live`-style example from the gist becomes an
  `anonymos_disposable` segment that flags disposable domains.
- **zsh-autosuggestions** + **zsh-syntax-highlighting** — vendor under `$ZSH/custom/plugins/`,
  enabled by default in the shipped `.zshrc` (this is Z9's "standard plugins load unchanged",
  pinned to the gist's choices). Syntax-highlighting grammar is extended for
  `objctl/identityctl/nsctl/servicectl/packagectl` (Z9).
- **Nerd Fonts** — bundle one patched Nerd Font into the asset blob (the GUI font path already
  ships TTFs); the terminal advertises it so the powerline glyphs render, ASCII fallback
  otherwise (Z7).
- **An installer for parity with the gist** — `omz-setup` (a native script, the AnonymOS
  analogue of `install-zsh.sh`): copies the default `.zshrc`, selects powerlevel10k, enables
  the two plugins, and is idempotent — so "set up my shell like the gist" is one command, but
  fully offline and capability-respecting (it never fetches from the network; everything is
  vendored).
- *Deliverables 8/10/11 (theme/plugin/completion) realized as the familiar OMZ experience.*

## Z10 — History (incl. secure) · ✅ DONE · P: Med · E: 2 · deps: Z1

- Persistent shared history (`fc`, `Ctrl-R`). **Per identity / per namespace / per
  disposable** history files, encrypted when `shell.json` requests it (over the existing
  crypto: ChaCha20-Poly1305 in [`core/secipc.d`](../src/kernel/d/core/secipc.d)), with
  automatic expiration for disposable domains. History is shared across namespaces only when
  policy allows (a `namespace_bind` decision). *Deliverable 12–15 (the integration set).*

**Sub-steps:**
- **Z10.1 — per-domain history file + interactive history.** `HISTFILE` was never set, so zsh kept
  history in RAM only.  `/etc/zshrc` now sets a **per-domain** `HISTFILE=~/.zsh_history.<domain>`
  (sanitized `EPIN_DOMAIN`), so identities/namespaces never share command history.  `EXTENDED_HISTORY`
  (timestamps), `INC_APPEND_HISTORY` (append-as-you-go), `SHARE_HISTORY` (live across concurrent
  terminals of the same domain), and the dedup/blank flags; sizes from `shell.json` (Z5).  `Ctrl-R`
  incremental search + `fc` work once `HISTFILE` is set.
- **Z10.2 — disposable = ephemeral.** A domain with `EPIN_NET=disposable` unsets `HISTFILE` and
  `SAVEHIST=0` — history is never written and dies with the shell (the policy's "automatic
  expiration").
- **Z10.3 — cross-reboot persistence + encryption (deferred, infra-gated).** Today `HISTFILE`
  lives in the ramfs, so history is persistent + shared *within a boot*; surviving a reboot needs a
  disk-backed home (object-FS **F4.3 writable storage**), and the `shell.json` *encrypted* option
  needs a **crypto syscall** over `secipc.d`'s ChaCha20-Poly1305 (with per-identity keys).  The
  cross-namespace `namespace_bind` sharing decision rides on the native ABI (Z4). All three are
  tracked; the per-domain isolation + interactive history (the security-relevant + UX core) land now.

## Z11 — Login flow + default shell · ☐ · P: Med · E: 2 · deps: Z1, Z5

- `display-manager → auth → identity → namespace → PTY → zsh → shell.json → .zshrc →
  plugins → theme → prompt`. New users get `/system/shell/zsh/zsh` as their login shell;
  the Domain Manager's per-domain Shell control gains a "zsh" option alongside linux/native.

## Z12 — Security review + tests + benchmarks · ✅ DONE · P: High · E: 3 · deps: all

**Complete.** Z12.1 security review (one High fix + two fail-closed hardenings + docs/ZSH_SECURITY_REVIEW.md),
Z12.2 regression + smoke harness (tests/zsh/zsh_smoke.py, 8/8 in-VM), Z12.3 benchmarks
(tests/zsh/bench.py — fits the 512 MiB ceiling with ~50× headroom, zsh startup ≈ busybox).


- *Deliverable 16 (security review):* zsh never bypasses the capability/identity/namespace
  managers — every privileged op goes through the native ABI (which is itself gated to the
  native personality), and Linux-personality zsh simply cannot reach the object ABI
  (`ENOSYS`, NATIVE_OBJECT_ABI §3). Audit the platform layer for ambient-authority leaks.
- *Deliverable 17 (test plan) + 18 (regression):* run upstream zsh's test suite (the
  subset the syscall set supports) on Linux-personality zsh; golden-prompt + completion +
  plugin smoke tests headless via the QMP harness (relative-mouse + screendump,
  [[window-decorations]]); reboot/persistence checks for history.
- *Deliverable 19 (benchmarks):* startup time, prompt render latency, completion latency vs
  busybox `ash` and `/hos-sh`; ensure zsh's larger footprint fits the 512 MiB boot ceiling.

Tracked sub-steps:

- **Z12.1 — Security review (D16)** · ✅ DONE · four independent adversarial audits of the platform
  layer (N0 gate, the six Z4 verbs, the anon.c `--wrap` hooks, the `zsh/anonymos` module, the
  native-exec personality binding).  Findings + dispositions in [docs/ZSH_SECURITY_REVIEW.md].
  **One High finding fixed: F1** — the native-personality grant keyed off the *request* basename
  (`origBase=="hos-zsh"`), so a user-created symlink `/tmp/hos-zsh -> /busybox` could smuggle an
  arbitrary image onto the object ABI; now requires the trusted *resolved* image
  (`execName=="zsh" && origBase=="hos-zsh"`, or `execName=="hos-sh"`).  Two fail-closed hardenings:
  **F2** `cap_grant` ceiling → 0 (deny) on a missing identity (was fail-open to `src.rights`); **F3**
  `ns_enter` re-validates the id still resolves to a live namespace (recycled-objId guard).
  Documented as pre-existing/out-of-scope: F4 (unchecked user `buf` in read/write — OS-wide, not
  native-specific, SMAP off in dev), F5 (nominal namespace gating — equal in both personalities),
  F6 (no per-file mode), F7 (`ns_clone` un-entered-clone leak).  Verified live: the core invariant
  holds both ways — a **Linux** zsh's `builtin obj` → "native object ABI unavailable" (`ENOSYS`),
  a **native** zsh's `builtin obj` → the live object table (the gate fix did not regress native launch).
- **Z12.2 — Regression + smoke tests (D17/D18)** · ✅ DONE · committed the reproducible headless
  harness [tests/zsh/zsh_smoke.py] (boots `hos.iso` under qemu, QMP-drives a terminal, asserts
  golden behaviours via serial-console markers) — **8/8 green on our kernel**: prompt (Z6/Z7),
  `$ZSH_VERSION`=5.9, builtin+pipe, completion (compinit/compdef, Z8), plugin (`_zsh_highlight`,
  Z9), history recording (Z10), aliases, and the native `builtin obj` object module (Z4c.4).  This
  in-VM smoke *is* "the subset the syscall set supports", and is the authoritative regression net.
  Results + the upstream-`Test/`-suite analysis in [tests/zsh/RESULTS.md]: the shipped shell is
  unmodified upstream zsh 5.9 + the single `zsh/anonymos` module, so upstream correctness carries;
  the full `make check` suite blocks in `pause()` headless without a controlling pty (a follow-up
  nicety, not a gate).  History: within-session verified; cross-reboot is documented as object-FS
  **F4.3**-gated (HISTFILE lives in ramfs `$HOME`; the on-disk store persists — boot counter climbs).
- **Z12.3 — Benchmarks (D19)** · ✅ DONE · committed [tests/zsh/bench.py] + the numbers in
  [tests/zsh/RESULTS.md].  **The ceiling question is settled: zsh fits the 512 MiB boot ceiling
  with ~50× headroom** — 10.1 MB on-disk footprint (2.0%) and a 4.0 MB peak RSS for the fully-loaded
  interactive shell (0.78%); the zsh *binary* (1.12 MB) is even smaller than busybox (1.42 MB).
  Startup latency: `zsh -fc exit` ≈ `busybox true` ≈ `/hos-sh sys` to within ~0.5% in any run — the
  per-exec cost is entirely the kernel's fork/exec/load path, so zsh adds no overhead over a 56 KB
  native shell.  (The *absolute* latency is unreliable on the cooperative dev kernel — 1.6–7 s
  run-to-run — so only the stable relative parity is reported; the latency floor is a kernel-exec
  optimisation target, orthogonal to the shell footprint.)

---

## Phased delivery (Deliverable 20 — milestones + dependencies)

Each milestone leaves the shell fully functional:

1. **M-Z-Linux** (Z0→Z1→Z3): real upstream zsh is the Linux-personality interactive shell;
   wl-term launches it; no regressions vs upstream. *Lowest risk, highest immediate value.*
2. **M-Z-Dynamic** (Z2): zmodules load dynamically; libzsh.so split done.
3. **M-Z-Config** (Z5→Z6→Z7): shell.json + the anonymos theme + the four-field prompt as a
   zsh theme (the prompt data is already live, Z6 ✅).
4. **M-Z-Integrate** (Z8→Z9→Z10): completion + plugins + secure history wired to the object/
   identity/namespace/capability managers.
5. **M-Z-Native** (Z4): native zsh over the platform layer; `/hos-sh` retires into a plugin.
6. **M-Z-Harden** (Z11→Z12): login flow, default shell, security review, regression +
   benchmarks.

Order rationale: Linux zsh first (it's just another musl binary over the live ABI), the
config/prompt/theme layer next (mostly data + a theme function, and the prompt fields are
already implemented), then the deep native port last (it needs the most platform plumbing).

---

---

## Companion: the native shell — `-sh` (LFE / Lisp-Flavored Erlang)

AnonymOS has **two interactive shells, one per personality** (NATIVE_OBJECT_ABI §3):

- **zsh** — the **Linux personality** shell (POSIX): everything above. Familiar, scriptable,
  Oh-My-Zsh-customizable; runs ordinary Linux/POSIX programs.
- **`-sh`** — the **native (AnonymOS) personality** shell: it abides by the **syntax and
  structure of LFE (Lisp-Flavored Erlang)** as defined by the
  [`-sh` project](https://github.com/Jonathan-R-Anderson/-sh). Where zsh is line-oriented
  POSIX, `-sh` is **s-expression / Lisp**, which fits the object-capability model directly:
  objects, capabilities, identities, and namespaces are first-class **data** (atoms, lists,
  tuples), and every action is a **form** — `(verb target args…)` — that maps onto a native
  object-ABI call. This is the "actual OS shell" the Domain Manager offers as the **native**
  option; it drives the kernel object model the way zsh drives POSIX.

**Why LFE for the native shell.** The native ABI is object-oriented and message-passing
(§6/§8); LFE's homoiconic forms + pattern matching + immutable data are a natural surface
for it — an object query is a list, a capability is a tagged tuple, a method call is a form,
and policies/declarative config (`shell.json`, the `/config` views) are just data the shell
reads and writes. It keeps the native shell *introspectable and scriptable* (the AI-/agent-
friendly goal) without bolting POSIX onto the object model.

### LFE integration phases (parallel to the zsh phases)

- **L0 — LFE reader (s-expressions) · ✅ DONE (first cut).** `hos-sh` now reads LFE forms:
  `(obj)`, `(id)`, `(ns)`, `(svc)`, `(sys)`, `(cd "/path")`, `(help)`, `(exit)` — outer parens
  dropped, `"string"` atoms unquoted, nested grouping flattened (`src/util/hos-sh.d`
  `lfeNormalize`). Bare words still work for convenience. Verified: `(sys)`/`(ns)`/
  `(cd "/objects/identities")` run and the prompt tracks the path.
- **L1 — vendor the `-sh` source · ✅ DONE · E: 3.** Vendored the upstream `-sh` (LFE) project
  cached + pinned under `deps/lfe-sh/`, the way `deps/zsh/` carries `zsh-5.9.tar.xz`; details in
  [deps/lfe-sh/VENDOR.md].
  - **L1.1 — vendor pinned source** · ✅ pinned `github.com/Jonathan-R-Anderson/-sh` at commit
    `a44ee38b`; the source tree (91 `.d` + 16 `.lfe`, excluding the upstream prebuilt binary/.o/.git)
    is a sha256-pinned tarball `deps/lfe-sh/lfe-sh-a44ee38bfa87.tar.gz`; `deps/lfe-sh/Makefile`
    unpacks + checksum-verifies (`make`) and host-builds to validate (`make host-build`).
    **Validated:** the vendored source compiles with `ldc2 1.36` + libreadline and evaluates LFE
    (`(+ 3 4)` → `7`).
  - **L1.2 — decide + document the runtime** · ✅ **native D evaluator, NOT LFE-on-BEAM** — upstream
    `-sh` is *already* a D Lisp/LFE interpreter (`src/interpreter.d`, `evalString`, `ldc2`-built), so
    it reuses the platform's compiler and avoids porting the whole Erlang VM; the betterC `hos-sh`
    (L0 `lfeNormalize`) is the bootstrap that `-sh` supersedes from L2.  OS-build adaptations deferred
    to L2 (an `ldc2` **musl** target + Phobos/druntime; **libreadline → OS PTY line input**; the
    object-ABI forms wired to `HOS_SYS_QUERY` behind the native-personality gate; staged at
    `/system/shell/-sh/`).  Full rationale in [deps/lfe-sh/VENDOR.md].
- **L2 — evaluator + builtins as LFE functions · ✅ DONE · E: 4 · deps: L1.** The object commands
  are LFE functions over the native ABI, and **forms evaluate to data that further forms consume**
  (composition, not text streams).  `hos-sh` grew from the L0 form-*reader* (`lfeNormalize`) into a
  real **evaluator** (`src/util/hos-sh.d`): an s-expression parses to an AST (a fixed betterC node
  pool) and evaluates to a tagged value — `(obj)`/`(id)`/`(ns)`/`(svc)`/`(sys)`/`(whoami)` →
  `HOS_SYS_QUERY` enumeration **as data**; `(ns-clone)`/`(ns-enter <id>)`/`(cap-grant <h> <r>)`/
  `(subscribe <ev>)` → the Z4 native verbs returning the id/handle/status; `(+ - * /)` arithmetic;
  `(cat …)`/`(cd …)`/`(print …)`/`(help)`/`(exit)`.  **Verified live:** `(ns-clone)` → `2193`,
  `(cap-grant 1 1)` → `32`, `(obj)` → the object table, and the headline composition
  **`(ns-enter (ns-clone))` → `0`** — the kernel logged `[ns-clone … -> 0x892]` then `[ns-enter
  ns=0x892]`, the *same* id flowing from the inner form into the outer (arithmetic nesting
  host-validated: `(+ (* 3 3) (* 4 4))` → `25`).
  **Approach note:** the full upstream `-sh` (full-D Phobos + libreadline) can't yet build for the
  OS — there is no musl-targeted D runtime (druntime/Phobos/libunwind), a separate toolchain port.
  So L2 ports the upstream *evaluation model* into the betterC `hos-sh` that already runs natively,
  gated, over `HOS_SYS_QUERY`; `(ns-bind …)` and `(spawn …)` (which need new kernel verbs) and the
  full-upstream build are L3/L4 follow-ups.
- **L3 — full LFE language · ✅ DONE (core) · E: 5 · deps: L2.** The native shell is now a real
  **programmable Lisp over the object model**.  The L2 flat-value evaluator grew into a cell-based
  interpreter (`src/util/hos-sh.d`, betterC, grow-only arenas, no GC): a full value model (ints,
  atoms, strings, **cons lists, tuples, closures**), lexical **environments** with a global frame,
  `defun`/`lambda`/`let`, `if`/`case` with **pattern matching + `when` guards**, **recursion**, and
  list/tuple ops (`list`/`cons`/`car`/`cdr`/`length`/`element`).  The object-ABI verbs are ordinary
  functions whose results feed the language.  **Verified** — host (language): `(fac 5)` → `120`
  (recursion), `((lambda (x) (+ x 1)) 41)` → `42`, `(let ((a 3)(b 4)) (+ (* a a)(* b b)))` → `25`,
  `(case (tuple 1 2) ((tuple a b) (+ a b)))` → `3`, `(case 5 (n (when (> n 3)) 'big) …)` → `big`;
  in-VM (object model): `(let ((n (ns-clone))) (ns-enter n))` → `0`, `(case (ns-enter (ns-clone))
  (0 'ok) (e 'fail))` → `ok`, and a recursive `(defun countdown …)` defined on one line then
  `(countdown 3)` → `done` (defuns persist across REPL lines).  **Remaining polish:** maps,
  `defmacro`/quasiquote, and list comprehensions (the advanced ~15%) — not required for the
  programmable-Lisp milestone.
- **L4 — capability/namespace/identity-aware forms · ✅ DONE · E: 3 · deps: L2.** First-class
  forms for the security model: `(identity)`/`(identity-switch …)`, `(namespace …)`, `(caps)`/
  `(cap-derive …)` — the same fields the prompt shows, manipulable as LFE. All gated by the
  native-personality gate (§3) and the identity ceiling — `-sh` never bypasses the managers.
  - **L4.1 — read forms (data)** · `(identity)` → a `#(user namespace caps)` tuple parsed from the
    kernel whoami; `(namespace)` → the namespace atom; `(caps)` → the rights as a list of atoms;
    `(cap-derive src rights)` → an alias for the attenuating `cap_grant`.  Pattern-matchable LFE.
  - **L4.2 — `(identity-switch <name>)`** · a new GATED kernel verb (`HOSQ_ID_SWITCH`):
    de-escalation-only (target identity trust ≤ current — never escalate), relabel the task's
    identity, and attenuate its capabilities to the new (lower) rights-ceiling so existing caps
    can't retain rights the new identity forbids.  **Verified live:** `(identity)` → `#(user System (fs:rw net:nat ipc exec admin))`,
    `(caps)` → `(fs:rw net:nat ipc exec admin)`; `(identity-switch Personal)` → `0` then `(identity)`
    → `#(user Personal (fs:rw net:nat ipc exec))` (**`admin` dropped** by the cap attenuation, prompt
    relabels to `user@Personal`); `(identity-switch System)` → `-1` (escalation back DENIED, trust
    100 > 50, kernel logged one `[id-switch … trust=0x32]` only); `(case (identity) ((tuple u n c) n))`
    → `Personal` (the security model is pattern-matchable LFE data).
- **L5 — the native shell is zsh *with LFE inside it* · ✅ DONE (corrected) · E: 2 · deps: L3.** The
  Domain Manager's per-domain Shell control offers **Linux (zsh)** / **Native (zsh+LFE)**; *both* run
  zsh — ONE shell, two personalities — and `wl-term` (then ratty) launches whichever on the PTY. The
  native shell's prompt already shows the four fields (Z6).
  - **L5.1 — LFE embedded inside the native zsh** (corrected from "separate `-sh`") · `wl-term`
    launches `/hos-zsh` — the SAME zsh in the *native* personality — for `EPIN_SHELL=native`, NOT a
    separate `-sh`. Inside that native zsh, LFE is reachable three ways: `obj`/`id`/`ns`/`svc`/`sys`
    are **in-process** native-ABI builtins (the `zsh/anonymos` module, Z4c.4, issuing
    `HOS_SYS_QUERY` directly); `lfe '<form>'` evaluates the **full LFE language** (defun/let/case/
    lists/tuples/pattern-matching + the object-ABI forms, L2–L4) via the *same* betterC evaluator as
    the standalone `-sh`; and everything else is ordinary POSIX zsh. The DM Shell label is now
    **"Native (zsh+LFE)"**. (`hos-sh.d` gained a `version(LfeLib)` switch: the one source compiles
    either as the standalone `-sh` tool *or*, with `-d-version=LfeLib`, as `lfe.o` exporting
    `lfe_eval_line` — the foundation for a future truly-in-process `lfe` *builtin* linked into the zsh
    binary via `libanon.a`; today `lfe` reuses that evaluator through the shared object shell.)
  - **L5.2 — confine the Linux shell to Linux** (security, requested) · a Linux-personality shell
    must only run ordinary Linux programs + the Linux syscall surface — never the native object ABI,
    *even by exec'ing `/hos-sh`*.  The kernel already `ENOSYS`-gates direct `HOS_SYS_QUERY` from a
    Linux task (Z12), but a Linux shell could exec the trusted native image to become native.  New
    kernel gate: a per-task `g_taskNativeLaunch` authorization (inherited on fork, held by the
    trusted desktop/terminal chain) is now *required* to enter the native personality on exec, and
    is **dropped when the Linux interactive shell (`/bin/zsh`) is exec'd** — so the Linux shell and
    everything it spawns can never reach the object ABI (running `/hos-sh` from it runs Linux-
    personality → `ENOSYS`).  The legit native launch (desktop → `wl-term` → `/hos-sh`) keeps the
    authorization; a re-run `/wl-term` from a Linux shell inherits the dropped flag and cannot.
    **Verified live (corrected build):** the DM Shell control reads **"Native (zsh+LFE)"** and the
    panel status line reads `shell Native (zsh+LFE)`; a native-domain terminal is *zsh* — POSIX
    `echo hi-from-native-zsh` works, `whence -w obj lfe echo` reports `obj: builtin`, `lfe: function`,
    `echo: builtin` (all in the one shell) — with `obj` returning the live object table in-process,
    `lfe '(- 43 1)'` → `42`, and `lfe '(defun inc (n) (- n 1)) (inc 43)'` → `inc` / `42` (the full LFE
    language, inside zsh).  A **Linux-domain** terminal runs Linux fine (`echo hello-from-linux` → ok)
    but `/hos-sh obj` / `/hos-sh sys` → `native query failed` (kernel `ENOSYS` ×3) — the Linux shell
    cannot reach the object ABI.  **This closes the L-series (L0–L5): the native shell is zsh with LFE
    embedded inside it, cleanly isolated from the Linux zsh.**

> **One shell (zsh), LFE inside, two personalities.** The native shell is *not* a separate `-sh` —
> it is zsh in the native personality with LFE embedded: in-process `obj`/`id`/`ns`/`svc`/`sys`
> builtins + the `lfe` full-language evaluator, atop ordinary POSIX zsh. The Linux personality is the
> same zsh, confined to POSIX. The terminal (`wl-term`, later ratty) hosts it; both share the rich
> prompt and the customization config.

---

## Companion: ratty terminal emulator roadmap

[ratty](https://github.com/orhun/ratty) (orhun) is a Rust, GPU-accelerated terminal
emulator. It is the **terminal** layer, distinct from the **shell** (zsh) above: ratty
draws the grid and owns the PTY; zsh runs inside it. The goal is to make ratty the
AnonymOS terminal that *hosts* zsh — the same "the terminal contains no shell logic, only
PTY + rendering" split this roadmap mandates (Z3). It supersedes/augments the current
`wl-term`. This was Track C of `SHELL_AND_COMMANDS_ROADMAP.md`; gated on a Rust toolchain
+ a GPU stack the OS does not yet have (software Pixman only — see [[weston-perf-profiling]]).

- **R0 — Rust musl toolchain · ✅ DONE · E: 3.** Stood up the Rust→musl cross-compiler — rustup
  `rustc 1.96` + cargo + the `x86_64-unknown-linux-musl` target — producing **non-PIE static-musl**
  AnonymOS binaries (matching the C clients), wired into the Makefile (`$(RUSTC)`, `RUSTFLAGS_STATIC`,
  the `hello-wl` target + conditional boot-module staging — skipped cleanly if rustc is absent).
  **Validated** with [src/util/hello-wl.rs], a pure-std (no-crate) "hello, Wayland" client: built
  static-musl, staged as `/hello-wl`, run from a terminal on the OS it connects to the compositor's
  socket over the live Linux ABI and **enumerates the full registry — 20 globals** (`wl_compositor`,
  `wl_shm`, `wl_seat`, `xdg_wm_base`, `weston_desktop_shell`, …): *"Rust speaks Wayland over the live
  Linux ABI. OK"*.  (Key OS quirk handled: sockets come back non-blocking + the scheduler is
  cooperative, so the client `poll`s — like libwayland — instead of busy-reading.)  R1+ (Ratatui CPU
  terminal, then the GPU stack) build on this.
- **R1 — CPU/Ratatui intermediate · ✅ DONE · E: 2 · deps: R0.** A CPU-rendered terminal in
  Rust ([src/util/hos-term.rs], `/hos-term`) on the software Wayland/SHM path the GUI clients use —
  proves PTY + input + glyph rendering in Rust without needing the GPU. A usable terminal on the
  current stack; de-risks the ratty port. Pure-std (no crates, like R0) so the build stays a single
  `rustc` invocation with zero dependency risk on the OS's partial Linux ABI. **Verified live:** the
  Rust terminal autostarts (also SUPER+R), hosts the Linux `/bin/zsh` on a PTY, renders its colored
  prompt + zsh syntax highlighting (`[user@linux] /`), and runs typed input — `echo rust-term-works`
  → the command echoes (green `echo`) and its output `rust-term-works` prints, then a fresh prompt.
  Sub-steps (all done):
  - **R1.1 — Rust Wayland SHM window** · bind `wl_compositor`/`wl_shm`/`xdg_wm_base`/`wl_seat`; create
    a surface + xdg-toplevel; **double-buffered** SHM (one pool, two buffers via `memfd_create`+
    `mmap`+`create_pool`, fd passed with `sendmsg`/`SCM_RIGHTS`) ping-ponged by `wl_buffer.release` —
    a single buffer deadlocks (the compositor never releases a re-attached buffer, so the grid froze).
  - **R1.2 — PTY + shell host** · `open(/dev/ptmx)` → `TIOCSPTLCK`/`TIOCGPTN` → `/dev/pts/N`,
    `TIOCSWINSZ`, `fork` → child `setsid`+`dup2`(slave→0/1/2)+`execve` zsh; parent reads the master.
  - **R1.3 — VT parser + cell grid** · printable + BS/TAB/LF/CR/BEL + CSI (CUU/CUD/CUF/CUB/CUP, ED/EL,
    SGR 16-colour) maintaining a `[ROWS][COLS]` grid of (glyph, fg, bg) with scroll.
  - **R1.4 — 8×8 bitmap font render** · reuse `gui_font.h` (extracted to `term_font8x8.rs`), 2× scale,
    fg/bg per cell + a block cursor.
  - **R1.5 — keyboard input** · `wl_keyboard` → reuse `wl-term`'s evdev `kmap`/`kmap_shift` +
    `special_key_seq` (arrows/Home/End) + ctrl/shift → write to the PTY master.
  - **R1.6 — stage + verify** · boot module + desktop autostart; verify live that the Rust terminal
    hosts zsh, renders its output, and accepts typed input.
- **R2 — GPU stack · 🚧 IN PROGRESS · E: 5 · R: high · deps: R1.** ratty renders via `wgpu`/Vulkan/GL.
  Today the OS is **software only**: `virtio_gpu.d` is a minimal *legacy* virtio-gpu driver that does
  **2D scanout** (`RESOURCE_CREATE_2D`/`SET_SCANOUT`/`TRANSFER_2D`) and Weston composites on the CPU
  (Pixman / `kms_swrast`). This is the same GPU stack tracked as R8 in `DESKTOP_RESPONSIVENESS_ROADMAP`
  — the largest dependency, where the Hyprland bring-up stalled on the dmabuf import. Real
  acceleration = QEMU `virtio-gpu-gl` (virgl) + a 3D-capable guest virtio-gpu driver + a Mesa virgl
  driver + EGL/dmabuf in the compositor. The host here CAN offer it (`virtio-gpu-gl`, `egl-headless`,
  `libvirglrenderer`, `/dev/dri/renderD128` all present). Multi-step sub-roadmap:
  - **R2.1 — virtio-gpu-gl device + virgl detection ✅ DONE** · QEMU runs `virtio-gpu-gl-pci` with a
    GL display (`-display egl-headless` headless / `gtk,gl=on` interactive); the kernel's
    `virtioGpuDetectVirgl()` (called from `kernel_main` after `random_init`) finds the modern device
    (`0x1AF4:0x1050`), **walks its PCI capability list to the MMIO common-config** (vendor cap 0x09,
    cfg_type=COMMON; the legacy IO path can't reach a modern-only device), reads `device_feature`,
    and tests `VIRTIO_GPU_F_VIRGL` (bit 0). **Verified live:** `low=0x30000003` (VIRGL + EDID +
    ring-indirect/event-idx), `high=0x00000101` (VERSION_1) → *"[virtio-gpu] R2.1: VIRGL 3D capability
    OFFERED -- GPU acceleration is reachable"*. The 3D path is reachable; foundation for R2.2+.
  - **R2.2 — modern virtio 1.0 transport · ✅ DONE** · full modern virtio-1.0 bring-up + a working
    control virtqueue. (a) Handshake: reset → ACKNOWLEDGE → DRIVER → read `device_feature` → **accept
    VIRGL + `VIRTIO_F_VERSION_1`** → `FEATURES_OK` → verify (status/feature/queue reached via the
    common-config with byte/word/dword volatile MMIO helpers). (b) Control split-virtqueue: DMA rings
    from `alloc_phys_page()` (the device DMAs PHYSICAL addresses — no low identity map), program
    `queue_desc/driver/device` (64-bit fields as **two 32-bit MMIO writes**) + `queue_enable`, parse
    the NOTIFY cap (`notify_off_multiplier`=4), `DRIVER_OK`. (c) A `GET_CAPSET_INFO` round-trip:
    build the cmd, chain a read+write descriptor, publish to avail, **`mfence` then kick** the per-
    queue notify register, poll `used`. **Verified live:** response type `0x1102`
    (`VIRTIO_GPU_RESP_OK_CAPSET_INFO`), **capset_id = 1 (VIRGL)** → *"VIRGL CAPSET QUERY OK -- modern
    virtqueue transport WORKS"*. (Traps: `mfence` before the kick so the rings reach memory; 32-bit
    halves for the 64-bit queue registers.) The 3D command path can now be built on this (R2.3).
  - **R2.3 — 3D context + resources + SUBMIT_3D · ✅ DONE** · a reusable `gpuCtrl()` control-queue
    helper (serial: reuse desc 0/1, wait per command) issued **`CTX_CREATE` (ctx 1) →
    `RESOURCE_CREATE_3D` (resource 1: 32×32 `B8G8R8A8`, bind RENDER_TARGET|SAMPLER_VIEW) →
    `CTX_ATTACH_RESOURCE`**, all `0x1100` (`OK_NODATA`).
    - **R2.3b — render command path ✅ DONE (commit 7ef4c51a4) — first real GPU accel** ·
      `RESOURCE_ATTACH_BACKING` (4 KiB page) → `CTX_ATTACH_RESOURCE` (after create+backing) →
      `SUBMIT_3D` (hand-encoded virgl stream `CREATE_OBJECT(SURFACE)` → `SET_FRAMEBUFFER_STATE` →
      `CLEAR` red, `VIRTIO_GPU_FLAG_FENCE`) → `TRANSFER_FROM_HOST_3D` → pixel read-back, **all with
      `hdr.ctx_id=1`**. ★ **Verified live: read-back = `0xFFFF0000` (RED)** at pixels [0,1,256,1023] —
      *"GPU CLEARED the resource RED -- virgl 3D rendering WORKS"* — the host NVIDIA GPU (GL 4.6 via
      `egl-headless`) actually rendered. **The long block was NOT the encoding** (byte-correct all
      along vs `virgl_protocol.h`/`virgl_hw.h`/Mesa `virgl_encode.c`) **— it was three SWAPPED
      virtio-gpu 3D command codes.** Correct (sequential from 0x0200): `CTX_ATTACH_RESOURCE=0x0202`,
      `TRANSFER_TO_HOST_3D=0x0205`, `TRANSFER_FROM_HOST_3D=0x0206`, `SUBMIT_3D=0x0207`. Found with
      **QEMU `--trace 'virtio_gpu_*'`** (showed `ctx_submit size 0` — my "transfer" decoded as a submit)
      + **`VIRGL_LOG_LEVEL=debug VIRGL_LOG_FILE=`** (host virglrenderer log; `VIRGL_DEBUG`/`VREND_DEBUG`
      alone don't set the log level). Desktop boot unaffected (virtio-gpu-gl is headless-test only).
  - **R2.4 — render node + Mesa virgl** · expose `/dev/dri/renderD128`; ship the guest Mesa virgl
    (`virtio_gpu`/`virpipe`) driver so GL/GLES programs get GPU acceleration.
    - **R2.4a — virtgpu DRM render-node uABI ✅ DONE (commit 4fcb08a12) — first userspace GPU accel** ·
      `handleVirtgpuIoctl` in posix.d implements the `DRM_IOCTL_VIRTGPU_*` family (GETPARAM,
      RESOURCE_CREATE, MAP, EXECBUFFER, TRANSFER_FROM/TO_HOST, WAIT, CONTEXT_INIT, GET_CAPS-stub)
      behind the existing `FD_DRM` dispatch (nr 0x41–0x4b), backed by new modern-transport primitives
      in virtio_gpu.d + a small GEM-handle table; `MAP` returns the backing phys so `FD_DRM` mmap maps
      it into user VA. A freestanding userspace program [drm-gpu-test.c](../src/util/drm-gpu-test.c)
      opens `/dev/dri/renderD128`, creates a 32×32 BGRA RT, mmaps it, `EXECBUFFER`s a
      CREATE_SURFACE+SET_FRAMEBUFFER+CLEAR-red virgl stream, `TRANSFER_FROM_HOST`s, and reads back
      **`0xFFFF0000` → "RESULT: PASS"**. Launched at boot only when `virtio-gpu-gl` is present
      (`g_gpuVirgl`); the desktop device set is unaffected.
    - **R2.4b — guest Mesa virgl driver ✅ DONE (commit cc1274f5f) — full GPU acceleration** ·
      - **step1 ✅ DONE (commit 3bcfaeb91)** · real `GET_CAPS` — `gpuDrmGetCapset` forwards the host
        `GET_CAPSET` (0x0109) blob to userspace; verified `drm-gpu-test` reads VIRGL2 capset
        `max_version=2`, caps bits `0xf03727fe`. EXECBUFFER now ctx-attaches referenced `bo_handles`
        (residency). Known limits: single global GEM table, EXECBUFFER streams capped at ~2 KB.
      - **step2 ✅ DONE (commit a62d00f86)** · large EXECBUFFER streams — `gpuDrmSubmit3D` uses a
        dedicated 64 KB DMA buffer + a 3-descriptor chain (`gpuCtrlChained`), lifting the ~2 KB cap so
        Mesa-sized command buffers fit; verified a 2460-byte padded stream renders red.
      - **step3 ✅ DONE (commit 7a54e4fcd)** · resource lifecycle — `DRM_IOCTL_GEM_CLOSE` frees a
        virtgpu GEM (`gpuDrmResourceUnref` = DETACH_BACKING + UNREF, then `free_phys_pages` the
        backing); handles based at `0x10000` to avoid KMS-dumb collision. Verified 100 create+close
        with no GEM/resource exhaustion. The clear path still renders red.
      - **step4a ✅ DONE (commit b8e45648c)** · built Mesa with the virgl gallium driver
        (`gallium-drivers=swrast,virgl`); the megadriver gains `virgl_create_screen` and the install
        produces `virtio_gpu_dri.so`, staged as a guest boot module. Desktop unaffected (virgl is
        additive; weston still brings up on the rebuilt megadriver).
      - **step4b ✅ DONE — GL_RENDERER=virgl, GPU acceleration end-to-end (commit cc1274f5f)** ·
        [drm-gl-test.c](../src/util/drm-gl-test.c) (dynamic-musl GLES2, gbm over `renderD128`) now reports
        **`GL_RENDERER=virgl (NVIDIA GTX 1080)`, `GL_VERSION=OpenGL ES 3.2 Mesa 23.3.5`** and reads back a
        real RED pixel: guest Mesa GLES2 → virgl gallium driver → kernel virtgpu DRM uABI → virglrenderer
        → host GPU. The earlier *softpipe-not-virgl* diagnosis (egl-headless `virgl_fence_set_fd` fence-fd
        export) was a **RED HERRING** — the real chain of blockers, each unblocking the next screen-create
        / EGL-init stage:
        - **kernel** (`core/syscalls/posix.d`, `drivers/graphics/virtio_gpu.d`): `DRM_IOCTL_VERSION` major
          must be **0** (virgl winsys rejects `major != 0`); `VIRTGPU_GETPARAM` must write the result to
          **`*value`** (value is a *userspace pointer* per the Linux uABI), not into the value field — Mesa
          read garbage for `3D_FEATURES` and bailed to softpipe; `GET_CAPS` must return the **full 1376-B**
          capset (was truncated at 1024 → `virgl_create_screen` choked); `renderD128` must `fstat()` as
          **`makedev(226,128)`** (`minor>>6 == DRM_NODE_RENDER`), not minor 0 (card0 stays minor 0).
        - **env**: drm-gl-test must unset a **fourth** software-forcing var the kernel seeds,
          **`GBM_ALWAYS_SOFTWARE=1`** (forces gbm's `dri_screen_create_sw` → kms_swrast, never trying the
          HW path) — in addition to `LIBGL_ALWAYS_SOFTWARE`/`GALLIUM_DRIVER`/`MESA_LOADER_DRIVER_OVERRIDE`.
        - **Mesa** (`deps/mutter/patches/mesa-virgl-minimal-sysfs.patch`, wired into the mesa build): this
          guest exposes **no `/sys` PCI tree**, so every `drmGetDevice2`/`drmGetDevices2` in EGL's gbm
          render-device path fails (`MESA-LOADER: failed to retrieve device information` →
          `DRI2: failed to get compatible render device`/`failed to setup EGLDevice`). Patch
          `loader_is_device_render_capable()` + `_eglFindDevice()` to fall back to a **sysfs-free
          fstat/minor node-type test** so eglInitialize reaches the already-created virgl screen instead
          of `EGL_NOT_INITIALIZED`. (TRAP: `drmGetNodeTypeFromFd` is NOT sysfs-free — on Linux it stats
          `/sys/dev/char/<m:n>/device/drm`; use a direct `fstat`+`minor` check. TRAP: do NOT set
          `MESA_LOADER_DRIVER_OVERRIDE=virtio_gpu` — gbm misreads it as a backend name.)
  - **R2.5 — EGL + dmabuf compositor ✅ DONE (commit ebd2a549e) — the desktop composites on the GPU** ·
    Weston now renders through its **OpenGL-ES renderer on virgl** (`GL renderer: virgl, NVIDIA GTX
    1080`) instead of Pixman/softpipe — compositing has left the CPU. Verified by screenshot: the full
    Domain Manager desktop composites + scans out correctly. Pieces: (1) rebuilt Weston
    `-Drenderer-gl=true` → `gl-renderer.so` (staged as a boot module + in `WESTON_MODULE_MAP`),
    `weston.ini renderer=gl`; (2) the kernel does NOT seed the four software-forcing env vars
    (`LIBGL_ALWAYS_SOFTWARE`/`GALLIUM_DRIVER=softpipe`/`GBM_ALWAYS_SOFTWARE`/`MESA_LOADER_DRIVER_OVERRIDE=kms_swrast`)
    for the `weston` binary, so it picks virgl (every other program stays on software Mesa);
    (3) the Mesa render-device fallback is broadened to accept ANY DRM node (major 226), so **card0**
    (the primary node the gl-renderer uses, not just the renderD128 render node) is render-capable —
    which also removes the NULL `queryCompatibleRenderOnlyDeviceFd` call the `GBM_ALWAYS_SOFTWARE`
    workaround existed to dodge; (4) **scanout bridge** in the kernel: `drmAddFb` accepts virtgpu GEMs
    (the GL scanout bo is a virgl resource, not a CPU dumb buffer) and `drmPresentFb` does
    `TRANSFER_FROM_HOST` (host GPU → guest backing) before the scanout memcpy — fixes "failed to create
    kms fb: Invalid argument". `zwp_linux_dmabuf` is compiled into gl-renderer; clients still use SHM
    (uploaded as GL textures) — **full dmabuf client buffers + a host SET_SCANOUT present (no per-frame
    transfer) are the remaining optimizations**. Unblocks the GPU-accelerated ratty (R3).
- **R3 — ratty port · E: 4 (revised: much higher) · deps: R2.** Build ratty for AnonymOS: PTY against
  `/dev/ptmx` (live) or the native `Device` PTY object (§12), input via the Wayland seat, clipboard via
  OSC52, and the GPU backend from R2. Honour the unspoofable per-domain window border (the identity
  color) the kernel/compositor already enforce.
  - **★ Feasibility probe (done):** [ratty](https://github.com/orhun/ratty) is NOT a lightweight
    terminal — it is **"a GPU-rendered terminal with inline 3D graphics built on Bevy + Ratatui"**, so
    it pulls in the **entire Bevy game engine** (`bevy_pbr`/`gltf`/`animation`/`ecs`/`render`, ~400+
    crates) + `wgpu`(core/hal/types) + `naga` + `glow` + `winit`. **COMPILE = feasible:** `cargo build
    --target x86_64-unknown-linux-musl` with `PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_SYSROOT_DIR=deps/
    gtk-stack/sysroot PKG_CONFIG_LIBDIR=…/lib/pkgconfig` builds through wgpu/naga/glow/winit/bevy_* with
    no hard musl blocker (the only `-sys` wall, `wayland-sys`, is resolved by that sysroot, which has
    wayland/xkb/egl/gbm/udev/x11 `.pc`s). **RUN = NOT feasible on the OS now:** Bevy/wgpu need real GPU
    acceleration (the OS is on **softpipe/CPU** — R2's virgl-as-renderer is unfinished; a 3D engine on
    softpipe is unusable) AND a far more complete Linux ABI + a full `winit`/Wayland environment than the
    OS provides. So ratty *links* but cannot *run* usefully until (1) R2 GPU acceleration (virgl) lands
    and (2) the Linux ABI is substantially expanded. Realistic alternative for the R3 *spirit* (a
    GPU/GL-rendered terminal hosting zsh): a small **GLES2 terminal** on the R2 Mesa GL stack, not the
    Bevy behemoth. Until then `hos-term` (R1, CPU) remains the Rust terminal.
  - **★ R3 foundation ✅ DONE (commit ade36f586) — a GLES2 Wayland client renders on the GPU desktop.**
    [gl-wl-test.c](../src/util/gl-wl-test.c): a minimal EGL/GLES2 Wayland client makes an EGL **window**
    surface on the Wayland platform, renders a GLES2 gradient triangle (vertex+fragment shaders), and
    `eglSwapBuffers` → Weston's virgl GL renderer composites it. **Screenshot-verified** (triangle window
    next to the Domain Manager). Launch-on-demand via SUPER+G. This is the client-side GL path a GLES2
    terminal needs.
  - **★ R3 TERMINAL ✅ DONE (commit e955365a1) — `gl-term`, a GLES2 terminal hosting zsh.**
    [gl-term.c](../src/util/gl-term.c) is `wl-term`'s full engine (FreeType grid render + CSI/VT parser +
    scrollback + CSD titlebar + per-domain identity border + kernel PTY `/dev/ptmx` + fork/exec the shell
    + `wl_keyboard` input) with the **wl_shm present swapped for GLES2**: it renders the grid into the CPU
    framebuffer `a->pixels` as before, then uploads it as a `GL_RGBA` texture and draws a fullscreen quad
    to an EGL **window** surface (`eglSwapBuffers`), so the client runs the real GL pipeline + Weston's GL
    renderer composites it (fragment shader swizzles `.bgr` since `a->pixels` is XRGB8888). **Verified
    end-to-end** (screenshot + serial): the "EpinAnonymOS Terminal" window shows the zsh prompt with
    antialiased coloured text + syntax highlighting; typing `echo glterm_ok` runs in the shell and renders
    the output. `GL renderer=softpipe` for now (the virgl-client dmabuf path below is still pending) — so
    the text rendering is CPU via the GL pipeline, but the architecture is the true-GPU foundation.
    Launch-on-demand via SUPER+L. **REMAINING for R3:** get the client onto **virgl** instead of softpipe
    (the virgl-client progress below).
  - **★ R3 virgl-client progress (commit c9f5ff339) — Weston now identifies its EGL render device.**
    Traced (multi-agent) why GPU clients fell back to softpipe: Weston logged *"failed to query rendering
    device from EGL"* → *"dmabuf support: no"*, so it never advertised a render device to clients. Fixed
    the kernel sysfs so libdrm works: **`/dev/dri` is now getdents-enumerable** (it was a synthetic dir
    never tagged → libdrm's `opendir("/dev/dri")+readdir` in BOTH `drmGetDevice2` and `drmGetDevices2`
    saw zero nodes), plus a **PCI sysfs subtree** for the virtio-gpu (`/sys/dev/char/226:{0,128}/device/`
    subsystem→`/sys/bus/pci`, uevent `PCI_SLOT_NAME`, vendor/device/…). And **reverted** the egldevice.c
    `_eglFindDevice` software-head Mesa patch (now that drmGetDevice2 works it must match the real DRM
    EGLDevice, not the software one). Weston now logs **"Using rendering device: /dev/dri/renderD128"**;
    desktop still virgl, no regression. **STILL REMAINING (deep):** the EGL display lacks
    `EGL_WL_bind_wayland_display` + `EGL_EXT_image_dma_buf_import` (the compositor↔client GPU-buffer-share
    extensions → need the **virgl PRIME/dmabuf** path for virtgpu GEMs), so clients still get softpipe;
    and the single shared unlocked `gpuCtrl` control queue must be **serialised** before a client renders
    on virgl concurrently with Weston (a non-cli/sti lock). The softpipe GLES2 client still composites
    fine meanwhile, so the **terminal can be built now** on that path.
- **R4 — make ratty the terminal · ✅ DONE · E: 2 · deps: R3.** `gl-term` (the GLES2 realization
  of "ratty"; the actual Bevy-based ratty can't run on the OS) is now the **default terminal**: the
  Domain Manager seeds every domain's terminal to `TERM_GL` (`gl-term`), so "Launch Terminal" and the
  desktop keybinding spawn it. It hosts `zsh` on a PTY and nothing else (Z3) with full `wl-term` parity
  (CSD decorations, the unspoofable domain border, scrollback); the dropdown still offers wl-term/hos-term.
  **Verified live (`roadmap/assets/r5-gl-term.png` GPU, `…-software.png` software):** SUPER+L →
  `G4TERM: spawned shell pid=13 on /dev/pts/0`, the colored zsh prompt renders.
  ★ **Software fallback (so it launches on EVERY desktop, not just the GPU one).** gl-term is a GLES2/EGL
  client, so on the **software (Pixman/gtk) desktop** — the default interactive boot — it couldn't create
  a GL surface and exited → "Launch Terminal → nothing". Fixed by giving it a **wl_shm software present**
  (double-buffered, the wl-term pattern): it already renders into a CPU buffer, so when there's no GL it
  presents that via wl_shm instead of exiting. On GL it shows `GL renderer=virgl (NVIDIA GTX 1080)`; with
  no GL it logs `software (wl_shm) present mode` and still hosts zsh (both verified). `HOS_TERM_SW=1` forces
  software. Also: `qemu-run.sh GPU=1` is now an **interactive** gtk/gl=on window (not headless); `HEADLESS=1`
  keeps the windowless egl-headless mode for automated runs.
  ★ A second blocker — *the GPU desktop itself wouldn't come up* — was fixed too: the GPU=1 boot **aborted
  QEMU** (`KVM_SET_USER_MEMORY_REGION failed`) because the L6 LKL auto-launch grabbed EpinOS's own
  **virtio-gpu** (PCI class 0x0380 under GPU=1) and corrupted its host-visible blob region. The LKL launch
  is now gated on a real LKL device, and `findDeviceByClass` skips virtio (0x1AF4) so the LKL can never be
  handed EpinOS's GPU.
- **R5 — advanced terminal features · ✅ DONE · E: 3.** All in `gl-term` (`src/util/gl-term.c`), verified
  it launches + hosts zsh with no regression from the (invasive) grid change:
  - **24-bit color** — already (Z7.1 SGR `38;2;R;G;B` truecolor).
  - **UTF-8 / Unicode** — the cell grid widened `char`→`uint32_t` codepoints; a UTF-8 decoder in the VT
    input; FreeType renders any codepoint (box-drawing, powerline-via-Unicode, etc.).
  - **Nerd-Font glyphs** — vendored `NerdFontsSymbolsOnly` (`deps/fonts/SymbolsNerdFontMono…`, staged in
    `fonts.blob`); loaded as a **fallback FT_Face** that `render_ft_glyph` uses for any PUA/icon glyph the
    primary font lacks (verified: `G9FONT: loaded Nerd symbols fallback`).
  - **Mouse reporting** — DECSET `?1000/?1002/?1003` (+`?1006` SGR, `?25`, `?2004`); `wl_pointer`
    button/drag/wheel encoded to the PTY (SGR or legacy X10), grid-only (titlebar/scrollbar stay local).
  - **Bracketed paste + OSC 52 clipboard** — `wl_data_device`: OSC 52 sets the system clipboard (base64
    → `wl_data_source`); Ctrl+Shift+V / Shift+Insert paste (`wl_data_offer` receive), wrapped in
    `ESC[200~/201~` when `?2004` is set.
  - **OSC 8 hyperlinks** — parsed, a per-cell link id + a URI ring, underline-rendered, click-to-copy
    (no browser to "open" them, so a click copies the URI to the clipboard).
  - *Kitty graphics + Sixel remain "future" per the roadmap.*

**Ordering / honesty:** R0→R1 are achievable on today's software stack and give a working
Rust terminal early; R2 (GPU) is the gating blocker and shares the desktop-GPU effort, so
the GPU-accelerated ratty is the last milestone. Until then, `wl-term` (with its new
decorations + 4-field prompt) remains the terminal, and Ratatui-CPU (R1) is the
intermediate. zsh integration (Z*) is independent of ratty — zsh runs in `wl-term` today
and in ratty later; neither blocks the other.

---

## See also

- [NATIVE_OBJECT_ABI.md](../docs/NATIVE_OBJECT_ABI.md) — the native ABI the platform layer
  targets + the personality gate the security review relies on.
- [SYSCALL_ABI.md](../docs/SYSCALL_ABI.md) — the Linux ABI Linux-personality zsh runs on.
- `roadmap/SHELL_AND_COMMANDS_ROADMAP.md` — the current busybox + `/hos-sh` shells this
  replaces; [[shell-track-a]] for the syscall traps (getpgid==1, PTY line discipline) zsh
  will also need.
