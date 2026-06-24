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

## Z4 — Native platform layer · ◐ IN PROGRESS · P: High · E: 5 · deps: Z1, Z2

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

### Z4b — signals + IPC · ◐ · deps: Z4a

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
- **Z4b.3 — Native async-event surface (`object_subscribe`, §6) for SIGCHLD + SIGINT** · ◐ ·
  the kernel already delivers these to native zsh — SIGCHLD as an rt_sigframe (Z1) and ^C as
  an EINTR at a blocking `device_read` (Z3/Z4a.6) — so native job-notify + interrupt already
  *work*; this step is the explicit native subscription registration (`object_subscribe(obj,
  events)`), a formalization of the already-functional delivery.  Deferred unless a concrete
  need (e.g. `zsh/zselect` on object events) forces it.
- **Z4b.4 — Native IPC message-passing (§8) behind coproc / `zsh/zselect`** · ◐ · zsh's coproc
  and `zsh/zselect` already move their bytes through `device_read`/`device_write` (Z4a.6 routes
  all native read/write), so the *data* path is native today; a dedicated native endpoint
  (`object_send`/`object_recv` over a §8 channel, replacing the pipe) is the fuller primitive —
  tracked refinement.
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

### Z4c — env + cap + namespace + object hooks · ◐ · deps: Z4a

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
- **Z4c.3 — Capability + namespace inheritance / hooks** · ◐ · a spawned child inherits its caps
  and namespace via fork/exec today, and `id`/`ns` (Z4c.1) read them back; explicit native
  cap-grant and namespace clone/enter on the §4 spawn manifest are **mutations** (deny-by-default
  gated on the identity ceiling) — a tracked refinement, not done here.
- **Z4c.4 — Real in-process zsh-module builtins** (overlaps Z9) · ◐ · the object commands as a
  zsh C module (builtin table calling HOSQ in-process) rather than the helper+functions of
  Z4c.1 — a fuller-integration refinement.

## Z5 — Configuration system · ◐ · P: Med · E: 3 · deps: Z1

Make the declarative `shell.json` the **source of truth** for the user-facing shell config —
today it is seeded at `/etc/shell.json` but nothing reads it (the zshrc settings are
hardcoded).  A translator reads it at shell startup and applies the settings, layered system
→ user.  Tracked sub-steps:

- **Z5.1 — `shell.json` schema** · ◐ · the declarative config (theme/prompt/history/completion/
  autosuggestions/highlighting/plugins/aliases) is already seeded at `/etc/shell.json`; tidy the
  `aliases` to real commands and add a marker so the translator is testable.  (Surfacing it as a
  `/config` object-FS view + `/system/config/shell.json` path is a later cross-link — refinement.)
- **Z5.2 — JSON→zsh translator (Deliverable 9)** · ☐ · a `zshenv`-style function
  `__hos_apply_shell_json <file>` that maps `shell.json` keys to zsh: `history.size`→
  `HISTSIZE`/`SAVEHIST`, `history.shared`→`SHARE_HISTORY`, `history.saveDuplicates:false`→
  `HIST_IGNORE_DUPS`, `completion.menu`→`zstyle … menu select`, `completion.caseInsensitive`→
  `zstyle … matcher-list`, and the `aliases` block→`alias`.  **Pure zsh** (reads the file with
  `read` + matches with `[[ … =~ … ]]`/`$match`), so it needs no external tool and runs in both
  flavors.  (A native C/D JSON-parser binary is the fuller Deliverable-9 form — refinement.)
- **Z5.3 — Wire into startup + resolution priority** · ☐ · at the end of `/etc/zshrc` apply the
  **system** `/etc/shell.json` then the **user** `~/.shell.json` (user overrides system); zsh
  sources `~/.zshrc` last, so an explicit user rc stays the final word.  (The brief's exact
  *user JSON > user `.zshrc`* ordering would need a one-shot `precmd` hook after the rc — refinement.)
- **Z5.4 — Verify** · ☐ · a JSON-only alias + a `history.size` value show up in the running shell
  (`alias z5demo`, `$HISTSIZE`), a user `~/.shell.json` overrides the system one, both flavors,
  no regression to the hardcoded defaults.

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

## Z7 — Theme engine · ☐ · P: Med · E: 3 · deps: Z5, Z6

- Oh-My-Zsh-style themes under `themes/`; ship `themes/anonymos.zsh-theme` with the
  multi-line layout (identity/namespace/capabilities/git/object/exit-status/exec-time).
- Nerd-Font glyphs when the terminal advertises them (an env/termcap probe), ASCII fallback.
- Window border color already matches the namespace (the unspoofable domain border in
  wl-term); the theme reads the same `EPIN_DOMAIN_COLOR`. *Deliverable 8 (theme engine).*

## Z8 — Completion engine · ☐ · P: Med · E: 3 · deps: Z2, Z5

- Upstream zsh completion + AnonymOS extensions (`_objctl`, `_identityctl`, `_nsctl`,
  `_capctl`, `_servicectl`, `_packagectl`): complete objects, capabilities, namespaces,
  services, packages, identities, permissions — driven by `object_enumerate`/`service_lookup`
  (native) or the `/objects` FS views (Linux). *Deliverable 11 (completion).*

## Z9 — Plugin system · ☐ · P: Med · E: 3 · deps: Z2

- Standard zsh plugins (`git`, `history`, `fzf`, `extract`) load unchanged. Native plugins
  (`objects`, `identity`, `namespace`, `capabilities`, `security`, `process`, `package`,
  `services`) wrap the object/native-ABI commands — the `/hos-sh` builtins reborn as zsh
  plugins. Integrate `zsh-autosuggestions` (history-driven) and `zsh-syntax-highlighting`
  (grammar extended for `objctl/identityctl/nsctl/servicectl/packagectl`).
- *Deliverable 10 (plugin architecture).* Plugins dynamically loaded (Z2).

## Z9b — Oh My Zsh + Powerlevel ("over 9000") · ☐ · P: Med · E: 3 · deps: Z5, Z7, Z9

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

## Z10 — History (incl. secure) · ☐ · P: Med · E: 2 · deps: Z1

- Persistent shared history (`fc`, `Ctrl-R`). **Per identity / per namespace / per
  disposable** history files, encrypted when `shell.json` requests it (over the existing
  crypto: ChaCha20-Poly1305 in [`core/secipc.d`](../src/kernel/d/core/secipc.d)), with
  automatic expiration for disposable domains. History is shared across namespaces only when
  policy allows (a `namespace_bind` decision). *Deliverable 12–15 (the integration set).*

## Z11 — Login flow + default shell · ☐ · P: Med · E: 2 · deps: Z1, Z5

- `display-manager → auth → identity → namespace → PTY → zsh → shell.json → .zshrc →
  plugins → theme → prompt`. New users get `/system/shell/zsh/zsh` as their login shell;
  the Domain Manager's per-domain Shell control gains a "zsh" option alongside linux/native.

## Z12 — Security review + tests + benchmarks · ☐ · P: High · E: 3 · deps: all

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
- **L1 — vendor the `-sh` source · ☐ · E: 3.** Vendor the upstream `-sh` (LFE) project under
  `/system/shell/-sh/` (cached, pinned), like zsh under `/system/shell/zsh/`. Decide the
  runtime: a native LFE reader+evaluator in betterC D/Rust, OR LFE-on-BEAM if/when an Erlang
  VM is ported. (The current D `hos-sh` is the bootstrap; `-sh` upstream supersedes it.)
- **L2 — evaluator + builtins as LFE functions · ☐ · E: 4 · deps: L1.** The object commands
  become LFE functions over the native ABI: `(objects)` → `object_enumerate`, `(cap-grant cap
  proc)` → `cap_grant`, `(ns-bind ns path obj rights)` → `namespace_bind`, `(spawn manifest)`
  → `spawn_process`. Forms evaluate to data (lists/tuples) that further forms consume —
  pipelines as composition, not text streams.
- **L3 — full LFE language · ☐ · E: 5 · deps: L2.** Atoms, lists, tuples, maps, `defun`/
  `lambda`, `let`, pattern matching, guards, list comprehensions, macros — the real LFE so
  the native shell is a programmable Lisp over the object model (scripts, functions, the
  theme/prompt as LFE).
- **L4 — capability/namespace/identity-aware forms · ☐ · E: 3 · deps: L2.** First-class forms
  for the security model: `(identity)`/`(identity-switch …)`, `(namespace …)`, `(caps)`/
  `(cap-derive …)` — the same fields the prompt shows, manipulable as LFE. All gated by the
  native-personality gate (§3) and the identity ceiling — `-sh` never bypasses the managers.
- **L5 — make `-sh` the native shell · ☐ · E: 2 · deps: L3.** The Domain Manager's per-domain
  Shell control offers **linux (zsh)** / **native (`-sh`/LFE)**; `wl-term` (then ratty)
  launches whichever on the PTY. The native shell's prompt already shows the four fields
  (Z6) and now reads LFE.

> **Two shells, one terminal.** zsh and `-sh` are independent — zsh is POSIX for Linux
> programs, `-sh` is LFE for the object model; the terminal (`wl-term`, later ratty) hosts
> either. Neither blocks the other; both share the rich prompt and the customization config.

---

## Companion: ratty terminal emulator roadmap

[ratty](https://github.com/orhun/ratty) (orhun) is a Rust, GPU-accelerated terminal
emulator. It is the **terminal** layer, distinct from the **shell** (zsh) above: ratty
draws the grid and owns the PTY; zsh runs inside it. The goal is to make ratty the
AnonymOS terminal that *hosts* zsh — the same "the terminal contains no shell logic, only
PTY + rendering" split this roadmap mandates (Z3). It supersedes/augments the current
`wl-term`. This was Track C of `SHELL_AND_COMMANDS_ROADMAP.md`; gated on a Rust toolchain
+ a GPU stack the OS does not yet have (software Pixman only — see [[weston-perf-profiling]]).

- **R0 — Rust musl toolchain · E: 3.** Stand up a Rust→musl cross-compiler producing static
  AnonymOS binaries (the analogue of the `musl-clang` C toolchain that builds the Wayland
  clients). Validate with a "hello, Wayland" Rust client over the live Linux ABI. **Hard
  dependency for everything below — no Rust on the host today.**
- **R1 — CPU/Ratatui intermediate · E: 2 · deps: R0.** A CPU-rendered Ratatui terminal (the
  ratatui ecosystem ratty builds on) on the software Wayland/SHM path the GUI clients use —
  proves PTY + input + Unicode rendering in Rust without needing the GPU. A usable terminal
  on the current stack; de-risks the ratty port.
- **R2 — GPU stack · E: 5 · deps: R1.** ratty renders via `wgpu`/Vulkan/GL. The OS is
  software-Pixman only; this needs the GPU/Mesa work tracked under desktop responsiveness
  R8 (a real render node + EGL, the dmabuf import the Hyprland bring-up stalled on). The
  largest dependency and the reason ratty is later-stage.
- **R3 — ratty port · E: 4 · deps: R2.** Build ratty for AnonymOS: PTY against `/dev/ptmx`
  (live) or the native `Device` PTY object (§12), input via the Wayland seat, clipboard via
  OSC52, and the GPU backend from R2. Honour the unspoofable per-domain window border
  (the identity color) the kernel/compositor already enforce.
- **R4 — make ratty the terminal · E: 2 · deps: R3.** ratty launches `zsh` on a PTY and
  nothing else (Z3); the desktop's terminal keybinding + the Domain Manager "Launch Terminal"
  target ratty. Feature parity with `wl-term` (decorations, domain border, scrollback) plus
  ratty's extras (tabs, true-color, ligatures, GPU scrolling, Kitty-graphics/Sixel later).
- **R5 — advanced terminal features · E: 3.** 24-bit color, Nerd-Font glyphs (shared with
  Z9b), bracketed paste, OSC52 clipboard, hyperlinks, mouse, Kitty graphics + Sixel (future).

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
