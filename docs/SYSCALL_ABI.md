# Syscall / ABI Reference

How userspace talks to the EpinAnonymOS kernel. There are **two** syscall surfaces:

1. **The Linux x86-64 ABI** — an emulated subset (160 syscalls) so unmodified Linux
   binaries (busybox, musl programs, Weston, GTK apps) run. Dispatched in
   [`dispatchSyscall`](../src/kernel/d/core/kernel_main.d) (`kernel_main.d`).
2. **The native object ABI** — `HOS_SYS_QUERY = 0x4000`, a single syscall outside the
   Linux range that exposes the kernel's own object/identity/namespace/service tables.
   Implemented in [`hoscall.d`](../src/kernel/d/core/hoscall.d).

> ⚠ = EpinAnonymOS deviates from stock Linux semantics here. Read these before assuming
> POSIX behaviour.

---

## 1. Calling convention

Standard Linux x86-64 (SysV). The userspace `syscall` instruction traps; the kernel
reads the registers (captured as `x64LastSyscallR*` in `core/exports.d`, mapped to
`a..f` in `dispatchSyscall`):

| Register | Role            |
|----------|-----------------|
| `rax`    | syscall number  |
| `rdi`    | arg 1 (`a`)     |
| `rsi`    | arg 2 (`b`)     |
| `rdx`    | arg 3 (`c`)     |
| `r10`    | arg 4 (`d`)     |
| `r8`     | arg 5 (`e`)     |
| `r9`     | arg 6 (`f`)     |
| `rax`    | return value    |

**Return / errno:** the handler returns a `long`. A value in `[-4095, -1]` is a negative
errno (e.g. `-2` = `ENOENT`, `-1` = `EPERM`, `-13` = `EACCES`, `-30` = `EROFS`). musl
negates it back into `errno`. There is **no** separate errno register.

**Blocking:** the kernel is cooperative and single-core. A handler that must block
(e.g. `wait4`, `futex`, a poll with no ready fds) returns a sentinel `-4`; the dispatcher
then *rewinds RIP by 2* (the `syscall` instruction width) and reschedules, so the syscall
transparently retries when the task is next run. See `case 61/114/202` in `kernel_main.d`.

---

## 2. Dispatch model

`dispatchSyscall(tid)` is a `switch (rax)`. Most cases are one-liners delegating to a
`linux_sys_*` function (in `core/syscalls/posix.d` and siblings). A handful are handled
**inline** because they touch the task/address-space directly:

| nr | name        | why inline |
|----|-------------|------------|
| 9  | `mmap`      | maps file/anon/DRM/memfd pages into the task address space (CoW-aware) |
| 10 | `mprotect`  | W^X / NX policy + page-table edit |
| 11 | `munmap`    | unmap + **free** owned phys pages (`removeRegion` + `free_phys_page`) |
| 25 | `mremap`    | grow/move a region (wl_shm resize) |
| 56 | `clone`     | thread (CLONE_VM shares fd/cap tables) or process |
| 57 | `fork`      | **copy-on-write** address space (refcount + PTE_COW) |
| 58 | `vfork`     | CLONE_VFORK semantics |
| 59 | `execve`    | load an ELF from a boot module, an RT/objstore path, or `/proc/self/exe`; ⚠ also the **F4.2 cap-gated launch** of `/objects/apps/<app>/executable` |
| 60 / 231 | `exit` / `exit_group` | tear down the task, free owned pages if no thread shares the CR3 |
| 61 / 114 | `wait4` / `wait4`(compat) | reap children; ⚠ `waitPid <= 0` = "any child" (busybox job control); blocks via `-4` |
| 202 | `futex`     | real FUTEX_WAIT/WAKE wait-queues |
| 435 | `clone3`    | the modern clone entry |

If `rax == 0x4000` the dispatcher calls `hosQuery` (the native ABI, §5). An unknown
number returns `-ENOSYS` (`-38`).

---

## 3. The Linux syscall table (emulated subset)

All 160 numbers the dispatcher accepts, by category. Numbers are the **x86-64** syscall
numbers. Unless flagged ⚠, behaviour matches Linux closely enough for the target
programs; many info syscalls return plausible constants.

### File I/O
`read`(0) · `write`(1) · `open`(2) · `close`(3) · `lseek`(8) · `pread64`(17) ·
`pwrite64`(18) · `readv`(19) · `writev`(20) · `pipe`(22) · `pipe2`(293) · `dup`(32) ·
`dup2`(33) · `dup3`(292) · `sendfile`(40) · `fcntl`(72) · `flock`(73) · `ftruncate`(77) ·
`getdents`(78) · `getdents64`(217) · `getcwd`(79) · `splice`(275) · `tee`(276) ·
`sync_file_range`(277) · `fallocate`(285) · `openat`(257)

- Reads/writes are dispatched through the object-ops table by fd type (`FD_FILE`,
  `FD_RTFILE`, `FD_PTY_*`, `FD_SOCKET`, `FD_PIPE_*`, `FD_TIMERFD`, …). PTY reads go
  through `fileObjRead`, **not** the inline `sys_read` branch.
- ⚠ `getdents64` is where the synthetic dirs (`/proc`, `/objects/*`, `/system/*`,
  `/config`, `/objects/apps/*`) enumerate — see [FILESYSTEM.md](FILESYSTEM.md).

### File metadata / stat
`stat`(4) · `fstat`(5) · `lstat`(6) · `newfstatat`(262) · `statx`(332) · `access`(21) ·
`faccessat`(269) · `statfs`(137) · `readlink`(89) · `readlinkat`(267)

- ⚠ `std::filesystem::exists` uses `newfstatat`(262), not `statx`(332).
- Device fds report the right `st_rdev` (DRM major 226, input major 13) so libdrm/
  libinput accept them.

### File mutation / directories
`chdir`(80) · `fchdir`(81) · `mkdir`(83) · `rmdir`(84) · `unlink`(87) · `mkdirat`(258) ·
`unlinkat`(263) · `renameat`(264) · `renameat2`(316) · `linkat`(265) · `symlinkat`(266) ·
`fchmodat`(268) · `fchownat`(260) · `utimensat`(280) · `mount`(165) · `sync`(162)

- These mutate the **RT ramfs** (`g_rt`) overlay. ⚠ Writes under the immutable trees
  (`/system`, the `/objects/*` views, `/config`) return `EROFS`.
- ⚠ `mount`(165) requires `CAP_RIGHT_ADMIN_MOUNT` (else `EPERM`) then returns success
  **without a real mount** — there is no mount table; the "mounts" are the synthetic VFS
  layers + namespace bindings.
- ⚠ The cwd is a **single global shim** (`g_cwd_buf`), not per-process — adequate for the
  foreground-tool case (e.g. `top` chdir-ing into `/proc`).

### Memory
`mmap`(9) · `mprotect`(10) · `munmap`(11) · `mremap`(25) · `madvise`(28) ·
`membarrier`(324) · `memfd_create`(319)

- `mmap` handles anonymous, file-backed (the dynamic linker), DRM-framebuffer, and
  growable `memfd` mappings. Anonymous/file pages are **owned** and freed on `munmap`/
  exit; DRM and shared-memfd pages are not.

### Process & threads
`fork`(57) · `vfork`(58) · `clone`(56) · `clone3`(435) · `execve`(59) · `exit`(60) ·
`exit_group`(231) · `wait4`(61) · `getpid`(39) · `getppid`(110) · `gettid`(186) ·
`set_tid_address`(218) · `prctl`(157)

- ⚠ `getpid`/`getppid` return constants in places (pid 1 family) — see the ids section.
- `execve` resolution order: `/proc/self/exe` → RT symlink canonicalisation (`/bin/cat`
  → `/busybox`) → boot-module basename → **`/objects/apps/<app>/executable`** (F4.2,
  cap-gated) → `ENOENT`.

### Signals
`rt_sigaction`(13) · `rt_sigprocmask`(14) · `sigaltstack`(131) · `tkill`(200) ·
`tgkill`(234) · `pause`(34) · `alarm`(37) · `signalfd4`(282/289)

- ⚠ Only **SIGINT/SIGQUIT** (default-terminate, from the PTY line discipline `^C`/`^\`)
  are actually delivered: a pending terminate-signal is applied from the *victim's own*
  run context (`exitTask(128+sig)`). SIGWINCH (ignore) and SIGTSTP (`^Z`, stop) are
  recorded but not yet driven through handler frames.
- `rt_sigaction` records the disposition bitmask (`g_taskSigCustom`); `execve` resets it.

### Scheduling & time
`sched_yield`(24) · `nanosleep`(35) · `clock_nanosleep`(230) · `clock_gettime`(228) ·
`clock_getres`(229) · `gettimeofday`(96) · `getitimer`(36) · `times`(100) ·
`sched_setparam`(154) · `sched_getparam`(155)

- ⚠ The clock is coarse (tick-based); `gettimeofday` returns zeroed wall-time. Timers
  (`timerfd`) drive the desktop frame pacing.

### Process IDs / credentials
`getuid`(102) · `getgid`(104) · `setuid`(105) · `setgid`(106) · `geteuid`(107) ·
`getegid`(108) · `setpgid`(109) · `getpgid`(121) · `getpgrp`(111) · `getsid`(124) ·
`setsid`(112) · `setreuid`(113) · `setresuid`(117) · `getresuid`(118) · `setresgid`(119) ·
`getresgid`(120) · `setgroups`(116)

- ⚠ **`getpgid`/`getpgrp` MUST return the constant `1`.** busybox ash's job-control init
  compares `getpgrp() == tcgetpgrp(tty)` to claim the terminal; returning real pgids makes
  it think it's a background shell and it never prints a prompt. `setpgid` still records
  `g_taskPgid` (used for `^C` group delivery), but the getters return 1.
- `getuid`/`geteuid` derive from the task's **User** object (`userObjId`).

### Polling & event fds
`poll`(7) · `ppoll`(271) · `select`(23) · `pselect6`(270) · `epoll_create`(213) ·
`epoll_create1`(291) · `epoll_ctl`(233) · `epoll_pwait`(232/281) · `epoll_pwait2`(441) ·
`eventfd2`(284/290) · `timerfd_create`(283) · `timerfd_settime`(286) ·
`timerfd_gettime`(287) · `signalfd4`(282/289) · `inotify_init`(254) · `inotify_init1`(294)

- ⚠ Historic traps (now fixed, but worth knowing): `epoll_ctl` is **233** (not
  `epoll_create`); the `epoll_event` struct is **packed** (`data` at offset 4). Getting
  either wrong silently breaks every event loop.
- ⚠ `timerfd_settime` honours `TFD_TIMER_ABSTIME` (flag bit 1): absolute vs relative
  expiry. `inotify` is a stub (init returns an fd; no events fire).

### Sockets (AF_UNIX focus)
`socket`(41) · `socketpair`(53) · `connect`(42) · `accept`(43) · `accept4`(288) ·
`bind`(49) · `listen`(50) · `sendto`(44) · `recvfrom`(45) · `sendmsg`(46) ·
`recvmsg`(47) · `sendmmsg`(307) · `recvmmsg`(299) · `getsockname`(51) ·
`getpeername`(52) · `setsockopt`(54) · `getsockopt`(55)

- The Wayland/seat stacks use `AF_UNIX` + `socketpair` + `SCM_RIGHTS` fd passing. ⚠
  `getsockopt(SO_PEERCRED)` returns **root creds** for any fd (so embedded seatd accepts
  the client). Sockets are **refcounted** (`LocalSocket.refCount`) so a forked server and
  its parent each `close()` their own copy without tearing down the shared pair.

### Synchronisation
`futex`(202) — real `FUTEX_WAIT`/`FUTEX_WAKE` wait-queues (musl threads, GTK).

### Info / misc
`uname`(63) · `sysinfo`(99) · `getrlimit`(97) · `setrlimit`(160) · `prlimit64`(302) ·
`getrandom`(318) · `rseq`(334) · `userfaultfd`(323) · `ioctl`(16)

- `ioctl` is a large multiplexer: TTY/PTY (`TCGETS`/`TCSETS`/`TIOCSPGRP`/`TIOCSWINSZ`),
  DRM/KMS (mode-set, dumb buffers, PRIME fd↔handle), and evdev. ⚠ `getrandom` is real
  (seeded PRNG); `userfaultfd`/`rseq` are minimal stubs.

> The authoritative, always-current list is the `switch` in `dispatchSyscall`. If you add
> a `case`, add a row here.

---

## 4. Errno values (the common ones)

Returned as the negation of these: `EPERM` 1 · `ENOENT` 2 · `EBADF` 9 · `ENOMEM` 12 ·
`EACCES` 13 · `EFAULT` 14 · `EEXIST` 17 · `ENOTDIR` 20 · `EISDIR` 21 · `EINVAL` 22 ·
`EMFILE` 24 · `EROFS` 30 · `ENOSYS` 38 · `ECHILD` 10 (no children). The internal `-4` is
**not** an errno — it is the "block + retry this syscall" sentinel and never reaches
userspace.

---

## 5. The native object ABI — `HOS_SYS_QUERY = 0x4000`

A single syscall outside the Linux range, dispatched in `kernel_main.d` to
`hosQuery(op, arg, buf, buflen)` (`core/hoscall.d`). It writes a human-readable text
listing into the caller's buffer and returns the byte count (or a negative errno). musl
side: `syscall(0x4000, op, arg, buf, len)` → `rdi=op, rsi=arg, rdx=buf, r10=len`.

| op | name             | returns |
|----|------------------|---------|
| 1  | `HOSQ_OBJECTS`   | object table: each live `ObjType` → count |
| 2  | `HOSQ_IDENTITIES`| identity domains: name, trust, ceiling, state |
| 3  | `HOSQ_NAMESPACES`| namespaces in use (by objId) |
| 4  | `HOSQ_SERVICES`  | services: name, started/stopped |
| 5  | `HOSQ_SYS`       | one-line system summary (object/identity/ns/service counts) |
| 6  | `HOSQ_WHOAMI`    | `"<user>@<namespace>"` for the calling task (the native shell prompt) |

This is **read-only enumeration**; the mutating object ops (cap/grant, ns/clone,
id/freeze, svc/start) are deny-by-default and gated on the identity ceiling — see
[IDENTITY_AND_CAPABILITIES.md](IDENTITY_AND_CAPABILITIES.md) (planned).

The same kernel tables are *also* exposed as a **filesystem** under `/objects`,
`/config`, `/system` — reached via ordinary `open`/`read`/`getdents`, no special syscall.
See [FILESYSTEM.md](FILESYSTEM.md). The native shell `/hos-sh` drives this ABI; busybox
and friends use the filesystem views.

---

## See also

- [FILESYSTEM.md](FILESYSTEM.md) — what paths resolve to, and in what order.
- [NAMESPACING.md](NAMESPACING.md) — how `open` is gated per-process/per-identity.
- `roadmap/DOCUMENTATION_ROADMAP.md` — the rest of the documentation plan.
