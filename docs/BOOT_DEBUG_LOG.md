# Desktop boot debugging log

Why the container-built ISO boots the kernel fine but never paints a desktop, and
what each iteration changed. Newest entry last.

## Symptom (constant across QEMU and VirtualBox)

Kernel boots completely, every selftest PASSes, `[install] READY`. Weston starts,
picks the Pixman renderer, enumerates devices, then goes silent — no output
created, no `/dev/input/event*` opened, no error. The kernel keeps running (SMP
heartbeat continues), so weston is *blocked*, not dead.

## Iteration 1 — DRM master EFAULT

**Found:** `handleDrmIoctl` (`src/kernel/d/core/syscalls/posix.d:12300`) had a blanket
`if (arg == 0) return negErrno(EFAULT);`. `SET_MASTER`/`DROP_MASTER` are `DRM_IO()`
ioctls carrying no argument — seatd calls `ioctl(fd, DRM_IOCTL_SET_MASTER, 0)`
(seatd-0.9.1 `common/drm.c:17`) — so the guard answered them EFAULT and made
`case DRM_NR_SET_MASTER: return 0;` (:12394) unreachable dead code.
Traced by 10 agents across weston 14, libseat/seatd 0.9.1, libinput 1.29.2,
libudev-zero and the kernel; all five verifiers independently converged on it.

**Changed:** exempt those two opcodes from the NULL-arg guard.

**Result:** `Could not make device fd drm master: Bad address` is GONE. Weston now
gets *past* the seat setup and completes KMS enumeration — 30 DRM ioctls
(GET_CAP, SET_CLIENT_CAP, GETRESOURCES, GETPLANERESOURCES, GETPLANE,
OBJ_GETPROPERTIES, GETPROPERTY, SET_MASTER ×1). Then it stops again.

## Iteration 2 — syscall tracing (poll/ioctl/sendmsg/recvmsg)

**Changed:** entry traces in `posix.d` for ioctl (fd+cmd), sendmsg/recvmsg
(fd+flags), poll/ppoll (nfds+timeout, capped at 300 so a polling loop cannot
flood the UART).

**Result:** ioctls are BOUNDED (30 total, then none) — so weston is not looping in
DRM. Afterwards only two pollers tick: nfds=2/timeout=-1 (the forked seatd child's
poller) and nfds=1/timeout=1000ms (the sshd launcher). Neither is weston.
No `sendmsg`/`recvmsg` from weston at all, which rules out the libseat
`open_device` round trip — weston never reaches it.

**Narrowed to:** libudev-zero's device scan (`udev_enumerate.c:288-302`) spawns one
pthread per `/sys/dev/char` entry (card0, renderD128, event0, event1 — exactly the
8 uevent reads in the log) and `pthread_join`s them. The kernel logs
`[clone] parent= thread= stack=` unconditionally on every successful thread
creation (`kernel_main.d:915`) — and **no `[clone]` line ever appears**. So the
threads are never created and the join can never return.

## Iteration 3 — clone/futex tracing (current)

**Changed:**
- `kernel_main.d` case 56: trace every `clone()` entry with flags+stack, *before*
  the `CLONE_VM` branch, to see whether clone is reached at all.
- `posix.d linux_sys_futex`: bounded trace of op/uaddr/val, with its own counter so
  the poll flood cannot starve it — `pthread_join` parks in FUTEX_WAIT with no
  timeout, so the last futex line before silence names the wait that never woke.
- `qemu-run.sh`: `HEADLESS=1` now works on the software path (`-display none`), so
  the VM can be booted from a non-interactive shell and diagnosed from serial.log.

**Expected outcomes:**
- `[trace] clone flags=...` appears → threads ARE requested; the bug is in
  cloneThread or the futex wake on thread exit (`CLONE_CHILD_CLEARTID`).
- No `[trace] clone` at all → musl's `pthread_create` failed before issuing clone,
  most likely the thread-stack `mmap`; next iteration traces mmap failures.

## Iteration 3 result — both theories dead

The traced kernel DID ship (`grep -a "trace] clone flags" dist/kernel.elf` → 1) and booted
(serial.log 16:47 > ISO 16:34), and it logged:

- **zero `[trace] clone`** — `clone()` is never called. No thread is ever requested, so
  libudev-zero's threaded scan is NOT what runs here and the `pthread_join` theory is dead.
  The eight uevent reads were done serially by weston's main thread.
- **zero `[trace] futex`** — no futex syscalls at all, consistent with a single-threaded
  process whose locks are uncontended.

**But the poll trace hid the answer.** Its 300-line budget was consumed entirely by two idle
processes that the kernel re-arms every tick: the forked seatd child (`nfds=2`, infinite)
and the sshd launcher (`nfds=1`, 1000 ms). libseat blocks weston with `poll(&fd, 1, -1)` —
`nfds=1` AND infinite — which matches neither pattern and would have appeared, had there
been any budget left when weston reached it.

## Iteration 4 — make the trace attributable and stop wasting the budget

**Changed** (`src/kernel/d/core/syscalls/posix.d`):
- `hangTraceWho()`: every `[trace]` line now ends with `who=<tid>:<execname>`, using
  `g_taskExecName[g_current_task_id]` (the same accessor the freeze watchdog uses at
  :11322). Previously the poll lines were unattributable and weston, seatd and the sshd
  launcher were indistinguishable.
- `hangTracePoll()`: skips the two known re-arm patterns before spending budget, so the 300
  lines go to NOVEL polls.

**Expected outcomes:**
- `[trace] poll nfds,timeout a=1 b=ffffffffffffffff who=N:weston` → weston IS blocked in
  libseat's `poll_connection`, and the bug is the seatd round trip (the child never answers
  `CLIENT_OPEN_DEVICE`, or the reply never wakes the parent).
- No weston poll line at all → weston is blocked in a syscall not yet traced; next step is
  to trace the syscall dispatcher itself for that task id.
