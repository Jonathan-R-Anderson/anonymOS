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

## Iteration 4 result — the trace answered, and the answer was silence

The iteration-4 kernel shipped and booted (ISO 19:07 > posix.d 18:33; `grep -a "trace] clone
flags" dist/kernel.elf` → 1). Weston reached libinput's device enumeration, read the four
sysfs uevent files, and stopped. The last kernel-visible event is

    [open] /sys/class/input/event0/uevent          (serial.log:341)

Weston's own clock puts all of it inside **31 ms**; the VM then sat wedged for 9+ minutes
with the vCPU thread holding a full core.

The decision tree lands on **branch 2 — no weston poll line at all** — and this time the
absence is real evidence rather than a starved budget: only **45 of the 300** trace lines
were spent (30 ioctl, 6 poll, 5 recvmsg, 4 sendmsg). ioctl/sendmsg/recvmsg are uncapped, and
clone/futex are still wired, so Weston genuinely issued **none** of the seven traced calls
after that open.

### But the instrumentation could not close it, and iteration 4 caused two of the three gaps

1. **The poll skip filtered by SHAPE, not by task.** It dropped every `nfds=2`/infinite and
   every `nfds=1`/1000 ms poll from *any* task. The justification was that libseat blocks
   weston with `nfds=1, timeout=-1`, which matches neither — but that is an assumption about
   the very thing being measured. Had weston blocked in either skipped shape, the filter
   would have discarded the one line it was added to capture.
2. **`who=` printed `?` on every line.** `g_taskExecName[0]` is null: PID1 is loaded by the
   boot path in `kernel_main.d` (~:4388), not through `execveTask`, so it never passes the
   boot-module scan at :1041 that assigns `execName`. tid 3 inherits the null from tid 0 via
   fork (:886). The tid half worked (0=weston, 2=sshd launcher, 3=seatd child); the name
   half was a no-op in every diagnostic, including the freeze HUD and crash HUD.
3. **Nothing could separate "weston blocked" from "kernel wedged".** `[open]` is logged at
   syscall *entry* (posix.d:3544) with no return, so it is not even known whether that last
   `open()` came back. And the new skip silenced the sshd launcher's 1 Hz poll — the log's
   last remaining liveness heartbeat. Nothing else in `kernelLoop` prints periodically:
   every `maybeSpawn*` that would log is latched off (dbus/NM/nmcli by `useDirectWifi()`,
   wpa/udhcpc by the absent `/run/hos-net.sock`, since `[lkl] no driveable PCI device`), and
   `freezeProbeKlog` returns immediately unless the desktop has **already presented a
   frame** — so the freeze watchdog is structurally incapable of firing for a hang that
   happens before the first present.

The 100 % CPU is not evidence either way: `kernelLoop` (kernel_main.d:3803) never halts
while any task exists — it runs `/idle` instead.

## Iteration 5 — stop instrumenting; measure the guest directly

Four rebuild-and-guess cycles happened because the VM is launched with **no monitor and no
gdbstub**, so a wedged guest can only be re-instrumented, never inspected.

**Changed:**
- `qemu-run.sh`: always pass `-monitor unix:$PWD/mon.sock,server=on,wait=off` (and `rm -f`
  it alongside `qmp.sock`). QMP stays on `qmp.sock` for the GPU path; the two coexist.
- `posix.d hangTracePoll()`: collapse by **(task, shape)** instead of by shape. The first
  poll of a given shape from a given task always prints; only a re-arm of that same shape by
  that same task is dropped. Per-task cap (32) for fairness, global 300 as a backstop. This
  cannot hide a task the way the shape filter could.
- `posix.d hangTraceWho()`: bounds-guard the tid index.
- `kernel_main.d`: set `g_taskExecName[0] = initExecName` where PID1 is loaded, so the
  compositor is named in the hang trace, the freeze HUD and the crash HUD.

**The measurement that makes the next iteration unnecessary** — no rebuild required, works
on the ISO already built:

    for i in $(seq 5); do echo "info registers" | nc -N -U mon.sock | grep -E '^[RE]IP'; sleep 1; done

    The `-N` is load-bearing: OpenBSD `nc` does not `shutdown(SHUT_WR)` on stdin EOF without
    it and HMP never closes its side, so a plain `nc -U` gets the dump and then blocks forever
    — the loop wedges on iteration 1. (Reproduced against a live QEMU 10.2.4 HMP socket:
    exit=124 after `timeout 4` without `-N`, exit=0 in 0s with it.) Do NOT append `quit` the
    way `scripts/qemu-g*-verify.sh` do — that kills the VM.

- RIP in kernel space and **moving** → the kernel loop is alive; weston is blocked in
  userspace, and the syscall it is parked in is one not yet traced.
- RIP in kernel space and **pinned** → the kernel is wedged inside that last `open()`.
- RIP in weston's range (`0x5a00_…`) → weston is spinning in userspace; no syscall involved,
  which is why no trace line was ever going to appear.

That single reading halves the search space in two minutes instead of a 30-minute Docker
rebuild, and it is the branch every previous iteration was implicitly guessing at.

### Unrelated, observed while diagnosing
- `wifi-host-bridge.log`: `setsid: failed to execute python3` — the host WiFi bridge never
  starts on this NixOS box, so `/run/wifi/*` is never fed.
- QEMU emulates COM2 regardless of whether a host peer connected, so the 16550 scratch probe
  still sets `g_wifiBridgePresent = true`. The guest therefore runs `wifiBridgePoll()`'s
  ~12k-node overlay scan at 10 Hz, under the BKL, for a bridge that is not there.

## Iteration 5 result — SOLVED. Weston spins in libudev-zero, in userspace.

The monitor socket did what five rounds of printf could not, in about two minutes.

**Step 1 — the same hang reproduces in VirtualBox**, byte-for-byte: identical last six log
lines, identical trace counts (30 ioctl / 4 sendmsg / 5 recvmsg). Not a QEMU device quirk.

**Step 2 — the kernel was never the problem.** The VirtualBox VM has 2 CPUs, so the AP
progress heartbeat at `kernel_main.d:3975` — which lives *inside* `kernelLoop`, right after
`increment_ticks()` and just before `wakePollers()`/`scheduleNext()` — keeps printing after
Weston goes silent, with `apicTicks`, `getpid`, `ipiCount` and `allocNoBKL` all climbing.
QEMU could never show this because it was run `-smp 1`, so `g_apSyscallCount` stays 0 and the
heartbeat never arms. **`SMP=2 ./qemu-run.sh` reproduces the heartbeat in QEMU too.**

**Step 3 — sample the guest RIP over `mon.sock`:**

    CPU#0  RIP=000074000005b3b8  CPL=3      <-- ring 3: USERSPACE
    CPU#0  RIP=000074000005b3bc  CPL=3
    CPU#0  RIP=000074000005b3bc  CPL=3

`CPL=3`, oscillating over four bytes. Weston is **spinning in userspace**, which is exactly
why no trace line ever appeared: it issues no syscalls at all. Disassembling there:

    b3b0:  movq  (%r14), %r14        ; entry = entry->next
    b3b3:  testq %r14, %r14
    b3b6:  je    out
    b3b8:  movq  0x10(%r14), %rdi    ; rdi = entry->name          <-- pinned here
    b3bc:  testq %rdi, %rdi
    b3bf:  je    b3b0                ; name == NULL -> next        <-- and here

That is `udev_list_entry_get_by_name()` from **libudev-zero 1.0.4**, statically linked into
libweston (`struct udev_list_entry { next@0x00; value@0x08; name@0x10; }` — matches exactly).
`RSI`/`R15` point at the search key, which reads:

    LIBINPUT_CALIBRATION_MATRIX

and the node it is stuck on is:

    0x7400007f6fb0:  next  = 0x7400007f6fb0     <-- points to ITSELF
                     value = 0x7400007f6fb0
                     name  = NULL

**The bug:** `udev_list_entry_get_by_name()` walks the property list with a plain
NULL-terminated loop (`while ((list_entry = list_entry->next))`). One self-referential `next`
and it never terminates. libinput trips it on *every* input device because it looks up
`LIBINPUT_CALIBRATION_MATRIX` — a property that is **normally absent**, so the lookup always
walks all the way to the end of the list. Present keys (`ID_SEAT`, `ID_INPUT_KEYBOARD`, …)
return early, which is why device setup gets as far as it does before wedging.

**Fixed** in `deps/weston/Makefile`: the `libudev-built` rule now patches the walk to be
bounded, so an absent key fails closed (`NULL` = "not found", which is what libinput expects)
instead of hanging the compositor. The rule gained `$(SELF)/Makefile` as a prerequisite so
editing the patch forces a rebuild, and a `grep` guard fails the build loudly if upstream text
drifts and the `sed` silently no-ops.

### Still open
The self-referential node is a *symptom* — something produced a list whose `next` points at
itself, with `value` aliasing the same address and `name` NULL. The guard stops the hang but
does not explain the corruption. `udev_list_entry_add()` does
`list_entry2->next = list_entry->next; list_entry->next = list_entry2;`, which yields exactly
this shape if `calloc()` ever hands back a block aliasing the list head — worth checking the
kernel's `mmap`/`brk` for overlapping allocations (note the `[mmap-einval] len=0` line that
appears in every boot log).
