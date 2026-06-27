# EpinAnonymOS SMP / Multi-core Roadmap

## North star
Run EpinAnonymOS across all cores of the target box (**i9-9900KF, 8C/16T**). The bare-metal vision
([[bare-metal-lkl]], `BARE_METAL_ROADMAP.md`) is a set of **per-device LKL driver-OSes + the desktop
compositor** — today they timeshare a single core cooperatively, a hard bottleneck. With SMP a usb-lkl, a
gpu-lkl, a net-lkl, and Weston each get their own core and run **in parallel**.

**Scope honesty (from the L5 isolation test, 2026-06-26):** SMP is the right architecture for the
multi-core target, but it is **NOT the fix for the L5 USB-enumeration stall**. That was proven a
transfer-*completion* stall, not CPU starvation: instrumenting the LKL's IRQ-poller thread (a real-time
heartbeat) showed it ran **135 000 polls, free-running on an idle core at the end of the boot, yet the USB
enumeration made zero further progress**. SMP speeds boot and lets drivers + desktop run concurrently; it
does not make a stuck device transfer complete. (It *would* remove the early boot-time CPU contention.)

## Current state (single-core — the starting point)
- **One CPU (the BSP).** No AP (secondary-core) bringup — the kernel never sends INIT/SIPI. `arch/x86_64`
  has the local APIC for the BSP, but no SMP boot path.
- **Cooperative scheduler** (`kernel_main.d:scheduleNext`, ~line 302): a single global
  **`g_current_task_id`**, a single `g_idleTid`, one run cursor. Tasks yield (poll/epoll park, futex,
  nanosleep); the PIT tick drives `wakePollers`. **No preemption.**
- **Pervasive global mutable state, UNLOCKED** — everything assumes a single kernel thread: `g_tasks[]`,
  `g_current_task_id`, `g_taskDevCap[]` (L4), the object/cap tables, the physical-page + heap allocators,
  the fd tables, the poll/epoll arrays, the namespace tables. **Making this concurrency-safe is the bulk of
  the work.**

## Key strategic insight: Big Kernel Lock first
The cheapest path to the *actual goal* (drivers + desktop in parallel) is a **Big Kernel Lock (BKL)**, not
fine-grained locking:
- One global lock taken on every kernel entry (syscall / fault / scheduler) → at most one CPU in the kernel
  at a time → the existing global state stays correct with **zero per-structure changes**.
- But **userspace runs in parallel**: CPU0 runs Weston's userspace while CPU1 runs an LKL's userspace,
  simultaneously. Drivers + the compositor are userspace-heavy, so this captures **most** of the benefit.
- Fine-grained locking (kernel scalability) becomes a later optimization, not a prerequisite.

So: **BKL → working multi-core with userspace parallelism → then lower lock granularity where profiling says
it matters.**

## Phases

- **S0 — Survey + design (no code).** Inventory every `__gshared` mutable structure reachable from a
  syscall/fault (the list above). Decide BKL-first (yes). Decide the per-CPU representation (a per-CPU area
  via `GS`-base). Define the AP idle loop. Add the limine SMP request.
- **S1 — AP bringup.** Use limine's **SMP boot protocol** (it enumerates CPUs and hands each AP an entry
  point + stack — no manual INIT-SIPI trampoline needed, a big simplification vs raw bare metal). Each AP:
  enter the kernel, load a per-CPU GDT/IDT/TSS, switch to the kernel CR3, init its local APIC, enter a
  per-CPU idle loop. **Verify:** each AP prints "CPU N online" and idles; the BSP keeps running the desktop.
- **S2 — Per-CPU state.** A per-CPU area addressed via `GS` (`swapgs` on kernel entry): `currentTask`,
  `idleTask`, local-APIC id, scheduler cursor, a per-CPU scratch stack. Replace the global
  `g_current_task_id` with the per-CPU current task (keep a shim during migration).
- **S3 — Big Kernel Lock.** One spinlock at every kernel entry (syscall/IRQ/fault prologue), released at
  exit (incl. before returning to userspace and around `scheduleNext`). Correct-but-serial kernel,
  **parallel userspace**. **Verify:** an LKL on CPU1 and the desktop on CPU0 both make full-speed progress
  at the same time (the L5 boot-contention disappears).
- **S4 — Per-CPU scheduler.** Per-CPU run queues + a balancer; tasks can be **pinned** (pin each
  per-device LKL to a core — ties into L4 isolation). Idle CPUs run idle or steal work. `scheduleNext`
  becomes per-CPU.
- **S5 — Preemption.** The per-CPU local-APIC timer drives a preemption tick → fair time-slicing *within* a
  core, and removes the cooperative-yield requirement (and the whole cooperative-starvation bug class). The
  real fix for "one task hogs the core."
- **S6 — Fine-grained locking.** Replace the BKL with per-subsystem locks, in contention order: page/heap
  allocator → object/cap tables → fd tables → namespace tables → scheduler queues. Each needs a lock-order
  audit (deadlock avoidance). **The large, careful, long-tail work — do it driven by profiling.**
- **S7 — IPIs.** Inter-processor interrupts for **TLB shootdown** (a CPU editing a shared page table —
  fork CoW / mmap / munmap — must invalidate the other CPUs' TLBs), cross-CPU wakeups, and a reschedule
  IPI. Needs local-APIC IPI send + a per-CPU IPI handler.
- **S8 — SMP-safe device bridge + per-device LKL pinning.** Lock `g_taskDevCap[]` (L4); pin each
  per-device LKL to its own core (S4) so usb-lkl / gpu-lkl / net-lkl truly run in parallel — the production
  realization of the bare-metal vision. The LKL's polled IRQ thread then owns a dedicated core (no
  contention).

## Risks + considerations
- **The global-state audit (S0/S6) is the real cost.** The kernel was written single-threaded; every shared
  structure is a potential race. The BKL (S3) sidesteps this for *correctness*; a fine-grained kernel (S6)
  is a major, careful effort.
- **TLB shootdown (S7)** is subtle and mandatory once page tables are edited concurrently (fork CoW, mmap).
- **The polling model:** EpinAnonymOS polls (no kernel device IRQ). Per-CPU polling + the LKL's polled IRQ
  thread on a dedicated core fit naturally; revisit whether real per-CPU APIC IRQ delivery is wanted.
- **QEMU:** test with `-smp N` (currently `-smp 1`); the host has the cores.
- **Determinism:** the cooperative model is deterministic; SMP introduces real concurrency — expect new
  heisenbugs. Invest in stress tests (and run them under TCG + KVM) early.

## Suggested first cut
**S0 → S1 (APs online) → S2 (per-CPU current) → S3 (BKL)** delivers *drivers + desktop running in parallel*
with bounded effort and no rewrite of the global state. **S4–S8** follow as scaling + correctness demand.
The win at **S3** is exactly the one the bare-metal vision needs; **S6** is the long game.
