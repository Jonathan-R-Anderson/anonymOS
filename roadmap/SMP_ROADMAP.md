# EpinAnonymOS SMP / Multi-core Roadmap

## North star
Run EpinAnonymOS across **all cores the host actually exposes — discovered at runtime, with NO fixed
limit.** The dev/target box happens to be an i9-9900KF (8C/16T), but **8 must never be hardcoded anywhere**:
the kernel enumerates the CPUs at boot and scales to whatever it finds — a 2-core VM, a 16-core laptop, a
64-core workstation — all from the same binary. The bare-metal vision ([[bare-metal-lkl]],
`BARE_METAL_ROADMAP.md`) is a set of **per-device LKL driver-OSes + the desktop compositor** — today they
timeshare a single core cooperatively, a hard bottleneck. With SMP a usb-lkl, a gpu-lkl, a net-lkl, and
Weston each get their own core and run **in parallel** — and on a bigger host, more drivers/apps spread
across more cores with zero code changes.

## Dynamic core count (HARD REQUIREMENT)
- **Discover N at runtime** from the limine SMP response (it returns the live CPU list) — fall back to the
  ACPI **MADT** (LAPIC entries) if needed. Never assume a count.
- **No magic 8.** Per-CPU structures are sized to the discovered N: either a runtime-allocated array of
  per-CPU areas (`percpu[N]`), or a generous compile-time `MAX_CPUS` (e.g. 256/512) indexed by the live
  count — never a literal 8. Run queues, idle tasks, APIC-id tables, and IPI bookkeeping all scale to N.
- **Bring up every AP** the firmware reports (not the first 8); each that comes online joins the scheduler.
- **Degrade gracefully:** N==1 must still boot (today's path); the code is "for each online CPU", so 1, 8,
  or 128 are the same logic. Optionally honor an `smp=` cap for debugging, defaulting to "all".

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

- **S4 — Per-CPU scheduler.** ◑ *(an AP RUNS A USERSPACE TASK in parallel with the desktop — S4.4a–d, the core goal — and tasks can be PINNED (the AP task is pinned, BSP-invisible); what remains of the FULL S4 is per-CPU run queues + a balancer + work-stealing so an AP picks from MULTIPLE tasks, not the one hardcoded pinned task — see Status).* Per-CPU run queues + a balancer; tasks can be **pinned** (pin each
  per-device LKL to a core — ties into L4 isolation). Idle CPUs run idle or steal work. `scheduleNext`
  becomes per-CPU.
- **S6 — Fine-grained locking.** ◑ *(REPRESENTATIVE slice done: the page allocator — top of the contention order — has its own leaf lock (`memory/mm.d` `g_physAllocLock`; `alloc_phys_page`/`alloc_phys_pages`/`free_phys_page` wrapped), so any CPU allocs/frees WITHOUT the BKL. Verified: the AP did 47+ alloc/free cycles lock-free-of-BKL, concurrent with the BSP's desktop allocs, 0 faults/OOM. The remaining subsystems are the long game — see below.)* Replace the BKL with per-subsystem locks, in contention order: page/heap
  allocator → object/cap tables → fd tables → namespace tables → scheduler queues. Each needs a lock-order
  audit (deadlock avoidance). **The large, careful, long-tail work — do it driven by profiling.**
- **S8 — SMP-safe device bridge + per-device LKL pinning.** ◑ *(MECHANISMS in place: `g_taskDevCap[]` now has its own leaf lock (`posix.d` `g_devCapLock` — the accessors wrapped → SMP-safe device bridge); and the AP's task is PINNED to its core (BSP-invisible, never migrates — verified `AP task tid=1 PINNED to CPU idx 1`). What remains is the PRODUCTION integration: running a real device LKL (usb-lkl/gpu-lkl/net-lkl) as the pinned task — the bare-metal-LKL bring-up on top of this SMP foundation, a large separate effort.)* Lock `g_taskDevCap[]` (L4); pin each
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
