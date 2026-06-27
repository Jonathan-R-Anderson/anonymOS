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

## Status (2026-06-27): S0 + S1 + S2 + S3 (lock) + S4 foundation + S4.1 (per-CPU GDT/TSS) DONE + verified

The first two phases are implemented and boot-verified — **the kernel now discovers the live core count and
brings every AP online**, with no hardcoded count:
- **S0 (dynamic discovery):** the limine **SMP request** (`arch/x86_64/limine.d` `limine_smp_request/response/
  info`, declared in `core/kmain.d` between the limine request markers); `smpBringup()` reads
  `response.cpu_count` + `bsp_lapic_id` at runtime. `MAX_CPUS=256` is a compile-time ceiling; the live count
  comes from limine. **No magic 8.**
- **S1 (AP bringup):** for every AP (`lapic_id != bsp_lapic_id`) the BSP stashes a per-CPU index in
  `extra_argument` and writes `apEntry` to its `goto_address`; the AP jumps there, marks `g_cpuOnline[idx]`,
  and parks (`cli; hlt`). The BSP waits (bounded) for all APs, then logs the tally. Runs early (while limine's
  page tables are active, so the APs share the BSP's address space for their memory-trivial idle).
- **`qemu-run.sh` gained an `SMP=N` knob** (default 1) so any core count is testable from one binary.
- **S2 (per-CPU state):** `struct PerCpu` (`selfPtr`@0 / `cpuIndex` / `lapicId` / `currentTask` / `idleTask` /
  `schedCursor`) and `g_percpu[MAX_CPUS]` — **one area per discovered CPU, sized to the runtime N.**
  `smpBringup` lays them out before releasing the APs; each AP then sets its **`IA32_GS_BASE`** to its area
  and verifies `%gs`-addressing round-trips (`readGsBase()` → `selfPtr`/`cpuIndex` match). `thisCpu()` /
  `thisCpuTask()` accessors; the BSP's `currentTask` is the **shim** that mirrors the global
  `g_current_task_id` (S3 makes the per-CPU field authoritative + adds swapgs). ★ KEY SAFETY: `IA32_GS_BASE`
  is the *same* MSR `arch_prctl(ARCH_SET_GS)` writes, so it is UNSAFE in the live syscall path without
  swapgs (userspace can clobber it) — S2 sets+verifies GS only on the **parked APs** (which never run
  userspace) and addresses the BSP's area **by index**; the swapgs live-path migration is S3.
- **S3 (Big Kernel Lock — the lock primitive, proven cross-core):** a correct test-and-set spinlock
  (`bklAcquire`/`bklRelease`; `xchg` with a memory operand is atomic on x86, no LOCK prefix). Proven by the
  **first real concurrent kernel code in the OS:** the BSP + every AP each increment a shared `g_bklCounter`
  100 000 times *only under the BKL*; a correct lock loses no updates → the counter must equal N × 100 000.
  ★ The live-entry-path wiring (taking the BKL in the syscall/IRQ/fault prologue) is deliberately deferred to
  **S4** — with the APs parked and running NO kernel code, wrapping the entry path serializes nothing and only
  adds prologue risk; so S3 here delivers the *load-bearing correctness* (a lock that actually mutually-excludes
  the real cores), and S4 wires it in once APs run tasks.
- **S4 foundation (sustained parallel AP execution):** instead of parking, each AP now runs a continuous
  kernel worker keyed off its **GS-addressed per-CPU area** — `++pc.heartbeat` lock-free (each `PerCpu` is
  cache-line-sized + 64-aligned, so the per-CPU writes never false-share), touching a shared `g_apWorkTotal`
  under the BKL every 65 536 iterations. So **N − 1 cores do real, continuous, BKL-coordinated kernel work
  while the BSP boots the whole desktop.** A post-desktop `smpWorkReport()` reads the counters to prove the
  parallelism actually overlapped the boot. ★ This is the *execution* foundation S4's scheduler needs proven;
  real per-CPU **tasks** (a per-CPU scheduler picking a task + swapgs + the entry-path BKL so an AP can `iret`
  to userspace) are the remaining full-S4 work.
- **Verified in-VM:** `SMP=4` → `4 CPUs discovered` + `3 of 3 APs online; 3 GS-addressed per-CPU verified` +
  **`BKL: counter=0x61a80 expected=0x61a80 PASS`** (4×100 000, zero lost updates) + **`AP parallel work … cpu1=
  0x0ac66eb0 cpu2=0x0a916059 cpu3=0x09a35d53; sharedWork=0x1f18`** + **`S4 foundation PASS: every AP ran
  sustained parallel kernel work`** (each AP did ~170 M lock-free iterations + the shared total is consistent
  with no lost updates — all while the desktop's 11 domains loaded), 0 faults, desktop boots. `SMP=1` →
  `counter=0x186a0` PASS + `single-core: no AP workers`, desktop boots — **degrades gracefully.**
- **S4.1 (per-CPU GDT + TSS + IST/kernel stack):** the kernel-entry path (`context.S`) uses ONE global TSS
  (`tssArea`, one shared kernel stack) + one `curUserSpaceState` + one IST — so two CPUs entering the kernel at
  once would corrupt them *before* any BKL could help. The unavoidable prerequisite is per-CPU entry state.
  S4.1 lands the first + load-bearing piece: each AP gets its **own GDT** (canonical kcode/kdata/ucode/udata +
  its own TSS descriptor — `ltr`'s busy bit forbids two CPUs sharing one) + **own TSS** (own `rsp0`/`ist1`
  kernel stack) + **own 8 KiB IST stack** (`arch/x86_64/gdt.d`: `prepareApCpuState`/`g_apGdt`/`g_apTss`). The
  **BSP builds them single-threaded before releasing the APs** (no allocator race); each AP `loadGdt`+`loadTr`s
  its own copy on entry. ★ TRAP 1: `loadGdt` reloads every segment selector incl. `%gs ← kdata (base 0)`,
  wiping the S2 GS base — so the AP re-runs `setGsBase` + re-verifies right after. ★ TRAP 2: `_start` runs
  `smpBringup` *before* `bootstrap_kernel→init_gdt`, so the BSP `gdt[]` is still zero then — building the AP GDT
  by *copying* it handed the AP a null code segment → `loadGdt`'s `lretq $0x08` triple-faulted (with
  `-no-reboot`, that froze the VM after "CPUs discovered"). Fixed by building from canonical descriptor values.
  **Verified `SMP=4`:** `3 of 3 APs installed their own per-CPU GDT/TSS (S4.1: ready for kernel entry)`, `str`
  confirms `TR==0x28`, the GS-driven workers keep running (~170 M iters → GS survived the reload), 0 faults,
  desktop boots; `SMP=1` unaffected.

**Next (S4.2 + the rest of full S4):** the descriptor foundation is in place; remaining is per-CPU **IDT** + per-
CPU **`curUserSpaceState`** + a per-CPU **syscall entry** (each AP's own `LSTAR` → a `swapgs`+BKL-aware stub) +
the **AP scheduler** picking a task + `iret`-to-ring3, plus taking the proven BKL on the **BSP's** entry too (so
the two CPUs are mutually excluded in the kernel). That is the point an AP runs a *real task* (the desktop on
CPU0, an LKL on CPU1) in parallel — the bare-metal-vision payoff. The parallel-execution, lock, and per-CPU
descriptor primitives it needs are now all proven.

## Phases

- **S0 — Survey + design (no code).** ✅ *(limine SMP request + runtime discovery — see Status above).* Inventory every `__gshared` mutable structure reachable from a
  syscall/fault (the list above). Decide BKL-first (yes). Decide the per-CPU representation (a per-CPU area
  via `GS`-base). Define the AP idle loop. Add the limine SMP request.
- **S1 — AP bringup.** ✅ *(every AP online + parked; verified `SMP=4` → 3 APs, `SMP=1` degrades — see Status).* Use limine's **SMP boot protocol** (it enumerates CPUs and hands each AP an entry
  point + stack — no manual INIT-SIPI trampoline needed, a big simplification vs raw bare metal). Each AP:
  enter the kernel, load a per-CPU GDT/IDT/TSS, switch to the kernel CR3, init its local APIC, enter a
  per-CPU idle loop. **Verify:** each AP prints "CPU N online" and idles; the BSP keeps running the desktop.
- **S2 — Per-CPU state.** ✅ *(per-CPU areas sized to runtime N; GS-addressing verified on every AP; BSP shim — see Status; swapgs live-path migration deferred to S3).* A per-CPU area addressed via `GS` (`swapgs` on kernel entry): `currentTask`,
  `idleTask`, local-APIC id, scheduler cursor, a per-CPU scratch stack — **one entry per discovered CPU,
  sized to the runtime N (allocated for the live count; never a fixed 8).** Replace the global
  `g_current_task_id` with the per-CPU current task (keep a shim during migration).
- **S3 — Big Kernel Lock.** ◑ *(the lock PRIMITIVE is done + proven cross-core — `bklAcquire`/`bklRelease`, 4×100k increments, zero lost updates; the entry-path wire-in is deferred to S4 when APs run kernel code — see Status).* One spinlock at every kernel entry (syscall/IRQ/fault prologue), released at
  exit (incl. before returning to userspace and around `scheduleNext`). Correct-but-serial kernel,
  **parallel userspace**. **Verify:** an LKL on CPU1 and the desktop on CPU0 both make full-speed progress
  at the same time (the L5 boot-contention disappears).
- **S4 — Per-CPU scheduler.** ◑ *(FOUNDATION done — APs run sustained parallel kernel work keyed off their GS per-CPU area, BKL-coordinated, ~170 M iters/AP while the desktop boots; the per-CPU run queue + userspace-task path remains — see Status).* Per-CPU run queues + a balancer; tasks can be **pinned** (pin each
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
