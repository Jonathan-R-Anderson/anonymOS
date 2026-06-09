# Desktop Responsiveness Roadmap

Goal: make the EpinAnonymOS Weston desktop feel snappy — input registers instantly,
windows repaint immediately, the frame rate is high. Ordered so we can go straight
down the list; each step is independently shippable and verifiable.

## Baseline (measured 2026-06-08, KVM on, 1280×800)

Profiled with the kernel `presentProfStats` / `schedProfStats` / `fdReadableStats`
instrumentation (see [[weston-perf-profiling]]):

- **Kernel present blit = ~5-7 ms but only ~1.4% of a 390-518 ms frame.** Not the
  bottleneck.
- **poll/epoll never blocked** → every event-loop thread busy-spun → the compositor
  got ~9% of the single core. **Fixed** (commit de2813b67): poll/epoll now park.
- **fps is gated by Weston present-pacing** — Weston coalesces ~23 client redraws
  into ~2 presents (~5 presents in 60 s).
- **~40% of paced keystrokes are dropped** before reaching the focused client.
- **No kernel-mode IRQ handling** (IDT maps CPU exceptions only; hardware IRQs fire
  only while in userspace) → the run loop can't `sti;hlt` to idle, so it still spins
  when fully idle.

Legend: **P** priority · **E** effort (1=hrs … 5=weeks) · **R** risk · deps.

---

## R1 — Input never drops  ·  P: Critical · E: 2 · R: low · deps: —

A keystroke/click that doesn't register feels worse than low fps. ~40% of paced
keys are lost today.

- Instrument the input path end-to-end: count scancodes the i8042 IRQ reads, events
  enqueued into `g_kbd_ring`/`g_mouse_ring`, ring overflows (drops), and events
  Weston consumes from the `FD_INPUT_EVENT` fd. Find where the 40% is lost.
- Likely culprits: (a) `handleKbdIRQ` not draining the i8042 output buffer fully per
  IRQ (multiple scancodes queued, only one read → i8042 overflow); (b) `g_kbd_ring`
  too small / overwritten; (c) Weston/libinput coalescing; (d) the old busy-spin
  starved Weston from draining input fast enough (may already be better post-de2813b67).
- Fix the dominant loss: drain the i8042 fully per IRQ, grow the rings, ensure the
  input fd wakes Weston promptly (the parking wake already covers this).
- *Verify:* send N paced keys via QMP `send-key`; ≥99% reach the focused client
  (`DOMAINMGR: key` count ≈ N). No dropped clicks in interactive use.

## R2 — Weston presents every frame it should  ·  P: Critical · E: 3 · R: med · deps: —

The real fps lever. Weston turns ~23 client redraws into ~2 presents — it is not
scheduling/committing repaints promptly.

- Instrument Weston-side: a `WESTON_HOS_PERF` build that logs, per output frame, the
  repaint-schedule → composite → page-flip → flip-complete timeline (timespecs).
  Rebuild `libweston` + `drm-backend` (ninja in build-epin).
- Determine why repaints coalesce: (a) repaint gated on a slow timer; (b) waiting on
  the flip-complete event (check the kernel `drmQueueFlipEvent` → card-fd-readable →
  Weston-wakes latency); (c) damage not scheduling a repaint; (d) the headless/DRM
  output's frame callback cadence.
- Fix so a client commit reliably yields a present within one refresh interval.
- *Verify:* 30 manager redraws → ≥~30 presents (`presentProfStats frames`); fps
  approaches the 60 Hz the mode advertises; screenshot tracks input within ~1 frame.

## R3 — Proper idle (stop spinning when there's nothing to do)  ·  P: High · E: 2 · R: med · deps: R4(ideal)

The poll/epoll parking (de2813b67) can't pay off while the all-idle fallback
force-wakes the pollers (because the kernel can't `hlt`). Give the scheduler a real
idle so the compositor gets the whole core during bursts and the CPU sleeps when idle.

- Interim (no R4): a dedicated **idle task** — a tiny userspace stub that `pause`-loops
  with interrupts enabled, scheduled only when every real task is parked. Keeps IRQs
  flowing without N pollers spinning (1 idle task instead of 5 spinners). Reduces idle
  CPU/heat and stops the helpers stealing the compositor's core between events.
- Proper (with R4): the run loop `sti; hlt`s when nothing is runnable and wakes on the
  next IRQ.
- *Verify:* `schedProfStats` at idle shows ~0% across real tasks (only the idle task /
  hlt); during a compositing burst the compositor (weston tid) gets the majority share.

## R4 — Kernel-mode interrupt handling  ·  P: High · E: 3 · R: med · deps: —

Today hardware IRQs are caught only while in userspace (returned as a "reason" from
`x64SwitchToUserspace`); the IDT (arch/x86_64/interrupts.d) maps CPU exceptions only.
This blocks a true `hlt` idle (R3) and preemption (R6), and adds a userspace round-trip
to every IRQ.

- Add IDT gates for the PIC/APIC IRQ vectors (0x20-0x2C) with real kernel-mode ISRs
  that run `increment_ticks`/`wakePollers`/input handling directly, save/restore state,
  and EOI — working whether the CPU was in user or kernel mode.
- Lets the run loop idle with `sti; hlt` (R3) and is the substrate for a preemption
  timer (R6) and per-CPU APIC timers (R7).
- *Verify:* take a PIT/keyboard IRQ while parked in the kernel `hlt` and resume
  correctly; existing userspace-trap path still works; no regression in syscalls.

## R5 — Cheap present wins (damage-tracked KMS blit + fast copy)  ·  P: Med · E: 2 · R: low · deps: —

Small (~1.4% of frame) but easy, and helps once R2 raises the present rate.

- Make the KMS `drmPresentFb` path damage-aware (Weston's DRM backend already tracks
  per-output damage; pass the damage rect like the HOS_PRESENT path does, blit only
  changed scanlines).
- Use non-temporal/SSE stores for the framebuffer copy (WC/MMIO writes ≈1 GB/s with a
  plain memcpy; `movnti`/`movntdq` can be several× faster).
- *Verify:* `presentProfStats present_us` drops for small damage; full-screen unchanged.

## R6 — Preemptive scheduling  ·  P: Med · E: 4 · R: high · deps: R4

The scheduler is cooperative — a task that doesn't yield (or a tight userspace loop)
can monopolize the core until the next syscall/IRQ. Add time-slice preemption.

- On the PIT/APIC tick (R4), if the current task has run past its quantum, save it and
  `scheduleNext` — so no task can hog the core, and the compositor is guaranteed turns.
- Requires the kernel-mode IRQ path (R4) to preempt userspace safely + careful state
  save (already mostly present via the trap mechanism).
- *Verify:* a deliberate userspace busy-loop no longer freezes the desktop; input/repaint
  latency stays bounded under load.

## R7 — Multi-core (SMP)  ·  P: Med · E: 5 · R: high · deps: R4, R6

The single core is the hard ceiling: the compositor, every app, and the kernel all
time-share one CPU. True parallelism lets the compositor run on its own core.

- **R7a — Big Kernel Lock SMP (pragmatic first):** boot the APs (APIC AP startup,
  per-CPU GDT/IDT/TSS/stacks, per-CPU current-task + run queue), run userspace in
  parallel on N cores, take one global lock on kernel entry (preserves the single-core
  kernel invariants — no need to lock every `__gshared` table yet). Because the wasted
  cycles are userspace, this alone lets the compositor composite on its own core.
- **R7b — Fine-grained locking (later):** replace the BKL with per-subsystem locks
  (object table, fd/cap tables, allocator, scheduler) for real kernel scalability.
- Plumbing: per-CPU APIC timers, IPIs, TLB shootdowns for the shared address space.
- *Verify:* `-smp 4`; `schedProfStats` shows the compositor pinned to its own core at
  high utilization while helpers run elsewhere; fps scales.

## R8 — GPU-accelerated compositing  ·  P: Med · E: 5 · R: high · deps: —

The deepest lever: today Weston composites every pixel on the CPU (Pixman). A real GPU
path removes that entirely.

- virtio-gpu (VIRGL/venus) in QEMU + a Mesa virtio driver in the guest, or a native GPU
  driver; wire Weston's GL renderer (the softpipe/llvmpipe path already exists from the
  Hyprland era — see [[weston-pivot]] / GUI progress) onto real acceleration.
- *Verify:* GL renderer active; compositing time drops to ~free; fps hits refresh.

---

## Milestones

- **M-R1 Snappy input.** R1: keystrokes/clicks never drop. *(highest felt win)*
- **M-R2 Real frame rate.** R2 (+R5): commits present within a frame; fps approaches 60.
- **M-R3 Quiet idle.** R3+R4: CPU sleeps when idle; compositor owns the core in bursts.
- **M-R4 Robust scheduling.** R6: no task can freeze the desktop.
- **M-R5 Parallel.** R7: compositor on its own core; fps scales with cores.
- **M-R6 Accelerated.** R8: GPU compositing; software-render ceiling gone.
