# Windows Disappearing — Investigation Roadmap

**Status: OPEN.** Windows render once when they map, then vanish permanently. The coloured
per-window identity borders stay on screen. Not flickering — stable, gone.

This file records what has been measured, what was tried, and what did **not** work, so the next
attempt does not re-run a dead end. Several confident diagnoses in this investigation were wrong;
they are kept below rather than deleted, because knowing a theory is dead is the useful part.

---

## 1. Current symptom

| | |
|---|---|
| Windows | render correctly on first map, then disappear permanently |
| Borders | remain visible (they are drawn by the **kernel**, not the compositor) |
| Flicker | none any more — earlier boots flickered, now it is a single permanent loss |
| Windows still mapped? | **yes** — `[g5] windows=` holds at 5 for the whole session |
| Client exits / crashes | **none** — no `COMPOSITOR DIED`, no faults, no exits |
| Presents in last boot | **60 total** for the whole session |

Why the borders survive: `hosDrawIdentityBorders()` (`src/kernel/d/core/syscalls/posix.d`) is
called from `drmPresentFb()`, from `drmPresentToFramebuffer()`, **and directly from
`drmSetHosWindows()`** (the `HOS_WINDOWS` ioctl, nr `0xf1`), whose own comment says it paints
"even without a fresh present blit". So borders are repainted on window-list changes independent
of the compositor. Their presence proves nothing about the compositor.

---

## 2. Attempts, in order

| # | Change | Commit | Outcome |
|---|---|---|---|
| 1 | `rounding = 0`, `dim_inactive = false` on the softpipe path | `5a818b018b` | **Helped.** Freeze events 40 → 18; longest stall 6s → 2s; stalls ≥3s: 12 → 0. Rounded corners are a per-fragment SDF and `rounding_power = 2.5` evaluates a `pow()` per pixel per window per frame |
| 2 | DRM cursor-disable ioctl returns success instead of `EINVAL` | `5a818b018b` | **Worked, cosmetic.** 437 `legacy drm: cursor null failed` per boot → 0. Removed a per-frame synchronous serial write; did not change the bug |
| 3 | `presentProfStats()` driven off a 5s wall clock | `5a818b018b` | **Instrumentation.** Its only call site was gated on `(g_objReconcileCtr & 0x3FFF) == 0`, which never fires in a desktop boot — a full Hyprland log had **zero** `[present]` lines |
| 4 | Build stamp via `__DATE__`/`__TIME__` klog'd at boot | `2761c9199f` | **FAILED — do not retry.** Printed an identical `18:09:00` from two ISOs built 13 min apart whose kernels demonstrably differed. The build is reproducible (`SOURCE_DATE_EPOCH`), so those macros are frozen |
| 5 | `[cmpduty]` — sample the presenter's parked-vs-running state | `e192d03a98` | **Instrumentation, worked.** See §3 |
| 6 | Calibration-free `wall_ms` / `fps_x100` | `dc980b369e` | **Instrumentation, worked.** Needed because `cpms` drifts (see §4) |
| 7 | `wl-logview`: diff against last presented frame, skip commit when identical, damage only changed rows | `7bca29b9fc` | **Worked as designed, and made the bug worse/visible.** It had been force-committing full-surface damage once a second, which was masking the underlying fault by forcing a full repaint every tick |
| 8 | `debug:damage_tracking = 1` (DAMAGE_TRACKING_MONITOR) | `cf19ac6783` | **DID NOT FIX.** Confirmed present in the booted ISO (`grep -ac "damage_tracking = 1" hos-install.iso` = 3). Windows still vanish. The "partial damage leaves stale swapchain buffers" theory is therefore **not sufficient, and may be wrong entirely** |

---

## 3. Measurements that are trustworthy

Taken from real boots, with the instrumentation above.

* **The kernel present path is exonerated.** `present_share_permil` = **1–3‰**. The kernel's
  scanout blit is ~2 ms of a ~1100 ms frame. `present_us` barely moves between the fast phase
  (1821 µs at 33 fps) and the slow one (2465 µs at 0 fps). Nothing on the kernel side of the DRM
  boundary explains the missing time.
* **The collapse is a cliff, not a slope.** 33–34 fps with **two** windows mapped; 0–1 fps with
  **four**. The two extra windows are the ones that *float* rather than tile (they set
  `min == max` size, so Hyprland classifies them as fixed-size dialogs): `1000x700 +140` and
  `1180x680 +50` sit on top of `629x750 +6` and `629x750 +645`, which tile cleanly. That is
  2.45 Mpx of window content over a 1.02 Mpx screen — 2.4× overdraw, which does **not** explain
  a 34× collapse.
* **The compositor is busy early, then asleep.** `[cmpduty] parked_permil` reads `0–12` while
  windows are loading (compositor computing, not blocked) and `949` afterwards (idle). It stops
  presenting; it is not stuck in a spin.
* **Hyprland forces a few full frames and then stops.** `HOSDBG renderMonitor` prints
  `forceFull=5` at startup and `forceFull=0` thereafter. Windows are present during the forced
  full frames. This correlation is real but attempt #8 shows it is not the whole story.
* **Hyprland presents ONLY via legacy `PAGE_FLIP` (nr `0xb0`).** The custom `HOS_PRESENT` ioctl
  (nr `0xf0`) is called **0** times. A "stall" therefore means literally no page-flip ioctl.

---

## 4. Traps — measurement and build errors that cost real time

* **`cpms` drifts 2.4× within one boot** (`13331978 → 9501029 → 7322338 → 6267753 → 5636254`).
  The `fps` and `frame_us` fields in `[present]` are derived from it and are **unreliable**. They
  reported `frame_us ≈ 1,700,000` (1 frame/1.7 s) while the cumulative counter in the same lines
  showed 265 presents in ~170 s (**1.56 fps**, a 0.64 s gap). The stall counter agreed with the
  counter, not with `frame_us`. Reading `frame_us` as "a second of render per frame" produced a
  wrong "render-bound" diagnosis. **Use `fps_x100`.**
* **Verifying a change reached the ISO:** grep the ISO for a **string literal** only the new code
  has — `grep -ac "cmpduty" hos-install.iso`. Costs nothing, needs no kernel change.
  * C/D **comments do not survive compilation** — grepping for one always returns 0 and proves
    nothing. This mistake was made twice.
  * The `__DATE__`/`__TIME__` build stamp does **not** work (see attempt #4).
* **Check commit time against ISO mtime before blaming the build.** `make iso` takes minutes; a
  commit made while a build is already running will not be in it. One "phantom build bug" was
  exactly this: commit 19:20:51, ISO 19:24:37, build started ~19:18.
* **`make iso` DOES rebuild the D kernel.** `hos-install.iso: stage-iso-tree` and
  `stage-iso-tree: kernel.elf`, with `build/libkernel_d.a: refresh-d-kernel` phony so the D
  sub-make is always entered. An earlier claim that it only packages a prebuilt tree was wrong
  in this respect. To force a full kernel rebuild anyway: `make -C src/kernel/d clean`.
* **`serial.log` contains NUL bytes** — plain `grep` reports "binary file matches". Use `grep -a`,
  or `tr -d '\000' < serial.log | sed 's/\x1b\[[0-9;]*m//g'`.
* **Do not boot with `GPU=1`.** `qemu-run.sh`'s own comment warns `gtk,gl=on` "gives a BLACK
  SCREEN on many hosts". Confirmed here. Use `GPU=1 HEADLESS=1` and read the log instead.

---

## 5. Ruled out — do not re-investigate without new evidence

* **Flip-event ring overflow** — `flipDrop=0` in every sample.
* **Lost wakeups / parked pollers** — the freeze watchdog re-wakes them; `CMP=... w0 p0 f0`
  shows the compositor runnable, not parked, during stalls.
* **`FD_DRM` readiness** — handled correctly in `poll`, `select` **and** `epoll_pwait`
  (`fdReadableImpl` → `drmEventPending`); `epoll_wait`/`epoll_pwait` (232/281) are in the
  dispatcher's park list in `kernel_main.d`.
* **A spinning task starving the compositor** — `hos-sshd-launch` was wrongly blamed; it made
  exactly one syscall. `HOG` is a scheduling histogram, not CPU time.
* **Memory pressure** — no OOM/alloc-failure lines; GEM buffers stable (3 created, 2 destroyed);
  swapchain steady at length 3.
* **Client crashes or exits** — none, in any boot exhibiting the bug.
* **Lost page-flip completions** — in 39 of 47 stalls `flipQ == flipRd`, i.e. nothing outstanding.
  (The 8 lagging cases are a separate, smaller effect.)

---

## 6. Open leads, ranked

1. **`fb_id → GEM handle → physAddr` mapping.** aquamarine rotates a **3-deep** swapchain, so
   three different framebuffer objects are page-flipped in turn. If `drmAddFb`/`findDrmFb`
   mis-maps an `fb_id`, or caches a stale `physAddr`, the kernel would blit a buffer Hyprland has
   stopped drawing into — which looks exactly like "the image froze on an old frame". *Untested.*
2. **Direct scanout.** `attemptDirectScanout()` / `canAttemptDirectScanoutFast()` in aquamarine
   can hand a **client** buffer straight to the display. If that happens and the client later
   destroys or reallocates the buffer, the scanned-out image would be stale or blank. *Untested.*
3. **`HOS_SCENE_RENDER` gating.** The kernel exports `HOS_SCENE_RENDER=1` unconditionally for
   Hyprland (`exports.d` ~line 1100). The HOS opt-outs are split across **two** predicates —
   that env var (`GLTexture.cpp` skip allocate, `SurfaceState.cpp` skip client texture upload,
   `Monitor.cpp` force software cursors) and `needsCPUCopy()` (`GLRenderer.cpp` `m_hosCPUFrame`,
   `hosComposeShmWindows`). A combination that skips **texture upload** while still building the
   scene would render background + borders and no window contents. *This matches the symptom
   closely and is the strongest lead.*
4. **Client buffer lifecycle.** `resize_buffer()` (added to `wl-installer.c` and
   `wl-cairo-demo.c`) destroys the `wl_buffer` and `munmap`s its shm before creating a new one.
   Check it cannot destroy a buffer the compositor is currently displaying, or leave a mapped
   surface with nothing attached. Likewise `wl-logview`'s new early-return commit path.
5. **Flip-completion ordering.** The kernel queues the completion **synchronously inside** the
   `PAGE_FLIP` ioctl (`drmQueueFlipEvent`), i.e. the flip completes *before* the ioctl returns —
   real hardware completes at vblank, strictly after. aquamarine sets `isPageFlipPending = true`
   *after* `drmModePageFlip` returns. Whether that ordering can wedge a connector permanently is
   unresolved; aquamarine's only escape hatch for a stale pending flip is gated on
   `NEEDS_RECONFIG` (`DRM.cpp:1987`), which never fires in steady state.

---

## 7. Dead theories (kept so they are not retried)

* **"Rounded corners are the whole cause."** They were a real cost (attempt #1 more than halved
  the freezes) but not the cause of the disappearance.
* **"The compositor renders at 1 fps because it is render-bound."** Derived from the broken
  `frame_us`; contradicted by the raw present counter and the stall counter. See §4.
* **"Partial damage leaves stale swapchain buffers."** Attempt #8 set `damage_tracking = 1`,
  which forces whole-monitor damage (`Renderer.cpp:2217`); confirmed in the ISO; did not fix it.
* **"A lost flip completion wedges the connector."** `flipQ == flipRd` in 39/47 stalls.
* **"`wl-logview` committing every second is the bug."** It was masking the fault, not causing
  it. Fixing it (attempt #7) was still correct on its own merits.
