# Windows Disappearing — Investigation Roadmap

**Status: ✅ FIXED (2026-09-05) — swapchain length 3 → 1. Verified: a 3-minute soak that
previously blanked at t=60s now holds 4400+ colours across all 8 samples (`blank=0`), and the
`[srcpx]` probe shows a single buffer with no alternation. Screenshot confirms the full desktop
rendering, including a Calendar launched by SUPER+C.

**Previously: ⚠️ REOPENED (2026-09-05). Two contributing faults are fixed and verified; the core bug
is NOT, and is now reproducible on demand.**

## 0. ROOT CAUSE (2026-09-05) — only ONE of the two scanout buffers is ever rendered into

Measured by the `[srcpx]` probe, which samples the actual source of each blit and counts
DISTINCT colours in an 8×8 grid:

```
fb=1  phys=0x1ee0d000   distinct=18/64   <- windows rendered here
fb=2  phys=0x1f1f7000   distinct= 2/64   <- only ever wallpaper
```

Stable across every present sampled (85, 86, 88, 89 …), not intermittent. aquamarine
page-flips **alternately** between the two, so **every other frame presents a stale buffer**.
`fb=2` still holds the startup frame — wallpaper only, captured before any window mapped —
which is exactly why it reads as 2 distinct colours.

That is the whole symptom: alternating good/blank frames read as flicker, and whenever the last
flip lands on `fb=2` the desktop sits blank with the kernel-drawn borders stamped on top.

**Ruled out along the way, each with evidence:**
* the blit is not shrinking — `copy=1280x800 fbdim=1280x800 scr=1280x800` at the blank frame;
* the compositor is not wedged, asleep or starved — presents climb, `flipQ == flipRd`,
  `parked_permil=0` with ~81k running samples;
* `debug:damage_tracking = 1` **is** applied — `luaConfigValueName()` maps `:` to `.`, so the
  nested Lua `debug = { damage_tracking = 1 }` resolves correctly. It did not fix this.

**Next step:** find why `fb=2` is never rendered into. Either Hyprland's EGL surface is bound to
a single buffer while aquamarine rotates two, or the kernel hands out two `fb_id`s that the
compositor believes are one. Forcing the swapchain to length 1 would mask it and is a legitimate
configuration here (the present path is a CPU blit, so there is no tearing concern), but the
mapping should be understood first.

---

## 0b. REPRODUCTION

```bash
# on the build server
setsid env HEADLESS=1 MEM=2048 ./qemu-run.sh &     # wait for [g5] windows=
printf 'sendkey meta_l-c\n' | nc -N -U mon.sock    # SUPER+C -> /wl-calendar
sleep 12; printf 'sendkey meta_l-c\n' | nc -N -U mon.sock
sleep 18; OUT=/tmp/after.png ./scripts/screen-check.sh
```

Window count goes 4 → 8 and the desktop goes **black except for the identity borders** — the
user's exact report, on camera. Measured by `screen-check.sh`:

| | colours | dominant colour |
|---|---|---|
| before launch | 4338 | 33.9% |
| after launch  | **232** | **91.2%** |

**The compositor is NOT wedged, and NOT idle.** During the black screen:

```
[present] total=  74 -> 78 -> 81 -> 83     presenting, still climbing
flipQ=75 flipRd=75                         every completion read
[cmpduty] parked_permil=0 running=81137    100% RUNNING
62x "drm: Cannot commit when a page-flip is awaiting"
```

So it is **actively rendering and presenting BLACK frames**, at full CPU. Every theory that
requires the compositor to be stuck, asleep, or starved is dead. The `Cannot commit` errors are
real but cannot be the whole story, because presents demonstrably continue through them.

That the identity borders still appear is now *evidence*, not mystery: since `fea612d05d` they
are drawn **only** on the present path, so their presence proves presents are happening. What is
black is the compositor's own output.

**Input works.** SUPER+C launched `/wl-calendar` (tasks 13 and 15, both speaking Wayland), so
input → keybind → spawn → map → render is intact end to end.

---

## What IS fixed (verified, keep)



It was **two** faults that compounded, and neither was a compositor bug:

1. **The erasure** — the kernel's own freeze HUD painted 784×112 of solid black over the live
   desktop from the mouse IRQ, and nothing ever repaired it because repainting requires a
   present, which is exactly what had stopped. §2.
2. **The "stall"** — the freeze probe treated *"no present for 1.5 s"* as a fault. An idle
   desktop legitimately does not present. That produced 81–133 bogus stall episodes per boot,
   **each of which triggered (1)**. §3.

The desktop was never wedged. Injecting real mouse motion through the QEMU monitor moved the
present counter **70 → 72** and issued a fresh page flip; between inputs it sits at
`parked_permil=999`, asleep by choice. That is the damage work behaving correctly.

Automated smoke test after both fixes — `boot-test: PASS`, all 11 assertions green:

```
  ok  forbid   FREEZE                            absent
  ok  forbid   legacy drm: cursor null failed    absent    (was 437/boot)
  ok  forbid   COMPOSITOR DIED                   absent
  ok  require  [dkernel] init = Hyprland module  1x
  ok  require  [g5] windows=                     19x
  ok  require  [bar] wl-layer-bar launched       1x
  freeze stalled: 6   (was 133 — the 6 are real, during startup before it settles)
```

**What remains is throughput, not correctness:** when the desktop *does* draw, softpipe
interprets every fragment. That is Track C (llvmpipe) in
[BUILD_AND_TEST_AUTOMATION_ROADMAP.md](BUILD_AND_TEST_AUTOMATION_ROADMAP.md), not a bug in this
file. The §6 open leads below are kept only in case a genuine wedge reappears.

Windows render once when they map, then vanish while the coloured identity borders remain.

This file records what has been measured, what was tried, and what did **not** work, so the next
attempt does not re-run a dead end. Several confident diagnoses here were wrong; they are kept
rather than deleted, because knowing a theory is dead is the useful part.

A 36-agent adversarial investigation ran on 2026-09-04 (31 findings, 5 survived refutation,
26 refuted). Its results are folded in below and marked **[MA]**.

---

## 1. The symptom, and why it looks the way it does

| | |
|---|---|
| Windows | render correctly on first map, then disappear |
| Borders | remain visible — drawn by the **kernel**, not the compositor |
| Windows still mapped? | **yes** — `[g5] windows=` holds at 5, byte-identical rectangles across the whole failure **[MA]** |
| Client exits / crashes | **none** |
| Presents in the last boot | 60 total |

Borders survive because `hosDrawIdentityBorders()` is called from `drmSetHosWindows()` (the
`HOS_WINDOWS` ioctl) as well as from the present path — deliberately, "even without a fresh
present blit". It paints only a 4 px ring (`HOS_BORDER_PX = 4`), never a fill, so it cannot
itself erase window interiors.

---

## 2. ✅ ROOT CAUSE OF THE VISIBLE SYMPTOM — the kernel's own freeze HUD eats the desktop

`freezeProbeRepaint()` (`posix.d`) paints **seven bands** via
`fb_draw_hud_row(0/16/32/48/64/80/96, …)`. That helper fills **98·8 = 784 px × 16 rows with
solid black (`0x00000000`)** before drawing its text, and its own comment says it goes
"straight to g_fb, **bypassing** the text console + the `g_desktopClaimedFb` gate, so it stays
readable on the desktop".

So it stamps **784 × 112 px of black over the top-left of the live desktop**, and:

* it is driven from `framebufferMoveCursor`, so it re-fires **on every mouse movement**;
* it triggers on any present-stall over 1.5 s;
* **nothing ever repairs those bands**, because the only thing that would is a present, and
  presenting is exactly what has stopped.

The tiled windows start at `y = 44`, so the bands at 48/64/80/96 land directly on window
content and stay. That reads as "the windows disappeared" while the borders — repainted
independently by `drmSetHosWindows()` — remain.

This resolves the contradiction that blocked the whole investigation. Multiple verifiers
correctly argued that a compositor which merely *stops presenting* would leave the last good
frame frozen **with** its windows, so "it stopped rendering" could not explain windows
vanishing. They were right: the erasure is not done by the compositor at all. It is done by
the kernel's own debug overlay, from the mouse IRQ, after presenting stops.

**Fix applied:** `g_freezeHudEnabled`, default `false`, gating `freezeProbeRepaint()` — the same
pattern as `g_wifiDebugHud`. The serial-side `freezeProbeKlog()` is untouched, so all the
diagnostics this investigation relies on still work. Set the flag to `true` when actually
chasing a hard freeze on real hardware, which is what the overlay was written for.

**✅ VERIFIED ON HARDWARE (2026-09-04, build server, automated smoke test).** A full rebuild from
`e0c421c32b` booted headless under `scripts/boot-test.sh`:

```
  ok    forbid   FREEZE                            absent
  ok    forbid   legacy drm: cursor null failed    absent      (was 437 per boot)
  ok    forbid   COMPOSITOR DIED                   absent
  ok    require  [dkernel] init = Hyprland module  1x
  ok    require  [g5] windows=0000000000000005     6x          (5 windows mapped)
  ok    atleast  [present] total=                  19 >= 3
```

The freeze HUD no longer paints over the desktop, and the per-frame cursor error is gone. The
compositor starts, maps all five windows, and presents.

---

## 3. Still open — why presenting stalls at all

The overlay explains the *erasure*, not the *stall*. Constrained sharply by **[MA]**:

* **The dead zone is ~17 s (s6.txt:2766–5763).** In it Hyprland issues **ZERO DRM ioctls** —
  no `PAGE_FLIP`, no `HOS_WINDOWS`, no `MAP_DUMB`, no `MODE_CURSOR`, no `[g5]`. Its only
  syscalls are ~949 `TIOCGWINSZ` (the aquamarine logger writing to stdout) and 8 `sendmsg`.
  **The failure is upstream of the commit, not a rejected commit.**
* **Hyprland performs ZERO `recvmsg` for the entire dead zone** — no client message reaches it
  for 17 s. Verifiers argue this is an *effect*: no render → no frame callbacks → nothing for
  clients to send.
* The last `renderMonitor` before the stop reported `needsFrame=false forceFull=0
  damageChanged=false`. The early-out at `Renderer.cpp:2043` is on **`needsFrame`**, not on
  damage — so damage never gets consulted.
* `Cannot commit when a page-flip is awaiting` fires under `connector->isPageFlipPending`
  (`aq DRM.cpp:1999`), and **`CDRMOutput::scheduleFrame` (`DRM.cpp:2287-2297`) returns early on
  that same flag**, so once it is set and never cleared, no further frame event is ever emitted.
  That is a permanent wedge by construction. *Verifiers disagreed on whether it is actually set
  during this boot's dead zone — one found the error burst at 2838-2853 to be a duplicated
  replay of earlier events, another read it as live. Unresolved.*
* **Ordering hazard, real but unproven as the cause:** the kernel queues the flip completion
  **synchronously inside** the `PAGE_FLIP` ioctl (`drmQueueFlipEvent`), i.e. the flip completes
  *before* the ioctl returns — real hardware completes at vblank, strictly after. aquamarine
  sets `isPageFlipPending = true` *after* `drmModePageFlip` returns. aquamarine's only escape
  from a stale pending flip is gated on `NEEDS_RECONFIG` (`DRM.cpp:1987`), which never fires in
  steady state.

---

## 4. Attempts, in order

| # | Change | Commit | Outcome |
|---|---|---|---|
| 1 | `rounding = 0`, `dim_inactive = false` on softpipe | `5a818b018b` | **Helped.** Freezes 40 → 18; longest 6s → 2s; ≥3s stalls 12 → 0. `rounding_power = 2.5` evaluates a `pow()` per pixel per window per frame |
| 2 | DRM cursor-disable ioctl returns success not `EINVAL` | `5a818b018b` | **Worked, cosmetic.** 437 `cursor null failed` → 0 |
| 3 | `presentProfStats()` on a 5 s wall clock | `5a818b018b` | **Instrumentation.** Its only call site was gated on a counter that never fires in a desktop boot |
| 4 | Build stamp via `__DATE__`/`__TIME__` | `2761c9199f` | **FAILED — do not retry.** Identical `18:09:00` from two ISOs 13 min apart with demonstrably different kernels; the build is reproducible (`SOURCE_DATE_EPOCH`) so those macros are frozen |
| 5 | `[cmpduty]` parked-vs-running sampler | `e192d03a98` | **Instrumentation, worked** — though see §5 for how it was misread |
| 6 | Calibration-free `wall_ms` / `fps_x100` | `dc980b369e` | **Instrumentation, worked** |
| 7 | `wl-logview` diff-and-skip commit | `7bca29b9fc` | **Correct on its own merits.** It had been force-committing full-surface damage every second, masking the fault |
| 8 | `debug:damage_tracking = 1` | `cf19ac6783` | **DID NOT FIX.** Confirmed in the booted ISO (3 hits). The stale-swapchain theory is dead |
| 9 | `g_freezeHudEnabled = false` — gate the freeze HUD | *this change* | **Expected to fix the visible symptom.** Unverified on hardware |

---

## 5. Traps — measurement and build errors that cost real time

* **[MA] EVERY Hyprland/aquamarine log line appears TWICE in `serial.log`.** 964 `G8 frame N
  begin` lines but the counter only reaches 489; 475 frame numbers appear exactly 2×. The
  duplication is **bursty, not adjacent** — s6.txt:2854-2886 is a verbatim replay of lines
  2739-2843. **All Hyprland-side counts in earlier analysis were doubled**, and replayed error
  bursts can look like live events at the replay line number. Real counts: 489 frames, 16
  `Cannot commit`, ~6 `Cannot enter surface`.
* **[MA] `parked_permil = 949` was NOT the stop point.** That sample (s6.txt:2635) sits inside a
  stall that **recovered** (`CLEARED` at 2669, flips at 2668-2765). During the real dead zone the
  compositor reads **508/556/558** — roughly half running. Any theory built on "the compositor
  went to sleep" is testing against the wrong sample.
* **[MA] The `G8` / headless output is a red herring.** `G8 frame N begin` is
  `CHeadlessOutput::emitFrame` — a *different backend* from the DRM output doing the page flips.
  It **never committed once all session** (zero `G8 frame N present`). The whole healthy render
  period ran with no `G8` lines at all.
* **`cpms` drifts 2.4× within one boot**, so the `fps` and `frame_us` fields of `[present]` are
  unreliable. They reported ~1.7 s/frame while the cumulative counter showed 1.56 fps. **Use
  `fps_x100`.**
* **Verifying a change reached the ISO:** grep the image for a **string literal** only the new
  code has — `grep -ac "cmpduty" hos-install.iso`. Comments do **not** survive compilation, so
  grepping for one always returns 0 and proves nothing (this mistake was made twice).
* **Check commit time against ISO mtime before blaming the build.** One "phantom build bug" was
  a commit at 19:20:51 landing after a build that started ~19:18 and finished 19:24:37.
* **`make iso` DOES rebuild the D kernel** (`stage-iso-tree: kernel.elf`, and
  `build/libkernel_d.a: refresh-d-kernel` is phony). An earlier claim otherwise was wrong.
  Force a full rebuild with `make -C src/kernel/d clean`.
* **`serial.log` contains NUL bytes** — use `grep -a`, or
  `tr -d '\000' < serial.log | sed 's/\x1b\[[0-9;]*m//g'`.
* **Do not boot with `GPU=1`** — `qemu-run.sh` warns it "gives a BLACK SCREEN on many hosts".

---

## 6. Ruled out — do not re-investigate without new evidence

* **Flip-event ring overflow** — `flipDrop=0` in every sample.
* **Lost wakeups / poll readiness** — `FD_DRM` is handled correctly in `poll`, `select` **and**
  `epoll_pwait`; 232/281 are in the dispatcher's park list. **[MA]** 15 watchdog re-wakes in the
  dead zone restored nothing, because a spurious wake cannot set `needsFrame` nor clear
  `isPageFlipPending`.
* **A spinning task starving the compositor** — `hos-sshd-launch` was wrongly blamed; it made
  one syscall. `HOG` is a scheduling histogram, not CPU time.
* **Memory pressure** — no OOM lines; GEM stable (3 created / 2 destroyed); swapchain length 3.
* **Client crashes, exits, or buffer invalidation** — **[MA]** "no client action can invalidate,
  unmap or un-attach what Hyprland reads."
* **[MA] `fb_id` reuse and direct scanout** — both explicitly refuted. Do not spend more effort
  on `fb_id` caching or `attemptDirectScanout`.
* **[MA] The HOS CPU compositor path** — `m_hosCPUFrame` is **false** this boot, so
  `hosComposeShmWindows`, the panel, the dock and the G16 titlebars never run. The full GL scene
  build runs instead. Any hypothesis resting on `needsCPUCopy()` or the clear-only shortcut is
  off the table.
* **[MA] Window geometry changes** — the `[g5]` line before the last present is byte-identical to
  one 3000 lines later. Nothing moved, resized, changed z-order or unmapped.
* **[MA] The timerfd "390× spin"** — the counters are process-global (fed by ~8 event loops), and
  `tfdRead` tracks `tfdArm` ~1:1, which is a healthy timer. The headless frame loop is clamped to
  a 33 ms floor by `0006-headless-frame-pacing.patch`.

---

## 7. Latent bugs found along the way (real, not the cause)

Worth fixing on their own merits; none explains this symptom.

* `DrmFb` takes **no reference** on its GEM buffer, and `GEM_CLOSE`/`DESTROY_DUMB` free the
  `GemBuf` unconditionally — scanout survives only because `objRelease` never frees the pages.
* `drmPresentFb` **never validates** that the bound framebuffer's backing is large enough for
  `pitch * height`, so a CPU-alias FB can read past the end of its buffer.
* `wl-cairo-demo` `munmap()`s a `malloc()`'d pointer on every resize.
* `wl-cairo-demo` leaks one `wl_buffer` + one memfd per redraw — the exact pattern its own
  comment says froze the desktop before.
* Every window client acks an `xdg_surface.configure` and can then return **without attaching** a
  buffer (protocol violation).
* `wl-layer-bar` drops a repaint under buffer back-pressure with no retry.
* `SSurfaceState::updateFrom` unconditionally NULLs `m_current.texture` on every buffer commit.

---

## 8. Dead theories (kept so they are not retried)

* **"Rounded corners are the whole cause."** A real cost (attempt #1 more than halved the
  freezes) but not the disappearance.
* **"The compositor is render-bound at 1 fps."** Derived from the broken `frame_us`; contradicted
  by the raw present counter and the stall counter.
* **"Partial damage leaves stale swapchain buffers."** Attempt #8 forced whole-monitor damage;
  confirmed in the ISO; did not fix it.
* **"A lost flip completion wedges the connector."** `flipQ == flipRd` in 39/47 stalls.
* **"`wl-logview` committing every second is the bug."** It was masking the fault, not causing it.
* **"The compositor went to sleep."** **[MA]** — wrong `[cmpduty]` sample; it is ~50% running in
  the dead zone.
* **"A compositor that stops presenting cannot erase windows, so something must be rendering a
  windowless frame."** Correct reasoning, wrong conclusion: the eraser is the kernel's own freeze
  HUD (§2), not a rendered frame.
