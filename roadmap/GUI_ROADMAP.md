# GUI Desktop Roadmap

## Current status (2026-06-02) — full scene rendering WORKS; OOM fixed, stable

> **Update:** the kernel OOM (F.4r) is **fixed** (physical page freeing), and with
> it **full scene rendering now works** — `HOS_SCENE_RENDER=1` (default) runs
> Hyprland's real `m_renderPass.render()` end-to-end with no OOM and no crash;
> screendump = `rgb(17,17,17)` (#111111), the real empty-workspace scene. The
> render pipeline is no longer the bottleneck. Remaining is *content*: the
> wallpaper PNG won't decode (rtfs/cairo), no Wayland client runs yet, and the
> compositor still re-inits 2-3× (harmless now). See the scene-rendering section.

**Hyprland boots, fully initializes, reaches `Hyprland is ready, running the event
loop!`, renders its compositor background, reads it back on the HOS CPU path, and
blits it to `g_fb`.** QEMU `screendump` = solid **`RGB 0f 17 1f` (rgb 15,23,31)**
across 1280×800 — Hyprland's fallback background (the `wall0.png` wallpaper asset
isn't shipped), **not** the old `0xFF` white placeholder. End-to-end chain verified:
dynamic load → EGL/GL softpipe (GLES 3.0) → Wayland → seat → xkb → headless output →
`renderer: using HOS CPU-readback clear frame path` → `rb: CPU readback into output
buffer completed` → screendump shows the rendered color.

**Hardened this session (2026-06-02):** the render had been intermittent because
Hyprland (a) burned ~60s in a cursor-theme search and (b) hid its own logs. Both
fixed → render is now reliably reached:
- **`XCURSOR_PATH=/usr/share/icons`** (exports.d): collapses libXcursor's 4-path
  "default" theme search. `index.theme` opens **2464 → 0**; cursor load is instant.
- **Force `m_logsEnabled=true`** (`debug/log/Logger.cpp:55`): `debug:disable_logs`
  was suppressing all Hyprland-core logs (renderer/EGL/assert) to the guest file.

### F.4r kernel OOM — FIXED 2026-06-02 (physical page freeing)
The render used to OOM after ~2 frames (`OOM in alloc_phys_page!` → GL
`GL_OUT_OF_MEMORY` → `std::bad_alloc` → `#GP`) because `mm.d`'s allocator was a pure
bump pointer with **no free path** — every mapped page leaked, and per-frame
CPU-readback buffers churned forever. **Fixed with a real free list:**
- `mm.d`: `g_free_pages` stack + `free_phys_page()` (guarded: only pool pages
  `[1 MB, high-water)` are accepted, so a stray device/`g_fb` phys can never be
  re-handed-out); `alloc_phys_page()` pops a freed page first.
- `arch.d`: `unmap_page_hhdm()` now **returns the unmapped physical address**.
- `task.d`: `AddrRegion.owned` — true only for private anonymous / file maps
  (pages from `alloc_phys_page`), false for DRM (`g_fb`) and memfd (shared) maps.
- `munmap` (kernel_main.d case 11) frees the range's pages when the region is
  `owned`; `exitTask` frees a dying task's owned pages **iff** it is the last task
  on its `pml4Phys` (threads share it — freeing then would corrupt the space).
  Fork deep-copies, so there is no CoW sharing to worry about.

**Result: the default run now executes the full ~200 s with `OOM=0` and no crash.**
The compositor renders its background continuously and stably.

*(The 2-3× compositor re-init still happens but no longer OOMs. The >512 MB boot
limit (Limine places the init module past the kernel's ~512 MB HHDM map → `[elf]
bad magic`) is unchanged but no longer on the critical path.)*

**Also fixed for stability:** `statx` (was an ENOSYS stub — now resolves via
`sys_open`+`fstat`); and a **null-surface guard** in Hyprland's `getBackground`
(`render/Renderer.cpp`) so a wallpaper whose PNG fails to decode is skipped instead
of segfaulting the compositor (`BGTex: ... cairo surface is null; skipping`).

### Full scene rendering — WORKING 2026-06-02 (after the OOM fix)
The HOS patch (`render/GLRenderer.cpp:endRender`) used to *bypass* the real scene
render on the CPU-readback path — it called `m_renderPass.clear()` and just
`glClearColor(0.06,0.09,0.12)` (= the `rgb(15,23,31)` clear color), because the full
render OOM'd. With page freeing in place that no longer happens. **`HOS_SCENE_RENDER=1`
(now the default in exports.d) runs the real `m_renderPass.render()`** — the readback
in `CGLRenderbuffer::unbind()` copies the scene into the dumb buffer.

**Verified:** full ~200 s run, `OOM=0`, no crash, no GL errors/asserts, the clear-only
shortcut is never taken, and the screendump is now **`rgb(17,17,17)` (#111111)** —
Hyprland's actual empty-workspace scene background, distinct from the old clear
color. So the compositor renders its **real scene** end-to-end. What's on it is
limited only by content, not the pipeline.

**Wallpaper plumbing — DONE (durable):** `scripts/pack-assets.py` packs
`build/assets/**` into `build/assets.blob` (same flat format as `xkb.blob`); the
Makefile bundles it as a boot module; `rtUnpackAssets()` (posix.d) unpacks it into
the rtfs overlay. Three 1280×800 gradient wallpapers ship to `/usr/share/hypr/
wall{0,1,2}.png` (real Hyprland ones are 8K/130 MB-decoded). Unpack confirmed.

### Wallpaper decode — FIXED 2026-06-02
The rtfs `wall0.png` opened and read fine, but Hyprgraphics' **format detection used
libmagic** (`src/image/utils/Format.cpp`: `magic_open`+`magic_load(nullptr)`+
`magic_file`). `magic_load(nullptr)` needs the compiled magic database
(`magic.mgc`, ~8 MB) which we don't ship → it failed → every image was reported
`IMAGE_FORMAT_ERROR` ("invalid file") **before any decoder ran**. **Fix:** added
`formatFromMagicBytes()` (PNG/JPEG/BMP/WEBP/SVG signatures) and use it first in both
`formatOf()` paths, falling back to libmagic. Rebuilt `libhyprgraphics.a`, installed
to the sysroot, relinked Hyprland. Now the wallpaper **decodes** (`BGTex created`,
no "invalid file", no null surface) and its pixels reach the screen — a continuous
screendump caught a frame with **646 distinct colors**, dominated by the exact wall0
gradient colors (`rgb(30,40,120)` … `rgb(115,71,183)`).

Also forced the background opacity to warp straight to 1 (`Renderer.cpp:getBackground`)
so the wallpaper doesn't sit invisible mid-fade on the idle headless frame loop.

### Wallpaper *display* — localized to softpipe texture upload/sampling (open)
The decoded wallpaper renders only as a **~16-20 px border** around the screen edge
(correct wall0 gradient) with the **entire interior black** — consistent and stable
(646 colors, ~93 % black). **Mesa-level tracing pinned it precisely** (temporary
probes, since removed):
- **`PNGDECODE` probe** (raw libpng output, on the worker thread): `1280x800
  center=[72,60,155] tl=[30,40,120]` — the decode is **full and correct** (`tl`
  matches wall0's top-left exactly). So decode is NOT the problem.
- **`GLFB` probe** (`glReadPixels` straight from softpipe's render target): the same
  frame reads `center=[0,0,0] leftedge=[28,60,135]` — the **render** produced the
  border. So the CPU readback into the dumb buffer is **innocent** (it faithfully
  copies what softpipe rendered).

So the fault is strictly **between a correct decoded image and the rendered output**,
i.e. the **GL texture upload (`glTexImage2D`) or softpipe's texture sampling**. Also
ruled out with valid builds: render-pass **occlusion** (0 opaque occluders logged);
**damage** (forcing full-monitor damage had zero effect); **readback stride** (solid
clears read back perfectly); monitor scale. A **solid-color quad fills cleanly**, so
softpipe rasterization/fill work — only the **textured** quad's interior comes out
black.

**Narrowed further (shader test):** temporarily made `surface.frag` output
`vec4(v_texcoord,0,1)`. A full-screen draw showed a **perfect horizontal `u`
gradient** (interpolation + rasterization work) but **`v` = 0 everywhere** — i.e.
`v_texcoord.y` is stuck at 0, so the texture only samples row 0. The vertex setup is
correct (`glVertexAttribPointer(texcoord, size=2, stride=16, offset=8)`; `fullVerts`
has `v=0,1,0,1`), so softpipe/Mesa-draw is mis-fetching the **interleaved
`texcoord.y` at vertex offset 12** while `pos.x/y` and `texcoord.x` (offsets 0/4/8)
read fine. (Caveat: `v=0` alone predicts a horizontal gradient, not the observed
border, so there may be a second factor or that frame was a different surface — the
non-deterministic late wallpaper load makes clean single-frame reads hard.)

**De-interleave workaround TRIED → FAILED:** moved `texcoord` into its own packed
`vec2` buffer (so `v` is at offset 4, not 12). The wallpaper **still** renders the
same 646-color / 93%-black border. So it is **not** an offset-12 interleaving bug —
softpipe drops the texcoord's **2nd component regardless of layout** (reads the
`vec2` as if size-1, `v=0`), or the `v_texcoord.y` varying is lost in the vs→fs
linkage. This **resists Hyprland-side workarounds** and points to a **Mesa softpipe
source fix** (draw-module vertex fetch or GLSL varying packing, in
`deps/mutter/build/mesa-23.3.5-epin`). Remaining untested idea: drop the unused 3rd
attribute/varying `texcoordMatte` from `tex300.vert` (only `rgbamatte.frag` uses it)
to test a varying-packing interaction. **Recommendation:** this is a deep softpipe
bug with very slow iteration (300 s/run + the late-wallpaper lottery) — best paused
unless the softpipe source is worth patching; the decode works and the compositor
renders + is stable. **Meta-blocker:** the wallpaper loads very late (~line 32024,
gated by the unsolved 2-3× compositor re-init), so each softpipe test is a 300 s run
+ a timing lottery — **fixing the re-init (1× compositor, wallpaper loads early) is
the highest-leverage unblock** for further iteration. Also watch the **stale-binary
trap**: a broken `ninja` leaves the old `Hyprland` in place (`make all` still says
"Build complete") — always grep the fresh binary for your probe string.

**Remaining for visible content:**
- **Wallpaper display** — the softpipe textured-render border artifact above.
- **A Wayland client window** — nothing runs as a client, so the desktop is empty.
- **Single compositor** — the 2-3× re-init still happens (one cause = the builtin
  seatd `fork`; `noop` backend cut it 3→2 but a second cause remains and `noop`
  crashes without a session). Harmless now (no OOM) but a correctness wart.
- **dmabuf EGLImage import** (`eglCreateImageKHR` → `EGL_BAD_PARAMETER 0x300c`) so GL
  renders straight into the dumb buffer (no CPU readback) — efficiency.
- A cursor/icon theme.

## Historical Phase G notes — startup and EGL unblocks

**Re-diagnosis (with Hyprland's logs now visible):** it is NOT a render/dma-buf
problem — the GL renderer is **never created**, `renderMonitor` **never runs**, and
no frame is ever drawn. Hyprland's last core log is **"Creating the
AsyncResourceGatherer!"**; then the aquamarine backend sets up (headless output,
swapchain, frame scheduling) and logs **libseat "Could not create client: Not a
socket"**, after which the main thread just busy-spins `epoll_pwait` forever. So
the white screen we saw is only the swapchain's pre-allocated buffers being
`memset(0xFF)` — not a render.

**Progress narrowing the stall (still not fully pinned):**
- **Ruled out** the `epoll_pwait` cooperative yield — reverted it (epoll busy-returns
  0 again, the way it did when Hyprland *did* reach the renderer earlier); the stall
  persists, so the yield wasn't the cause.
- **Ruled out** an AsyncResourceGatherer worker deadlock — in steady state **only
  task 0 runs** (no worker thread active); task 0 finishes setup and waits in
  `epoll_pwait` forever for an fd that never becomes ready.
- **Seat — FIXED 2026-06-02:** `Seat opened with backend 'builtin'`. The embedded
  seatd (libseat builtin) **forks** a server process (`builtin_open_seat`:
  socketpair → fork → child closes `fds[1]` and runs the server loop, parent closes
  `fds[0]` and does the handshake). On Linux `fork` *copies* the fd table so each
  side closes only its own copy; our **global fd table** meant both closes destroyed
  the shared socketpair → "Could not flush". Four kernel fixes (posix.d unless
  noted): (1) `getsockopt(SO_PEERCRED)` returns User-object creds for any fd; (2) socket
  **refcounting** (dup-aware `closeLocalSocket`); (3) **per-process fd tables**
  (`g_fdTabs` + active `g_fdTable` ptr set per task at dispatch; `forkTask` copies
  the parent's table + bumps refcounts, `cloneThread` shares — task.d gains
  `fdTabId`); (4) `fdReadable(FD_SOCKET)` is now accurate (ready only when data is
  queued or the peer hung up) so `poll` yields and the forked seatd child gets
  scheduled to respond. *(aquamarine still logs "Failed to open a session" → "DRM
  Backend failed" — that's the DRM-backend session opening devices via the seat;
  it falls back to headless as designed and is not the libseat seat.)*

**MAJOR BUG FIXED 2026-06-02 — `epoll_ctl` was mis-routed.** The kernel dispatch had
`case 233: linux_sys_epoll_create` — but **233 is `epoll_ctl`**. So every
`wl_event_loop_add_fd` → `epoll_ctl(ADD)` actually created a *new* epoll instead of
registering the fd → **no fds were ever added to any epoll**, and the main loop
polled an empty set forever. This was the long-standing "task 0 spins `epoll_pwait`"
stall. Fixed: `213=epoll_create`, `232=epoll_wait`, `233=epoll_ctl`. The event loop
now works (epfd 3 gets 8 fds incl. the frame timerfd, and `epoll_pwait` returns
events).

**SECOND epoll bug FIXED 2026-06-02 — `epoll_event` was not packed.** Once
`epoll_ctl` worked, Hyprland's `wl_event_loop_dispatch` **crashed** calling a
NULL/garbage callback (`rip=0`, `ret0`→`wl_event_loop_dispatch`). Cause: our
`EpollEvent { uint events; ulong data; }` let D pad `data` to offset 8, but the
x86-64 kernel `epoll_event` is **packed** (`data` at offset 4). So the 8-byte
source pointer round-tripped at the wrong offset → corrupted source → NULL
callback. Fixed with field-level `align(1):` (now `sizeof==12`, asserted). Crash
gone (`pf=0`).

**Current blocker (F.4p) — pre-`start()` stall after cursor/icon load.** Hyprland
now (no crash) does the cursor/icon theme load on the **main thread** (task 0):
~2464 `open`s of `index.theme` + cursor-shape files (baked HanonymOS sysroot
`share/{pixmaps,icons}/default`, `/root/.local/share/icons`, `/root/.icons`) — these
don't exist, so it's searching for a theme we don't ship. It then sits in
`epoll_pwait` (now functional), still **before** `m_aqBackend->start()` returns
(`Instance-Sig=0`, `CHyprOpenGL=0`). Next: figure out the pre-start loop — is the
AsyncResourceGatherer's cursor/icon load looping/awaiting, and which epoll fd keeps
it spinning (eventfd/timerfd not drained?). Shipping a minimal cursor/icon theme or
pointing `XCURSOR_PATH`/`XCURSOR_THEME` at one, and/or making the load terminate,
is the likely unblock.

**F.4q — EGL context creation FIXED 2026-06-02.** With logs visible, the actual
assertion was **not** the expected GLES 3.2 probe failing with `EGL_BAD_MATCH`.
Hyprland had `DRMFD=-1` / `RENDERNODEFD=-1` on the sessionless headless backend,
then fell through to GBM and asserted on `Couldn't open a gbm fd` / `Couldn't open
a gbm device`; our non-fatal `SIGABRT` handling let it continue into accidental
context creation. Fixed by using `EGL_MESA_platform_surfaceless` when no DRM fd is
available, and by only marking GBM successful after both `openRenderNode` and
`gbm_create_device` succeed. Verified in QEMU: no GBM assertions,
`EGL: initialized surfaceless platform display`, GLES 3.2 still logs
`EGL_BAD_MATCH` then the GLES 3.0 fallback succeeds (`OpenGL ES 3.1 Mesa 23.3.5`,
`Renderer: softpipe`), `Hyprland init finished`, and swapchain buffers are
acquired.

**F.4r — render + present with distinct buffers VERIFIED 2026-06-02.** The old
direct-alias present path is gone. `CREATE_DUMB` now allocates distinct off-screen
dumb buffers, Aquamarine headless commits the pending CPU-readable buffer via a
private `DRM_IOCTL_HOS_PRESENT` (`nr=f0`), and the kernel row-blits that buffer into
`g_fb`.

What changed:
- Kernel DRM shim: `DRM_NR_HOS_PRESENT = 0xf0` copies `{data,width,height,stride,format,size}`
  from userspace into `g_fb`, disables framebuffer console writes, and keeps
  fullscreen dumb buffers distinct instead of aliasing `g_fb`.
- Aquamarine headless: `commit()` opens `/dev/dri/card0`, maps the pending buffer
  with `beginDataPtr()`, and submits the HOS present ioctl.
- Hyprland sessionless headless output is treated as an active normal output, not
  unsafe fallback state.
- Hyprland GL output renderbuffer: if dma-buf EGLImage import fails (expected with
  surfaceless swrast: no dma-buf import), render into a GL-owned framebuffer and
  read pixels back into the mapped dumb buffer before commit.

Verification:
- QEMU 45s headless run: no page faults, no `RASSERT`/`SIGABRT` restart loop.
- Serial shows 6 kernel present ioctls (`nr=...f0`) and CPU readback completed
  before present.
- QEMU PPM screendump is a single dark clear color (`RGB 0f 17 1f`) across
  1280×800. `pnmtopng` compresses that to a tiny 1-bit single-color PNG, but the
  raw PPM pixels confirm the frame reached the screen.

Remaining rendering limitation:
- This milestone presents a deterministic clear frame through the real distinct
  buffer → readback → kernel blit path. Full Hyprland scene rendering is still
  bypassed for the HOS CPU-readback path because Mesa shader compilation and some
  later fallback framebuffer allocations are still unstable in the guest. Those
  failures are now nonfatal; next work is to re-enable real scene rendering on top
  of the proven present path.

## Later

- **Phase 6 — first real GUI app:** port SDL2 (large, but unlocks many apps).
- Minimal Wayland client (weston-simple-shm); `shm_open`/POSIX shm (layer on memfd).
- **Per-task fd tables** — the kernel has a *global* fd table, so a real
  `posix_spawn`/vfork sharing fds would let a child's `dup2`/`close` corrupt the
  parent's, and forked children's fds aren't closed on exit (breaks pipe `POLLHUP`).
  Not needed for the boot path (the one output-capturing spawn is stubbed).

---
## Syscall gaps (cross-cutting)

| Syscall | Status | Needed for |
|---------|--------|-----------|
| `sigprocmask`/`sigaction` with delivery | partial | app error handling |
| `shm_open` / POSIX shm | not done (layer on memfd) | Wayland shm alt path |

(memfd, timerfd, eventfd, sendmsg/recvmsg+SCM_RIGHTS, dup/dup2/dup3, nanosleep,
clone/futex, flock, getdents64, PRIME_HANDLE_TO_FD are implemented.)

## Known issues / notes

- DRM ioctl can #GP when the kernel writes a user pointer under SMAP. Mitigated via
  `-cpu qemu64,-smap,-smep` in `qemu-run.sh`; real fix = STAC/CLAC around copies.
- **Hyprland's `RASSERT` does `raise(SIGABRT)`, which the kernel does NOT make
  fatal** — a failed assertion *continues* and crashes downstream. When reading a
  crash, find the FIRST `Assertion failed!` + matching `libEGL debug:`/EGL error,
  not the final `[pf]`. The serial log has binary bytes → use `grep -a`.
- Hyprland uses a **lua** config (`/etc/hypr/hyprland.lua`); how it's served in the
  guest is unresolved (not in the `g_vfs` table) — blocks easy config-based tweaks.
- **Debug logging still on, trim once rendering works:** `[xkb]` unpack counts,
  `[mmap-einval]`, `[mmap-so]`, `[drm] nr=`, `[sc] t=`, `[futex-*]`, PF `rsp/ret0`,
  the `H`/`I`/`D` `console_putchar` in `linux_sys_ioctl`/`handleDrmIoctl`, and
  `EGL_LOG_LEVEL=debug`.

## How to run

```
make all && ./qemu-run.sh    # boots Hyprland as initial userspace
```
> Rebuild note: top-level `make` targets no-op when artifacts exist — after editing
> kernel source, delete the stale object (`build/d/.../*.o`) and
> `build/libkernel_d.a` to force a recompile.

In-house compositor demo instead (in busybox): run `/compositor &` then two
`/hello-gui &` clients (Alt+Tab to switch, drag titlebars).
