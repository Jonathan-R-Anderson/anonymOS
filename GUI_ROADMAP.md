# GUI Desktop Roadmap

## Current status (2026-06-01) — GL renderer up, blocked in input (xkb)

Hyprland boots **dynamically** (ld.so) all the way through: `CCompositor()` →
Aquamarine headless backend → Wayland socket bind → DRM/GPU enumeration → Mesa
**softpipe driver loads** → `CHyprOpenGLImpl::initEGL`, and after this session's
fixes **`eglInitialize` SUCCEEDS** with valid GBM configs (ARGB8888/XRGB8888).

**F.4k chain solved this session** (the previous "eglInitialize SUCCEEDS" note was
wrong — it was *failing*; the non-killing `raise(SIGABRT)` in Hyprland's `RASSERT`
let each failed assertion fall through into a confusing downstream
`strlen(NULL)`/`std::string=NULL` crash, masking the real cause). Diagnosed via
Mesa's `EGL_LOG_LEVEL=debug` output (`libEGL debug:` lines on stderr — note the
serial log has binary bytes, so use `grep -a`). Two env fixes landed
([exports.d](src/kernel/d/core/exports.d)):
1. `GALLIUM_DRIVER=llvmpipe` → **`softpipe`** — our driver is `-Dllvm=disabled`, so
   llvmpipe doesn't exist and screen creation failed.
2. **`GBM_ALWAYS_SOFTWARE=1`** — `MESA_LOADER_DRIVER_OVERRIDE=kms_swrast` made GBM's
   *hardware* path succeed (`gbm_dri->software=false`), so `dri2_initialize_drm`
   ran the PRIME render-GPU code: `loader_is_device_render_capable(card0)` is false
   (dumb KMS node, no render node) → it called
   `gbm_dri->mesa->queryCompatibleRenderOnlyDeviceFd` = **NULL** → call-through-0.
   `GBM_ALWAYS_SOFTWARE=1` forces the sw path and skips that block.

**F.4k.2 dual-glapi — FIXED 2026-06-01.** Symptom: `eglCreateContext` GLES3.2 fails
(softpipe caps below 3.2 → `EGL_BAD_MATCH`, expected), 3.0 retry succeeds, but
`glGetString(GL_EXTENSIONS)` (OpenGL.cpp:359) returned **NULL** → `RASSERT` → fall
through → `m_extensions = NULL` crash. Root cause (readelf): the driver's
`_glapi_tls_Dispatch`/`_glapi_tls_Context`/`_glapi_set_dispatch` were **`LOCAL`**
(glapi is built as a static `libglapi.a` with `gnu_symbol_visibility: 'hidden'`,
then localized by the driver's `--version-script dri.sym` `local: *`), while
Hyprland **exports** those TLS vars `GLOBAL`. So `eglMakeCurrent` set the *driver's*
dispatch table but Hyprland's `glGetString` read *Hyprland's* (empty) → NULL.
**Fix (driver-side, no full Mesa rebuild):** in
`deps/mutter/build/mesa-23.3.5-epin`, patched `src/mapi/shared-glapi/meson.build`
`gnu_symbol_visibility: 'hidden'` → `'default'` (so glapi's TLS access is the
interposable general-dynamic model, not local-exec) and added
`_glapi_tls_Dispatch`/`_glapi_tls_Context`/`_glapi_set_dispatch`/`_glapi_get_dispatch`
to `src/gallium/targets/dri/dri.sym` `global:`, then `ninja` the driver. The
driver's `_glapi_tls_*` are now `GLOBAL TLS` (exported, interposable) → bind to
Hyprland's exported defs at dlopen → one shared dispatch. Installed as both
`kms_swrast_dri.so` and `swrast_dri.so`. **Result: `glGetString` works, the GL
renderer initializes, and Hyprland advances ~5000 log lines deeper** (past EGL into
backend/input setup).

**Current blocker (F.4l) — xkb keymap data.** Crash now in input setup:
`xkbcommon: ERROR: failed to add default include path …/share/X11/xkb`, then
`xkb_context_new`/keymap returns NULL and `xkb_context_ref(NULL)` SIGSEGVs
(cr2=0, `rip`=xkb_context_ref, `ret0=0xedc92d`). Fix: ship xkeyboard-config data
(`share/X11/xkb/*`) or a precompiled keymap, or set `XKB_*` env so xkbcommon
finds/builds a keymap, or make the input path tolerate a NULL keymap.

**Also seen (Phase-G prep):** aquamarine logs `failed to map a drm_dumb buffer:
Operation not permitted` — the kernel's `DRM_IOCTL_MODE_MAP_DUMB` (or the
subsequent `mmap`) returns `EPERM`. Needed before we can present.

> Debug logging is currently on (`[sc] t=`, `[drm] nr=`, `[mmap-so]`, `[futex-*]`,
> PF `rsp/ret0`) plus `EGL_LOG_LEVEL=debug`. Trim once rendering works.
>
> NOTE: Hyprland's `RASSERT` does `raise(SIGABRT)`, which our kernel does NOT turn
> into task death, so a failed assertion *continues* and crashes downstream. When
> reading a crash, find the FIRST `Assertion failed!` + the matching `libEGL
> debug:`/EGL error, not just the final `[pf]`.

---

## Completed (2026-05-31 → 2026-06-01)

**Compositor bring-up (pre-rendering):**
- **rtfs runtime-fs overlay** (posix.d): writable `/run`,`/tmp`,`/var`; `FD_RTFILE`;
  `mkdir/unlink/rename` with real errno → `XDG_RUNTIME_DIR` works.
- **thread/`clone`** (kernel_main.d): `CLONE_VM`→`cloneThread` (shared PML4,
  per-thread mmap windows, TLS, cleartid) → `std::thread` works.
- **fork() page-table copy fix** (addrspace.d): mask PTE frame bits (`PTE_ADDR_MASK`)
  so the NX bit no longer corrupts `copy_phys_page` → fork stops faulting.
- **headless dumb-buffer backend**: durable Aquamarine patch
  (`patches/0001-headless-dumb-allocator.patch`) opens `/dev/dri/card0` +
  `CDRMDumbAllocator`; kernel `fstat` reports the DRM fd as char dev
  `makedev(226,0)` + `/sys/dev/char/226:0/device/drm` → `CBackend::start()`
  succeeds (headless `poll()` loop).

**Dynamic linker (rendering needs runtime `dlopen`):**
- **A** musl `--enable-shared` → `ld-musl-x86_64.so.1`/`libc.so`.
- **B** kernel loads `PT_INTERP`/`ET_DYN` + auxv (`AT_BASE/AT_PHDR/…`) in
  `loadElf`+`d_kernel_main` (interp at `0x5A0…`, PIE main at `0x550…`).
- **C** file-backed `mmap` (`mmapCopyFileRange`) so ld.so can map `.so` segments.
- **D** `.so` resolution by basename (`findBootModuleLib`) + **unique `(st_dev,st_ino)`
  per file** (fstat) — required for ld.so's DSO dedup, else `dlsym` fails.
- **E** verified end-to-end: `make DYNTEST=1` → `DYNHELLO: dlopen+dlsym+call OK`.
- **F.1–F.3** Hyprland relinked **dynamic** (`PT_INTERP`, `--export-dynamic`),
  ships `ld-musl` + driver as boot modules; boots & runs the full 38 MB binary.
- Log visibility: kernel mirrors rtfs `*.log` writes to the console.

**Driving Hyprland through startup to EGL:**
- **F.4a** seat env `LIBSEAT_BACKEND=builtin` (libseat uses builtin backend).
- **F.4b** `poll`/`ppoll` cooperative-yield — fixed an event-loop busy-spin that
  starved every other task under the cooperative scheduler.
- **F.4e** spawn-deadlock RESOLVED: two scheduler bugs (`scheduleNext` never
  rescheduled task 0; `exitTask` rejected task 0 as a `wait4` parent), `CLONE_VFORK`
  (vfork), `execAndGet` stub (Hyprland forked `/bin/sh` for `lspci` before the
  renderer), `flock`(73)+`getdents64`(217) dispatch (flock ENOSYS broke the
  wayland socket bind). Durable hyprutils patch `patches/0002-cprocess-build-argv-prefork.patch`.
- **F.4f** DRM `VERSION` ioctl returns non-empty `date`/`desc` (was NULL →
  `drmGetVersion` `strlen(NULL)`).
- **F.4g** real `FUTEX_WAKE` wait-queues (per-task tracking) — no longer a no-op.
- **F.4h/F.4i** **Mesa driver rebuilt against shared musl.** The shipped
  `kms_swrast_dri.so` statically embedded musl whose `__libc` is never initialized
  for a dlopen'd `.so`, so its malloc dereffed NULL. Fixed by rebuilding the Mesa
  softpipe `dri` target for this tree against shared musl — new driver imports
  libc (`NEEDED libc.so`, `malloc` undefined; UND 4→243) and binds Hyprland's
  initialized libc at dlopen. Shipped as both `kms_swrast_dri.so` and
  `swrast_dri.so`.
  - Rebuild: `ninja -C deps/mutter/build/mesa-23.3.5-epin/build src/gallium/targets/dri/libgallium_dri.so`
    (cross file `deps/mutter/musl-cross-epin.ini`, `PATH=deps/.host-tools/bin`),
    then copy to `deps/gtk-stack/sysroot/lib/dri/{kms_swrast,swrast}_dri.so`.

**Known limitation (revisit later):** the kernel has a **global fd table**, so a
proper `posix_spawn`/vfork that shares fds would let a child's `dup2`/`close`
corrupt the parent's fds, and forked children's fds aren't closed on exit (breaks
pipe `POLLHUP`). For real subprocess output capture, add **per-task fd tables**.
Not needed for the boot path (the one output-capturing spawn is stubbed).

---

## To do

### F.4k → renderer (current blocker, see above)
Fix the NULL `EGL_EXTENSIONS` from Mesa's software EGL, then GLES context creation
and the first frame.

### Phase G — Present
Wire the headless dumb-buffer swapchain to the screen: KMS modeset + page-flip (or
a CPU blit of the dumb buffer to the Limine framebuffer). Kernel DRM already has
CREATE_DUMB/MAP_DUMB/ADDFB/PAGE_FLIP; validate PRIME_HANDLE_TO_FD + dumb-buffer
`mmap`.

### Phase 6 — First real graphical application
Port **SDL2** — much larger but unlocks many existing apps.

### Other remaining
- Port a minimal Wayland client (weston-simple-shm).
- `shm_open` / POSIX shm (can be layered on memfd).
- Per-task fd tables (see Known limitation above).

---

## Syscall gaps to fill (cross-cutting)

| Syscall | Status | Needed for |
|---------|--------|-----------|
| `sigprocmask` / `sigaction` with delivery | partial | app error handling |
| `shm_open` / POSIX shm | not done (layer on memfd) | Wayland shm alt path |

(memfd, timerfd, eventfd, sendmsg/recvmsg+SCM_RIGHTS, dup/dup2/dup3, nanosleep,
getpid/getppid, clone/futex, flock, getdents64 are implemented.)

### Known issues
- DRM ioctl can #GP when the kernel writes a user pointer while SMAP is active.
  Mitigated for QEMU by `-cpu qemu64,-smap,-smep` in `qemu-run.sh`; real fix =
  STAC/CLAC around user-space copies.

---

## How to run

```
make all && ./qemu-run.sh    # boots the Hyprland Limine module as initial userspace
```

For the in-house compositor demo instead, in busybox:
```
/compositor &
/hello-gui &
/hello-gui &        # second client; Alt+Tab to switch, drag titlebars
```
Each client draws into its own memfd-backed window; the compositor blits + handles
input, animating via a timerfd frame clock.

> Rebuild note: the top-level `make` targets have no prerequisites and no-op when
> artifacts already exist — after editing kernel source, delete the stale object
> (`build/d/.../*.o`) and `build/libkernel_d.a` to force a recompile.
