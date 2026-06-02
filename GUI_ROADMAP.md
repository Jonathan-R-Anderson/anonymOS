# GUI Desktop Roadmap

## Current status (2026-06-01) — Hyprland's EGL initializes

Hyprland boots **dynamically** (ld.so) all the way through: `CCompositor()` →
Aquamarine headless backend → Wayland socket bind → DRM/GPU enumeration → Mesa
**softpipe driver loads and initializes** (parses `/etc/drirc`) → its GL renderer
`CHyprOpenGLImpl::initEGL`, where `eglGetPlatformDisplayEXT(GBM)` returns a valid
display and **`eglInitialize` SUCCEEDS**.

**Current blocker (F.4k):** right after init, `eglQueryString(dpy, EGL_EXTENSIONS)`
returns **NULL**, and Hyprland does `std::string(NULL)` → `strlen(NULL)` SIGSEGV
([OpenGL.cpp:170](deps/hyprland/src/render/OpenGL.cpp#L170); caller located via
the page-fault handler's `rsp/ret0` logging). So Mesa's software EGL initializes
but yields a NULL display-extension string. Next: find why the swrast/GBM EGL
platform returns NULL `EGL_EXTENSIONS` post-`eglInitialize` (check `major/minor`,
Mesa `_eglQueryString`/`disp->Extensions`; or make the GBM device valid enough
that Mesa populates extensions). Then GLES context → first frame → Phase G.

> Debug logging is currently on (`[sc] t=`, `[drm] nr=`, `[mmap-so]`, `[futex-*]`,
> PF `rsp/ret0`). Trim once rendering works.

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
