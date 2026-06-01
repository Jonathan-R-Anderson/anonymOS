# GUI Desktop Roadmap

## Current status (2026-06-01)

Hyprland now boots **dynamically** (ld.so), past `CCompositor()`, the Aquamarine
backend, the spawn-deadlock (`getSystemInfo`), the **Wayland socket bind**, into
DRM/GPU enumeration and Mesa driver loading. GBM tries `virtio_gpu_gbm.so`, falls
back, opens `kms_swrast_dri.so`, and no longer gets stuck in the ld.so/Mesa futex
loop.

**F.4g is DONE:** `FUTEX_WAKE` is no longer a no-op. The scheduler now tracks
per-task futex waits, wakes matching waiters, handles bitset wake/requeue paths
well enough for musl/Mesa, and logs `[futex-wake]`/`[futex-unblock]`. The former
ld.so futex (`u≈0x5a00000b2d68`) now unblocks when the word flips to 0, and the
foreground task gets past Mesa driver dlopen/init.

**Current blocker (F.4h) — ROOT-CAUSED 2026-06-01:** `kms_swrast_dri.so` statically
embeds musl, and its embedded `__libc` is never initialized (a `dlopen`'d shared
object never runs `__libc_start_main`), so the driver's own malloc derefs NULL.
- Driver load base (from `[mmap-so]`) = `0x740000138000`; crash
  `rip=0x740000856c70` ⇒ driver `.text` offset **`0x71EC70`** = `__malloc_alloc_meta+0x50`.
  Disasm: `mov 0x5dc804(%rip),%rax  # __libc+0x8` (= `__libc.auxv`), then
  `mov -0x8(%rax,%r14,1),%rcx` faults because `__libc.auxv == NULL`. (musl's
  mallocng walks `auxv` for `AT_RANDOM`; `auxv` is set by `__init_libc`, which the
  driver never runs.) Earlier ".rodata/nir_opt_algebraic" was wrong — that assumed
  base `0x740000000000`; real base is `0x740000138000`.
- **The real fix = the driver must use the HOST libc, not its own.** Build-side
  facts (from `deps/mutter/build/mesa-23.3.5/build/build.ninja`, target
  `src/gallium/targets/dri/libgallium_dri.so` → installed as `kms_swrast_dri.so`):
  driver is **softpipe** (`-DGALLIUM_SOFTPIPE`, **no LLVM**); link uses
  `-Wl,--no-undefined` + the musl-clang++ wrapper, which at build time (2026-03-28,
  **before** musl `--enable-shared` on 05-31) pulled in **`libc.a`** → musl
  embedded. The build dir's `LINK_ARGS` also point at **`/home/bruns/Documents/
  HanonymOS/...`** (built for the sibling tree, copied into this sysroot), so it's
  not a clean in-place relink.
- **Fix options (pick one):**
  1. **Relink the driver against shared musl** so libc is NEEDED, not embedded:
     drop `--no-undefined` (or add `-Wl,--allow-shlib-undefined`) and ensure
     `-lc` resolves to `libc.so`; the undefined `malloc`/etc. then bind at dlopen
     to Hyprland's initialized `libc.so`. Requires reconfiguring Mesa for this
     tree's paths (the HanonymOS-path build is stale) → a real Mesa build task.
  2. ~~Kernel/ld.so hack~~ **TRIED & REJECTED 2026-06-01.** A NULL-page guard
     (map a zeroed RO page at addr 0 on read-fault) got past the `auxv` read but
     just **moved the crash**: next fault `rip=0x1000 err=0x14` (instruction
     fetch) — the driver then **called a NULL function pointer** and executed the
     zero page. So the embedded musl has **multiple** uninitialized pointers
     (`__libc.auxv` AND a function table), and per-NULL stop-gaps don't work. The
     guard was reverted. **Conclusion: F.4h REQUIRES the Mesa relink (option 1).**
  3. **Mesa source is STRIPPED** (`deps/mutter/build/mesa-23.3.5/src` has 0 `.c`
     files; `target.c.o` missing), and the build used **HanonymOS's static-only
     musl**. So the relink needs a **full Mesa re-extract + reconfigure + build**
     for THIS tree against shared musl (`deps/mutter/downloads/mesa-23.3.5.tar.xz`;
     meson with `-Dgallium-drivers=softpipe`, libc.so). That's the real next task
     — a bounded but multi-step Mesa build.
- This means the **self-contained-driver assumption (F-intro) was wrong**: a
  dlopen'd `.so` that embeds a static libc has an uninitialized `__libc`.

(Debug logging currently on: `[sc] t= n=`, `[drm] nr=`, `[mmap-so]`, `[futex-*]`,
fatal-PF `rip=`. Trim once F.4h is closed.)

Secondary noise (not the foreground crash): leftover fork child reaches
Aquamarine/libseat; libseat reports `Not a socket` on a child-side
`getsockopt(SO_PEERCRED)` over a pipe fd. `membarrier`/`tkill` ENOSYS gone.

### Earlier milestones (all DONE)
- rtfs runtime-filesystem overlay; thread/`clone` + futex; fork page-table copy
  fix; headless dumb-buffer backend; full dynamic linker (A–F.1); poll/ppoll
  cooperative-yield; seat env; **scheduler fixes** (reschedule task 0; task 0 as
  `wait4` parent); **vfork (CLONE_VFORK)**; `flock`/`getdents64` dispatch; the
  `execAndGet` spawn-deadlock stub.

**Current blocker → next milestone:** actual **rendering**. The compositor runs
but draws nothing yet — Hyprland's GL renderer needs a working EGL/GLES context,
and the gallium driver (`kms_swrast_dri.so`) is `dlopen`'d at runtime, which the
current static, no-dynamic-linker environment can't do. **Chosen approach:
dynamic linker + shipped `.so` (see "PLAN: rendering via dynamic linker" below
for the full phased roadmap).** Next session starts at Phase A (rebuild musl
`--enable-shared`).

---

## PLAN: rendering via dynamic linker + shipped .so (chosen 2026-05-31)

Decision: bring up rendering the upstream-faithful way — make the GL stack
dynamic, ship the musl dynamic linker + Mesa/LLVM `.so` in the ISO, and let
musl's `ld.so` do relocation/symbol/TLS/`dlopen` in userspace (the kernel just
has to load the interpreter and mmap files). This is multi-session; do the
phases **in order** and stop at each verification gate before moving on.

### Why (recon, 2026-05-31)
- Hyprland already statically contains the EGL/GLES **API** (570 `egl*/gl*`
  symbols), but `libEGL.a` still **dlopens the gallium driver** at runtime
  (`MESA-LOADER: dlopen(%s)`, "falling back to kms_swrast"). The driver
  (`kms_swrast_dri.so`) is a separate object — not a static megadriver.
- Environment can't dlopen: musl built `--disable-shared`
  ([deps/musl/Makefile:47](deps/musl/Makefile#L47)) so there is **no
  `ld-musl-x86_64.so.1` / `libc.so`**; binaries are static; `AT_BASE`=0 ("no
  interpreter", [kernel_main.d:1282](src/kernel/d/core/kernel_main.d#L1282)); the
  ISO bundle has **zero `.so`**.
- ELF loader ([elf_loader.d](src/kernel/d/core/elf_loader.d), 139 lines) only
  maps fixed-address `PT_LOAD` (`e_type` unchecked) — no `PT_INTERP`, `ET_DYN`,
  `PT_TLS`, or relocations.
- `mmap` (kernel_main.d case 9, ~line 690) handles anonymous / DRM-phys / memfd
  only — **no file-backed `MAP_PRIVATE`** of a regular file.
- Mesa 23.3.5 (llvmpipe + `kms_swrast_dri.so`) is built under
  `deps/mutter/build/mesa-23.3.5`, but only as `.so` needing dlopen; **no
  `libLLVM` is present** (llvmpipe needs it) — must be built/shipped.

### Phase A — Toolchain: dynamic musl — DONE 2026-05-31
- Changed [deps/musl/Makefile:47](deps/musl/Makefile#L47) `--disable-shared` →
  `--enable-shared` and rebuilt. (Gotcha hit: the extracted `musl-1.2.5/ldso/`
  tree had been stripped; `rm -rf musl-1.2.5` forced a clean re-extract from the
  tarball — the Makefile re-extracts when the source dir is absent.)
- Verified: `deps/musl/install/lib/ld-musl-x86_64.so.1` → `libc.so` (ELF shared
  object exporting `dlopen`/`dlsym`/`__libc_start_main`); static `libc.a` still
  present, so existing static binaries (busybox/compositor/test-drm) are
  unaffected. `musl-clang` now emits **dynamic PIE** ELFs by default.
- **Carry-forward for Phases B/D/E/F:** the baked-in `PT_INTERP` is the absolute
  *host build path* (`…/deps/musl/install/lib/ld-musl-x86_64.so.1`), NOT a target
  path. When linking target binaries, pass
  `-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1` so the kernel can resolve the
  interp from the ISO at `/lib/...` (and stage `ld-musl-x86_64.so.1` there — it's
  an absolute symlink today, so ship the real `libc.so` as that path).

### Phase B — Kernel: load the dynamic interpreter — DONE (kernel side) 2026-05-31
- `loadElf` ([elf_loader.d](src/kernel/d/core/elf_loader.d)) now takes a
  `loadBias` + interp-out buffer, handles `ET_DYN` (adds bias to every `p_vaddr`
  and to `e_entry`), detects `PT_INTERP` (copies the path out), and computes the
  real in-memory `phdrVaddr` (segment covering `e_phoff`), returning
  `phdrVaddr/phEnt/phNum/hasInterp/isDyn`.
- `d_kernel_main` ([kernel_main.d](src/kernel/d/core/kernel_main.d)): ET_EXEC →
  bias 0; ET_DYN main → `MAIN_PIE_BASE=0x550000000000`. If `hasInterp`, finds the
  ld.so boot module (`findInterpModule`, matched by `ld-musl` substring), loads
  it at `INTERP_BASE=0x5A0000000000`, sets `AT_BASE`=that base, and starts RIP at
  the **interp entry**. Auxv now uses real `phdrVaddr/phEnt/phNum` (replaced the
  hardcoded `0x400000+e_phoff`). ld.so does all relocs/TLS itself.
- **Verified:** static (ET_EXEC) path byte-identical — Hyprland still boots to its
  `poll()` loop, no regression (`[elf] type=2 entry=0x4966f0 bias=0`). The dynamic
  path is wired but **not yet exercisable** until Phase C (file-backed mmap so
  ld.so can map `libc.so`) + Phase D (bundle `ld-musl` as a boot module + a
  dynamic init/test binary).
- **Caveats / carry-forward:**
  - `execveTask` still loads statically (bias 0, no interp) — fine for now (init
    comes via `d_kernel_main`); add dynamic support there when spawning dyn progs.
  - brk is effectively disabled for a PIE main (`brkTask` caps newBrk at
    `0x8000000`, but a PIE `brkStart` ≈ `0x550000000000`); musl malloc uses mmap,
    so OK — but revisit if something needs brk.
  - ld.so is found via boot module today; once binaries link with
    `-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1`, prefer resolving the interp
    through the FS instead of a name-substring match.

### Phase C — Kernel: file-backed mmap — DONE 2026-05-31
- `mmapCopyFileRange(fd, off, dst, len)` added in
  [posix.d](src/kernel/d/core/syscalls/posix.d): copies a file's bytes (zero-fill
  past EOF) for `FD_BUNDLE`/`FD_BOOT_MODULE`/`FD_FILE`(virtual)/`FD_RTFILE`,
  returns 0 for non-mappable fds (caller → anon zero page).
- `mmap` (kernel_main.d case 9): new `useFile` branch — when not anon/DRM/memfd
  and `fd` is a real file, alloc fresh pages and copy the file content at
  `moffset` per page (MAP_PRIVATE semantics; MAP_FIXED segment re-maps work since
  it copies at the fixed addr). Pages stay RW + executable: the kernel never sets
  NX, so `PROT_EXEC` is satisfied and ld.so/JIT can execute, and writable so
  ld.so can apply relocations; `sys_mprotect` (already flips W↔X) tightens RELRO.
- **Verified:** static path unaffected (anon/DRM/memfd byte-identical) — Hyprland
  still reaches its `poll()` loop, no regression. File-backed path will be
  exercised once ld.so maps `libc.so` (Phase D/E).
- Note: NX is intentionally never set (EFER.NXE state unverified); W^X is not
  enforced — acceptable for bring-up, revisit for hardening.

### Phase D — Filesystem: ship + resolve libraries — DONE 2026-05-31
- `.so`s shipped as **boot modules** (limine `module_path`); the kernel resolves
  library opens by **basename**: `findBootModuleLib` in
  [posix.d](src/kernel/d/core/syscalls/posix.d) matches a `.so` request
  (`/lib/libfoo.so`, dlopen search paths, …) to a bundled module, wired into
  `sys_open` (so `newfstatat`/`access` resolve too). The ld.so module is found by
  `findInterpModule` (`ld-musl` substring), independent of the PT_INTERP path.
- **Critical fix:** `fstat` now returns a **unique non-zero `(st_dev, st_ino)`**
  per file (`st_dev` 1=module/2=bundle, `st_ino`=backend+1). Without it the
  dynamic linker's DSO dedup-by-(dev,ino) collapsed every `.so` onto one (ino 0)
  and `dlsym` failed.
- musl note: `libc.so` ≡ `ld-musl-x86_64.so.1` (one file), so a NEEDED `libc.so`
  is satisfied by the interpreter itself — no separate libc module needed.

### Phase E — VERIFICATION GATE — PASSED 2026-05-31
- Test harness: `src/test-dyn/` (`dyntest.c` dynamic PIE + `libfoo.c`→`libfoo.so`);
  staged + made init via `make DYNTEST=1 hos.iso` (kernel prefers a `dyntest`
  module; gated so normal builds keep Hyprland as init).
- Result in serial: `DYNHELLO: main running via ld.so` **and**
  `DYNHELLO: dlopen+dlsym+call OK` — ld.so relocated itself+main, ran main, then
  `dlopen("libfoo.so")` (file-backed-mmapped via the kernel, 4× `mmap(9)`),
  `dlsym("foo")`, and `foo()`→4242. **Phases A–D proven end to end.**
- To re-run: `make DYNTEST=1 hos.iso && ./qemu-run.sh` (or headless), grep
  `DYNHELLO`. Default `make hos.iso` ships Hyprland as init (no dyntest).

### Phase F — Mesa/LLVM dynamic + EGL/GLES — IN PROGRESS

**Big simplification found:** `kms_swrast_dri.so` is **self-contained** (14.6 MB,
LLVM statically embedded, only 4 UND symbols: libgcc EH + `_glapi_tls_*`). So
there is **no need to build/ship `libLLVM` or rebuild Mesa as `.so`** — ship the
one driver `.so` and keep Hyprland's static `libEGL.a`/`libGLESv2.a`/`libgbm.a`.
The only requirement is that Hyprland be a **dynamic executable** so its built-in
`dlopen` works, and that it **export** `_glapi_tls_Dispatch`/`_glapi_tls_Context`
for the driver to bind.

**F.1 — Hyprland is now dynamic — DONE 2026-06-01.**
- `deps/hyprland-hos/Makefile` link flags: `-static -no-pie …` →
  `-no-pie -Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1 -Wl,--export-dynamic …`.
  Result: ET_EXEC + `PT_INTERP`, `NEEDED libc.so`, 22.7k exported dynsyms,
  `_glapi_tls_*` exported.

**F.2 — ship loader + driver — DONE.** Main `Makefile` stages (with Hyprland):
`ld-musl-x86_64.so.1` (=libc.so) and `kms_swrast_dri.so` as boot modules
(resolved by basename via `findBootModuleLib`).

**F.3 — dynamic Hyprland boots & runs — VERIFIED 2026-06-01.** ld.so relocates
the full 38 MB binary + libc, runs it (`Welcome to Hyprland!`), through
CCompositor + Aquamarine backend start, into the `poll()` event loop — no crash.
The dynamic loader scales from the `dyntest` toy to the real compositor.
- Added log visibility: kernel mirrors rtfs `*.log` writes (Hyprland's
  `hyprland.log`) to the console (`rtNameEndsWith` in posix.d), since Hyprland
  disables stdout logging after startup.

**F.4a — seat — DONE 2026-06-01.** `linux_seed_initial_stack` (exports.d) already
injects a rich envp (it was NOT empty — roadmap note was wrong); added
`LIBSEAT_BACKEND=builtin` (+ `LIBGL_ALWAYS_SOFTWARE=1`, `GALLIUM_DRIVER=llvmpipe`,
`MESA_LOADER_DRIVER_OVERRIDE=kms_swrast`, `AQ_TRACE=1`). The `libseat → seatd`
"Connection refused" error is **gone** — libseat uses its builtin backend.

**F.4b — poll/ppoll cooperative-yield fix — DONE 2026-06-01 (major).** Root cause
of the prior livelock: under the cooperative scheduler, `poll()` returned 0
immediately when nothing was ready, so an event-loop thread busy-spun on `poll`
(~879k calls), **monopolising the CPU** — the worker thread / fork children that
would make an fd ready never got scheduled. Fix (kernel_main.d syscall
dispatcher): when `poll`(7)/`ppoll`(271) find nothing ready and the caller wants
to wait, **rewind RIP + `scheduleNext`** (yield), like the console-read path; the
task re-runs the poll after others get a turn. Also fixed `linux_sys_ppoll`
(posix.d) which returned 0 unconditionally — now scans fd readiness via shared
`pollScanFds` (so it can actually report ready). Result: the fork children now
reach `execve` (`/bin/sh` → ENOENT → exit) instead of hanging; Aquamarine backend
creation + libseat seat0 now run.

**F.4c — futex handling improved + deadlock root-caused.** Extended the futex
dispatcher (kernel_main.d): now handles `FUTEX_WAIT_BITSET` (as WAIT) and
`WAKE_BITSET`/`REQUEUE`/`CMP_REQUEUE`/`WAKE_OP` (as no-op WAKE) instead of
returning ENOSYS. Added instrumentation (`g_futexLogCount`) logging
`op/uaddr/val/*u/task`.

**Diagnosis (the real wall): a multithreaded-fork lock-inheritance deadlock.**
Futex trace shows: task 1 (worker) and task 2 (a fork child) each stuck in
`FUTEX_WAIT` on a **contended mutex (value 2, *u==2)** that never changes; task 0
(main) does NO futex and is NOT scheduled. Scheduler/`wait4` analysis: **main is
blocked in `wait4`** (its `waiting` flag set), waiting for the fork child (task 2)
to exit. But task 2 **inherited a locked C++ `std::mutex` (value 2) from the
multithreaded parent** — a lock held by a thread that doesn't exist in the child —
so it deadlocks in `FUTEX_WAIT` **before reaching `execve`** and never exits ⇒
`wait4` hangs forever. (Contrast: task 3, an earlier fork, *did* reach
`execve("/bin/sh")`→ENOENT→exit; timing-dependent whether a lock was held at fork.)
- This is a **userspace fork-safety hazard** (a C++ mutex, not a musl-internal
  lock — `pthread_atfork` resets musl's own locks but not app/libc++ mutexes).
  Hard to fix cleanly kernel-side. Options to explore next:
  1. Make `fork()` from a multithreaded process safer — e.g., on fork, reset
     obviously-held futex words in the child? (fragile/incorrect in general).
  2. Avoid the fork+wait stall: implement `vfork`/`posix_spawn`-style semantics,
     or have the spawn path `execve` directly without touching app locks.
  3. Real futex **timeout** support (track PIT ticks) so a stuck `FUTEX_WAIT`
     eventually returns ETIMEDOUT — lets the child's lock loop give up and
     (best case) proceed to `execve`.
  4. Reduce what the child does pre-`execve` (the deadlock is a lock taken between
     fork and exec — likely malloc/logger); investigate which mutex (uaddr
     0x740000129b70, in the worker-thread stack region).
- Only once the spawn/`wait4` no longer hangs does `start()` return → STAGE_LATE →
  `eglInitialize` → driver `dlopen` → EGL/Mesa tail.

### F.4d — IN PROGRESS: fork/exec spawn deadlock (definitive diagnosis 2026-06-01)
**Done so far:**
- Patched hyprutils `CProcess::runSync`/`runAsync` to build argv (`strdup`/
  `std::vector`) **before** `fork()` so the child path is async-signal-safe
  (durable: `deps/hyprland-hos/patches/0002-cprocess-build-argv-prefork.patch`,
  applied in `hyprutils-extract`). Correct fix, but **did not unblock** — the
  deadlocking child runs a different code path.
- Added per-task syscall logging (`[sc] t=<tid> n=<num>`) + futex instrumentation.

**Definitive picture (per-task trace):** `SystemInfo::getSystemInfo()` (right
after `backend->start()`, before the renderer) calls `execAndGet("lspci…")` →
`CProcess::runSync` → `pipe`,`pipe`,`fork`(child 2),`fcntl`(nonblock),then **main
`poll`s the child's stdout pipe**. The child (task 2) does
`set_tid_address`/`pipe`/`mmap`/`rt_sigaction` then **deadlocks in `FUTEX_WAIT`**
on a mutex (value 2) **inherited locked** from the multithreaded parent — so it
never `execve`s, never writes output, never closes the pipe ⇒ **main's `poll`
blocks forever** (task 0 = 0 syscalls in steady state; tasks 1+2 spin on futex).

**The real fix — vfork/`posix_spawn` (next):**
1. Implement **`CLONE_VM|CLONE_VFORK`** in `kernel_main.d` case 56: child shares
   the parent PML4 (no deep copy of locked mutexes), parent suspended until the
   child `execve`s or `_exit`s.
2. Make `execveTask` handle dynamic (`PT_INTERP`/`ET_DYN`) binaries (reuse Phase-B
   loader) and return clean ENOENT for missing ones.
3. **Patch `CProcess` to use `posix_spawn`** (file-actions for the pipe dup2/close)
   instead of `fork()+execvp`, so it goes through the `CLONE_VFORK` path and the
   child never runs lock-taking app code. (musl `posix_spawn` already emits
   `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)`.)
- Verify: `execAndGet` returns (empty, since `/bin/sh`/`lspci` are absent),
  `getSystemInfo` completes, main proceeds to STAGE_LATE → renderer/EGL.

### F.4e — spawn deadlock RESOLVED 2026-06-01
The multithreaded-fork deadlock that stalled startup is fixed. What it took:
- **Two scheduler bugs (the big ones)** in `kernel_main.d`: (1) `scheduleNext`
  had `if (next==0) next=1`, so **task 0 (the main process) was never
  rescheduled** once it blocked (poll/futex/vfork) — permanent starvation; now it
  round-robins all slots incl. 0. (2) `exitTask` required `parent > 0`, so
  children of task 0 never set its `childExited[]` → its `wait4` hung; now
  `parent >= 0`.
- **`CLONE_VFORK` (vfork)** in clone case 56: child shares the parent PML4 and
  runs to `execve`/`_exit` on its own stack; parent suspended until then
  (`g_vforkParentPlus1` + `resumeVforkParent`, called from `execveTask` success
  and `exitTask`). Validated end-to-end via the `dyntest` harness
  (`posix_spawn` → exec-fail → reap → continue → clean halt).
- **`execAndGet` stubbed** in Hyprland (`MiscFunctions.cpp`): it forked `/bin/sh`
  to run `lspci` (GPU info, right before the renderer) — `/bin/sh` is absent and
  the synchronous `CProcess` blocked forever polling the deadlocked child's pipe.
  It produced nothing useful anyway. (Durable: it's in the vendored
  `deps/hyprland/src` checkout.)
- **`flock` (73) + `getdents64` (217)/`getdents` (78)** added to the syscall
  dispatch — `flock` was ENOSYS, so libwayland's `wl_socket_lock` thought every
  `wayland-N` was taken and the socket bind failed.
- CProcess argv-prefork patch (F.4d) kept (correct, durable).

**Known limitation / real next-gen fix:** the kernel has a **global fd table**, so
a proper `posix_spawn`/vfork that shares fds (`CLONE_VM`) would let the child's
`dup2`/`close` corrupt the parent's fds, and forked children's fds aren't closed
on exit (breaks pipe `POLLHUP`). For correct subprocess output capture, implement
**per-task fd tables** (copy-on-fork). Not needed for the boot path (we stub the
one output-capturing spawn), but required for real `execAndGet`/screenshot/etc.

### F.4f — NEXT: DRM-ioctl NULL-deref crash
Hyprland SIGSEGVs (`cr2=0`) right after a DRM ioctl on `/dev/dri/card0`, before
the renderer. Find the offending ioctl (`handleDrmIoctl` in posix.d ~4356) — it's
returning a value/struct Hyprland treats as a pointer and derefs. Likely
`DRM_IOCTL_MODE_GETRESOURCES`/`GET_CAP`/version returning 0 counts/NULL where
Aquamarine's DRM backend expects data. Either return sane data or make the DRM
backend `attempt` fail cleanly (so headless-only proceeds). Then STAGE_LATE →
`eglInitialize` → driver `dlopen` → EGL/Mesa tail → Phase G.

### F.4z — (parked): vfork/posix_spawn full implementation details
Goal: make a subprocess spawn from a multithreaded process reach `execve` without
deadlocking on a lock held by another (now-absent) thread. Recommended approach,
in order:
1. **vfork / `CLONE_VFORK` + `CLONE_VM` semantics.** Today `clone` with `CLONE_VM`
   makes a thread and a plain `fork` (syscall 57) deep-copies the address space.
   musl's `posix_spawn` uses `clone(CLONE_VM|CLONE_VFORK|SIGCHLD, stack, …)`: the
   child runs in the **parent's** address space on a tiny supplied stack, does its
   fd/signal setup, then `execve` — and the parent is **suspended** until the
   child execs or `_exit`s. Implement this in `kernel_main.d` case 56: when
   `CLONE_VM` **and** `CLONE_VFORK` (0x4000) are set, create a task sharing the
   parent PML4 (like a thread) but mark the parent blocked until the child
   execs/exits, and the child must run a real `execve`. This avoids the
   deep-copy-of-locked-mutexes entirely (no app locks are taken — the child only
   does fd setup + `execve`).
2. **Make `execve` work for the vfork child** (and dynamic binaries): `execveTask`
   is currently static-only and doesn't handle `PT_INTERP`/`ET_DYN`. Reuse the
   Phase-B loader path (load interp, set `AT_BASE`, jump to ld.so) so a spawned
   dynamic helper actually runs; for missing binaries return ENOENT cleanly so the
   child `_exit`s and the parent's `wait4`/vfork-resume proceeds.
3. **`wait4` correctness** with the above: parent resumes when the vfork child
   `execve`s (vfork semantics) or exits. Verify `wait4Task` wakes the parent.
4. **Fallback / partial mitigation** if vfork is too big this pass: real futex
   **timeout** (track PIT ticks in `FUTEX_WAIT`) so a stuck child eventually
   returns `ETIMEDOUT` — won't fix a permanently-held lock but surfaces progress
   and prevents indefinite hangs; pair with making the fork child's pre-`execve`
   path avoid app locks.
- Verification: boot dynamic Hyprland; confirm the spawn child reaches `execve`
  (or clean ENOENT exit), `wait4` returns, `start()` completes, and the post-
  `start()` logs (`Instance Signature`, `Running on DRMFD`) appear — then the
  renderer/EGL stage begins.

### Phase G — Present
- Wire the headless dumb-buffer swapchain to the screen: KMS modeset + page-flip
  (or a CPU blit of the dumb buffer to the Limine framebuffer). Kernel DRM
  already has CREATE_DUMB/MAP_DUMB/ADDFB/PAGE_FLIP; validate
  PRIME_HANDLE_TO_FD + dumb-buffer `mmap`.

### Risks / gotchas
- llvmpipe needs `mmap(PROT_EXEC)` JIT pages + threads (clone already works) +
  big RAM (bump QEMU `-m`). LLVM is huge to build/ship.
- TLS: ld.so sets up TLS for each `.so`; kernel just needs `arch_prctl(SET_FS)`
  (already present) and correct initial aux/TLS for the main exe.
- W^X: file-backed exec mappings and JIT require honoring `PROT_EXEC`; current
  page flags force/keep NX in places — audit.
- Keep static path working for busybox/compositor/test-drm (don't break them when
  making Hyprland dynamic).

### First steps next session
1. ~~Phase A: dynamic musl~~ **DONE 2026-05-31**.
2. ~~Phase B: kernel `PT_INTERP`/`ET_DYN` load + auxv~~ **DONE 2026-05-31**
   (kernel side; needs C+D to exercise).
3. ~~Phase C: file-backed `mmap`~~ **DONE 2026-05-31**.
4. ~~Phase D: ship + resolve `.so`~~ **DONE 2026-05-31**.
5. ~~Phase E: dynamic `hello` + `dlopen` gate~~ **PASSED 2026-05-31**
   (`make DYNTEST=1`). Dynamic-linking foundation proven end to end.
6. **Next: Phase F** — make Hyprland dynamic + bring up Mesa/LLVM `.so` + EGL/GLES.
   Stage `ld-musl` unconditionally, link Hyprland dynamic, ship Mesa `.so`s +
   `libLLVM`, then `eglInitialize`. Expect a tail of missing syscalls/ioctls.

---

## Milestone: runtime filesystem overlay (rtfs) — DONE 2026-05-31

A minimal in-memory tmpfs layered on the read-only synthetic namespace, so
programs can create dirs/files under writable roots (most importantly
`XDG_RUNTIME_DIR=/run/user/1000`). All in `src/kernel/d/core/syscalls/posix.d`:
- `RtNode[512] g_rt` node table (fused inode+dentry), seeded at boot by `rtInit`
  (called from `initFdTable`): `/run`, `/run/user`, `/run/user/1000` (0700),
  `/tmp` (01777), `/var`, `/var/tmp`, `/var/run`.
- `mkdir/mkdirat/unlink/unlinkat/rmdir/rename` operate on the overlay with real
  Linux errno semantics (`EEXIST`/`ENOENT`/`ENOTDIR`/`EROFS`); were all `-EROFS`.
- `sys_open` resolves and creates overlay dirs/files; new `FD_RTFILE` fd type
  with page-backed payload (`alloc_phys_pages`), wired into read/write/fstat.

Future hardening (not blocking Hyprland): per-process cwd + real `*at` dirfd
resolution, `getdents64` over overlay dirs, a real inode/dentry VFS + mount table.

---

## Milestone: thread / `clone` support — DONE 2026-05-31

`std::thread` / `pthread_create` now work. In `src/kernel/d/core/kernel_main.d`:
- `clone(flags, stack, ptid, ctid, tls)` (syscall 56) with `CLONE_VM` →
  `cloneThread`: a new `Task` **sharing the caller's PML4** (page tables), resumed
  at the post-syscall RIP with `rax=0` on the caller-supplied stack. Handles
  `CLONE_SETTLS` (FS base), `CLONE_PARENT_SETTID`/`CLONE_CHILD_SETTID`, and
  `CLONE_CHILD_CLEARTID` (tid word zeroed on exit in `exitTask` →
  `g_threadCleartidVirt`). Non-`CLONE_VM` clone still falls through to `fork`.
- Each thread gets a disjoint 64 GiB mmap window (`mmapNext + tid*0x10_0000_0000`)
  so concurrent `mmap`s in the shared address space don't collide.
- Cooperative blocking **futex** (syscall 56's sibling, 202) in the main switch:
  `FUTEX_WAIT` rewinds RIP + `scheduleNext` when `*uaddr==val` (re-tests on each
  reschedule); `EAGAIN` on mismatch; `FUTEX_WAKE` returns 0 (waiters poll).
- `gettid` returns the per-task id.

Verified: `[clone] parent=0 thread=1` in `serial.log`, both threads then issuing
gettid/timerfd/socket/mmap/clock syscalls; the old `thread constructor failed:
Resource temporarily unavailable` exception is gone.

Known limitations: `exit_group` exits only the calling task (no thread-group
teardown); futex timeouts are ignored (infinite waits only); a lone runnable
thread doing `FUTEX_WAIT` busy-reschedules.

---

## Milestone: fork() page-table copy fix — DONE 2026-05-31

`fork()` faulted in the kernel (`copy_phys_page`) the first time a real app
forked. Root cause in `walkAndCopyUserPages` (`src/kernel/d/core/addrspace.d`):
it extracted the physical frame from each PTE with `& ~0xFFF`, which keeps the
high flag bits — the **NX bit (63)** is set on every non-executable user page
(stack/heap/data), so the "physical address" carried `0x8000_0000_0000_0000` and
`copy_phys_page`'s `HHDM + phys` dereference hit a wild address
(`cr2≈0x7fff800001e51000`). Fix: mask frames with `PTE_ADDR_MASK`
(`0x000F_FFFF_FFFF_F000`, bits 51:12) at every level, preserve the full flag set
(incl. NX) on the copied leaf, and skip/guard PS huge-page entries defensively
(none occur — user space is all 4 KiB). Verified: `[fork] parent=0 child=2`
completes with no fault, no huge-page skips.

---

## Milestone: headless backend (CBackend::start) — DONE 2026-05-31

Hyprland requests HEADLESS as **mandatory** (Compositor.cpp), but Aquamarine's
`CBackend::start()` only builds a GBM/GPU allocator (gated on a DRM backend's
`drmFD()>=0`); headless exposes none, so start() threw "no allocator available"
→ Hyprland `throwError("CBackend::create() failed!")`. Two-part fix:
- **Aquamarine patch** (`deps/hyprland-hos/patches/0001-headless-dumb-allocator.patch`,
  applied during `aquamarine-extract`): when no GBM allocator exists, open
  `/dev/dri/card0` and create a `CDRMDumbAllocator` — pure libdrm
  (CREATE_DUMB/MAP_DUMB/PRIME), no Mesa/GBM/dlopen, so it works with no GPU.
- **Kernel** (`posix.d`): `fstat` on the DRM fd now reports a char device with
  the DRM major (`makedev(226,0)`) so libdrm's `drmGetNodeTypeFromFd` accepts it
  as a primary node; added the `/sys/dev/char/226:0/device/drm` synthetic tree
  that `drmNodeIsDRM()` stat()s. (`GET_CAP DUMB_BUFFER=1` was already present.)

Verified: no `CBackend::create() failed!`, no exception/fault anywhere; the
process settles into a continuous `poll()` event loop = a live (if not-yet-
rendering) headless compositor.

NOTE: the Aquamarine patch is now durable via the `patches/` file + Makefile
`patch -p1 --forward`; a clean `aquamarine-extract` re-applies it.

---

## Phase 5 — Hyprland compositor target

Dependency stack is **complete** (2026-05-31): all 20 core packages + protocol/
input/image transitive upgrades build into the musl sysroot; Hyprland links as a
static non-PIE ELF, staged into the ISO as `/Hyprland` and appended as a Limine
module the kernel prefers as the initial userspace target. Build glue:
`deps/hyprland-hos/Makefile.deps` + `Makefile.upgrades`; toolchain
`deps/musl/install/bin/musl-clang(++)` (clang 18), host tools in
`deps/.host-tools/bin`. Run `make -C deps hyprland-status` to inspect.

Modern Wayland compositors expect AF_UNIX, epoll, memfd, `SCM_RIGHTS`, and
`mprotect` — all implemented (Phase 4).

Remaining:
- [ ] **Rendering: EGL/GLES via dynamic linker + shipped .so** (current blocker).
      Full phased plan in the "PLAN: rendering via dynamic linker" section above.
      Order: (A) dynamic musl → (B) kernel PT_INTERP/ET_DYN load → (C) file-backed
      mmap → (D) ship/resolve `.so` → (E) verify with a dynamic `hello`+`dlopen`
      gate → (F) Mesa/LLVM `.so` + EGL/GLES → (G) KMS present.
- [ ] Port a minimal Wayland client (weston-simple-shm)
- [ ] `shm_open` / POSIX shm (can be layered on memfd)

---

## Phase 6 — First real graphical application

**Port SDL2** — much larger but unlocks many existing apps.

---

## Syscall gaps to fill (cross-cutting)

| Syscall | Status | Needed for |
|---------|--------|-----------|
| `clone` (thread flags) / `tkill` | ❌ EAGAIN / ENOSYS | Hyprland threads — current blocker |
| `sigprocmask` / `sigaction` with delivery | partial | app error handling |
| `shm_open` / POSIX shm | not done (layer on memfd) | Wayland shm alt path |

(memfd, timerfd, eventfd, sendmsg/recvmsg+SCM_RIGHTS, dup/dup2/dup3, nanosleep,
getpid/getppid are implemented.)

### Known issues
- DRM ioctl (`DRM_IOCTL_VERSION`) can #GP (exception 0x0D) when the kernel writes
  the user-space pointer while SMAP is active. Mitigated for QEMU by
  `-cpu qemu64,-smap,-smep` in `qemu-run.sh`; real fix = STAC/CLAC around
  user-space copies in the DRM ioctl handler.

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
Each client draws into its own memfd-backed window; the compositor blits +
handles input, animating via a timerfd frame clock.

> Rebuild note: the top-level `make` targets have no prerequisites and no-op when
> artifacts already exist — after editing kernel source, delete the stale object
> (`build/d/.../*.o`) and `build/libkernel_d.a` to force a recompile.
