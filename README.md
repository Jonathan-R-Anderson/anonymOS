# HanonymOS

HanonymOS is an experimental 64-bit operating system that mixes a Haskell kernel core with low-level runtime, bootstrap, and hardware support written in D, C, and assembly. The kernel's high-level scheduling, task, syscall, and address-space logic lives in Haskell; hard realtime and hardware-facing work stays in D and C where that is the practical choice.

## Current Status

**May 2026 — desktop stack built, process creation is the critical gap**

The kernel boots, enters Haskell land, and runs the init task with a rich Linux-compatibility surface. A large software stack has been built and loaded into the ISO. The missing piece is process creation: `fork`, `clone`, and `execve` all return `ENOSYS` because the Haskell task scheduler does not yet implement them. Everything above that layer is waiting on this single unlock.

### What works today

**Kernel and boot:**
- ISO builds with `make hos.iso` and boots reliably under QEMU
- D bootstrap → Haskell kernel → Linux-personality init task handoff
- Serial console and framebuffer console
- Memory manager: physical page allocator, paging, `brk`, `mmap`/`munmap` with allocate-on-demand BSS and copy-on-write
- JHC pipeline: Haskell → C → freestanding kernel binary

**Linux compatibility layer (~100+ syscalls):**
- Core I/O: `read`, `write`, `open`, `close`, `stat`/`fstat`/`lstat`, `lseek`, `ioctl`, `fcntl`
- Memory: `mmap`, `munmap`, `mprotect`, `brk`, `memfd_create` with `ftruncate` + shared `mmap`
- File ops: `openat`, `newfstatat`, `readlinkat`, `faccessat2`, `getdents64`, `chdir`, `getcwd`, `access`
- Pipes: `pipe`/`pipe2` with ring-buffer `PipeBuf`, ref-counted lifetime, `dup`/`dup2`/`dup3`
- Sockets: `socket`, `bind`, `listen`, `connect`, `accept`, `send*`, `recv*`, `getsockopt`, `setsockopt`
- IPC: `epoll_create1`/`epoll_ctl`/`epoll_pwait`, `eventfd`/`eventfd2`, `timerfd_create`/`timerfd_settime`, `socketpair`, `SCM_RIGHTS` fd passing over `sendmsg`/`recvmsg`
- Signals: `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigsuspend`, `rt_sigtimedwait`, `sigaltstack`
- Time: `clock_gettime`, `gettimeofday`, `nanosleep`, `settimeofday`, `adjtimex`
- Process info: `getpid`, `gettid`, `getuid`/`gid`/`euid`/`egid`, `getppid`, `uname`, `arch_prctl`
- Threading: `futex`, `set_tid_address`, `set_robust_list`, `rseq`, `sched_setaffinity`, `clone` (ENOSYS)
- Process: `fork` (ENOSYS), `execve` (ENOSYS), `exit`/`exit_group`, `wait4` (ECHILD), `kill`, `tgkill`
- Misc: `getrandom`, `writev`, `statfs`, `poll`, `select`, `prlimit64`, `setrlimit`, `prctl`, `reboot`
- xattr group (188–199): ENOTSUP stubs
- DRM/KMS: `ioctl` on `/dev/dri/card0` handles 23 cases including `MODE_GETRESOURCES`, `MODE_GETCRTC`, `MODE_SETCRTC`, `MODE_GETCONNECTOR`, `MODE_CREATE_DUMB`, `MODE_MAP_DUMB`, `MODE_PAGE_FLIP`

**Virtual filesystem:**
- `/proc`: `version`, `self/cgroup`, `self/environ`, `self/maps` (stub), `mounts`
- `/dev`: `console`, `null`, `zero`, `urandom`, `random`, `tty`, `dri/card0`, `dri/renderD128`, `input/event0-1`
- `/sys`: DRM connector status, input device names
- `/etc`: `hostname`, `passwd`, `group`, `fstab`, `rc.conf`, `inittab`, `machine-id`, `locale.conf`, `elogind/logind.conf`, `dbus-1/system.conf`, GTK/font config
- `/run`: `openrc/` tree, `user/1000/wayland-0` (in-kernel Wayland socket), `seatd.sock` stub

**Userland binaries built and loaded into ISO:**
- `init.elf` — kernel launches this as the first task
- `busybox` — BusyBox 1.36.1 (ash + coreutils + grep + sed + awk + tar + vi), static musl build
- `openrc` — OpenRC 0.54 init system, static musl build
- `elogind` — elogind 255.4 session manager, static musl build
- `gtk-hello` — GTK3 test binary (18-package static build chain)
- `mutter` — Mutter 44.9 compositor (11-package static build chain including Mesa 23.3.5 swrast)
- `Hyprland` — external compositor target; source is vendored in `deps/hyprland` and included in the ISO only after `make deps-hyprland` produces a binary

**Display:**
- Framebuffer bridge initialized at boot, DRM/KMS stubs expose it as `/dev/dri/card0`
- In-kernel Wayland server listening on `/run/user/1000/wayland-0`
- DRM dumb buffer mmap: full-screen GEM buffers map directly to the Limine framebuffer physical address (page flip = no-op), other sizes allocate physical RAM
- Input polling infrastructure (USB HID) wired but deferred until a task owns the input queue

---

## Critical Blocker: Process Creation

`fork`, `clone`, and `execve` are currently `ENOSYS` stubs. Implementing them in the Haskell task scheduler is the single most important next step. Every layer of the stack above the init task — BusyBox, OpenRC, the GTK app, Mutter — is waiting for this.

The kernel already has most of what is needed:
- ELF parser (used to load `init.elf`)
- Address space and paging layer
- `mmap`/`munmap`/`mprotect` working
- Linux-style initial stack setup
- Linux personality established for the first task

What is missing is the Haskell scheduler implementing task duplication (fork) and image replacement (execve).

---

## Next Steps

Steps are ordered by dependency. Each unlocks the one after it.

### 1. Implement `fork` / `clone` in the Haskell scheduler

- Duplicate the current task's address space (COW page table copy)
- Duplicate the file descriptor table
- Return 0 to child, child PID to parent
- This is the single blocker for everything else

Relevant files:
- [src/kernel/hs/main.hs](src/kernel/hs/main.hs) — task creation entry point
- [src/kernel/hs/Hos/LinuxCompat.hs](src/kernel/hs/Hos/LinuxCompat.hs) — dispatch table

### 2. Implement `execve`

- Re-use the existing ELF loader (already used for `init.elf`)
- Replace the calling task's address space with the new image
- Set up a fresh Linux-style initial stack with `argv`/`envp`/`auxv`

### 3. Validate musl startup end-to-end

- musl does `arch_prctl(ARCH_SET_FS)`, `set_tid_address`, `set_robust_list`, then enters `main`
- Some `futex` paths need real blocking (currently stubs that return immediately)
- Signal mask and `sigaltstack` need to hold state per-task

### 4. Run the init → OpenRC → userland chain

- `init.elf` should exec `/openrc` which runs rc scripts and spawns services
- BusyBox ash becomes the interactive shell
- `/dev/console` stdio is already wired

### 5. Reconcile the kernel Wayland server with Mutter

- The in-kernel `wserver.d` currently owns `/run/user/1000/wayland-0`
- Once Mutter is launched via `execve`, it will try to create that socket
- Either disable `wserver.d` before Mutter starts, or make it hand off
- Mutter will enumerate `/dev/dri/card0` via DRM `MODE_GETRESOURCES`, create dumb buffers, mmap them, and render via the swrast Mesa path

### 6. DRM / Mutter bring-up

- Verify `MODE_GETRESOURCES` returns a consistent connector/CRTC/encoder set
- Verify `MODE_CREATE_DUMB` + `MODE_MAP_DUMB` round-trips correctly
- Mutter's GBM/EGL path uses Mesa swrast; no GPU needed
- Watch for `libseat` probing `/run/seatd.sock` — stub is in place, may need expansion

### 7. Login manager and session

- gdm can be added after Mutter runs
- Or drop directly into a GNOME Shell session once the compositor is up
- Session environment (`WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, `DISPLAY`) must be seeded before GTK apps launch

### 8. Writable filesystem

- Today the filesystem is a read-only bundle
- A simple tmpfs-style writable layer would unblock most of the remaining userland friction
- `/tmp`, `/run/user/1000/`, and `/var` need to be writable for session plumbing

### 9. Real signal delivery

- Signal delivery is currently stub-level; the mask is stored but signals are not actually queued or delivered asynchronously
- This matters for job control, `SIGCHLD`, and `SIGTERM` handling in init scripts

### 10. Real `futex` blocking

- `futex(WAIT)` returns immediately today; real thread synchronization requires suspending the calling task
- Needed for proper musl threading and any multi-threaded userland

---

## Architecture Overview

The system is split into four layers.

### 1. Boot and machine bring-up

Limine loads the kernel. Early startup, memory map handoff, framebuffer, and entrypoint ownership live in the D bootstrap:

- [src/kernel/d/core/kmain.d](src/kernel/d/core/kmain.d)
- [src/kernel/d/arch](src/kernel/d/arch)

### 2. Haskell kernel core

The higher-level kernel logic: task and schedule state, syscall modeling, address-space manipulation, IPC, Linux compatibility handoff. Compiled with JHC to C, then compiled freestanding.

- [src/kernel/hs/main.hs](src/kernel/hs/main.hs)
- [src/kernel/hs/Hos/LinuxCompat.hs](src/kernel/hs/Hos/LinuxCompat.hs)

### 3. Low-level runtime and support

Runtime system, garbage collector, machine glue, drivers, display bridge, and all D-side syscall implementations:

- [src/libs/rts](src/libs/rts)
- [src/kernel/d/core](src/kernel/d/core)
- [src/kernel/d/memory](src/kernel/d/memory)
- [src/kernel/d/drivers](src/kernel/d/drivers)
- [src/kernel/d/display](src/kernel/d/display)

The Linux syscall implementations live in:

- [src/kernel/d/core/syscalls/posix.d](src/kernel/d/core/syscalls/posix.d)

### 4. Userland and bundled programs

- [src/progs](src/progs) — in-tree programs: `init`, `esh`, storage/ATA utilities
- [src/progs/deps/redepend/esh](src/progs/deps/redepend/esh) — `esh` shell
- [deps/musl](deps/musl) — musl 1.2.5 static libc
- [deps/busybox](deps/busybox) — BusyBox 1.36.1
- [deps/openrc](deps/openrc) — OpenRC 0.54
- [deps/elogind](deps/elogind) — elogind 255.4
- [deps/gtk-stack](deps/gtk-stack) — 18-package GTK3 static build chain
- [deps/mutter](deps/mutter) — 11-package Mutter compositor build chain
- [deps/hyprland](deps/hyprland) — Hyprland upstream checkout with submodules
- [deps/hyprland-hos](deps/hyprland-hos) — HanonymOS build glue and dependency gate for Hyprland

---

## Repository Layout

- [src/kernel/hs](src/kernel/hs) — Haskell kernel
- [src/kernel/d](src/kernel/d) — D bootstrap, memory, drivers, display, syscalls
- [src/libs/rts](src/libs/rts) — JHC runtime and GC support
- [src/libs/common](src/libs/common) — shared kernel/userland code
- [src/progs](src/progs) — userspace programs
- [src/boot](src/boot) — Limine bootloader config
- [src/docs](src/docs) — subsystem notes and roadmaps
- [deps](deps) — vendored dependencies and build chains
- [build](build) — generated build output
- [cd](cd) — ISO staging directory

Key files:

- [Makefile](Makefile) — top-level build orchestration
- [build.opts](build.opts) — toolchain and path configuration
- [qemu-run.sh](qemu-run.sh) — quick serial-log boot run
- [qemu-test.sh](qemu-test.sh) — verbose QEMU debug run

---

## Build System

1. JHC compiles kernel Haskell sources to C
2. Generated C is postprocessed for the freestanding environment
3. Clang compiles to object code
4. D and C runtime/kernel components are built separately
5. Everything is linked into `kernel.elf`
6. Programs are built and packed into `hos.bundle`
7. ISO assembled with Limine boot assets

Build the core kernel and ISO:

```bash
make
make hos.iso
```

Build optional desktop dependency chains (heavy, not in default build):

```bash
make deps-desktop
make deps-hyprland
```

Primary outputs:

- [kernel.elf](kernel.elf)
- [hos.iso](hos.iso)
- [build/hos.bundle](build/hos.bundle)

Clean:

```bash
make clean
```

---

## Toolchain

Expects a Unix-like host with:

- `jhc` (JHC 0.8.2)
- `clang` / `ldc2`
- `ld`, `as`, `ar`
- `xorriso`
- GNU `make`

Configured in [build.opts](build.opts). JHC material and patches live in [jhc-0.8.2](jhc-0.8.2) and [deps/bdepend/toolchain](deps/bdepend/toolchain).

---

## Boot Flow

1. Limine loads `kernel.elf`, `hos.bundle`, `init.elf`, and optional desktop modules
2. D bootstrap initializes CPU, paging, framebuffer, GDT/IDT
3. Haskell kernel starts, parses `init.elf`, creates the first task with a Linux-personality stack
4. `init.elf` runs; it is expected to `execve` into the real init chain once fork/exec are implemented

---

## Running Under QEMU

```bash
./qemu-run.sh
tail -f serial.log
```

Verbose diagnostic run:

```bash
./qemu-test.sh
```

The serial console is the primary debug channel while the system is in bring-up.

---

## Debugging

Start with [serial.log](serial.log) and [qemu.log](qemu.log). The kernel emits explicit diagnostics for:

- kernel faults (`KERNEL FAULT trap=...`)
- JHC runtime failures (`JHC Case Fell Off line: ...`)
- physical memory exhaustion (`OOM in alloc_phys_page!`)
- syscall traces (enabled in the Linux compat layer)

---

## Known Limitations

- `fork`/`clone`/`execve` return `ENOSYS` — no child processes can be spawned yet
- Filesystem is read-only (boot bundle); no writable layer
- `futex(WAIT)` returns immediately — no real task suspension
- Signal delivery is stub-level (masks stored, not delivered asynchronously)
- DRM/KMS stubs are sufficient for Mutter enumeration but untested end-to-end
- The kernel Wayland server will conflict with Mutter once it runs; needs handoff

---

## Why The Name?

Historically the project used the shorter name `Hos`, and that still appears throughout paths and code. The current project identity is `HanonymOS`; both names are in the tree.





https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/6a1b70e3-cf4c-83ea-bd42-ba2e23f7fea9 (fully homomorphic encryption)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/6a1b708e-099c-83ea-a574-b84fd3f39645 (Secure IPC)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/685f2539-45d4-8007-bbed-b3de3f8b462f (acyclic object tree)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/69371c98-eef4-8331-9719-070b2df3ea90 (perlin noise generator)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/69372881-2548-8332-a7ac-1c9f0b1e0844 (blockchain)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/691e83c5-3d50-832c-9ec3-88540840f991 (android process secure)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/6a1b6ec0-a26c-83ea-b69e-bd63462a14b7 (immutable kernel)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099/c/69223f4f-0fd0-8331-9858-3588655227d6 (everything-as-an-object)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/6a0cd0e9-8620-83ea-9081-8208ef797e3b (distributed os)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/6a1b900c-4c1c-83ea-b830-3a0137c662cc (dynamically linked)

https://chatgpt.com/g/g-p-685cd97493e08191aa5b5ca1ce6f9099-anonymos/c/6a1b92a0-a1d8-83ea-b43b-22632cb2c59a (react os compatibility layer)

make sure the kernel can handle multiple cores/multithreading

make sure it does hardware abstraction

control panel like with qubes os, different subsystems have colored borders to indicate profiles