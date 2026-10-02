# Android (Waydroid) bring-up — running Android apps natively in a domain

Goal: run Android apps inside an anonymOS domain through **Waydroid**, with no VM. Waydroid runs a
full Android system (a GSI image) in a container and shows its apps over Wayland. On stock Linux it
leans on kernel features anonymOS does not have; this is the roadmap to build them in the D kernel.

This is a large, multi-phase effort. It is tracked here so the work is ordered by what unblocks the
most, and so each phase has an exit criterion that can be demonstrated rather than asserted.

## Why it cannot run today

Waydroid needs, from the kernel:

- **binder** — Android's IPC driver (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`). Every
  Android process talks to `servicemanager` and the system services over it. Nothing in Android
  starts without it.
- **ashmem / memfd** — Android's anonymous shared memory. Modern Android uses `memfd_create` with
  seals where the kernel supports it, falling back to `/dev/ashmem`.
- **cgroups v2, and the namespace set** (mount, pid, net, ipc, uts, user) — the container Waydroid
  puts Android in, via **LXC**.
- **A few more**: `/dev/binderfs` (the modern way binder nodes are created), fuse (optional),
  and the usual `/proc`, `/sys` surface Android's init reads.

anonymOS has none of binder, ashmem, cgroups, or the `CLONE_NEW*` namespace flags today (verified:
`src/kernel/d/core/kernel_main.d` routes no `unshare`/`setns`/`CLONE_NEW*`; no binder/ashmem device).

## Phases

| Phase | What | Exit criterion |
|---|---|---|
| **A1 — binder device** (started) | `/dev/binder` as an in-kernel device: open/close, `BINDER_VERSION`, `BINDER_SET_MAX_THREADS`, `BINDER_SET_CONTEXT_MGR`, and the `BINDER_WRITE_READ` command/return framing (BC_*/BR_*). | A self-test opens `/dev/binder`, reads protocol version 8, registers a context manager, and round-trips a transaction through `BINDER_WRITE_READ`. **Done: `core/android/binder.d`, `[binder] selftest PASS`.** |
| **A2 — binder mmap + buffers** (done) | mmap the receive buffer; the kernel allocates transaction buffers from it and writes transaction data there; `BC_FREE_BUFFER` reclaims. | libbinder (`servicemanager`) opens, mmaps, and blocks in its read loop without error. **Done: `/dev/binder` mmap + bump allocator + data carried into the target's region (copy-in under SMAP) + free; `[binder] selftest PASS (A1+A2 …)`.** |
| **A3 — binder objects & handles** (done; fd deferred to A3b) | Flat-object translation (BINDER_TYPE_BINDER/HANDLE), per-proc handle tables, node table + ref counting, synchronous reply routing via a transaction stack, death notifications, the thread pool (`BC_REGISTER_LOOPER`). | Two processes pass a binder reference across a transaction, a reply routes back to the caller, and a crash fires a death notification. **Done: node/handle tables + BINDER↔HANDLE translation + `BC_REPLY`→`BR_REPLY` routing + `BC_REQUEST_DEATH_NOTIFICATION`→`BR_DEAD_BINDER`; `[binder] selftest PASS (A1+A2+A3 …)`.** |
| **A3b — fd passing** (done) | `BINDER_TYPE_FD` translation: install the sender's fd into the target's fd table across a transaction, via a cross-table dup that mirrors `fork`'s fd-table copy (shares the open file description, bumps the shared backend's refcount, publishes the capability). | A fd object carried in a transaction is dup'd into the receiver's fd table and rewritten to the receiver's new fd. **Done: `binderFdInstall` in posix.d + `BINDER_TYPE_FD` case in `translateObject`; `[binder] selftest PASS (… fd passing …)` + `[binder] fd-pass selftest PASS`.** |
| **A4 — binderfs + hw/vnd binder** (done) | Independent binder *contexts* (each its own context manager + handle-0 + node namespace), the three well-known devices `/dev/binder` / `/dev/hwbinder` / `/dev/vndbinder`, and binderfs: `/dev/binderfs/binder-control` with `BINDER_CTL_ADD` creating named devices, opened at `/dev/binderfs/<name>`. | Two contexts each register their own context manager without EBUSY-ing the other, and handle 0 in each routes to that context's manager. **Done: context table in binder.d + name→context map + binder-control in posix.d; `[binder] selftest PASS (… independent contexts)`.** |
| **A5 — ashmem / memfd seals** (done) | `memfd_create` with `F_SEAL_*` (already present) **and** `/dev/ashmem` ioctls (SET/GET NAME, SET/GET SIZE, SET/GET PROT_MASK, PIN/UNPIN, GET_PIN_STATUS, PURGE_ALL_CACHES), backed by the memfd machinery so mmap/fstat/dup reuse that path. | Android's `libcutils` ashmem path allocates and maps a region. **Done: `/dev/ashmem` in posix.d (memfd-backed) + the memfd+seals path; `[ashmem] selftest PASS`.** |
| **A6 — cgroups v2** (done) | A mutable cgroup2 hierarchy under `/sys/fs/cgroup`: `mkdir`/`rmdir` sub-cgroups, per-cgroup control files (cgroup.controllers / subtree_control / procs / threads / type / events / stat, memory.max/current, pids.max/current, cpu.max), pid attachment, and the cgroup2 statfs magic. | A cgroup is created, controllers enabled, a pid attached and read back, and the cgroup removed. **Done: in-kernel cgroup tree in posix.d hooked into open/read/write/getdents/mkdir/rmdir/statfs; `[cgroup] selftest PASS`.** |
| **A7 — namespaces** (done; isolation is A7b) | `unshare(CLONE_NEW*)` assigns per-task namespace ids (mnt/pid/net/ipc/uts/user/cgroup/time), `setns` accepts, and `chroot`/`pivot_root` set a real per-task filesystem root applied at open resolution (both were no-ops/EINVAL before). Child tasks inherit the namespace set + root at fork. | A process unshares a mount+pid namespace and `pivot_root`s into an image, after which a path resolves under it. **Done: per-task ns ids + rerooting in posix.d, syscalls 155/161/272/308 routed; `[ns] selftest PASS (… pivot_root into image, rerooted open)`.** |
| **A7b — namespace isolation** (done; net/clone-time are follow-ons) | Per-pid-ns pid numbering + `getpid`/`getppid` translation (each ns starts at pid 1 → disjoint pid sets), and a per-mnt-ns mount set so `mount`/`umount` in one mnt-ns is scoped to it. | Two pid namespaces see disjoint pid sets; a mount in one mnt-ns is invisible in another. **Done: pid-ns translation table + per-mnt-ns mount registry in posix.d, `getpid`/`getppid`/`mount`/`umount` hooked; `[nsiso] selftest PASS`.** Still open: per-net-ns/ipc stacks, `CLONE_NEW*` at clone-time, `/proc/<pid>/ns/*` fds. |
| **A8 — container runtime** (done: built-in equivalent) | `hos-container` (`src/util/hos-container.c`) — a static-musl container launcher (the "built-in equivalent" in lieu of vendoring ~100k-line liblxc): it `unshare`s mount/pid/uts/ipc, becomes **pid 1** in its new pid namespace, creates and joins a cgroup, makes a mount private to its mount namespace, optionally `pivot_root`s into a rootfs, and execs the container init. | A real userland process creates a container (new namespaces + cgroup + mount-ns + pid 1) and runs inside it. **Done: runs in the VM — `[hos-container] A8 PASS: namespaced (pid 1), cgrouped, mnt-ns up`. This is the engine `hos-waydroid` drives once an image exists (A9).** |
| **A9 — Android userland + image (Waydroid path)** | The chosen path (native, no VM): bring up Android's own userland on the A1–A8 container. Broken into sub-phases below. | The Android launcher renders in the domain; an `.apk` launches and draws. |
| **A9.1 — Android kernel-ABI surface** (done) | selinuxfs stub (`/sys/fs/selinux/{enforce=0,policyvers,checkreqprot,mls}` + statfs magic) so Android init/libselinux find SELinux present-but-permissive; a container-readiness probe confirming the whole kernel ABI is reachable from inside a confined container. | A confined container opens binder×3 + ashmem + cgroup2 + selinuxfs. **Done: in the VM — `[hos-container] android-abi: READY (binder x3, ashmem, cgroup2, selinuxfs reachable in-container)`.** |
| **A9.2 — property-area substrate** (done; the service itself is userland) | `/dev/__properties__` is now a writable, shared-mmap area (transparently backed by an rtfs directory, created per-domain on first touch, never shadowing synthetic `/dev`) so bionic's `__system_properties_init` can map it and the property service can build the per-context files. | A container creates a context file under `/dev/__properties__`, writes it through one shared mmap, and a second independent mmap sees the same bytes. **Done: in the VM — `[hos-container] prop-area: shared R/W OK`.** The property trie/service on top is bionic's (A9.3). |
| **A9.3a — ext4 reader for the image** (done) | A read-only ext4 driver (`core/android/ext4.d`): superblock, 32/64-bit block-group descriptors, inodes, extent trees, linear directories. The `system.img`/`vendor.img` are attached as raw disks and read directly. | The kernel reads a real file out of Android's `/system` ext4. **Done: with the VANILLA `system.img` attached, `[ext4] selftest PASS (read Android build.prop from ext4 image on disk 0, 4096 bytes, block=4096)`.** |
| **A9.3b — mount the images into the VFS** (done) | The system image (system-as-root) is mounted read-only at `/aroot` and the vendor image at `/aroot/vendor` (`FD_EXT4` in posix.d: open/read/stat/getdents served from the ext4 driver). Android's files resolve by path. | A userland process opens a real Android ELF binary by path out of the image. **Done: in the VM — `[hos-container] android-image: MOUNTED (/aroot/system/bin/app_process64 read 8 bytes, ELF=1, 64-bit=1)`.** |
| **A9.3c — exec bionic** (linker running; libs next) | ext4-backed `execve` (reads an Android ELF from the image into a contiguous blob), ext4 symlink following, a bootstrap-linker fallback (`/system/bin/linker64`→inactive APEX ⇒ `/system/bin/bootstrap/linker64`), and chroot/pivot_root into `/aroot`. | Exec a real Android binary; the dynamic linker runs. **Done: in the VM, `app_process64` exec'd, its bootstrap `linker64` loaded and RAN, and it performed dynamic linking (parsed DT_NEEDED, tried to load libandroid_runtime/libbinder/libc++/… — present in `/system/lib64`). Clean userland exit 127, no kernel fault.** |
| **A9.3d — shared-library loading** (done) | `FD_EXT4` files are now mmap-able (via `mmapCopyFileRange`, the loader's file-backed mmap path), and `LD_LIBRARY_PATH=/system/lib64…` gives the bootstrap linker a search path. | The linker loads and maps app_process64's libraries from the image. **Done: in the VM, `/system/lib64/libandroid_runtime.so` and many more mapped and relocated (2000+ reloc lines); 0 kernel faults.** |
| **A9.3e — APEX activation + the real Android linker** (done) | APEX is flattened in this image (`/system/apex/<name>/` are directories), so the ext4 VFS redirects `/apex/<name>` → `/system/apex/<name>` to activate it; and the interpreter now loads Android's `linker64` from the image FIRST (not the musl `ld.so` fallback that cannot link Android libs). | app_process64 links fully — all libraries loaded, no missing symbols. **Done: in the VM, Android's `linker:` runs and links app_process64 against 201 libraries (bionic `libc`, `libc++`, `libandroid_runtime`, `libbinder`, ART's `libnativeloader`/`libsigchain`, …) with ZERO "not found" / "symbol not found" errors; app_process64 then enters `main` (Zygote) and crashes in ART startup — userland only, 0 kernel faults.** |
| **A9.3f — Zygote / ART runtime** (done) | app_process64's `main` starts the Android runtime (ART). Done: general `mremap` (linker CFI shadow), a writable `/data` overlay (`/data`→rtfs `/.adata`, with the dalvik-cache/local/app/… skeleton), `chown` persisted on the overlay, and `sched_getscheduler/setscheduler` (bionic `pthread_create`). | app_process64 reaches the runtime and reads properties. **Done: CFI passes, ART initializes, creates + chowns its dalvik-cache, spawns threads, reads system properties, and proceeds past them (0 kernel faults).** |
| **A9.3g — system properties** (done) | Seed the bionic property area: a `prop_area` trie (name→value) + a serialized `property_info` (property→context, byte-exact AOSP `TrieNodeInternal` layout — `property_entry` offset, child/prefix/exact-match node arrays) + `properties_serial`, laid down as **root-owned** (uid=gid=0, 0644) rtfs files under `/dev/__properties__` (→ `/.__properties__`), populated with the `ro.*` properties ART needs (abilist64=x86_64, sdk=33, …). The `/aroot` chroot form is handled. | ART reads `ro.product.cpu.abilist64` and continues. **Done: in the VM, bionic resolves properties with 0 misses — the "Access denied finding property" and "Unable to determine ABI list" errors are GONE; `app_process64` reads `property_info` + `properties_serial` + `u:object_r:default_prop:s0` and continues. (Two fixes landed it: the corrected `property_info` serialization, and removing a container probe that was clobbering the seeded context file.)** |
| **A9.3h — a log sink (logd)** (done) | A connect to `/dev/socket/logdw` is answered in-kernel (`sys_connect` marks the socket `isLogSink`, no listener needed), and every datagram written to it is decoded (printable-run extraction — robust to the bionic header-format drift across Android versions) and printed to the kernel log (`[logd] …`). Hooked at `sys_sendmsg` (gathers the record's iovecs into one datagram) and `localSocketWrite` (the `write()` path). | ART's log becomes visible on serial. **Done: in the VM, the `logdw` connects now return `ok=0` (was `ECONNREFUSED`), and ART's log streams: the 201-library linker warnings (`readlink("/proc/self/fd/N")`, `unable to get realpath …Will use given path`, `no /linkerconfig/ld.config.txt` — all benign), then the handoff line `AndroidRuntime: >>>>>> START com.android.internal.os.ZygoteInit uid 1000 <<<<<<`. 0 KF, 0 GURU, VMState=running, desktop clean.** |
| **A9.3i — make `startVm` visible, and the ART env roots** (done) | The silent exit right after `START …ZygoteInit` was `startVm()` failing — and `AndroidRuntime::start` returns on a non-zero `startVm` **without logging**. Fixes: (a) the exec-bionic child now routes stderr → serial (`dup2(1,2)` + a probe); (b) set the APEX-root env vars recent ART derives its paths from and app_process does not default — `ANDROID_ART_ROOT=/apex/com.android.art`, `ANDROID_I18N_ROOT=/apex/com.android.i18n`, `ANDROID_TZDATA_ROOT=/apex/com.android.tzdata`, `ANDROID_RUNTIME_ROOT=/apex/com.android.runtime` (unset, `startVm` failed silently before ever building options). | `startVm` logs its real failure. **Done: with the env roots set, `startVm` now builds all VM options (`option[0..16]`: `-Xzygote`, `-Xms4m/-Xmx16m`, `--cpu-abilist=x86_64`, boot-image compiler opts…) and reaches `JNI_CreateJavaVM`, which fails with the concrete, logged reason: `zygote64: Boot classpath is empty` → `AndroidRuntime: JNI_CreateJavaVM failed`. Also surfaced (non-fatal so far): `Could not reserve sentinel fault page`, `Error opening /proc/self/cmdline`. 0 KF, 0 GURU, VMState=running, desktop clean.** |
| **A9.3j — the boot classpath + boot image** (frontier) | `JNI_CreateJavaVM` fails because the **boot classpath is empty**: we never export `BOOTCLASSPATH`. On a real device `derive_classpath` builds it from the per-APEX `etc/classpaths/*.pb` fragments and init exports it; here the container must set `BOOTCLASSPATH` (and likely `DEX2OATBOOTCLASSPATH`, `SYSTEMSERVERCLASSPATH`) to the GSI's core jars (`/apex/com.android.art/javalib/{core-oj,core-libart,…}.jar`, `/apex/com.android.i18n/javalib/core-icu4j.jar`, `/apex/com.android.conscrypt/javalib/conscrypt.jar`, `/system/framework/{framework,ext,…}.jar`, …). Then ART opens those dex jars and needs a **boot image** (`boot.art`/`boot.oat`) — prebuilt in the image or generated into `dalvik-cache` via `dex2oat` — or an imageless/interpreter fallback (`-Xno-image-dex2oat` / `-Ximage:` pointing at nothing). | `JNI_CreateJavaVM` succeeds and ART enters `ZygoteInit.main`. |
| **A9.3g — init + servicemanager** | Android `init` / `servicemanager` run on the binder that already works. | `servicemanager` comes up and registers with binder. |
| **A9.4 — HALs + gralloc** | The graphics/allocator HAL surface Android needs (`gralloc`/`mapper`, `ion`/dmabuf) mapped onto our GPU/memory. | SurfaceFlinger allocates a buffer. |
| **A9.5 — SurfaceFlinger → Wayland + the image** | Fetch/verify a Waydroid GSI (system + vendor) into the ISO/image store, bridge SurfaceFlinger output to the domain's Wayland surface. | The Android launcher renders in the domain; an `.apk` launches and draws. |

Phases A1–A5 are kernel device work; A6–A8 are the Linux-container surface; A9 is image + display.
A9's display path reuses the domain's existing Wayland plumbing (the compat launcher `hos-waydroid`
already dispatches `waydroid app …`). None of A2–A9 is a flag: each is a subsystem.

## Current status

- **A1 binder device + A2 mmap/buffers + A3 objects/handles: implemented and self-tested** —
  `src/kernel/d/core/android/binder.d`, opened at `/dev/binder` (`FD_BINDER` in `posix.d`),
  `mmap`-able receive region with a bump allocator; transaction data is copied from the sender into
  the target's region and freed on `BC_FREE_BUFFER`. A3 adds the node table, per-proc handle tables,
  BINDER↔HANDLE flat-object translation across a transaction's offsets, synchronous reply routing
  (a transaction stack so `BC_REPLY` reaches the original caller as `BR_REPLY`), and death
  notifications (`BC_REQUEST_DEATH_NOTIFICATION` → `BR_DEAD_BINDER` when an owner proc goes away).
  Boot self-test: `[binder] selftest PASS (A1+A2+A3 …)` exercises two procs — a context-manager
  server and a client — passing a binder reference both directions, a reply, and a death.
- **A3b fd passing: implemented and self-tested** — a `BINDER_TYPE_FD` object in a transaction is
  now dup'd from the sender's fd table into the receiver's (`binderFdInstall` in `posix.d`, wired
  through `binderSetFdDup`/`binderSetProcTab`), mirroring `fork`'s per-entry fd-table copy. The
  binder self-test proves the translation path (with a stub installer); a second boot self-test
  (`[binder] fd-pass selftest PASS`) proves the real cross-table dup.
- **A4 binderfs + contexts: implemented and self-tested** — binder is no longer a single global
  context. `binder.d` has a context table; `/dev/binder`, `/dev/hwbinder` and `/dev/vndbinder` are
  three independent contexts, each with its own context manager and handle-0 node namespace, and
  `/dev/binderfs/binder-control` (`BINDER_CTL_ADD`) creates more named contexts openable at
  `/dev/binderfs/<name>` (`posix.d`). The self-test proves two contexts register managers
  independently, a second manager in one context is refused (EBUSY), and handle 0 routes per
  context: `[binder] selftest PASS (… independent contexts)`.
- **A5 shared memory: implemented and self-tested** — `memfd_create` with the full `F_SEAL_*` set
  was already present (the path modern Android prefers); `/dev/ashmem` is now added for the legacy
  path, backed by the memfd machinery (an ashmem fd is an `FD_MEMFD` under the hood, so mmap, fstat
  and dup reuse that code) with the ashmem ioctl surface (name, size, prot mask, pin) and freed on
  last close. `[ashmem] selftest PASS` drives the libcutils create sequence and proves the region is
  named, sized and backed by real mappable memory.
- **A6 cgroups v2: implemented and self-tested** — `/sys/fs/cgroup` is now a mutable cgroup2
  hierarchy (an in-kernel tree in `posix.d`, hooked into open/read/write/getdents/mkdir/rmdir/statfs
  only on the `/sys/fs/cgroup` prefix). `mkdir` creates a cgroup with the full control-file set,
  `cgroup.subtree_control` and `cgroup.procs` are writable, and statfs reports `CGROUP2_SUPER_MAGIC`.
  `[cgroup] selftest PASS` drives the lxc-start sequence end-to-end through the real syscalls.
  Limits (memory.max/pids.max) are stored but not accounted — lxc-start needs the interface.
- **A7 namespaces: the syscall surface is implemented and self-tested** — `unshare(CLONE_NEW*)`
  assigns per-task namespace ids, `setns` accepts, and `chroot`/`pivot_root` set a real per-task
  filesystem root applied at `open` resolution (guarded so the desktop, which sets no root, pays one
  comparison). `[ns] selftest PASS` unshares mnt+pid+uts and pivot_root's into a created image dir,
  proving a path then resolves under it.
- **A7b namespace isolation: implemented and self-tested** — the ids now mean something. Each pid
  namespace has its own pid numbering (starts at 1), `getpid`/`getppid` translate into the caller's
  pid-ns, so two pid namespaces hold disjoint pid sets; each mount namespace has its own mount set,
  so a `mount`/`umount` in one is invisible in another. `[nsiso] selftest PASS` proves both. Still
  open: per-net-ns/ipc stacks, `CLONE_NEW*` at clone-time (vs `unshare`), and `/proc/<pid>/ns/*` fds.
- **A8 container runtime: done and run in the VM.** `hos-container` (the built-in liblxc equivalent)
  creates a container — new namespaces, pid 1, a joined cgroup, a private mount — and runs inside it:
  `[hos-container] A8 PASS`.
- **A9.1 Android kernel-ABI surface: done and run in the VM.** A selinuxfs stub (permissive) plus a
  container-readiness probe: `[hos-container] android-abi: READY (binder x3, ashmem, cgroup2,
  selinuxfs reachable in-container)`. The container now exposes everything Android's kernel ABI needs.
- **A9.2–A9.5 are the remaining Waydroid bring-up, and they are Android's own userland** (the chosen
  native, no-VM path): the property service, bionic + `init` + `servicemanager`, the HAL/gralloc
  surface, and SurfaceFlinger→Wayland plus the GSI image. Those are bionic binaries with
  Android-specific assumptions on top of our musl personality — a large userland effort, and the
  full stack cannot boot without the multi-GB system image (which needs real resources/hardware).

This is the honest state: binder IPC, shared memory, cgroup2, namespaces (surface + isolation), a
working container runtime, and the full Android kernel-ABI surface are in and proven in the VM. What
remains (A9.2+) is Android's userland and image — the frontier, and the part that needs the image to
actually come up.
