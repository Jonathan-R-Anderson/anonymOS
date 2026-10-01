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
| **A7b — namespace isolation** | Make the ids *mean* something: separate mount tables per mnt-ns, pid translation per pid-ns, a per-net-ns stack, and `CLONE_NEW*` at clone-time (not just `unshare`); `/proc/<pid>/ns/*` fds for `setns`. | Two pid namespaces see disjoint pid sets; a mount in one mnt-ns is invisible in another. |
| **A8 — LXC** | The container runtime Waydroid drives (`lxc` + liblxc), or a built-in equivalent that satisfies Waydroid's container contract. | `waydroid init` lays down the container config; `waydroid session start` gets Android's `init` to run. |
| **A9 — Android image + Wayland** | Fetch/verify a Waydroid GSI (system + vendor), and wire Android's SurfaceFlinger/Wayland output into the domain's compositor surface. | The Android launcher renders in the domain; an `.apk` installed with `waydroid app install` launches and draws. |

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
  proving a path then resolves under it. **Isolation semantics (separate mount/pid/net tables,
  `CLONE_NEW*` at clone-time, `/proc/<pid>/ns/*`) are the A7b follow-on** — the ids are identities,
  not yet enforced boundaries.
- **A8 (LXC) and A9 (Android image) are not started.** `hos-waydroid` reports Waydroid-not-installed
  until the stack can start a session, so nothing pretends to run.

This is the honest state: binder IPC, shared memory, cgroup2 and the namespace/chroot *syscall
surface* are in and proven. Namespace isolation (A7b), the LXC container runtime (A8) and the Android
system image + SurfaceFlinger→Wayland (A9) are the remaining frontier, and the last two need the
container userland that does not exist in this environment yet.
