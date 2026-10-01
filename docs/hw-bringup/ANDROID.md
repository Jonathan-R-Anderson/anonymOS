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
| **A3b — fd passing** | `BINDER_TYPE_FD` translation: install the sender's fd into the target's fd table across a transaction. Needs cross-proc fd dup (posix.d fd-table plumbing), so it is its own step; A3 safely *rejects* a transaction carrying an fd rather than deliver a bogus one. | A process passes an open fd to another over a transaction and the receiver reads from it. |
| **A4 — binderfs + hw/vnd binder** | `/dev/binderfs` with `binder-control`; the `hwbinder` and `vndbinder` contexts Android needs. | `servicemanager` and a `hwservicemanager` come up on their own contexts. |
| **A5 — ashmem / memfd seals** | `/dev/ashmem` ioctls (SET_NAME/SET_SIZE/PIN/UNPIN) and/or `memfd_create` with `F_SEAL_*`. | Android's `libcutils` ashmem path allocates and maps a region. |
| **A6 — cgroups v2** | A cgroup2 mount, the controllers Android/LXC require, and the clone/attach plumbing. | `lxc-start` creates and enters a cgroup without error. |
| **A7 — namespaces** | `CLONE_NEWNS/NEWPID/NEWNET/NEWIPC/NEWUTS/NEWUSER`, `unshare`, `setns`, `pivot_root` (the last is stubbed today). | A process unshares a mount+pid namespace and `pivot_root`s into an image. |
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
- **A3b (fd passing) and everything from A4 on are not started.** A3 deliberately rejects a
  transaction carrying a `BINDER_TYPE_FD` object rather than deliver an untranslated fd.
  `hos-waydroid` reports Waydroid-not-installed until the stack can start a session, so nothing
  pretends to run.

This is the honest state: the IPC core — the part nothing in Android starts without — is in and
proven; binderfs, shared memory, cgroups, namespaces, LXC and the image are not built.
