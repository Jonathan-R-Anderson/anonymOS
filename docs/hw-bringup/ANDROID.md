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
| **A3 — binder objects & handles** | Flat-object translation (BINDER_TYPE_BINDER/HANDLE/FD), per-proc handle tables, ref counting, death notifications, the thread pool (`BC_REGISTER_LOOPER`). | Two processes pass a binder reference and an fd across a transaction; a crash fires a death notification. |
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

- **A1 binder device + A2 mmap/buffers: implemented and self-tested** — `src/kernel/d/core/android/binder.d`,
  opened at `/dev/binder` (`FD_BINDER` in `posix.d`), `mmap`-able receive region with a bump
  allocator; transaction data is copied from the sender into the target's region and freed on
  `BC_FREE_BUFFER`. Boot self-test: `[binder] selftest PASS (A1+A2 …)`.
- Everything from A3 on is not started. `hos-waydroid` reports Waydroid-not-installed until the
  stack can start a session, so nothing pretends to run.

This is the honest state: the foundation stone is in and proven; the building is not built.
