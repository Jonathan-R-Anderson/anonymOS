# Object-Oriented OS Migration Roadmap

> Goal: incrementally turn the current kernel into a **capability-secured object
> graph** — everything an `Object`, the native kernel reduced to {Scheduler, Object
> Manager, Capability Manager, IPC Router, Memory Manager, HAL}, and Linux support
> demoted to a set of objects. **Grounded in the actual source tree** (`src/kernel/d/`).
> No greenfield; every step is a refactor of code that exists today.

---

## The one insight this whole plan rests on

The codebase **already has a primitive object system and doesn't know it.** In
`src/kernel/d/core/syscalls/posix.d`:

```d
struct File { FileType type; int flags; ulong offset; void* backend; ulong fileSize; }
enum FileType { FD_NONE, FD_CONSOLE, FD_FILE, FD_SOCKET, FD_PIPE_READ, FD_PIPE_WRITE,
                FD_EPOLL, FD_EVENTFD, FD_DRM, FD_INPUT_EVENT, FD_MEMFD, FD_TIMERFD,
                FD_ZERO, FD_RANDOM, FD_URANDOM, FD_RTFILE, FD_BUNDLE, FD_BOOT_MODULE }
```

`sys_read`/`sys_write`/`sys_close`/`sys_open` are giant `switch (f.type)` statements —
i.e. **manual virtual dispatch over a tagged union**, with `backend` as the
per-instance payload. That *is* an object with a type and methods. The fd table
`File[1024][FDTAB_COUNT] g_fdTabs` + `g_fdTable` (per-process, copied on `fork` by
`fdtabForkCopy`) is **a handle table that is one rights-field away from a capability
table.** The whole migration is: generalize `File`→`Object` (real method table),
generalize the fd index→capability (handle + rights), and feed every other subsystem
(`Task`, `AddrRegion`, devices, windows, users) through the same `Object`. We grow the
object model **outward from the fd layer**, which is the lowest-risk seam.

---

## PHASE 1 — Current state analysis

**Goal:** catalogue what exists and classify each subsystem as proto-object,
convertible, or must-build. (Analysis only; no code change.)

What exists, by subsystem (exact locations):

| Subsystem | Where | State vs object model |
|---|---|---|
| **fd/file** | `posix.d`: `struct File`, `FileType`, `g_fdTabs`/`g_fdTable`, `sys_open/read/write/close`, `fdtabForkCopy` | **Proto-object** (tagged union + type-dispatch + per-process handle table). The seed. |
| **Process/thread** | `core/task.d`: `struct Task`, `g_tasks[MAX_TASKS]`, `allocTask`/`releaseTask`; `kernel_main.d`: `forkTask`, `cloneThread`, `execveTask`, `exitTask`, `dispatchSyscall`, `scheduleNext`, `g_current_task_id` | **Proto-object** (fixed array of structs, integer ids). Threads vs processes already distinguished by `fdTabId`/`pml4Phys` sharing. |
| **Memory region / VMO** | `task.d`: `struct AddrRegion {start,end,type,perms,physBase,owned}`, `Task.regions[MAX_REGIONS]`, `addRegion`/`removeRegion`/`findRegion`; `mmap.d`: `sys_mmap/munmap/mprotect`; `mm.d`: `alloc_phys_page`/`free_phys_page`/`g_free_pages`; `arch/x86_64/arch.d`: `map_page_hhdm`/`unmap_page_hhdm` | **Proto-object** (`AddrRegion` ≈ VMO mapping; `RegionType`/`RegionPerms` ≈ object type+rights). No sharable VMO identity yet. |
| **Pipe / socket / memfd / timerfd / eventfd / epoll** | `posix.d`: `PipeBuf g_pipes`, `LocalSocket`/`LocalSocketBuffer`, `MemFdRec`, timerfd/eventfd/epoll tables, all reached via `File.backend` | **Convertible** (each is already a typed backend behind a `File`). |
| **rtfs / synthetic fs / namespace** | `posix.d`: `RtNode g_rt[RT_MAX_NODES]` (RT_DIR/RT_REG), `rtResolve`, `isSyntheticDirectoryPath`, `statSyntheticPath`, boot-module + bundle providers | **Convertible** to Directory/File objects; **namespace is global** (must build per-process namespace). |
| **Block device** | `drivers/block/ahci.d`: `struct AHCIDeviceInfo` | **Convertible** (no object wrapper, not yet a `File` backend). |
| **Network iface** | `drivers/network/network.d`: `struct NetworkDevice` | **Convertible** (standalone struct). |
| **DRM/graphics device** | `posix.d` `handleDrmIoctl` (FD_DRM), `display/`, `drivers/graphics/` | **Partially** an object (FD_DRM file) but logic is in-kernel. |
| **Window / compositor** | `display/wayland/wserver.d`, `display/compositor/`, `display/window_manager/`, `display/server/` | **Must build** window objects; today it's an in-kernel Wayland server. |
| **User** | `core/user.d`: `ObjType.User`, `Task.userObjId`; `posix.d` identity/syscred path | **Implemented** (default subject uid/gid 1000; `/etc/passwd` derives from User objects). |
| **Service** | `core/servicemgr.d`, `core/ipc.d` endpoints | **Implemented** as kernel objects with least-privilege rights metadata. |
| **Capability** | `core/cap.d` | **Implemented** (per-task cap tables, subset derive, revoke, admin caps). |
| **Object Manager / IPC Router** | `core/objmgr.d`, `core/ipc.d` | **Implemented** (central object table + endpoint/message router). |

**Risks:** none (read-only). **Difficulty:** 2. **Prerequisites:** none.

---

## Dependency graph

```
P1 ─▶ P2 ─┬─▶ P3(memory) ─┬─▶ P4(process) ─────────────┐
          │               │                              │
          ├─▶ P5(file objs)┴─▶ P6(capability) ─▶ P7(IPC) ─┼─▶ P8(device/driver)
          │                                              │        │
          │                                              ├─▶ P9(namespace)
          │                                              ├─▶ P10(user/service)
          │                                              └─▶ P11(window)  [needs P7,P8]
          │
          └────────────── P3..P10 ──────────────────────▶ P12(Linux objects) ─▶ P13(reduce kernel)
```

## Critical path

`P1 → P2 → P5(file→objops) → P6(capabilities) → P7(IPC) → P9(namespace) → P10(rootless user/service) → P12(LinuxSyscallObject) → P13`.

Memory/process (P3/P4) are **parallelizable** with P5 after P2, but P12 cannot start
until the native objects it translates into (P3–P10) exist. The capability layer (P6)
is the true bottleneck: every later "object owned via cap" claim depends on it, and it
must not be skipped or faked (see `IMMUTABLE_ROOTLESS_ROADMAP.md` §G).

## Milestones

**1. Minimum Viable Object OS (MVOO).** *Progress: P2 ✅, P3 ✅, P4 ✅, P5 ✅,
P6 ✅ — MVOO reached; P7 ✅.* Phases **2 + 5 + 6**: an `Object` header +
central table, `sys_read/write/close/open` dispatch via `g_objOps`, and fd tables are
capability tables with rights-narrowing on `fork`/`dup`/`SCM_RIGHTS`. *Provable by:*
every fd is an entry in `g_objects`; a child cannot hold more rights than its parent.
The kernel is now "an object graph with capabilities," even though most objects still
live in their legacy arrays.

**2. Linux Compatibility Object.** ✅ *Reached (P9 ✅, P12 ✅; on top of MVOO +
P3/P4/P8/P10/P11 ✅).* Phases **9 + 12**:
`LinuxSyscallObject`/`LinuxVFSObject`/`LinuxProcessObject`/`LinuxELFLoaderObject`/
`LinuxDeviceAdapterObject` exist; `dispatchLinuxSyscall` is reached only through the
`LinuxSyscallObject` gate and *translates* into native object ops; BusyBox/Hyprland run
unchanged through the object graph. *Provable by:* the `LinuxObject` subtree's master
switch — disabling it makes every Linux syscall return `-ENOSYS` without touching the
native kernel (`[lx] selftest PASS` exercises exactly this gate).

**3. Fully Object-Oriented OS.** ◑ *Structurally reached (P13 ✅ verification); one
mechanical cleanup remains.* Native kernel = {Scheduler, Object Mgr, Capability Mgr, IPC
Router, Memory Mgr, HAL}; processes, threads, memory, VMOs, files, directories, devices,
drivers, NICs, windows, users, services, namespaces, and Linux compat are all objects in
one tree (the Phase 13 census confirms **16 live object families** atop the six pillars),
and authority for the fd surface flows via capabilities. *Proven at runtime by:*
`[census] PASS` — the object graph is the authority and the Linux personality is a
removable gated subtree. *Not yet:* a `grep` of `kernel_main.d`/`posix.d` still shows the
translation *bodies* physically in place (after Phase 12 they are the Scheduler pillar +
the `LinuxSyscallObject` translator, reached only through objects); relocating those
bodies into object methods, and routing the last inline-dispatched syscalls
(mmap/fork/clone/exec/futex) through the gate, is the remaining cleanup — pure churn
against the highest-regression surface, deliberately deferred over a behavioural change.

---

## What should remain unchanged (and why)

- **HAL — `arch/x86_64/` (`map_page_hhdm`, `unmap_page_hhdm`, context switch, GDT/IDT,
  `arch.d`).** It *is* the HAL pillar; objects call it, it isn't an object.
- **Scheduler core — `scheduleNext`/`g_current_task_id` (`kernel_main.d`).** A native
  pillar; it schedules Thread *objects* but stays low-level.
- **Physical allocator mechanics — `mm.d` `alloc_phys_page`/`free_phys_page`.** Becomes
  the *implementation* under Untyped/MemRegion objects; the algorithm stays.
- **The Linux *syscall numbers/ABI* surface.** Kept verbatim as the personality; only
  its *implementation* moves behind objects (Phase 12).

*Companion roadmaps in this folder:* `GUI_ROADMAP.md` (desktop/compositor bring-up;
converges here at Phase 11) and `IMMUTABLE_ROOTLESS_ROADMAP.md` (immutability + rootless
admin; shares the Capability Manager P6 and User/Service P10).
