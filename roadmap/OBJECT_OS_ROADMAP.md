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
| **User** | `posix.d`: `getuid/geteuid`→`0`, synthetic `/etc/passwd` | **Must build** (no user object; everyone root). |
| **Service** | userspace OpenRC/init; no kernel notion | **Must build**. |
| **Capability** | — | **Must build** (does not exist). |
| **Object Manager / IPC Router** | — | **Must build** (no central object table; IPC today = the Linux socket/pipe paths in posix.d). |

**Risks:** none (read-only). **Difficulty:** 2. **Prerequisites:** none.

---

## PHASE 2 — Introduce the base `Object` abstraction  ✅ DONE

> **Status: implemented & proven at runtime.** Object Manager lives in
> `core/objmgr.d` (named *objmgr* not *object* to avoid D's special root `object`
> module). `ObjHeader{id,type,refCount,ownerCap,version_,mark,impl}`, central
> `g_objects[8192]` with a free-list, empty `g_objOps[ObjType.Count]` (dispatch
> still legacy — that's Phase 5). `objAlloc/objGet/objRetain/objRelease` (release
> is idempotent/underflow-safe) + `objStats`.
>
> **Adoption strategy chosen: amortized reconciliation, not per-call-site hooks.**
> `File` gained `uint objId`; instead of editing the dozen-plus fd
> create/dup/`SCM_RIGHTS`/fork/close sites, `posix.d:objReconcileFds()` mirrors the
> active fd table into the object table and validates each object's `impl` points
> back at its exact slot — one check self-heals every create/copy/close path with
> zero per-site edits. Called every 256 syscalls from `dispatchSyscall`, off the
> I/O path; `objStats()` every ~16k.
>
> **Proof:** `[obj] live=39` steady-state, invariant `live == alloc − freed` holds —
> every fd is an entry in `g_objects`, no leak. (Acceptance met.)

**Goal:** create the common object header + a central Object Manager, and make `File`
the *first adopter* without changing syscall behaviour.

**New abstractions (new file `core/object.d`):**
```d
enum ObjType : uint { Invalid, File, Process, Thread, MemRegion, Vmo, Directory,
                      Device, Driver, NetIf, Window, User, Service, Namespace,
                      Capability, Endpoint, LinuxProcess, ... }
struct ObjHeader {
    uint    id;          // dense index into g_objects
    ObjType type;
    uint    refCount;
    uint    ownerCap;    // capability id of owner (Phase 6); 0 for now
    uint    version_;    // metadata/version history hook
    void*   impl;        // subsystem payload (was File.backend)
}
__gshared ObjHeader[OBJ_MAX] g_objects;     // central object table
uint  objAlloc(ObjType t, void* impl);
void  objRetain(uint id); void objRelease(uint id);
ObjHeader* objGet(uint id);
// method table: per-ObjType function pointers for read/write/close/stat/map/ioctl
struct ObjOps { ssize_t function(ObjHeader*, void*, size_t) read; ... }
__gshared ObjOps[ObjType.max+1] g_objOps;
```

**Files/modules to modify:**
- new `core/object.d`; wire build (Makefile/JHC object list).
- `posix.d`: add `uint objId;` to `struct File` (keep `type`/`backend` during
  transition); on `sys_open`/socket/pipe/etc. creation, also `objAlloc(...)` and store
  the id. **Do not** route dispatch through `g_objOps` yet — just register, to prove
  the table tracks every fd.

**Existing abstractions to remove:** none yet (additive phase).

**Risks:** object-table sizing vs the existing fixed arrays; double-bookkeeping during
transition. **Difficulty:** 5. **Prerequisites:** Phase 1.

---

## PHASE 3 — Convert the memory subsystem (Memory Region / VMO objects)  ✅ DONE

> **Status: implemented as additive object identity and audit accounting.**
> `AddrRegion` has `objId` (`MemRegion`) and `vmoObjId` (`Vmo` for shared
> backings). `addRegion` now creates the `MemRegion` object immediately, region
> teardown releases it, and `task.d:objReconcileRegions()` remains as the
> amortized safety net for moved/copied slots. mmap/brk/ELF-load/fault/fork paths
> now attribute mapped physical pages to the owning `MemRegion` and, for shared
> backings, the stable `Vmo`.
>
> **Key difference from Phase 2:** `AddrRegion` slots are *not* address-stable —
> `removeRegion` swap-removes (a surviving region + its `objId` moves slots) and
> `forkTask` deep-copies the whole `Task`. The impl-pointer check alone can't free
> the orphans those moves create, so `objmgr.d` gained a **mark-sweep generation**
> (`mark` field + `objBeginSweep/objMark/objSweepType`): the reconcile re-registers
> any slot whose object doesn't point back at it, then sweeps every `MemRegion`
> object no live slot claimed (orphans from swap-remove, munmap, fork, exit).
>
> **VMO identity:** `MemFdRec` and DRM `GemBuf` records carry `Vmo` object ids.
> Normal memfds allocate a VMO at `memfd_create`; DRM dumb buffers allocate one
> at `MODE_CREATE_DUMB`; PRIME-exported memfds retain and reference the GEM's
> same VMO, so memfd/DRM aliases share object identity.
>
> **Physical-page audit:** `memory/mm.d` now keeps page-indexed
> `{MemRegion,Vmo}` owner tables. Private pages are attributed to their
> `MemRegion`; shared pages record the mapping `MemRegion` plus stable backing
> `Vmo`; `free_phys_page`/`munmap` clear stale audit ownership.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. `objStats()` prints `vmo=` along with `file=`, `mem=`, `proc=`, and
> `thread=`.
>
> **Deferred out of Phase 3:** folding `RegionType`/`RegionPerms` into
> capability rights and gating allocation on an Untyped-memory capability remain
> Phase 6 work, where permissions actually start routing through caps.

**Goal:** make `AddrRegion` a first-class **MemRegion/VMO object**, so memory is
delegable and accountable — the prerequisite for capability-scoped allocation.

**Files/modules to modify:**
- `core/task.d`: keep `AddrRegion` but give each region an `objId` (type `MemRegion`);
  `addRegion`/`removeRegion`/`findRegion` register/release objects.
- `core/syscalls/mmap.d`: `sys_mmap`/`sys_munmap`/`sys_mprotect` create/destroy
  MemRegion objects instead of bare table entries; `sys_mmap` of a shared backing
  (memfd/DRM) references a **Vmo** object so two mappings share identity.
- `memory/mm.d`: `alloc_phys_page`/`free_phys_page` become the *implementation* under
  an **Untyped memory** object (Phase 6 gates allocation on holding it); for now just
  attribute pages to the owning MemRegion's `objId` for audit.
- `arch/x86_64/arch.d`: unchanged (HAL stays low-level; `map_page_hhdm`/
  `unmap_page_hhdm` are the HAL the MemRegion object calls).

**New abstractions:** `Vmo` object (shareable physical backing) distinct from
`MemRegion` (a mapping of a Vmo into one address space) — mirrors the existing
`AddrRegion.physBase` + the memfd-aliasing already in `handleDrmIoctl`/`MemFdRec`.

**Existing to remove:** eventually the raw `Task.regions[]` array becomes a list of
MemRegion object ids; the inline `RegionType`/`RegionPerms` fold into object
type+rights.

**Risks:** this is the hottest path (every fault/`mmap`); a regression breaks all
userspace. CoW/fork deep-copy (`forkTask` → `walkAndCopyUserPages`) must keep working.
**Difficulty:** 7. **Prerequisites:** Phase 2.

---

## PHASE 4 — Convert the process subsystem (Process / Thread objects)  ✅ DONE

> **Status: implemented as split Process/Thread object identity.** Every runnable
> `Task` is now scheduled as a `Thread` object (`Task.objId`), including process
> leaders. Process ownership is separate (`Task.processObjId`), with
> `Task.processLeaderTid` and `Task.parentObjId` recording the first real
> parent→child object-tree metadata. Fork creates a new Process object plus a
> leader Thread; clone creates a new Thread sharing the parent's Process object;
> a vfork-style child is promoted to its own Process object after successful
> `execve`.
>
> **Lifecycle wiring:** `allocTask` creates the Thread object; `forkTask` creates
> the child Process object after assigning the new PML4/fd table; `cloneThread`
> inherits the parent Process object; `execveTask` resets MemRegions and refreshes
> process ownership; `exitTask`/`releaseTask` release Thread objects and region
> children. `objReconcileTasks()` marks/sweeps both Thread and Process objects.
>
> **Linux compatibility view:** `getpid`/`gettid`/`getppid`, fork/clone return
> values, `set_tid_address`, and `wait4` now use the same object-backed PID/TID
> view instead of `getpid→1` and raw scheduler-slot assumptions. The scheduler
> still runs `g_tasks`/`g_current_task_id`; Linux sees stable small ids derived
> from the Process/Thread object metadata.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. `objStats()` prints `proc=` and `thread=` counts alongside
> `file=`/`mem=`/`vmo=`.
>
> **Deferred out of Phase 4:** capability table copy/reset policy remains Phase 6,
> where capabilities actually exist. Namespace objects remain Phase 9.

**Goal:** `Task` becomes a **Process/Thread object**; `g_tasks` is its
implementation array; `fork`/`clone`/`exec`/`exit` become object operations.

**Files/modules to modify:**
- `core/task.d`: `struct Task` gains `objId` (type `Process` if it owns its
  `pml4Phys`, else `Thread`); `allocTask`/`releaseTask` ↔ `objAlloc`/`objRelease`.
- `kernel_main.d`: `forkTask` = "clone Process object + its MemRegion children +
  copy capability table"; `cloneThread` = "new Thread object sharing parent's address
  space + cap table"; `execveTask` = "reset object's MemRegions + cap table per
  policy"; `exitTask` = `objRelease` + free owned MemRegions (already does page-free).
- `dispatchSyscall`/`scheduleNext`: scheduler keeps operating on `g_tasks`/
  `g_current_task_id` (it's the Scheduler — stays native), but the *identity* it
  schedules is now a Thread object id.

**New abstractions:** Process owns {Thread objects, MemRegion objects, a Namespace
object (Phase 9), a capability table (Phase 6)}. This is the first real **parent→child
object tree** node.

**Existing to remove:** integer-pid assumptions (`getpid`→1, `g_current_task_id` as
the only identity) give way to object ids; keep a pid *view* for Linux compat.

**Risks:** scheduler/IPC churn; `fork` semantics already fragile (the 2-3× compositor
re-init noted in `GUI_ROADMAP.md` lives here). **Difficulty:** 7. **Prerequisites:**
Phase 2, 3.

---

## PHASE 5 — Convert fd/file backends into File/Directory/Device objects  ✅ DONE

> **Status: implemented as object-method dispatch for the fd syscall surface.**
> `ObjOps` now covers `read`, `write`, `close`, `stat`, `ioctl`, and `mmap`.
> The public Linux syscall entry points in `posix.d` validate the fd, resolve or
> self-heal its `ObjHeader`, then call `g_objOps[obj.type].*`; backend-specific
> behavior lives behind `fileObjRead/fileObjWrite/fileObjClose/fileObjStat/
> fileObjIoctl/fileObjMmap`.
>
> **Object typing:** fd slots are now registered as broad object families:
> `Device` for console/zero/random/input/DRM, `Directory` for synthetic
> directories, `Endpoint` for local sockets, `Vmo` for memfds, and `File` for the
> remaining regular/runtime/pipe/event/timer/epoll compatibility backends. The
> old `File.type` tag is retained only inside those object methods as the Linux
> backend discriminator; the syscall fan-in no longer switches on it.
>
> **mmap routing:** `kernel_main.d` case 9 no longer peeks at `FD_DRM` or
> `FD_MEMFD`. It asks the fd object via `fdMmapBacking`, preserving shared DRM
> dumb-buffer and memfd mappings plus VMO attribution.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A 15s headless QEMU smoke boot reached Hyprland/Mesa startup and the
> serial log had no kernel fault, panic, JHC falloff, or OOM signatures.

**Goal:** route `sys_read`/`sys_write`/`sys_close`/`sys_stat`/`mmap`/`ioctl` through
`g_objOps` method tables instead of `switch (f.type)`. This is the **payoff** of
Phase 2 and the model for everything else.

**Files/modules to modify (all in `posix.d` unless noted):**
- Replace each `switch (f.type)` arm in `sys_read`/`sys_write`/`sys_close`/
  `linux_sys_fstat`/`linux_sys_ioctl`/`sys_mmap`(case 9 in `kernel_main.d`) with
  `g_objOps[obj.type].read(obj,...)` etc.
- Register ops per type: `FD_RTFILE`→`g_rt`/`RtNode` File object; `FD_SOCKET`→
  `LocalSocket` object; `FD_PIPE_*`→`PipeBuf` object; `FD_MEMFD`→`MemFdRec` Vmo;
  `FD_TIMERFD`/`FD_EVENTFD`/`FD_EPOLL`→their objects; `FD_DRM`→Device object;
  `FD_CONSOLE`/`FD_ZERO`/`FD_RANDOM`→Device objects.
- `rtResolve`/`isSyntheticDirectoryPath`/`statSyntheticPath`: directories become
  **Directory objects**; `sys_open` becomes "resolve a name in a Namespace to an
  object, return a handle (capability) to it."

**Existing to remove:** the `FileType` mega-switches in the I/O syscalls (kept only as
a thin Linux-personality fan-in). `File.type`/`File.backend` collapse into
`File.objId` → `ObjHeader{type,impl}`.

**Risks:** the I/O hot path again; subtle behaviour per fd type (EAGAIN/EOF/poll
readiness) must be preserved exactly (`fdReadable`). **Difficulty:** 7.
**Prerequisites:** Phase 2.

---

## PHASE 6 — Capability Manager (handles → capabilities)  ✅ DONE

> **Status: implemented as the first per-process capability table.**
> `core/cap.d` defines `Capability{objId,rights,deriveParent,revoked}`,
> `CapTable[64]`, rights bits for read/write/close/stat/ioctl/mmap/dup/pass,
> `capDerive`, `capRevoke`, `requireCap`, active-table selection, clone/clear
> helpers, and runtime stats.
>
> **Linux fd integration:** `Task` now has `capTabId` alongside `fdTabId`.
> `dispatchSyscall` selects both tables before servicing a syscall, and the
> Linux fd entry points now publish/self-heal a capability for the fd handle
> before resolving the backing object. `read`/`write`/`close`/`fstat`/`ioctl`/
> `mmap`, poll readiness, dup/fcntl, timer/event/epoll/socket creation, and
> SCM_RIGHTS materialization all route through capability publication or
> `requireCap`.
>
> **Compatibility boundary:** `File[]` remains the backing payload table for now.
> Capabilities point at the Phase 5 fd-slot `File` objects and carry rights;
> fork starts from `capTableCloneNarrowing` then rebinds each copied fd to the
> child-local File object. Dup and SCM_RIGHTS install derived/narrowed caps for
> the destination handle. Collapsing `File[]` fully into a pure object/cap table
> is deferred until the Phase 7 IPC work removes raw SCM_RIGHTS payload copying.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A 15s headless QEMU smoke boot reached Hyprland/Mesa startup with no
> kernel fault, panic, JHC falloff, OOM, or capability-denial regressions.

**Goal:** turn the fd index into a **capability** (handle + rights + object id) and
add a per-process **capability table** — generalizing `g_fdTabs`. This is where the
permission model becomes real.

**New abstractions (`core/cap.d`):**
```d
struct Capability { uint objId; uint rights; uint deriveParent; } // rights = bitset
struct CapTable { Capability[CAP_MAX] caps; }   // generalizes File[1024]
uint  capDerive(uint capId, uint subsetRights); // rights must be a subset
bool  requireCap(int tid, uint capId, uint rights);
void  capRevoke(uint capId);                    // invalidates derived caps
```

**Files/modules to modify:**
- `posix.d`: `g_fdTabs`/`g_fdTable` become `CapTable` (each entry: object id + rights);
  `fdtabForkCopy` becomes `capTableCloneNarrowing` (child gets ≤ parent rights);
  `fdtabSetActive` unchanged in spirit.
- `kernel_main.d` `dispatchSyscall`: before privileged ops, `requireCap`.
- `core/task.d`: `Task` references its `CapTable` (per-process).

**Existing to remove:** "fd is just an index into File[]"; ambient privilege.

**Risks:** must not break `dup`/`dup2`/`SCM_RIGHTS` fd passing — those become
**capability delegation** (`capDerive` + send over endpoint). **Difficulty:** 7.
**Prerequisites:** Phase 2, 5.

---

## PHASE 7 — IPC Router + Endpoint objects  ✅ DONE

> **Status: implemented as a native message router with Endpoint objects, a
> Service registry, and capability-by-value delegation.** New module
> `core/ipc.d` provides `Endpoint` rendezvous/queue objects (allocated in the
> central object table as `ObjType.Endpoint`), a fixed message format
> (`IpcMessage` = inline bytes + up to 8 `IpcCapDesc{objId,rights}` capability
> descriptors), `ipcSend`/`ipcRecv`, the native `objCall(endpointObjId, msg)`
> primitive, and a name→endpoint **Service registry**
> (`ipcServiceRegister`/`ipcServiceLookup`). Authority crosses an endpoint only
> **by value** — every queued descriptor is re-validated against the live object
> table (`objGet`) on send, so a stale/dead object is never delegated and a raw
> backend pointer is never enqueued.
>
> **SCM_RIGHTS becomes capability delegation:** `posix.d`'s `LocalSocket` SCM
> queue changed `passedCaps` from a full `Capability` copy to an `IpcCapDesc`
> ring. `sys_sendmsg` now delegates each passed fd's authority via
> `ipcDelegateCap(objId, rights)` (validated, rights-clamped); `sys_recvmsg`
> materialises the receiver's own handle and narrows it to `ipcAcceptCap(desc)`.
> The `File` payload copy is retained as the Linux-compat backend-materialisation
> detail (the `g_fdTabs` File store collapse is left to the Linux-object phases),
> but the *authority* now flows through the router's delegate/accept primitives.
> Drained in lockstep with the existing `passedFiles` ring, so fd passing is
> byte-for-byte identical to before from userspace's view.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot reached Hyprland/Mesa compositor rendering
> (which exercises SCM_RIGHTS DRM/memfd fd passing over Unix sockets) with no
> kernel fault, panic, JHC falloff, or OOM. The one-shot boot self-test logged
> `[ipc] selftest PASS` — a message carrying a delegated capability round-tripped
> through an endpoint and a service resolved by name. `ipcStats()` prints
> endpoint/send/recv/delegate/accept/service counters alongside `objStats()` and
> `capStats()`.
>
> **Deferred out of Phase 7:** `objCall` is asynchronous (enqueue + return); a
> reply-endpoint round-trip rendezvous, blocking semantics, and routing the
> generic message queue into a live service (vs. the per-fd SCM descriptor ring)
> arrive with the Phase 10 service manager and Phase 12 Linux-object work.

**Goal:** a native **IPC Router** with `Endpoint` objects; SCM_RIGHTS fd passing
becomes capability delegation; user-space services become reachable by holding an
endpoint capability.

**Files/modules to modify:**
- `posix.d`: the `sendmsg`/`recvmsg`/`SCM_RIGHTS` path and `LocalSocket` become the
  *Linux view* of `Endpoint` objects; add native `objCall(endpointCap, msg)`.
- new `core/ipc.d`: route messages between objects; deliver capabilities (validated
  via Capability Manager) — never raw pointers.

**New abstractions:** `Endpoint` (a rendezvous/queue object), `Service` registration
(name→endpoint cap). **Existing to remove:** in-kernel direct calls between subsystems
become IPC messages (incremental).

**Risks:** performance (every cross-object call); ordering/blocking semantics.
**Difficulty:** 7. **Prerequisites:** Phase 6.

---

## PHASE 8 — Device and Driver objects  ✅ DONE

> **Status: implemented as a Driver/Device object registry with `/dev`
> resolution.** New module `core/device.d` wraps the kernel's free-standing
> driver globals as first-class objects in the central table: `driverRegister`
> creates a `Driver` object per class (console, mem, rng, drm, input, ahci/block,
> net), `deviceRegister` creates a `Device` object (`ObjType.Device`, or
> `ObjType.NetIf` for the NIC) carrying a minor, an ops table
> (`DevReadFn`/`DevWriteFn` for in-kernel block I/O), and a back-pointer to the
> driver-owned payload. `deviceRegistryInit()` (called from `d_kernel_main`
> before the init process starts) stands up the synthetic `/dev/*` tree that
> actually exists at runtime — `/dev/console`, `/dev/tty`, `/dev/zero`,
> `/dev/random`, `/dev/urandom`, `/dev/dri/card0`, `/dev/dri/renderD128`,
> `/dev/input/event0`, `/dev/input/event1` — plus identity `Driver` objects for
> the AHCI block and NIC globals (`g_ahciDevices`/`g_netDevice`), registering a
> Block `Device`/`NetIf` for each that is actually present/initialised.
>
> **`/dev/*` resolves to Device objects:** every `/dev/*` arm of `sys_open` in
> `posix.d` now calls `deviceNoteOpen(path)`, which resolves the path to its
> persistent `Device` object id and counts the binding — the proof that opening a
> device node is "resolve a name to a Device object," not just stamping a
> `FileType`. The fd still gets its Phase 5 `ObjType.Device` fd-object + Phase 6
> capability; the registry adds the stable per-device identity behind it.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot reached Hyprland/Mesa compositor rendering
> (which opens `/dev/dri/card0` and `/dev/input/event*`) with no kernel fault,
> panic, JHC falloff, or OOM. The one-shot boot self-test logged
> `[dev] selftest PASS` — `/dev/dri/card0` and `/dev/input/event0` resolve to
> distinct live Device objects and an unknown path resolves to 0. `deviceStats()`
> prints driver/device/netif/open counters alongside the other subsystems.
>
> **Deferred out of Phase 8:** exposing block devices as `/dev/sd*` File fds that
> route reads/writes through `g_objOps` (no consumer yet, and the AHCI controller
> is not probed on the live cdrom boot), and gating device access behind a
> capability ("reachable only via caps") — both land with the Linux-object
> (Phase 12) and rootless (Phase 10) work. The ops table and Driver/Device
> identity needed for them exist now.

**Goal:** wrap existing drivers as **Device/Driver objects** reachable only via caps.

**Files/modules to modify:**
- `drivers/block/ahci.d` (`AHCIDeviceInfo`) → Block **Device object** + a **Driver
  object**; expose as a File-like object (so `sys_read`/`write` route via `g_objOps`).
- `drivers/network/network.d` (`NetworkDevice`) → **NetIf object**.
- `drivers/input/*`, `drivers/graphics/*`, DRM (`handleDrmIoctl`) → Device objects;
  `/dev/*` synthetic nodes (`posix.d`) resolve to these Device objects in a Namespace.

**New abstractions:** Driver object (manages its Devices), Device object (ops table).
**Existing to remove:** drivers as free-standing globals called directly.

**Risks:** drivers touch hardware/HAL; keep the HAL boundary (`arch/`) intact.
**Difficulty:** 6. **Prerequisites:** Phase 5, 7.

---

## PHASE 9 — Namespace objects (per-process object graph)  ✅ DONE

> **Status: implemented as per-process Namespace objects with fork-time cloning
> and namespace-routed open resolution.** New module `core/namespace.d` defines a
> `Namespace` object (`ObjType.Namespace`) holding a small binding table
> (`NsBinding` = mount-point path → target object id + rights). Every namespace
> is created with a `"/"` → **rtfs-root Directory object** binding: the global
> `g_rt` root is now a first-class `ObjType.Directory` object (`g_rootDirObjId`)
> that each namespace *mounts* at `/`, rather than being "the filesystem."
> `nsAlloc`/`nsClone`/`nsRelease`/`nsBind`/`nsResolve` (longest-prefix,
> component-boundary match) make up the resolver.
>
> **Per-process lifecycle (`core/task.d`):** `Task` gains `namespaceObjId`.
> `objEnsureNamespace` gives each process leader a namespace and makes threads
> share their leader's; `objCloneNamespace` (called from `forkTask`) gives a fork
> child a private clone so later rebinds don't cross the fork boundary;
> `cloneThread` shares the process namespace; `objReleaseTask` releases the
> namespace when the last sharing thread exits; `objReconcileTasks` self-heals
> (the init task, post-exec) every 256 syscalls.
>
> **Routed resolution (`posix.d`):** `sys_open` now calls `namespaceRouteOpen`,
> which resolves the path against the *calling task's* Namespace root via
> `nsResolve` before the legacy rtfs/synthetic resolution runs. Because every
> namespace binds `"/"` to the rtfs-root Directory, the existing resolver backs
> the `/` mount and behaviour is unchanged — but resolution now flows through the
> per-process namespace, not a global ambient root.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot reached Hyprland/Mesa compositor rendering
> (exercising `forkTask`→`objCloneNamespace` and `cloneThread`→shared namespace)
> with no kernel fault, panic, JHC falloff, or OOM. The one-shot boot self-test
> logged `[ns] selftest PASS` — a namespace allocates with a `/` root binding, a
> clone is a distinct live object sharing that root, a rebind in the clone does
> not leak into the parent, and a path resolves to the root Directory.
> `nsStats()` prints live/alloc/clone/bind/resolve counters alongside the other
> subsystems.
>
> **Deferred out of Phase 9:** divergent per-process mounts (`unshare`/`mount`/
> bind-mounting additional Directory/Device objects) and resolving the `/dev`
> Device tree (Phase 8) as distinct namespace mounts rather than through the
> posix.d `/dev/*` arms — the binding table and resolver needed for both exist
> now; only the syscall surface to drive them is left.

**Goal:** replace the **global** synthetic/rtfs namespace with **per-process Namespace
objects**; a process sees exactly the objects bound into its namespace (Plan 9 model).

**Files/modules to modify:**
- `posix.d`: `sys_open`/`rtResolve`/`isSyntheticDirectoryPath`/`statSyntheticPath`
  resolve against `Task`'s Namespace object, not globals `g_rt`/synthetic tables.
- `core/task.d`: `Task` gains a `namespaceObjId`; `fork` clones the namespace (binds),
  `unshare`/`mount`-like ops rebind.

**New abstractions:** `Namespace` object = a map of name→object-capability (mounts/
binds). **Existing to remove:** global ambient root; `g_rt` becomes *a* mountable
Directory object, not *the* fs.

**Risks:** path-resolution is everywhere; the existing rtfs-first ordering fixes
(noted in memory) must be preserved. **Difficulty:** 7. **Prerequisites:** Phase 5, 6.

---

## PHASE 10 — User and Service objects; least-privilege init

**Goal:** **User objects** (no UID 0) and a native **Service Manager** that spawns
services as Process objects holding only delegated caps.

**Files/modules to modify:**
- `posix.d`: `getuid`/`geteuid`/`setuid`/`SO_PEERCRED` consult a **User object** + caps
  (kill the hardcoded `0`); synthetic `/etc/passwd` provider derives from User objects.
- `core/exports.d` (init/userspace bring-up) + a new `core/servicemgr.d`: PID1 becomes
  a Service Manager holding a minimal cap set; each service gets an endpoint cap + a
  narrowed cap table.

**New abstractions:** `User`, `Service` objects; admin actions = distinct caps.
**Existing to remove:** UID-0 privilege; omnipotent PID1.

**Risks:** breaks anything assuming root (BusyBox, OpenRC, elogind). **Difficulty:** 6.
**Prerequisites:** Phase 6, 7. (Overlaps `IMMUTABLE_ROOTLESS_ROADMAP.md` Phase 3.)

---

## PHASE 11 — Window objects (display as objects)

**Goal:** the in-kernel Wayland/compositor becomes **Window/Surface/Display Device
objects** owned via caps (and, per `GUI_ROADMAP.md`, eventually a user-space service).

**Files/modules to modify:** `display/wayland/wserver.d`, `display/compositor/`,
`display/window_manager/`, `display/server/`; DRM Device object (Phase 8).
**New abstractions:** `Window`/`Surface`/`Output` objects. **Existing to remove:**
in-kernel global compositor state as ambient authority.

**Risks:** large in-kernel subsystem; do **after** Device objects and IPC.
**Difficulty:** 8. **Prerequisites:** Phase 7, 8.

---

## PHASE 12 — Linux compatibility as objects (`LinuxObject` tree)

**Goal:** demote the Linux layer from "the OS" to an object subtree. The huge
`dispatchLinuxSyscall` switch (`kernel_main.d`) becomes a **`LinuxSyscallObject`** that
**translates** Linux ops into native object operations from Phases 3–10.

**New abstractions (the requested tree):**
- `LinuxProcessObject` — wraps a native Process object; owns the Linux pid view,
  signal state, `brk`.
- `LinuxVFSObject` — maps Linux paths/fds to Namespace + File/Directory objects
  (replaces direct `g_fdTabs`/`g_rt` reach).
- `LinuxSyscallObject` — the translator; the `dispatchLinuxSyscall` switch moves here
  and calls native object ops instead of touching globals.
- `LinuxELFLoaderObject` — wraps `execveTask`/`loadElf` (`kernel_main.d`).
- `LinuxDeviceAdapterObject` — presents native Device objects as `/dev/*` Linux nodes
  (DRM, input, console, null/zero/random).

**Files/modules to modify:** `kernel_main.d` (move the switch out), `posix.d` (becomes
the bodies of `LinuxSyscallObject` methods, calling native ops), `core/exports.d`.
**Existing to remove:** Linux globals as the *source of truth* — they become caches/
views inside `LinuxObject`.

**Risks:** highest behavioural-regression surface (BusyBox/Hyprland depend on exact
semantics). Do it **after** the native objects it will call exist. **Difficulty:** 9.
**Prerequisites:** Phases 3–10.

---

## PHASE 13 — Reduce the native kernel to the six pillars

**Goal:** verify the native kernel contains only **Scheduler** (`kernel_main.d`
`scheduleNext`/`dispatchSyscall`), **Object Manager** (`core/object.d`), **Capability
Manager** (`core/cap.d`), **IPC Router** (`core/ipc.d`), **Memory Manager** (`mm.d` +
MemRegion/Vmo + HAL in `arch/`), **HAL** (`arch/x86_64/`). Everything else is an object.

**Existing to remove/relocate:** any remaining subsystem logic in `posix.d`/
`kernel_main.d` that isn't translation moves into objects. **Risks:** mostly cleanup;
risk is calling it "done" prematurely (see milestones). **Difficulty:** 5.
**Prerequisites:** Phases 2–12.

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

**2. Linux Compatibility Object.** Phases **9 + 12** (on top of MVOO + P3/P4/P8/P10):
`LinuxSyscallObject`/`LinuxVFSObject`/`LinuxProcessObject`/`LinuxELFLoaderObject`/
`LinuxDeviceAdapterObject` exist; `dispatchLinuxSyscall` only *translates* into native
object ops; BusyBox/Hyprland run unchanged through the object graph. *Provable by:*
Linux globals are no longer a source of truth — disabling the `LinuxObject` subtree
removes Linux support without touching the native kernel.

**3. Fully Object-Oriented OS.** Phase **13**: native kernel = {Scheduler, Object Mgr,
Capability Mgr, IPC Router, Memory Mgr, HAL}; processes, threads, memory, VMOs, files,
directories, devices, drivers, NICs, windows, users, services, namespaces, and Linux
compat are all objects in one tree; authority flows only via delegated capabilities.
*Provable by:* a `grep` of `kernel_main.d`/`posix.d` shows no subsystem logic outside
translation, and no privilege path reads anything but a capability.

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
