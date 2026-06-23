# Native Object ABI — design specification

The **AnonymOS native ABI**: an object-oriented, capability-based syscall surface for
the EpinAnonymOS microkernel. It is the counterpart to the Linux compatibility ABI
([SYSCALL_ABI.md](SYSCALL_ABI.md)). Where the Linux ABI exists so unmodified Linux
binaries run, the native ABI is the *real* OS interface: every kernel resource is a
first-class object reached through unforgeable capabilities, and almost all OS services
are implemented in user-space servers rather than the kernel.

> **Status.** This is a *design spec*, staged for incremental implementation. What is
> live today is the read-only enumeration core (`HOS_SYS_QUERY` ops 1–6 in
> [`core/hoscall.d`](../src/kernel/d/core/hoscall.d)) plus the object/capability/identity/
> namespace/service tables it reflects, and the **access gate** (§3) that restricts the
> native ABI to the AnonymOS native shell. Everything else here is specified and
> roadmapped (§30). Each syscall is tagged `[live]`, `[partial]`, or `[planned]`.

---

## 1. Design philosophy

1. **Object-oriented, not POSIX-centric.** The unit of the ABI is the *object* and the
   *method call on a capability*, not the file descriptor + ioctl. POSIX is one
   user-space personality layered on top (the Linux ABI).
2. **Capabilities, not ambient authority.** There is no global root, no `uid==0` bypass.
   A task can only act on objects it holds capabilities for. Authority is granted,
   delegated, attenuated, and revoked explicitly. (Grounded in
   [`core/cap.d`](../src/kernel/d/core/cap.d): the 19 `CAP_RIGHT_*` bits + per-identity
   rights ceilings in [`core/identity.d`](../src/kernel/d/core/identity.d).)
3. **Everything is a first-class object.** Processes, threads, memory regions, channels,
   files, directories, devices, drivers, namespaces, identities, services, even
   capabilities themselves are typed kernel objects (the `ObjType` enum,
   [`core/objmgr.d`](../src/kernel/d/core/objmgr.d)).
4. **Message passing over shared global state.** Cross-domain interaction is a typed
   message on a channel/endpoint, not a shared mutable table. The kernel exposes the
   primitives; servers build the protocols.
5. **Reflection & introspection.** Objects carry runtime type identity, metadata, an
   interface/method list, properties, and an event stream. The ABI is self-describing
   (`object_typeof`, `object_list_methods`, `object_query`).
6. **User-space servers, minimal kernel.** The kernel implements only primitives:
   object lifetime, capability enforcement, address spaces, scheduling, IPC transport.
   Filesystems, network stacks, device drivers, and policy live in user space.
7. **Declarative & immutable-friendly.** State is expressible as data (the `/config`
   declarative views, snapshots, generations) so the system can be configured, snapshotted,
   and reproduced declaratively.
8. **Scales embedded → server.** The same primitives work with a handful of objects on a
   microcontroller or millions across a multicore machine; nothing in the ABI assumes a
   particular scale.

---

## 2. The ABI mechanism

### 2.1 Entry point and encoding

The native ABI enters the kernel through one syscall number outside the Linux range:

```
HOS_SYS_QUERY = 0x4000     (rax)        // the native ABI multiplexer
  rdi = op        (NABI_*; the operation / verb)
  rsi = handle    (a capability handle, or 0)
  rdx = a0        (arg / in-buffer pointer)
  r10 = a1        (arg / in-buffer length)
  r8  = a2        (arg / out-buffer pointer)
  r9  = a3        (arg / out-buffer length)
  → rax = result  (≥0 = bytes written / value; <0 = −errno)
```

A single multiplexed entry keeps the trap surface tiny (one number to audit/gate) while
the `op` space is large and versioned. Structured arguments are marshalled as a compact
TLV (type-length-value) blob in the in/out buffers — language-neutral, forward-compatible,
and the same wire format used for `object_call` marshalling and IPC messages. Today's
ops 1–6 are the read-only `HOSQ_*` listings; the full `NABI_*` op space below extends it.

> **Why a multiplexer, not N syscall numbers?** It makes the *one* native entry trivially
> auditable and **gateable** (§3) — the kernel allows or denies the entire native surface
> with a single check — and lets the op table grow without consuming scarce syscall
> numbers. Hot paths (read/write/IPC) may later be promoted to dedicated numbers; the
> multiplexer remains the canonical, self-describing surface.

### 2.2 Handles

A **handle** is a process-local index into the task's capability table
([`core/cap.d`](../src/kernel/d/core/cap.d)) that names a kernel object **plus the rights
the holder has over it**. Handles are unforgeable (the kernel validates every one),
copyable only via `cap_delegate`/`object_retain` (which can only *attenuate* rights), and
revocable. A handle is the union of "which object" and "what am I allowed to do to it" —
there is no separate ACL.

### 2.3 Errors

Negative return = `−errno`. The native ABI reuses the Linux errno integers for the
overlapping cases and adds native ones:

| errno | meaning (native usage) |
|---|---|
| `EPERM` 1 | capability lacks the required right; or the **native ABI is gated off** for this task (§3) |
| `ENOENT` 2 | no such object / method / property / service |
| `EBADF` 9 | invalid or revoked handle |
| `ENOMEM` 12 | object table / arena exhausted |
| `EACCES` 13 | namespace/policy denied the operation |
| `EFAULT` 14 | bad user pointer |
| `EEXIST` 17 | object/name already exists |
| `EINVAL` 22 | malformed op, args, or TLV |
| `ENOSYS` 38 | op not implemented, or **native ABI not present for this personality** (§3) |
| `EROFS` 30 | immutable object (e.g. a `Generation`, a `/system` view) |
| `ESTALE` 116 | object destroyed underneath the handle |
| `ETIMEDOUT` 110 | a `*_wait`/`channel_call` deadline elapsed |
| `EOWNERDEAD` 130 | the owning server died mid-call |

---

## 3. Access control — personalities & the native gate

> This section is the **security spine** and the explicit requirement: the native ABI is
> reachable **only from the AnonymOS native shell context**, never from a Linux-personality
> process — yet the native context can see *down* into the Linux process table and
> override Linux state.

### 3.1 Two personalities

Every task runs under one of two **personalities**, a per-task property:

- **Linux personality** — busybox, musl programs, the GUI clients, Weston. They speak the
  Linux ABI ([SYSCALL_ABI.md](SYSCALL_ABI.md)). `HOS_SYS_QUERY` returns **`ENOSYS`** for
  them: the native object ABI simply does not exist in their world.
- **Native (AnonymOS) personality** — the native object shell `/hos-sh` and anything it
  spawns. It speaks **both** ABIs: the full native object ABI *and* the Linux ABI. The
  latter is deliberate — it is how the native context reaches *down* into Linux state.

This is **asymmetric by design**: Linux ⊄ native (a Linux process cannot escalate into the
object ABI), native ⊃ Linux (the native shell is a superset — it can inspect and override
Linux processes, permissions, namespaces, and devices).

### 3.2 How the personality is assigned

- A task acquires the **native personality** only by being the trusted native-shell image
  launched through the trusted path. In the live implementation the kernel sets a per-task
  native-context flag when `execve` loads the `/hos-sh` boot module
  ([`execveTask`](../src/kernel/d/core/kernel_main.d)); the flag is **inherited by
  `fork`/`clone`** (so native helpers the shell spawns stay native), and **cleared on
  `execve` of any non-native image** (so the shell can't launch a Linux tool *into* the
  native ABI).
- **Production hardening (planned):** bind the native personality to a *capability grant*
  from a trusted launcher (the desktop session / Domain Manager) rather than to the binary
  name, and additionally require the task's **identity ceiling** to include
  `CAP_RIGHT_ADMIN_INSPECT`. That closes the self-exec corner (a sandboxed-domain process
  `exec`-ing `/hos-sh` gets the binary but **not** the native authority, because its
  identity ceiling lacks the admin right) without weakening the common desktop flow, where
  the native shell runs in the System domain (ceiling `0x7ffff`, which includes it).

### 3.3 The gate

```
case HOS_SYS_QUERY:
    if (!taskNativePersonality(tid))      // Linux personality → native ABI absent
        return -ENOSYS;
    return nabiDispatch(op, handle, a0..a3);
```

A single check on the single native entry. There is no partial exposure: a Linux process
sees `ENOSYS` for *every* native op, identical to a kernel that never compiled the ABI in.

### 3.4 Downward visibility (native → Linux)

The native context manages Linux from above, through ordinary native objects:

- **Process table.** Each Linux process is a `LinuxProcess` object; `object_enumerate` over
  the process collection lists them, `object_get_property` reads pid/ppid/state/comm/uid,
  and `/objects/processes` (the object FS, which the native shell can `cd` into) mirrors
  `/proc`. The native shell `obj` command already reports the live `LinuxProcess` count.
- **Override / control.** Because a `LinuxProcess` is a native object, native ops act on it
  with native authority: `process_kill`/`process_set_priority` (§4), `cap_*` on the
  process's capability set, `namespace_*` to re-bind what it can see,
  `object_set_property` to change a managed setting. This is the "manage permissions and
  override settings" path — and it is unavailable to Linux processes, which have no native
  handles at all.
- **No upward path.** A Linux process holds no native handle and cannot mint one; the gate
  denies `HOS_SYS_QUERY` before any handle is even examined.

---

## 4. Process management

| op | signature | purpose | errors | rights |
|---|---|---|---|---|
| `spawn_process` | `(cptr manifest, size n, handle ns, handle idn) → handle` | Create a process from a manifest (image cap, args, env, initial caps, identity binding) in namespace `ns` under identity `idn`. Returns a `Process` handle. `[planned]` | EPERM, ENOMEM, EACCES | `CAP_RIGHT_CALL` on a spawn service + the image cap |
| `spawn_object` | `(sym type, cptr init, size n) → handle` | Generic typed-object factory (the primitive `spawn_process` and `object_create` build on). `[planned]` | EINVAL, ENOMEM | type-specific |
| `process_exit` | `(int code) → !` | Terminate the calling process; closes its handles (sockets hang up peers). `[live, via task exit]` | — | — |
| `process_kill` | `(handle proc, int sig) → long` | Deliver a termination/signal to another process object. Works on `LinuxProcess` too (§3.4). `[planned]` | EPERM, ESRCH | `CAP_RIGHT_WRITE` on `proc` |
| `process_wait` | `(handle proc, cptr status, u64 deadline) → long` | Block until `proc` exits (or deadline); reaps it. `[planned]` | ECHILD, ETIMEDOUT | `CAP_RIGHT_STAT` |
| `yield` | `() → 0` | Cooperatively yield the CPU. `[live, Linux sched_yield]` | — | — |
| `sleep` | `(u64 nsec, int clock) → long` | Sleep on the monotonic/realtime clock. `[live, nanosleep]` | EINVAL | — |
| `clone_thread` | `(cptr attrs, size n) → handle` | Create a thread in the caller's address space (entry, stack, TLS, affinity, priority). `[partial, Linux clone]` | ENOMEM | — |
| `join_thread` | `(handle thr, cptr ret, u64 deadline) → long` | Wait for a thread to finish. `[planned]` | ETIMEDOUT, EBADF | `CAP_RIGHT_STAT` |
| `get_pid` / `get_tid` | `() → long` | Identity of the calling process / thread. `[live]` | — | — |
| `set_priority` / `get_priority` | `(handle thr, int prio) → long` | Scheduler priority of a thread object. `[planned]` | EPERM, ERANGE | `CAP_RIGHT_WRITE` |

**Example — launch a sandboxed server, deny it the network:**
```c
handle ns  = namespace_clone(self_ns());            // fresh namespace
namespace_unbind(ns, "/net");                       // no network objects visible
handle p   = spawn_process(manifest, n, ns, untrusted_identity);
cap_drop(process_caps(p), CAP_RIGHT_ADMIN_ALL);     // attenuate before it runs
```

---

## 5. Thread scheduling

Threads are `Thread` objects; scheduling is policy over those objects.

| op | purpose | errors | rights |
|---|---|---|---|
| `thread_create(attrs)` | create a thread (entry/stack/TLS/cpu/prio). `[partial]` | ENOMEM | — |
| `thread_suspend(thr)` / `thread_resume(thr)` | freeze / unfreeze a thread. `[planned]` | EPERM | `CAP_RIGHT_WRITE` |
| `thread_migrate(thr, cpu)` | move a thread to another CPU. `[planned]` | EINVAL | `CAP_RIGHT_WRITE` |
| `thread_set_affinity(thr, cpumask)` / `_get_affinity` | restrict/read the CPU set. `[planned]` | EINVAL | `CAP_RIGHT_WRITE`/`STAT` |
| `sched_set_policy(thr, policy, params)` | cooperative / preemptive / deadline / batch. `[planned]` | EINVAL | `CAP_RIGHT_WRITE` |
| `sched_hint(thr, hint)` | advisory hint (latency-sensitive, background, gang). `[planned]` | — | — |
| `cpu_stats(cpu, cptr out, size n)` | per-CPU utilization/idle/steal counters. `[partial, present-prof]` | — | `CAP_RIGHT_ADMIN_INSPECT` |

> The kernel ships a cooperative single-core scheduler today; this category specifies the
> object surface so a user-space scheduler/governor can be layered on (the kernel keeps
> only the mechanism: run-queue + the `Thread` objects).

---

## 6. Object system (the core)

The reflective heart of the ABI. Every other object inherits these verbs.

#### `object_create(sym type, cptr init, size n) → handle` `[partial]`
Instantiate a typed object; returns an owning handle (full rights). The `type` is an
`ObjType` symbol (`File`, `Channel`, `Vmo`, `Namespace`, …).
- **Errors:** EINVAL (unknown type / bad init), ENOMEM, EPERM (type needs authority).
- **Security:** creating privileged types (`Admin`, `Identity`, `Device`) requires the
  corresponding `CAP_RIGHT_ADMIN_*` in the identity ceiling.

#### `object_destroy(handle obj) → long` `[partial]`
Request destruction. Succeeds when the last reference drops (see `object_release`).
- **Errors:** EBADF, EPERM (no `CAP_RIGHT_CLOSE`), EROFS (immutable object), EBUSY.

#### `object_open(handle dir, sym name, u32 rights) → handle` `[partial]`
Resolve a name in a container object (namespace/directory) to a new handle, attenuated to
`rights`. The naming counterpart of `cap_derive`.
- **Errors:** ENOENT, EACCES (namespace policy), EPERM (rights ⊄ holder's rights).

#### `object_close(handle obj) → long` `[live]`
Drop the caller's handle (one reference). For socket/channel objects this propagates the
hang-up to peers — the same mechanism that makes a closed window's client teardown reach
the compositor.

#### `object_retain(handle obj) → handle` / `object_release(handle obj) → long` `[partial]`
Reference counting. `retain` returns a new handle (rights ≤ source); `release` drops one.
The object lives until refs reach 0 **and** `object_destroy` was requested.

#### `object_query(handle obj, sym what, cptr out, size n) → long` `[live, partial]`
Reflection: read metadata — `type`, `id`, `refs`, `owner`, `name`, `state`, the interface
list, capability set, relationship edges. (The `/objects/<kind>/<obj>/{meta,capabilities,
relationships}` FS views are the filesystem projection of this op.)

#### `object_set_property(handle obj, sym key, cptr val, size n) → long` / `object_get_property(...)` `[partial]`
Typed key/value metadata on an object. Setting requires `CAP_RIGHT_WRITE`; some properties
are sealed/read-only (`EROFS`). This is the "override a managed setting" primitive (§3.4).

#### `object_call(handle obj, sym method, cptr args, size argsz, cptr out, size outsz) → long` `[planned]`
**Dynamic method dispatch** — invoke a method by symbol on the object's interface. The call
is delivered to the object's owning server (in *its* domain, not the caller's) as a
marshalled message; this is the unification of "syscall" and "RPC".
- **Errors:** ENOSYS (no such method), EINVAL (marshalling), EPERM (no `CAP_RIGHT_CALL`),
  ETIMEDOUT, EOWNERDEAD.
- **Security:** gated on `CAP_RIGHT_CALL` in the handle; arguments that are themselves
  handles are *delegated* (attenuable) into the callee.

#### `object_cast(handle obj, sym iface) → handle` `[planned]`
Narrow/widen to a different interface the object implements (interface-based polymorphism);
fails `EINVAL` if the object does not implement `iface`.

#### `object_typeof(handle obj) → sym` `[live]` · `object_list_methods(handle obj, cptr out, size n) → long` `[planned]`
RTTI + interface enumeration — the basis of a self-describing, scriptable system.

#### `object_enumerate(handle container, cursor c, cptr out, size n) → long` `[live, partial]`
Iterate the members of a container object (a collection/namespace/directory). Cursor-based,
restartable. (`getdents` over `/objects/<kind>` is the FS projection.)

#### `object_clone(handle obj, cptr opts, size n) → handle` `[planned]`
Structural copy (copy-on-write where the type allows — e.g. `Vmo`, `Namespace`).

#### `object_subscribe(handle obj, u32 event_mask, handle channel) → handle` / `object_unsubscribe(handle sub) → long` `[planned]`
Register for the object's **event stream** (state change, child added/removed, destroyed);
events are delivered as messages on `channel`. The reactive/observer primitive.

#### `object_wait(handle obj, u32 event_mask, u64 deadline, cptr out, size n) → long` `[planned]`
Synchronous wait for one of the events without a channel; returns the event that fired or
`ETIMEDOUT`.

**Inheritance / interfaces / reflection.** Object *types* form an inheritance lattice
(every object implements the base `Object` interface above; `File` implements `Stream`;
`Directory` implements `Container`; `Channel` implements `Endpoint`). `object_cast`,
`object_typeof`, and `object_list_methods` expose it at runtime, so a generic agent can
discover and drive any object without compile-time knowledge — the AI-friendly property.

---

## 7. Capability-based security

Capabilities are themselves objects (`ObjType.Capability`) and handles *are* capabilities
(§2.2). The rights are the 19 `CAP_RIGHT_*` bits in [`core/cap.d`](../src/kernel/d/core/cap.d).

| op | signature | purpose | errors |
|---|---|---|---|
| `cap_create` | `(handle obj, u32 rights) → handle` | Mint a capability to `obj` with `rights` (⊆ caller's rights on `obj`). `[partial]` | EPERM, EBADF |
| `cap_grant` | `(handle cap, handle target_proc) → long` | Install `cap` into another process's table. `[planned]` | EPERM, ENOMEM |
| `cap_revoke` | `(handle cap) → long` | Revoke `cap` **and its whole delegation subtree** (transitive). `[partial, capRevokeClosure]` | EPERM |
| `cap_delegate` | `(handle cap, u32 rights) → handle` | Hand off an attenuated copy (rights ⊆ source); the basis of least-privilege sharing. `[planned]` | EPERM |
| `cap_derive` | `(handle cap, u32 rights, cptr badge, size n) → handle` | Derive a *badged*, attenuated capability (a sub-authority with an opaque tag the server sees). `[planned]` | EPERM |
| `cap_check` | `(handle cap, u32 rights) → long` | Test whether `cap` carries `rights` (no side effects). `[live, requireCap]` | — |
| `cap_drop` | `(handle cap, u32 rights) → handle` | Permanently remove `rights` from a capability (monotonic attenuation). `[partial]` | — |
| `cap_rights` | `(handle cap) → u32` | Read the rights mask (decoded by `/objects/.../capabilities`). `[live]` | EBADF |
| `cap_seal` | `(handle cap, handle sealer) → handle` | Seal a capability so it is opaque/unusable except to a holder of the matching `unseal` authority (token passing, deferred grants). `[planned]` | EPERM |
| `cap_unseal` | `(handle sealed, handle sealer) → handle` | Reverse `cap_seal`. `[planned]` | EPERM |

**Properties.** Delegation (attenuate-only), inheritance (children inherit a *subset* of
the parent's caps), sealing (opaque hand-off), **expiration** (a derived cap may carry a
`u64` deadline after which `cap_check` fails `EPERM`), and fine-grained per-object rights.
The invariant the kernel enforces everywhere: **a derived capability's rights are always a
subset of its source's** (the same rights-narrowing the service manager already enforces).

**Example — deferred, time-boxed delegation:**
```c
handle ro   = cap_derive(file_cap, CAP_RIGHT_READ, badge, n);  // read-only, badged
handle tok  = cap_seal(ro, courier);                           // opaque token
channel_send(ch, &tok, sizeof tok, 0);                          // hand it across a domain
// receiver: handle ro2 = cap_unseal(tok, courier);  // only the courier-holder can open it
```

---

## 8. IPC — message-passing primitives

Channels/endpoints are objects; higher protocols (RPC, pub/sub, mailboxes) are libraries.

| op | purpose | errors | rights |
|---|---|---|---|
| `channel_create() → (handle, handle)` | make a connected channel pair (two endpoints). `[partial, socketpair]` | ENOMEM | — |
| `channel_open(sym name) → handle` | connect to a named endpoint (a service). `[partial]` | ENOENT, EACCES | namespace bind |
| `channel_close(handle) → long` | close one endpoint; peer sees hang-up. `[live]` | — | — |
| `channel_send(handle, cptr msg, size n, handle* caps, u32 ncaps) → long` | enqueue a message **plus capabilities** (fd/handle passing). `[partial, SCM_RIGHTS]` | EPIPE, ENOBUFS | `CAP_RIGHT_WRITE` |
| `channel_receive(handle, cptr buf, size n, handle* caps, u32* ncaps, u64 deadline) → long` | dequeue a message + any passed caps. `[partial]` | EAGAIN, ETIMEDOUT | `CAP_RIGHT_READ` |
| `channel_reply(handle, token, cptr msg, size n) → long` | reply to a specific received message (request/response correlation). `[planned]` | EINVAL | — |
| `channel_call(handle, cptr req, size rn, cptr rep, size pn, u64 deadline) → long` | **synchronous RPC**: send + block for reply (one trap). `[planned]` | ETIMEDOUT, EOWNERDEAD | `CAP_RIGHT_CALL` |
| `channel_forward(handle from, handle to) → long` | splice/forward a message between channels (proxies, brokers). `[planned]` | EPERM | `CAP_RIGHT_PASS` |
| `channel_poll(handle* set, u32 n, u64 deadline) → long` | wait for readability/writability/hang-up across channels. `[partial, epoll]` | — | — |

**Higher layers (user-space libraries over the above):**
- **Shared memory** — pass a `Vmo` capability over a channel; both map it (§9). Zero-copy.
- **RPC** — `channel_call` + TLV marshalling + an IDL-generated stub == `object_call`.
- **Publish/subscribe** — a topic is a `Service` object; `object_subscribe` registers a
  delivery channel; `service_notify` fans out.
- **Broadcast** — a multicast endpoint object that copies a message to all subscribers.
- **Mailboxes / event queues** — a channel with buffering + a name == a mailbox; an
  eventfd/timerfd/signalfd surfaces as an `Endpoint` you `channel_poll`.

---

## 9. Virtual memory

Memory regions (`MemRegion`) and memory objects (`Vmo`) are first-class; mappings are caps.

| op | purpose | errors | rights |
|---|---|---|---|
| `vm_alloc(size, u32 flags) → handle` | create an anonymous `Vmo` (zero-filled, demand-paged). `[partial]` | ENOMEM | — |
| `vm_free(handle vmo) → long` | release a `Vmo`. `[partial]` | EBUSY | `CAP_RIGHT_CLOSE` |
| `vm_map(handle as, handle vmo, u64 vaddr, u64 off, size len, u32 prot, u32 flags) → u64` | map a `Vmo` into an address space (shared/private/COW/fixed/exec/huge). `[live, mmap]` | EINVAL, ENOMEM, EPERM(exec) | `CAP_RIGHT_MMAP` (+`EXEC` for PROT_EXEC) |
| `vm_unmap(handle as, u64 vaddr, size len) → long` | unmap; frees owned pages. `[live, munmap]` | EINVAL | — |
| `vm_protect(handle as, u64 vaddr, size len, u32 prot) → long` | change protections (W^X enforced). `[live, mprotect]` | EACCES(W^X), EPERM(exec) | `CAP_RIGHT_MMAP` |
| `vm_clone(handle as) → handle` | COW-clone an address space (fork's primitive). `[live]` | ENOMEM | — |
| `vm_share(handle vmo, handle target) → handle` | hand a `Vmo` cap to another process (shared mapping). `[partial]` | EPERM | `CAP_RIGHT_PASS` |
| `vm_advise(handle as, u64 vaddr, size len, int advice) → long` | willneed/dontneed/sequential/hugepage. `[partial, madvise]` | — | — |
| `vm_query(handle as, u64 vaddr, cptr out, size n) → long` | region metadata (prot/backing/refs/resident). `[planned]` | — | `CAP_RIGHT_STAT` |
| `vm_lock` / `vm_unlock(handle as, u64 vaddr, size len)` | pin/unpin pages (no eviction). `[planned]` | EPERM, ENOMEM | `CAP_RIGHT_ADMIN_*` |

**Supported:** copy-on-write (`vm_clone`, live), demand paging, huge pages (flag),
memory objects (`Vmo`), shared mappings (`vm_share`), executable mappings (gated on
`CAP_RIGHT_EXEC`, the W^X policy).

---

## 10. Filesystem (VFS as objects)

Files, directories, pipes, sockets, and devices are all objects implementing `Stream` /
`Container`. The POSIX file calls are the Linux personality projecting these objects; the
native ABI exposes them directly. Each native op maps to an object verb:

| native op | object verb | Linux projection `[live]` |
|---|---|---|
| `fs_open(dir, name, rights)` | `object_open` on a `Container` → `Stream` handle | `open`/`openat`(2,257) |
| `fs_close(h)` | `object_close` | `close`(3) |
| `fs_read(h, buf, n)` / `fs_pread(h, buf, n, off)` | `Stream.read` | `read`(0)/`pread64`(17) |
| `fs_write(h, buf, n)` / `fs_pwrite(...)` | `Stream.write` | `write`(1)/`pwrite64`(18) |
| `fs_seek(h, off, whence)` | `Stream.seek` | `lseek`(8) |
| `fs_stat(h)` / `fs_lstat(dir,name)` | `object_query("meta")` | `fstat`(5)/`newfstatat`(262)/`lstat`(6) |
| `fs_mkdir`/`fs_rmdir`/`fs_unlink`/`fs_rename`/`fs_symlink`/`fs_readlink`/`fs_truncate` | `Container` mutators | `mkdir`(83)…`renameat`(264)… |
| `fs_readdir(dir, cursor)` | `object_enumerate` | `getdents64`(217) |
| `fs_fsync(h)` | `Stream.flush` | `fsync` |
| `fs_chmod`/`fs_chown(h, …)` | `object_set_property("mode"/"owner")` | `fchmodat`(268)/`fchownat`(260) |
| `fs_mount(at, fs_server)` / `fs_unmount(at)` | `namespace_bind` a filesystem server object | `mount`(165, cap-gated) |

> **Filesystems are user-space servers.** The kernel knows only `Stream`/`Container`
> objects and channels; a filesystem is a server that owns a subtree of objects and answers
> `object_call`s. The VFS is namespace composition (§11), not a kernel mount table. The
> object-FS views (`/objects`, `/config`, `/system`) are the kernel's *own* objects projected
> as a filesystem; the persisted store (`objstore.d`) is one such server.

---

## 11. Namespace management

A namespace (`ObjType.Namespace`) is a set of *bindings* — `path → (object, rights)` — that
defines what a process can see and reach. Grounded in
[`core/namespace.d`](../src/kernel/d/core/namespace.d) + the per-identity views in
[`core/idns.d`](../src/kernel/d/core/idns.d). See [NAMESPACING.md](NAMESPACING.md).

| op | purpose | errors | rights |
|---|---|---|---|
| `namespace_create() → handle` | empty namespace. `[partial]` | ENOMEM | — |
| `namespace_destroy(ns)` | drop a namespace. `[planned]` | EBUSY | `CAP_RIGHT_CLOSE` |
| `namespace_clone(ns) → handle` | copy bindings (per-process restriction starts here). `[live]` | ENOMEM | — |
| `namespace_bind(ns, path, obj, rights)` | mount an object at a path with rights. `[live]` | EEXIST, EPERM | `CAP_RIGHT_WRITE` on `ns` |
| `namespace_unbind(ns, path)` | remove a binding (hide a subtree). `[live]` | ENOENT | `CAP_RIGHT_WRITE` |
| `namespace_lookup(ns, path) → (handle, rights, rest)` | longest-prefix resolve → object + granted rights + suffix. `[live]` | ENOENT, EACCES | — |
| `namespace_list(ns, cursor)` | enumerate bindings. `[partial]` | — | `CAP_RIGHT_STAT` |
| `namespace_enter(ns)` / `namespace_leave()` | switch the calling task's namespace (containers). `[planned]` | EPERM | `CAP_RIGHT_ADMIN_*` |

**Isolates:** processes, users, devices, filesystems, networking, IPC, and services — each
is just a subtree of objects a namespace may or may not bind. Containers and per-domain
worlds are namespace compositions, not a separate subsystem.

---

## 12. Device management

Devices are `Device` objects owned by **user-space drivers** (`Driver` objects). The kernel
brokers access + interrupts; it implements no driver logic.

| op | purpose | rights |
|---|---|---|
| `device_open(name) → handle` | obtain a `Device` capability (namespace-mediated). | bind + `CAP_RIGHT_ADMIN_DEVICE` for raw |
| `device_close(h)` | release. | — |
| `device_read`/`device_write(h, buf, n, off)` | stream/block transfer. | `CAP_RIGHT_READ`/`WRITE` |
| `device_ioctl(h, req, arg)` | typed control (prefer `object_call`). | `CAP_RIGHT_IOCTL` |
| `device_map_memory(h, off, len, prot) → u64` | map device MMIO/BAR (DMA-safe). | `CAP_RIGHT_MMAP` + admin |
| `device_subscribe_event(h, mask, channel)` / `_unsubscribe` | route IRQs/hotplug to a channel (`object_subscribe` specialization). | `CAP_RIGHT_ADMIN_DEVICE` |
| `device_list(class, cursor)` | enumerate devices (`object_enumerate` over the device collection). | `CAP_RIGHT_ADMIN_INSPECT` |
| `driver_load(image, cptr manifest)` / `driver_unload(drv)` / `driver_restart(drv)` | manage user-space drivers (a driver is a `spawn_process` bound to a device class). | `CAP_RIGHT_ADMIN_DEVICE` |

> **User-space drivers.** A driver is a process holding a `Device` capability + an MMIO
> mapping + an interrupt channel. `driver_restart` is just kill + respawn — drivers are
> restartable without rebooting (the resilience the microkernel buys). Today's AHCI/input/
> framebuffer paths are in-kernel; the roadmap moves them behind this surface.

---

## 13. Events & synchronization

Primitives the kernel provides; richer locks are user-space over futexes + these.

| op | purpose | Linux projection `[live]` |
|---|---|---|
| `event_create/destroy/signal/reset/wait` | manual/auto-reset event object. | eventfd2(284) |
| `mutex_create/lock/unlock` | a futex-backed mutex (mostly user-space). | futex(202) |
| `semaphore_create/wait/post` | counting semaphore. | futex/eventfd |
| `rwlock_create` + `condition_wait/signal` | reader/writer + condvars (user-space over futex). | futex |
| `poll`/`select` | readiness over handles. | poll(7)/select(23)/ppoll(271) |
| `epoll_create/epoll_wait` + `_ctl` | scalable readiness set; an `Epoll` object you add handles to. | epoll_create1(291)/epoll_pwait(232)/epoll_ctl(233) |

> Most synchronization stays in user space over `futex` (live) and the event objects; the
> kernel exposes only the wait/wake primitive + the waitable objects. `object_wait`/
> `object_subscribe` (§6) generalize all of these to *any* object's event stream.

---

## 14. Networking

The stack is a **user-space server**; the ABI gives capabilities to socket objects. A
`socket` is `object_open` on a protocol family object; the BSD calls are the Linux
projection of the same socket objects.

| native | Linux `[live/partial]` | notes |
|---|---|---|
| `net_socket(domain, type, proto) → handle` | socket(41) | AF_UNIX live; AF_INET/INET6 via the user-space stack `[planned]` |
| `net_bind`/`net_listen`/`net_accept`/`net_connect` | 49/50/43/42 | endpoint lifecycle |
| `net_send`/`net_recv`/`net_sendto`/`net_recvfrom` | 44/45/46/47 | + cap-passing on AF_UNIX (SCM_RIGHTS, live) |
| `net_shutdown` | shutdown | half-close |
| `net_getsockopt`/`net_setsockopt` | 54/55 | option objects |
| `net_resolve(name, hints) → addrs` | getaddrinfo (libc) | a name-service `object_call`, not a kernel call |

**Families:** IPv4/IPv6, Unix sockets (live), and — as additional protocol-family server
objects — Bluetooth, CAN bus, raw sockets, TLS-offload (a `SecChannel` in front of a
socket; the ChaCha20-Poly1305 secure-IPC layer already exists in
[`core/secipc.d`](../src/kernel/d/core/secipc.d)), and virtual networking (a software
switch object joining `NetIf` objects across namespaces).

---

## 15. User & identity management

Users (`ObjType.User`) and identities/security-domains (`ObjType.Identity`) are objects;
identity is **capability-based**, not a numeric uid check. Grounded in
[`core/user.d`](../src/kernel/d/core/user.d) + [`core/identity.d`](../src/kernel/d/core/identity.d).

| op | purpose | rights |
|---|---|---|
| `get_uid`/`get_gid`/`get_groups` | read the calling subject's User object. `[live]` | — |
| `set_uid`/`set_gid`/`set_groups(creds)` | drop/transition credentials (monotonic without admin). `[partial]` | `CAP_RIGHT_ADMIN_USER` to raise |
| `login_context(provider, cptr creds) → handle` | authenticate via a pluggable provider; returns a `Session`/identity capability. `[planned]` | — |
| `logout_context(session)` | end a session, revoking its derived caps. `[planned]` | `CAP_RIGHT_CLOSE` |
| `session_create(identity)` / `session_destroy(s)` | a session is a capability bundle + namespace + identity binding. `[planned]` | `CAP_RIGHT_ADMIN_IDENTITY` |

**Pluggable authentication:** a provider is a `Service` object answering a `login`
`object_call`; the kernel never sees passwords/keys — it only mints the identity capability
the provider vouches for. **Capability-based identity:** holding the identity capability
*is* the authorization; there is no ambient "I am root."

---

## 16. Time

| op | purpose | Linux `[live]` |
|---|---|---|
| `clock_gettime(clk)` / `clock_settime(clk, t)` | read/set monotonic or realtime. | clock_gettime(228) / `[planned, cap-gated]` |
| `gettimeofday()` | wall clock. | gettimeofday(96) |
| `nanosleep(nsec, clk)` | sleep. | nanosleep(35)/clock_nanosleep(230) |
| `timer_create(clk, channel) → handle` | a `Timer` object firing onto a channel. | timerfd_create(283) |
| `timer_start(t, when, interval)` / `timer_stop(t)` / `timer_delete(t)` | arm/disarm/free. | timerfd_settime(286) |
| `uptime()` | seconds since boot. | sysinfo |

Both monotonic and realtime clocks; `clock_settime` requires `CAP_RIGHT_ADMIN_*`.

---

## 17. Randomness & cryptography

| op | purpose | notes |
|---|---|---|
| `getrandom(buf, n, flags)` | CSPRNG bytes. `[live, getrandom 318]` | seeded kernel PRNG |
| `crypto_hash(alg, in, n) → digest` | SHA-256/… `[partial, core SHA-256 exists]` | |
| `crypto_encrypt`/`crypto_decrypt(key_cap, alg, in, n)` | AEAD (ChaCha20-Poly1305 live in secipc). `[partial]` | key is a **sealed capability**, never raw bytes to the caller |
| `crypto_sign(key_cap, in, n)` / `crypto_verify(key_cap, sig, in, n)` | signatures (the update/boot-measurement path uses these). `[partial]` | |
| `secure_zero(buf, n)` | wipe without dead-store elimination. `[planned]` | |

**Pluggable providers:** a crypto provider is a `Service` object; keys are **capabilities to
key objects** (sealed, non-extractable) — the caller calls `crypto_*` *through* the key cap,
so a compromised caller cannot exfiltrate the key material.

---

## 18. Debugging

| op | purpose | rights |
|---|---|---|
| `debug_log(level, msg, n)` | structured log to the kernel ring / serial. `[live, klog]` | — |
| `debug_break()` | trap into the debugger. `[planned]` | `CAP_RIGHT_ADMIN_INSPECT` |
| `trace_start(mask, channel)` / `trace_stop()` / `trace_read(buf, n)` | event tracing to a channel/buffer. `[partial, [sc] trace exists]` | `CAP_RIGHT_ADMIN_INSPECT` |
| `ptrace(proc, op, …)` | attach/inspect/control another process (incl. `LinuxProcess` — §3.4). `[planned]` | `CAP_RIGHT_ADMIN_INSPECT` + `CAP_RIGHT_WRITE` on the target |
| `dump_object(obj)` / `dump_process(proc)` / `dump_memory(as, vaddr, n)` | structured introspection dumps. `[partial]` | `CAP_RIGHT_ADMIN_INSPECT` |
| `performance_counter(which, cptr out)` | hardware/software perf counters. `[partial, present/sched prof]` | `CAP_RIGHT_ADMIN_INSPECT` |

> All debug authority is a capability; there is no global `CAP_SYS_PTRACE`-style switch.
> `ptrace` on a `LinuxProcess` is precisely the "see down into the Linux process table and
> override settings" path, and it is unreachable from the Linux personality (§3).

---

## 19. System information

| op | purpose | Linux `[live]` |
|---|---|---|
| `sysinfo()` | aggregate (objects/identities/namespaces/services counts). | sysinfo(99); native = `HOSQ_SYS` (live) |
| `uname()` | kernel name/version. | uname(63) |
| `get_cpu_info()` / `get_memory_info()` | topology, free/used phys. | sysinfo |
| `get_boot_info()` | boot generation, modules, command line. | — (Generation objects) |
| `get_module_list()` | loaded modules/servers. | — |
| `get_scheduler_info()` | policy, run-queue, per-CPU stats. | — |
| `get_object_statistics()` | per-`ObjType` counts + churn. | native = `HOSQ_OBJECTS` (live) |

All read-only; most need `CAP_RIGHT_ADMIN_INSPECT` for cross-domain detail.

---

## 20. Power management

| op | purpose | rights |
|---|---|---|
| `reboot()` / `shutdown()` | restart / power off. `[planned]` | `CAP_RIGHT_ADMIN_REBOOT` |
| `suspend()` / `hibernate()` | S3 / S4. `[planned]` | `CAP_RIGHT_ADMIN_REBOOT` |
| `sync()` | flush dirty state (stores/filesystem servers). `[live]` | — |
| `checkpoint(scope) → handle` / `restore_checkpoint(h)` | freeze a process/namespace tree to a restorable image (live-migration / fault recovery). `[planned]` | `CAP_RIGHT_ADMIN_*` |

Checkpoint/restore builds on `vm_clone` + capability serialization + the content-addressed
store — the same machinery as snapshots (§22).

---

## 21. Module management

| op | purpose | rights |
|---|---|---|
| `module_load(image, cptr manifest) → handle` | start a kernel-adjacent service/server (a `spawn_process` with a service manifest). `[planned]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `module_unload(m)` | stop + reclaim. `[planned]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `module_reload(m, image)` | hot-swap (state handed across via checkpoint). `[planned]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `module_query(m)` | metadata/health. `[partial]` | `CAP_RIGHT_ADMIN_INSPECT` |
| `module_dependencies(m)` | dependency graph (the service DAG). `[partial, service deps]` | `CAP_RIGHT_ADMIN_INSPECT` |

> Because services are user-space, "kernel module management" is mostly *service* management
> (§23). The kernel stays small; the dependency-ordered start already exists in
> [`core/servicemgr.d`](../src/kernel/d/core/servicemgr.d).

---

## 22. Service manager

Services (`ObjType.Service`) are named, rights-narrowed server objects with an endpoint.
Live foundation in [`core/servicemgr.d`](../src/kernel/d/core/servicemgr.d) (§HOSQ_SERVICES).

| op | purpose | rights |
|---|---|---|
| `service_register(name, endpoint, rights_subset) → handle` | publish a service; its authority is clamped ⊆ the registrant's. `[partial]` | `CAP_RIGHT_CALL` |
| `service_unregister(svc)` | retire. `[partial]` | `CAP_RIGHT_CLOSE` |
| `service_lookup(name) → handle` | resolve a name to a (cap-attenuated) endpoint. `[partial]` | namespace bind |
| `service_publish(svc, topic)` | advertise a pub/sub topic. `[planned]` | `CAP_RIGHT_WRITE` |
| `service_subscribe(topic, channel) → handle` | receive notifications on a channel. `[planned]` | `CAP_RIGHT_READ` |
| `service_notify(svc, cptr event, size n)` | fan a notification to subscribers. `[planned]` | `CAP_RIGHT_WRITE` |

---

## 23. Package & snapshot management

Built on the content-addressed store + immutable `Generation` objects
([`core/store.d`](../src/kernel/d/core/store.d)) and the persisted object store
([`core/objstore.d`](../src/kernel/d/core/objstore.d)).

| op | purpose | rights |
|---|---|---|
| `snapshot_create(scope) → handle` | capture an immutable `Generation` of a subtree (system / namespace / app). `[partial, genCreate]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `snapshot_restore(gen)` | atomically repoint to a generation (anti-rollback enforced). `[partial, genSetActive]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `snapshot_delete(gen)` | drop a non-active generation. `[planned]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `package_install(bundle, sig)` | verify + stage an app object into the store (cap-gated launch). `[partial, objstore]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `package_remove(app)` / `package_update(app, bundle, sig)` | uninstall / upgrade an app object. `[planned]` | `CAP_RIGHT_ADMIN_UPDATE` |
| `package_verify(app)` | re-check signatures / store integrity (dm-verity-style). `[partial, storeImageIntact]` | `CAP_RIGHT_ADMIN_INSPECT` |

This is the immutable-OS spine: updates land as new signed generations, snapshots are
atomic repoints, and apps are persisted, signed, cap-gated objects (the F4 north star).

---

## 24. Observability

| op | purpose | rights |
|---|---|---|
| `metrics_query(selector, cptr out, size n)` | structured counters (object/present/sched/IPC stats). `[partial]` | `CAP_RIGHT_ADMIN_INSPECT` |
| `tracing_enable(mask)` / `tracing_disable()` | toggle event tracing. `[partial]` | `CAP_RIGHT_ADMIN_INSPECT` |
| `profiling_start(what, channel)` / `profiling_stop()` / `profiling_read(buf, n)` | sampling/instrumentation to a channel. `[partial, present/sched prof]` | `CAP_RIGHT_ADMIN_INSPECT` |

All observability is read-only and gated on `CAP_RIGHT_ADMIN_INSPECT`; the native shell
holds it, Linux apps do not.

---

## 25. Recommended additional subsystems

Beyond the requested set, a modern object microkernel should also expose:

- **Transactions / atomic groups** — `txn_begin`/`txn_commit`/`txn_abort` so a sequence of
  object mutations (e.g. a namespace re-bind + cap-grant + property set) applies atomically
  or not at all. Critical for declarative config and snapshots.
- **Object persistence & passivation** — `object_freeze`/`object_thaw` to swap idle objects
  to the store and revive on first touch (scales object counts beyond RAM).
- **Distributed object references** — `object_export`/`object_import` of a capability across
  a `SecChannel` to another node, with leased/expiring remote caps (the `distos.d`
  federation primitives) — network-transparent objects.
- **Quotas & resource accounting** — `resource_limit`/`resource_account` binding CPU/mem/IO
  budgets to a capability or namespace (per-container limits without a global cgroup tree).
- **Audit log** — an append-only `Audit` object recording every privileged `object_call` /
  `cap_grant`; the hardening audit log already exists and should be a first-class object.
- **Policy / verifier objects** — declarative, signed policy objects the kernel consults on
  grant/transition (the identity `policyEpoch` mechanism generalized).
- **Notification / completion ports** — a unified `Port` object aggregating channel,
  timer, event, and IRQ completions (one wait for everything) — the scalable async core.
- **Capability backup/restore** — serialize a process's whole cap set into a sealed blob for
  checkpoint/migration.
- **Watchdog / supervision trees** — a `Supervisor` object that restarts failed children by
  policy (Erlang-style resilience over the restartable user-space servers).

---

## 26. AI-/agent-friendly properties (how the requirements are met)

| requirement | how the ABI delivers it |
|---|---|
| object-oriented, not POSIX | every resource is a typed object; the verb is `object_call`, not ioctl (§6) |
| capabilities, not global perms | handles *are* capabilities; no ambient root (§3, §7) |
| every resource a first-class object | the `ObjType` lattice (§6); the FS, net, devices, processes are all objects |
| message passing over shared state | channels/endpoints + cap-passing (§8); cross-domain is a message |
| reflection / introspection | `object_typeof`/`object_query`/`object_list_methods`/`object_enumerate` (§6) — self-describing |
| user-space servers, minimal kernel | kernel = objects + caps + AS + sched + IPC; FS/net/drivers/policy in user space |
| primitives only; libraries above | RPC, pub/sub, locks, mailboxes, name resolution are all libraries over §6/§8/§13 |
| declarative / immutable / containers / distributed | `/config` views + snapshots/generations (§23); namespaces = containers (§11); distributed object refs (§25) |
| embedded → server scale | nothing assumes scale; a `Port` + per-CPU sched + leased remote caps cover both ends |

A generic agent can therefore *discover* the system (enumerate objects, read their types and
methods) and *drive* it (call methods, hold capabilities) without compile-time knowledge —
the system is introspectable and scriptable end to end, while every action is capability-checked.

---

## 30. Implementation roadmap

The kernel already has the substrate (objects, caps, identities, namespaces, services, the
store/generations, secure IPC). Staging:

- **N0 — access gate `[implementing now]`.** The per-task native personality + the
  `HOS_SYS_QUERY` gate (§3): native shell only, Linux denied `ENOSYS`, native retains Linux
  introspection. The security precondition for everything else.
- **N1 — object core.** Promote `HOSQ_*` enumeration to the full `object_*` verb set over a
  handle table (§6): `object_open/close/retain/release/query/typeof/enumerate` + the
  property ops. Wire handles to the existing cap table.
- **N2 — capabilities.** `cap_*` (§7) over `core/cap.d` (mint/derive/delegate/revoke-closure
  exist; add seal/expire/grant). Make handles carry rights end to end.
- **N3 — IPC.** `channel_*` + `object_call` (§8, §6) over the AF_UNIX/secure-IPC transport;
  cap-passing already works (SCM_RIGHTS).
- **N4 — process/thread/VM.** `spawn_process`, thread scheduling, `vm_*` as native verbs over
  the live fork/clone/mmap mechanisms (§4, §5, §9).
- **N5 — servers.** FS/device/net as user-space servers behind §10/§12/§14; move AHCI/input
  out of the kernel behind `device_*`.
- **N6 — power/module/package/observability.** §20–§24 over the store/generation/service
  machinery.
- **N7 — additional subsystems.** Transactions, distributed refs, supervision (§25).

Each phase keeps the Linux personality working unchanged and adds native ops behind the
single gate, so the kernel grows in capability without growing its trusted attack surface.

---

## See also

- [SYSCALL_ABI.md](SYSCALL_ABI.md) — the Linux compatibility ABI (the other personality).
- [FILESYSTEM.md](FILESYSTEM.md) · [NAMESPACING.md](NAMESPACING.md) — the object FS + the
  namespace gate these objects compose into.
- `roadmap/OBJECT_FILESYSTEM_ROADMAP.md`, `roadmap/CAPABILITY_MODEL.md`,
  `roadmap/IDENTITY_DOMAIN_ROADMAP.md`, `roadmap/SECURE_IPC_ROADMAP.md` — the design
  lineage of the live substrate.
