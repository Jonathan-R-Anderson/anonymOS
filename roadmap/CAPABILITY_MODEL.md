# Capability Model — ratified spec (IMMUTABLE_ROOTLESS_ROADMAP §0.1)

> Deliverable of **Phase 0, task 0.1** of `IMMUTABLE_ROOTLESS_ROADMAP.md`: the
> written specification of capability structure, rights bits, derivation, and
> revocation — the rules every later rootless/immutable phase encodes.
> **Grounded in the current `src/kernel/d/` tree**, which (unlike the roadmap's
> original §0 assessment) now has a working capability manager.

---

## 0. Status correction — capabilities already exist

The roadmap's §0 table says *"Capability-based security: None."* **That is no longer
true.** Since it was written, the Object-OS roadmap (`OBJECT_OS_ROADMAP.md`) and the
Object-Reference-Graph roadmap (`OBJECT_REFERENCE_GRAPH_ROADMAP.md`) were implemented,
and they include a real capability manager. Ground truth today:

| §0 claim ("Reality") | Now |
|---|---|
| "No capability type" | `core/cap.d`: `Capability{objId, rights, deriveParent, revoked, capObjId}`; every live cap slot has an `ObjType.Capability` object. |
| "no grant/delegate" | `capDerive`/`capDeriveObjectTo[In]` — subset-narrowing delegation; `SCM_RIGHTS` fd passing routes through it (`ipcDelegateCap`/`ipcAcceptCap`). |
| "no enforcement" | `requireCap(tid, capId, rights)` gates the fd syscall surface; endpoint calls require `CAP_RIGHT_CALL`; absolute `open()` resolves through namespace binding rights; admin actions require typed `ObjType.Admin` caps. |
| "no revocation" | `capRevoke`/`capRevokeIn` — **transitive** derive-DAG closure (ORG P7.2). |
| "every task is root / UID 0" | `getuid`/`geteuid`/`SO_PEERCRED` now read the task's **User object** (`core/user.d`); the default subject is uid/gid 1000, while PID1 holds only explicit admin caps. |

So this spec **documents and ratifies the implemented model** and states the
invariants the remaining rootless/immutable phases (notably 8.3 cap-gated
`mmap(PROT_EXEC)`) must preserve — rather than designing from a vacuum.

What is **implemented**: cap structure, rights bits, first-class cap-slot objects,
subset derivation, transitive revocation, per-process cap tables, fork-narrowing,
fd-surface enforcement, IPC delegation, endpoint/service call gating, namespace
binding-right checks for absolute opens, typed admin-cap gating (3.2), non-root
default task identity (3.1), untyped-memory allocation gating (1.4), and (via ORG)
edge-level rights/label-monotonicity checks + an audit log.
What is **still spec-only** (future phases): cap-gating `mmap(PROT_EXEC)` (8.3) and
the immutable store/verification stack.

---

## 1. Capability structure (`core/cap.d`)

```d
struct Capability {
    uint objId;        // the object this capability names (0 = empty slot)
    uint rights;       // rights bitset (subset of CAP_RIGHT_UNIVERSE)
    uint deriveParent; // handle this cap was derived from; CAP_INVALID for roots
    uint revoked;      // non-zero ⇒ explicitly revoked (and all its descendants)
    uint capObjId;     // ObjType.Capability identity for this live handle
}
struct CapTable { Capability[CAP_MAX] caps; }   // CAP_MAX = 2048
__gshared CapTable[CAPTAB_COUNT] g_capTabs;      // CAPTAB_COUNT = 64
```

- **A capability is a (object, rights, derivation-parent) triple held in a table
  slot.** The *handle* is the slot index — a small integer scoped to one cap table,
  **not** a pointer or a global id. A holder cannot name a capability outside its own
  table, and cannot fabricate one (see §4 unforgeability).
- **A live cap slot is also an object.** `capInstallIn` allocates an
  `ObjType.Capability` object for the slot (`capObjId`), and clear/revoke/table-clear
  release it. This makes capability handles visible to the object census/graph without
  making the handle itself forgeable.
- **Per-process cap space.** Each `Task` references a cap table by `capTabId`
  (alongside `fdTabId`); `dispatchSyscall` selects it before servicing a syscall. This
  is the seL4 *CNode* / Genode *cap space* role: the task's authority **is** its table.
- **The named object** lives in the central object table (`core/objmgr.d`,
  `ObjHeader{id,type,refCount,ownerCap,...}`); `capUsable` requires `objGet(objId)`
  to be live, so a capability to a freed object is dead.

## 2. Rights bits

```d
CAP_RIGHT_READ  = 1<<0   CAP_RIGHT_WRITE = 1<<1   CAP_RIGHT_CLOSE = 1<<2
CAP_RIGHT_STAT  = 1<<3   CAP_RIGHT_IOCTL = 1<<4   CAP_RIGHT_MMAP  = 1<<5
CAP_RIGHT_DUP   = 1<<6   CAP_RIGHT_PASS  = 1<<7
CAP_RIGHT_RETYPE = 1<<8  // Untyped-memory retype, not an fd right
CAP_RIGHT_CALL   = 1<<9  // Endpoint/service call, not an fd right
CAP_RIGHT_ADMIN_MOUNT   = 1<<10
CAP_RIGHT_ADMIN_REBOOT  = 1<<11
CAP_RIGHT_ADMIN_UPDATE  = 1<<12
CAP_RIGHT_ADMIN_USER    = 1<<13
CAP_RIGHT_ADMIN_DEVICE  = 1<<14
CAP_RIGHT_ADMIN_INSPECT = 1<<15
CAP_RIGHT_ALL   = (fd-surface rights above)
CAP_RIGHT_ADMIN_ALL = (admin rights above)
CAP_RIGHT_UNIVERSE = CAP_RIGHT_ALL | CAP_RIGHT_RETYPE | CAP_RIGHT_CALL | CAP_RIGHT_ADMIN_ALL
```

Rights are a **lattice under bitwise-AND (meet)**: `r1 ⊑ r2  ⟺  r1 & r2 == r1`.
`CAP_RIGHT_ALL` is the top of the *fd-surface* lattice — note it is **not** a "god"
right: it confers only the fd operations, never `RETYPE`, `CALL`, or administrative
authority. Admin authority is split across distinct `ObjType.Admin` caps with one
right per action. Rights are per-capability, so two handles to the same object may
carry different rights.

## 3. Derivation (delegate only what you hold; monotonically non-increasing)

```d
capDerive(srcHandle, subsetRights) -> newHandle | CAP_INVALID
```

- **Meet-narrowing.** `capDerive` computes `rights = subsetRights & src.rights` and
  **fails (`CAP_INVALID`) if `subsetRights ⊄ src.rights`** — a derived capability can
  only ever hold a subset of its parent's rights. This is invariant **I5** in
  `ORG_ARCHITECTURE.md`, enforced again at the graph layer (`edgeAdd(Cap)` rejects an
  edge whose rights exceed the parent's `heldRights`, and whose MAC label exceeds the
  parent's).
- **Derivation builds a DAG**, recorded by `deriveParent` (the source handle). Roots
  have `deriveParent == CAP_INVALID`.
- **Object-to-handle derivation also requires a live source cap.**
  `capDeriveObjectTo[In]` refuses to materialise a destination handle unless the
  source handle is usable and covers the requested rights. Kernel-owned root grants
  are explicit `capInstall[In]` calls with `CAP_INVALID` parent.
- **Delegation over IPC** (`SCM_RIGHTS`): a sender delegates *by value* —
  `ipcDelegateCap(objId, rights)` produces an `IpcCapDesc{objId, rights}` validated
  against the live object table; the receiver's `recvmsg` materialises a new handle in
  **its own** cap table narrowed via `ipcAcceptCap` (`posix.d`, `core/ipc.d`). A raw
  pointer is never transferred, so a receiver can hold no more than it was sent.
- **Service/endpoint authority is a capability.** `objCallCapIn` and
  `ipcServiceConnectIn` accept endpoint-cap handles, not raw endpoint object ids, and
  require the held cap to name the registered endpoint with `CAP_RIGHT_CALL`.
- **Administrative authority is typed and action-specific.** `core/admin.d` creates
  `ObjType.Admin` objects for mount, reboot, update, user, device, and inspect. The
  Linux personality gates `mount`/`umount2`/`chroot`, `reboot`, identity/ownership
  changes, and ORG graph export through the matching admin cap; `uid==0` is never a
  privilege predicate.
- **Fork narrows, never widens.** `capTableCloneNarrowing(src, dst, rightsMask)`
  copies the parent's table into the child intersecting every cap with `rightsMask`
  (`fdtabForkCopy` path) — a child cannot inherit more authority than the parent.

## 4. Unforgeability

- A capability is **only** created by `capInstall[In]` / `capDerive[ObjectTo][In]`,
  which require a **live** target object (`objGet(objId) != null`) and (for derive) a
  usable source whose rights cover the request. There is no syscall that mints a
  capability from a bare integer, and a handle is just a table index — guessing an
  index in *your own* table only reaches caps you were already given; you cannot index
  *another* task's table at all (dispatch selects your `capTabId`).
- `capUsable(cap)` is the single liveness predicate: not null, `revoked == 0`,
  `objId != 0`, and `objGet(objId)` live. Every `requireCap` consults it.

## 5. Revocation (transitive closure — I7)

```d
capRevoke(handle)                // active table
capRevokeIn(tableId, handle)     // explicit table
```

- Revoking a capability clears it **and iterates the forward derive-DAG to a
  fixpoint**, revoking every transitively-derived descendant (child, grandchild, …) —
  not just direct children. This is invariant **I7**; proven by `[cap] revclosure
  PASS`. Revocation is the basis of logout, service kill, and downgrade.
- Each revocation is written to the audit log (`core/audit.d`,
  `AuditKind.Revocation`) so it is attributable (ORG P8.2).

## 6. Invariants (the rules later phases must not break)

1. **Subset derivation.** `rights(child) ⊑ rights(parent)` always (`capDerive`,
   I5). No derivation widens rights.
2. **Label monotonicity.** `label(child) ⊑ label(parent)` down ownership/cap edges
   (ORG I5); reference/observer edges convey no authority (I6).
3. **Unforgeability.** Capabilities arise only from install/derive against a live
   object; handles are table-local indices, never pointers or global ids.
4. **Revocation closure.** Revoking a cap kills its entire derive-subtree (I7).
5. **No ambient authority via tables.** `g_capTabs`/`g_fdTabs`/`g_tasks` are
   *storage*; an authority decision reads a **capability**, never `uid==0` or a raw
   table flag (mistake #8). The fd surface already obeys this via `requireCap`.
6. **No god capability.** `CAP_RIGHT_ALL` is fd-surface-only; administrative powers
   (mount/reboot/update/bind-device/create-user) must be **distinct typed caps**
   (§3.2), never a single all-implying right (mistake #2).
7. **Per-process cap space is the only ambient authority.** A task's reachable
   authority is exactly its cap table; `fork` narrows it, `execve` may reset it.
8. **No ambient RAM allocation.** Public physical allocation consumes the task's
   active `Untyped` object through `CAP_RIGHT_RETYPE`; a task with no selected
   untyped budget or an exhausted one is denied.
9. **No raw endpoint calls.** A client can call a service endpoint only by presenting
   a live endpoint cap with `CAP_RIGHT_CALL`; service-name lookup alone conveys no
   authority.
10. **No ambient absolute namespace root.** Absolute `open()` resolves through the
    task's Namespace object and the matching binding must grant the requested
    read/write rights. The default `/` binding grants all rights for compatibility,
    but restricted namespaces can deny before the legacy resolver runs.
11. **No UID-derived privilege.** `Task.userObjId` names the subject; `getuid`,
    `SO_PEERCRED`, and file-owner defaults read that object. Privileged actions check
    typed admin caps, never `uid==0`.

## 7. Threats this model addresses (maps to §G mistakes)

| §G mistake | Addressed by |
|---|---|
| #1 surviving `uid==0` | non-root default User object + typed admin-cap gates — invariant 11 |
| #2 a "god" capability | `CAP_RIGHT_ALL` is fd-only; admin = many narrow typed caps — invariant 6 |
| #3 ambient resource allocation | `alloc_phys_page(s)` retypes from a task-held `Untyped` object; absolute `open()` consumes namespace binding rights — invariants 8, 10 |
| #6 forgeable / non-revocable caps | §4 unforgeability + §5 transitive revocation — invariants 3, 4 |
| #8 global table as authority source | invariant 5: authority = caps, tables = storage |

## 8. What 0.1 ratifies vs. defers

**Ratified (implemented + spec'd):** cap structure, first-class cap-slot objects,
rights lattice, subset derivation, IPC delegation, endpoint/service cap-gated
connect, namespace binding-right enforcement, fork-narrowing, transitive revocation,
unforgeability, fd-surface enforcement, typed admin-cap gates, non-root task identity,
untyped-memory allocation gating, and the eleven
invariants.

**Deferred to later phases (spec mandates, not yet built):**
- **8.3 W^X / cap-gated `mmap(PROT_EXEC)`:** minting executable pages requires a
  capability. (Mistake #7.)

These are the next tasks on the rootless critical path; each must obey the eleven
invariants above.
