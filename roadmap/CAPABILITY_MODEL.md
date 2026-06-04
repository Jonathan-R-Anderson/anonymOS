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
| "No capability type" | `core/cap.d`: `Capability{objId, rights, deriveParent, revoked}`. |
| "no grant/delegate" | `capDerive`/`capDeriveObjectTo[In]` — subset-narrowing delegation; `SCM_RIGHTS` fd passing routes through it (`ipcDelegateCap`/`ipcAcceptCap`). |
| "no enforcement" | `requireCap(tid, capId, rights)` gates the fd syscall surface (read/write/close/stat/ioctl/mmap/dup/pass) from `dispatchSyscall`. |
| "no revocation" | `capRevoke`/`capRevokeIn` — **transitive** derive-DAG closure (ORG P7.2). |
| "every task is root / UID 0" | `getuid`/`geteuid`/`SO_PEERCRED` now read a **User object** (`core/user.d`); default identity is still root, but it is *sourced from an object*, not a hardcoded `0` (OO-P10). |

So this spec **documents and ratifies the implemented model** and states the
invariants the remaining rootless phases (3.x admin caps, 1.4 untyped memory, 8.3
cap-gated `mmap(PROT_EXEC)`) must preserve — rather than designing from a vacuum.

What is **implemented**: cap structure, rights bits, subset derivation, transitive
revocation, per-process cap tables, fork-narrowing, fd-surface enforcement, IPC
delegation, and (via ORG) edge-level rights/label-monotonicity checks + an audit log.
What is **still spec-only** (future phases): untyped-memory caps gating allocation
(1.4), admin caps replacing the last ambient-root defaults (3.2), flipping the default
identity to non-root (3.1), and cap-gating `mmap(PROT_EXEC)` (8.3).

---

## 1. Capability structure (`core/cap.d`)

```d
struct Capability {
    uint objId;        // the object this capability names (0 = empty slot)
    uint rights;       // rights bitset (subset of CAP_RIGHT_ALL)
    uint deriveParent; // handle this cap was derived from; CAP_INVALID for roots
    uint revoked;      // non-zero ⇒ explicitly revoked (and all its descendants)
}
struct CapTable { Capability[CAP_MAX] caps; }   // CAP_MAX = 1024
__gshared CapTable[CAPTAB_COUNT] g_capTabs;      // CAPTAB_COUNT = 64
```

- **A capability is a (object, rights, derivation-parent) triple held in a table
  slot.** The *handle* is the slot index — a small integer scoped to one cap table,
  **not** a pointer or a global id. A holder cannot name a capability outside its own
  table, and cannot fabricate one (see §4 unforgeability).
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
CAP_RIGHT_ALL   = (all of the above)
```

Rights are a **lattice under bitwise-AND (meet)**: `r1 ⊑ r2  ⟺  r1 & r2 == r1`.
`CAP_RIGHT_ALL` is the top of the *fd-surface* lattice — note it is **not** a "god"
right: it confers only the fd operations, never administrative authority (that is the
future typed admin-cap set, §3.2, kept deliberately separate per mistake #2). Rights
are per-capability, so two handles to the same object may carry different rights.

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
- **Delegation over IPC** (`SCM_RIGHTS`): a sender delegates *by value* —
  `ipcDelegateCap(objId, rights)` produces an `IpcCapDesc{objId, rights}` validated
  against the live object table; the receiver's `recvmsg` materialises a new handle in
  **its own** cap table narrowed via `ipcAcceptCap` (`posix.d`, `core/ipc.d`). A raw
  pointer is never transferred, so a receiver can hold no more than it was sent.
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

## 7. Threats this model addresses (maps to §G mistakes)

| §G mistake | Addressed by |
|---|---|
| #1 surviving `uid==0` | identity sourced from a User object; privilege checks consult caps (the remaining default-root flip is §3.1) |
| #2 a "god" capability | `CAP_RIGHT_ALL` is fd-only; admin = many narrow typed caps (§3.2) — invariant 6 |
| #6 forgeable / non-revocable caps | §4 unforgeability + §5 transitive revocation — invariants 3, 4 |
| #8 global table as authority source | invariant 5: authority = caps, tables = storage |

## 8. What 0.1 ratifies vs. defers

**Ratified (implemented + spec'd):** cap structure, rights lattice, subset
derivation, IPC delegation, fork-narrowing, transitive revocation, unforgeability,
fd-surface enforcement, the seven invariants.

**Deferred to later phases (spec mandates, not yet built):**
- **1.4 Untyped→typed memory:** allocation must consume an *untyped-memory
  capability*, so RAM is delegated/accountable — no ambient `mmap`. (Mistake #3.)
- **3.1/3.2 Rootless admin:** flip the default subject to non-root and express
  mount/reboot/update/etc. as distinct admin caps. (Mistakes #1, #2.)
- **8.3 W^X / cap-gated `mmap(PROT_EXEC)`:** minting executable pages requires a
  capability. (Mistake #7.)
- **2.3 Endpoint/service caps as the unit of "talk to service X"** already exist as
  objects (`core/servicemgr.d`, `core/ipc.d` endpoints); wiring connection
  establishment to *require holding* the endpoint cap is the remaining step.

These are the next tasks on the rootless critical path; each must obey the seven
invariants above.
