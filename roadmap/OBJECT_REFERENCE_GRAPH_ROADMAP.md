# Object Reference Graph (ORG) Subsystem — Implementation Roadmap

> A directed-graph subsystem over the object model: relationship tracking, cycle
> detection (DFS + Tarjan SCC), coherence + security-inheritance validation, a runtime
> validator, GC for unreachable cycles, visualization, and a path to distributed object
> graphs. **Grounded in `src/kernel/d/`** and **critical** about what doesn't exist yet.

---

## Critical framing — read before Phase 1

Three things must be stated bluntly or this subsystem will be built on sand:

1. **There is no Object Manager to graph yet.** The ORG presupposes the `Object`
   header + central table from `OBJECT_OS_ROADMAP.md` (its Phase 2) and capabilities
   (its Phase 6). Today the "objects" are disjoint typed arrays (`g_tasks`, `g_fdTabs`
   `File[]`, `g_rt` `RtNode[]`, `LocalSocket`, `PipeBuf`, `MemFdRec`, `EpollInst`,
   `AHCIDeviceInfo`, `NetworkDevice`). **Edges between them are implicit integer
   indices** (`File.backend`, `LocalSocket.peerId`, `RtNode.parent`,
   `EpollWatch.watchFd`, `Task.parentId`). *Building ORG before the object header is
   premature.* This roadmap therefore starts by making those implicit edges explicit.

2. **There are two different graphs, and the project conflates them.** The design goal
   says "single hierarchical object tree" *and* "directed graph." Those are not the
   same:
   - The **ownership graph** must be a **forest/tree** (each object has exactly one
     strong owner; the root is the object-tree root). Security inheritance is defined
     **only** along these edges.
   - The **reference graph** (capability edges, socket peers, epoll watches, SCM_RIGHTS
     in-flight fds, service endpoints) is a **general directed graph that *will* have
     cycles**. Security is **not** inherited along these edges.
   Collapsing them ("security inherited downward through *the* hierarchy") is an
   architectural weakness: it's only sound on ownership edges. **The ORG must track
   edge *kind* and apply different rules per kind.**

3. **Pure reference counting leaks cycles — and anonymOS already has the canonical
   one.** `LocalSocket.passedFiles[]` queues full `File` copies passed via
   `SCM_RIGHTS` (`sendmsg`, posix.d ~3471). A unix socket can hold a `File` that
   references another unix socket that holds a `File` referencing the first; if both
   processes close their direct fds, the pair is **unreachable but refcount-pinned** —
   exactly the Linux `net/unix/garbage.c` problem, *already reproducible in this
   codebase*. The existing `refCount` fields (socket/pipe/memfd) **cannot** collect it.
   ORG must include a **tracing collector** for this case, not just refcounting.

---

## Where cycles can occur in anonymOS today (exact code)

| Edge | Source (file/struct) | Cycle? | Required rule |
|---|---|---|---|
| Socket ⇄ peer | `posix.d` `LocalSocket.peerId` (`socketpair`/`connect`) | **2-cycle** (each peers the other) | peer edge is **weak**; break on close (already half-done via `peerClosed`/`refCount`). |
| Socket → in-flight fd | `posix.d` `LocalSocket.passedFiles[]` (SCM_RIGHTS, ~3471) | **Arbitrary cycles**, unreachable | **strong but GC-tracked**; needs tracing collector (Linux-style in-flight GC). |
| epoll → watched fd | `posix.d` `EpollWatch.watchFd`, `EpollInst` | **Cycle if epoll watches epoll** | weak observer edge + **nesting-depth bound** (Linux caps at 5). |
| Task → child / child → parent | `kernel_main.d` `Task.childExited[]` (down), `parentId` (up) | up-edge would pin parent | parent back-edge is **weak**; owner edge is the launcher. |
| fd → backend | `posix.d` `File.backend`/`File.objId` | tree-ish; cycle only via the above | **strong owning** edge fd→object (refcounted). |
| Directory → child | `posix.d` `RtNode.parent` (`..` computed, not stored) | **No cycle today** (proper tree) | keep single-parent invariant; future binds/hardlinks must use weak/second-class edges. |
| Mapping → backing (Vmo) | `task.d` `AddrRegion.physBase`, `MemFdRec` aliasing | shared backing, no cycle | strong ref to Vmo; Vmo never refs mappings (back-edges weak). |
| Capability → object / derived caps | future `core/cap.d` | derive chain is a DAG; cap→obj→cap could cycle | cap→object **strong**; object→cap **must not** create ownership cycles. |
| Service A ⇄ Service B endpoints | future service mgr | **cycle** (mutual clients) | endpoint edges **weak/capability**, never ownership. |

**Objects that must NEVER participate in a cycle (fail-stop if they do):** the
object-tree **root**; the **Object Manager / Capability Manager** roots; any object on
the **ownership** spanning tree (ownership must stay acyclic); **capability
definitions**, **security policy** and **immutable** objects; a **Process's ownership**
of its Threads/MemRegions/Namespace.

**Cycles acceptable *iff* a weak reference breaks them:** socket peers; epoll/observer
watches; parent back-pointers; namespace binds that re-reference an already-owned
object; caches; service mutual-client endpoints; Linux `..`/symlink-like views.

---

## Formal models (the spec the phases implement)

**Object graph invariants (validator enforces these):**
- **I1 Single owner:** every non-root object has exactly one **strong ownership**
  in-edge. (Ownership = forest.)
- **I2 Ownership acyclic:** the ownership subgraph has no cycle (DFS/Tarjan over
  strong-owner edges yields no SCC of size > 1).
- **I3 Root reachable:** every live object is reachable from a root via strong edges;
  unreachable strong-SCCs are garbage (collect) — *not* leaks.
- **I4 No dangling strong edges:** a strong edge's target is live and its refcount ≥
  number of strong in-edges.
- **I5 Rights monotonicity:** for any capability/ownership edge p→c,
  `rights(c) ⊆ rights(p)` and `label(c) ⊑ label(p)` (security never increases
  downward).
- **I6 Edge-kind typing:** every edge is tagged {StrongOwn, StrongRef, Weak, Cap,
  Observer}; inheritance rules apply only to StrongOwn/Cap.
- **I7 Revocation closure:** revoking a capability invalidates all caps derived from it
  (transitive closure over derive-edges).
- **I8 Weak coherence:** a weak edge to a dead object reads as null, never as a stale
  live pointer.

**Ownership model:** exactly one **owner capability** per object (`ObjHeader.ownerCap`).
Ownership forms the tree that *is* the primary namespace. Destroying an owner destroys
(or orphans to a reaper) its owned subtree. All other relationships are non-owning
(StrongRef counted, or Weak).

**Capability propagation model:** a parent may `derive(cap, subsetRights)` → child;
`rights` is a lattice meet (can only narrow); derivation builds a **derive-DAG**;
`revoke(cap)` walks the derive-DAG forward and kills descendants (I7). Delegation over
IPC (SCM_RIGHTS today) creates a derive-edge in the receiver's cap table, never a raw
pointer.

**Security inheritance model:** labels propagate **down ownership edges only**;
`label(child) ⊑ label(parent)` (MAC lattice). Reference/observer edges carry **no**
label authority — an object you can *see* via a weak edge grants you nothing. This is
the fix for framing-weakness #2.

**Corruption recovery:** the validator is **fail-stop on ownership invariants** (I1,
I2, I4 violation ⇒ quarantine the offending SCC, refuse new edges into it, raise a
security event) and **self-healing on reference invariants** (I3/I8: run mark-sweep,
collect unreachable SCCs, null dead weak edges). Recovery uses a **shadow refcount
rebuild**: mark from roots, compare to stored refcounts, repair or quarantine
discrepancies. Never "best-effort continue" on an ownership-tree break.

**Scaling to millions:** **never stop-the-world global Tarjan.** (a) Edges are
**region/owner-local**; validate per-subtree with **epoch/generation** stamps — only
re-validate subtrees whose edges changed. (b) Cycle detection runs **incrementally**
at edge-insert time on the *affected* component only (online cycle detection /
bounded-search), not over the whole graph. (c) The tracing GC for in-flight cycles is
**generational + incremental** (young objects scanned often, old rarely), bounded per
tick. (d) The full audit (Tarjan SCC) is a **background, interruptible** sweep with a
work budget, not on the syscall hot path.

**Evolution to distributed OS:** an object ref becomes `{nodeId, objId, epoch}`.
**Cross-node edges are always weak + leased** (a lease that must be renewed; expiry =
edge death) — this sidesteps distributed strong-cycle GC, which is undecidable to do
cheaply. Local strong ownership stays node-local. Distributed reachability uses
**reference-listing** (each node knows who holds leases to its objects); distributed
cycle detection is **back-pressure + per-node SCC + distributed termination
detection**, run lazily. The object tree federates: each node's root mounts under a
global namespace via weak, capability-gated edges.

---

## Dependency graph & critical path

```
P1(arch) ─▶ P2(structs) ─▶ P3(tree integ.) ─▶ P4(ORG core) ─┬▶ P5(cycle) ─▶ P6(coherence/GC)
                                                            ├▶ P7(security)  │
                                                            │                ▼
                                                            └──────────────▶ P8(validator) ─▶ P9(viz)
P3 ─▶ P10(linux) ; P4 ─▶ P11(distributed) ; all ─▶ P12(test)
```
**Critical path:** `P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8 → P12`. P6 (GC for unreachable
strong cycles) is the real bottleneck and the highest-risk code (a bug there is a
use-after-free); it cannot be skipped, because refcounting alone leaks the SCM_RIGHTS
cycle that **already exists** in `posix.d`.

## Milestones
## Hard truths / recommended improvements
- **Don't build ORG before the Object Manager (`OBJECT_OS_ROADMAP.md` P2/P6).** This
  roadmap's P2/P3 *are* that integration; sequence accordingly.
- **Separate ownership (tree) from references (graph)** in the type system, or the
  "security inherited downward" goal is unsound on reference edges.
- **Refcounting is necessary but not sufficient.** Ship the tracing GC (P6) or accept
  leaks on the cycle that's already in the code.
- **Never run global Tarjan on the syscall path.** Online prevention for ownership;
  budgeted background sweep for everything else.
- **Make cross-node strong cycles impossible** (weak+leased only), rather than trying
  to GC them.

*Companion roadmaps in this folder:* `OBJECT_OS_ROADMAP.md` (the object/capability
substrate ORG graphs — its P2/P6 are ORG's prerequisites), `SECURITY_ROADMAP.md`
(capability/label/audit machinery ORG validates — shares `core/audit.d` and the cap
manager), and `IMMUTABLE_ROOTLESS_ROADMAP.md` (immutable/signed objects ORG must treat
as never-mutate, never-cycle roots).
