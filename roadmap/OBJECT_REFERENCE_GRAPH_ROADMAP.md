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

## PHASE 1 — Architecture  ✅ DONE

> **Status: ratified spec written → [`ORG_ARCHITECTURE.md`](ORG_ARCHITECTURE.md).**
> A design/docs phase (no code). The spec (a) ratifies the edge taxonomy
> {StrongOwn, StrongRef, Weak, Cap, Observer} with per-kind life/security/cycle
> rules and **classifies all 20 concrete edges in the current tree** (E1–E20 —
> a superset of this roadmap's 9-row table, extended to the objects added by
> Object-OS Phases 7–12); (b) reduces the ownership / capability-propagation /
> security-inheritance / corruption-recovery models to **checkable predicates**
> I1–I8, each with its enforcement point and current status; (c) maps the threat
> model **T1–T10** (cycle-leak DoS, epoll watch-bomb, label-escalation via ref
> edges, stale revocation, validator-as-oracle, …) to invariant(s) + mitigating
> phase + current status, verifying no threat is unassigned.
>
> **Key framing correction the spec records:** this roadmap's opening premise
> ("there is no Object Manager to graph yet") is now **outdated** — Object-OS
> Phases 2–13 are implemented, so `ObjHeader{…ownerCap,mark}`, `Capability`, and
> per-family `objId`s already exist. ORG-P2 therefore extends a *real* object
> header; the remaining gaps the spec pins down are: edges are still untyped
> subsystem fields (no `edgeAdd` chokepoint, **I6**), the `SCM_RIGHTS` in-flight
> cycle is still uncollectable (**T1/I3**), epoll nesting is unbounded (**T3**),
> and revocation cascades only one level (**T6/I7**). Distributed specifics
> deferred to P11 per the risk note.

*Why:* lock the two-graph model, edge kinds, and invariants before code, so later
phases don't bake in the ownership/reference conflation. *Affected:* docs; design of
`core/object.d` (OO roadmap). *Risks:* over-design; mitigate by deferring distributed
specifics to Phase 11. *Refactoring:* none. *Performance:* n/a.

- **1.1** — P: Critical · Subsystem: design · Deps: `OBJECT_OS_ROADMAP.md` P2 ·
  Complexity: Medium · *Desc:* ratify edge taxonomy {StrongOwn, StrongRef, Weak, Cap,
  Observer} and invariants I1–I8. *Accept:* written spec; each existing edge in the
  table above classified.
- **1.2** — P: Critical · design · Deps: 1.1 · Complexity: Medium · *Desc:* formal
  ownership / capability-propagation / security-inheritance models (above). *Accept:*
  models reviewed; reduce to checkable predicates.
- **1.3** — P: High · design · Deps: 1.1 · Complexity: Low · *Desc:* ORG threat model:
  cycle-leak DoS, label-escalation via ref edges, validator-as-oracle. *Accept:* each
  threat maps to an invariant/phase.

## PHASE 2 — Kernel Data Structures  ✅ DONE

> **Status: implemented as a typed edge graph keyed by the object table.** New
> module `core/org.d` provides the `EdgeKind` taxonomy {StrongOwn, StrongRef, Cap,
> Weak, Observer}, a pooled intrusive out-edge list per object
> (`OrgEdge{kind,fromId,toId,rights,toGen,next}` + `OrgNode{outHead,strongIn,
> strongOut,owner,gen}` keyed by `objId`), and the three deliverables:
> **2.1** per-object adjacency enumerable in O(deg) (`orgOutDegree`/`orgStrongIn`/
> `orgStrongOut`/`orgOwner`/`orgHasEdge`) with `ObjHeader.ownerCap` wired by
> StrongOwn edges; **2.2** `edgeAdd`/`edgeRemove` as the sole relationship
> mutators, maintaining strong in/out counts + a global epoch; **2.3** weak
> references — Weak/Observer edges don't count toward life, and `weakGet` returns
> null when the target is dead or its slot was reused (per-slot `gen` snapshot).
>
> **Free-notify hook:** `objmgr.d` gained a `g_objFreeNotify` function pointer
> (null until `org.d` sets it at `orgInit`, avoiding an import cycle) that
> `objRelease` calls on every slot free; `orgOnFree` drops the object's out-edges,
> releases the strong-in counts they held, and bumps the slot generation so all
> weak in-edges go stale. The adjacency is a side table keyed by `objId` (not
> embedded in the hot 8192-entry `ObjHeader`), the same choice used for the
> device/window/namespace registries.
>
> **Scope:** this builds and proves the *mechanism*; rewiring the existing
> subsystems (E1–E20 in `ORG_ARCHITECTURE.md`) to create their edges through
> `edgeAdd`/`edgeRemove` — and thereby making the legacy `refCount` fields derived
> from strong-in counts — is **Phase 3**.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot — in which the free-notify hook now fires
> on *every* object free during the per-256-syscall reconcile churn — reached
> Hyprland/Mesa compositor rendering with no kernel fault, panic, JHC falloff, or
> OOM. The one-shot self-test logged `[org] selftest PASS`: a 3-node graph shows
> correct out-degree and strong in/out counts (the weak edge excluded from life),
> owner wiring, and — the 2.3 acceptance — dropping a target's last strong ref
> frees it despite a weak in-edge, after which `weakGet` reads null. `orgStats()`
> prints edges/adds/removes/freedrops/weaknull/epoch alongside the other subsystems.

*Why:* make edges **explicit, typed, and enumerable** (today they're scattered ints).
*Affected:* `core/object.d` (new), `task.d`, `posix.d`. *Risks:* memory overhead per
object; double-bookkeeping vs legacy arrays. *Refactoring:* add edge lists to the
object header. *Performance:* +1 indirection on edge ops; keep edge lists intrusive.

- **2.1** — P: Critical · object mgr · Deps: P1, OO-P2 · Complexity: High · *Desc:*
  `ObjHeader` gains `ownerCap`, `strongIn`/`strongOut` counts, and an **adjacency
  representation** (intrusive edge nodes: `{toId, kind, rights}`). *Accept:* every
  object enumerates its out-edges in O(deg).
- **2.2** — P: Critical · object mgr · Deps: 2.1 · Complexity: Medium · *Desc:*
  `edgeAdd(from,to,kind,rights)` / `edgeRemove` as the **only** way to relate objects;
  maintain refcounts + epoch stamps. *Accept:* no subsystem mutates relationships
  except through these.
- **2.3** — P: High · object mgr · Deps: 2.1 · Complexity: Medium · *Desc:* **weak
  reference** support: weak edges don't count toward life; reads via `weakGet` return
  null if target dead/epoch-stale. *Accept:* dropping the last strong ref frees the
  object even with weak in-edges; `weakGet` then null.

## PHASE 3 — Object Tree Integration  ✅ DONE

> **Status: the legacy tables are now mirrored into one typed object graph,
> driven from the amortized reconcile passes** (idempotent `edgeEnsure` + dead-edge
> `orgPruneDeadOut`, not per-syscall hooks — the same low-risk adoption strategy
> the object identity used). New `org.d` helpers: `edgeEnsure`, `orgPruneDeadOut`,
> a `strongOwnIn` count for I1, and `orgAudit` (I1 single-owner + I4
> refcount ≥ strong-in).
>
> **3.1 ownership tree (`task.d:orgReconcileOwnership`):** Process →(StrongOwn)
> Thread / Namespace / MemRegion (E1/E3/E2), Process →(Weak) parent Process (E5),
> MemRegion →(StrongRef) Vmo (E8). Pruning each process's dead out-edges means
> killing a task tears its threads/regions/namespace out of the graph, and a
> parent's death never dangles a child (the back-edge is Weak).
> **3.2 fd/memory (`posix.d:orgReconcileFdEdges`):** fd handle →(Cap, rights)
> object (E6); the legacy `refCount` is shown *consistent with / derived from* the
> strong-in count by the **I4 audit holding** (`refCount ≥ strongIn`).
> **3.3 ipc/epoll:** epoll →(Observer, weak) watched fd (E11) modeled in the
> graph, plus a concrete **epoll nesting-depth bound** (≤5, returns `ELOOP`) added
> at `epoll_ctl` so a watch-of-watch bomb can't build unbounded nesting (threat
> T3). Observer/Weak edges are excluded from the life count, so these never pin.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot reached Hyprland/Mesa compositor rendering
> (Hyprland is a heavy epoll/fd user — the nesting bound and per-256-syscall edge
> reconcile caused no regression) with no kernel fault, panic, JHC falloff, or OOM.
> The one-shot proof logged `[org] integ PASS edges=0x5b I1ok I4ok` — the reconcile
> built a **91-edge** graph from the live process/memory/fd relationships and the
> invariant audit confirms single-owner (I1) and refcount ≥ strong-in (I4) both
> hold over it. `orgStats()` adds ensure/prune/audit/i1v/i4v counters.
>
> **Deferred (mechanism ready, wiring follows where it pays off):** the
> `LocalSocket.peerId` Weak edge and the `SCM_RIGHTS passedFiles[]`
> **StrongRef-GC-tracked** edges (E9/E10) — the peer's object id isn't resolvable
> from the socket struct cross-process, and the SCM in-flight cycle only becomes
> *collectable* once the tracing GC exists, so modeling it as StrongRef is
> sequenced with **P5.3/P6** (wiring it now would mirror a pin nothing yet
> collects). The `RtNode.parent` directory tree (E12) and per-region Vmo back-edge
> pruning are likewise left for the cycle/GC phases. The `EdgeKind` machinery
> needed for all of them exists.

*Why:* connect the disjoint legacy tables into one ownership tree so there *is* a graph
to validate. *Affected:* `task.d` (`Task`→Threads/MemRegions), `posix.d` (`File`→backend,
`g_fdTabs` as cap edges, `g_rt` directory tree), drivers. *Risks:* this touches every
subsystem; sequence behind OO roadmap P3–P5. *Refactoring:* replace implicit indices
with typed edges. *Performance:* create/destroy paths gain edge ops.

- **3.1** — P: Critical · process/mem · Deps: 2.2, OO-P3/P4 · Complexity: High ·
  *Desc:* model `Task`→Thread, `Task`→MemRegion, `Task`→Namespace, `Task`→CapTable as
  **StrongOwn** edges; `Task.parentId` as **Weak**. *Accept:* killing a Task tears down
  its owned subtree; parent death doesn't dangle children.
- **3.2** — P: Critical · fs/fd · Deps: 2.2 · Complexity: High · *Desc:* `fd`→object as
  **Cap** edge (rights), `File.backend`→{socket/pipe/memfd/...} as **StrongRef**;
  `RtNode.parent` as the single-parent **StrongOwn** tree (preserve "no stored `..`").
  *Accept:* the legacy `refCount` fields are *derived from* strong in-edge counts.
- **3.3** — P: High · ipc · Deps: 2.3 · Complexity: Medium · *Desc:* `LocalSocket.peerId`
  → **Weak** peer edge; `EpollWatch.watchFd` → **Observer (weak)** edge w/ nesting
  bound; `passedFiles[]` (SCM_RIGHTS) → **StrongRef, GC-tracked** edges. *Accept:* the
  socket-pair 2-cycle and epoll-on-epoll no longer pin memory.

## PHASE 4 — Object Reference Graph (core API)  ✅ DONE

> **Status: the queryable graph API the validator/GC/tools run on is in
> `core/org.d`, all allocation-free.**
> **4.1 query/iterate:** `orgEpoch`, `orgNextLiveNode` (node iteration), an
> allocation-free out-edge cursor (`orgFirstOutEdge`/`orgNextEdge` +
> `orgEdgeTarget`/`orgEdgeKind`/`orgEdgeRights`), `orgOutDegreeKind` (kind-filtered
> degree), `orgInDegree` and `orgCountKind` (O(E) scans, off the hot path).
> **4.2 reachability:** a budgeted, **resumable** mark-from-roots over *strong*
> edges — `orgAddRoot`/`orgClearRoots`, `orgReachBegin`, `orgReachStep(budget)`
> (returns "work remains", driven by an on-stack worklist, no heap), `orgReachable`
> /`orgReachableCount`. Roots are the externally-anchored set (the scheduler's
> process-leader objects, registered by `task.d:orgReconcileRoots`); anything not
> marked after a full pass is unreachable over strong edges ⇒ the GC candidate set
> (I3) that P6 collects. **4.3 namespace validation:** `nsValidateBindings` flags
> every bound name whose target object is no longer live — dangling = flagged,
> never a crash.
>
> **Live integration:** the periodic stats pass registers the live roots and runs
> a 256-node-budget reachability over the real graph; `nsStats` reports dangling
> bindings; `orgStats` reports `roots`/`reach`.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot reached Hyprland/Mesa compositor rendering
> with no kernel fault, panic, JHC falloff, or OOM. The one-shot self-test logged
> `[org] api PASS`: 4.1 — out-degree/kind-filter/target/rights/in-degree/
> count-by-kind/node-iteration all correct; 4.2 — a budgeted (1-node-slice)
> reachability from a root marks its StrongOwn/StrongRef descendants
> (`reachableCount == 3`) and excludes a disconnected node; 4.3 — a namespace
> binding whose target is then freed is reported dangling (not a crash). `[org]
> selftest PASS` (P2) and `[org] integ PASS` (P3) continue to hold.
>
> **Note:** in-degree/kind-count are O(E) scans (no reverse adjacency) used only by
> the budgeted background validator, never on the syscall path — consistent with
> the roadmap's "traversals must be budgeted/incremental."

*Why:* the queryable graph the validator/GC/tools run on. *Affected:* new
`core/org.d`. *Risks:* becoming a global mutable hotspot. *Refactoring:* none beyond
P2/3. *Performance:* traversals must be budgeted/incremental.

- **4.1** — P: Critical · org · Deps: P2/3 · Complexity: Medium · *Desc:* `org.d`:
  iterate nodes/edges, in/out-degree, edge-kind filters, epoch queries. *Accept:* O(V+E)
  traversal with kind filtering; no allocation on the hot path.
- **4.2** — P: High · org · Deps: 4.1 · Complexity: Medium · *Desc:* **reachability**
  (mark from roots over strong edges), with a **work budget** + resumable cursor.
  *Accept:* `reachable(root)` set computable incrementally without stop-the-world.
- **4.3** — P: Medium · org · Deps: 4.1 · Complexity: Low · *Desc:* **namespace
  validation**: every name in a Namespace resolves to a live object via a Cap edge.
  *Accept:* dangling name = flagged, not a crash.

## PHASE 5 — Cycle Detection  ✅ DONE

> **Status: online ownership-cycle prevention + background Tarjan SCC + GC-target
> classification/collection, all in `core/org.d`.**
> **5.1 (fail-closed at insert):** `edgeAdd(StrongOwn)` now rejects an edge that
> would give `to` a second owner (I1) or close an ownership cycle (I2) — the
> latter via `wouldFormOwnCycle`, a bounded DFS from `to` over StrongOwn edges
> (the ownership graph is a forest, so it never revisits; a budget overrun fails
> closed). No StrongOwn cycle can ever enter the graph.
> **5.2 (Tarjan SCC):** `orgTarjanRun` is an **iterative** (no recursion → no
> kernel-stack blowup) Tarjan over *strong* edges — O(V+E), each node stamped with
> its SCC representative, the run stamped with the graph epoch; the explicit DFS
> stack makes it drivable in budgeted slices by the P8 validator.
> **5.3 (classify + collect):** `orgSccIsGcTarget` flags a non-trivial SCC whose
> members are all unreachable from the registered roots (the SCM_RIGHTS in-flight
> case); `orgCollectScc` reclaims it (object-level release that breaks the cycle
> via the free-notify path). The live periodic pass runs Tarjan **read-only** (it
> reports SCC count but never auto-collects — the root set is process-leaders only
> for now, so auto-GC over the live graph waits for the complete root set in
> P6/P8); collection is exercised on a controlled cycle in the self-test.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot — now also running a background Tarjan SCC
> pass over the live graph — reached Hyprland/Mesa compositor rendering with no
> kernel fault, panic, JHC falloff, or OOM. The one-shot self-test logged
> `[org] cycle PASS`: 5.1 — an ownership cycle (`o1→o2→o3→o1`) and a second owner
> are both rejected at insert; 5.2 — a strong-ref 2-cycle `x↔y` is found by Tarjan
> as a single SCC distinct from the root's; 5.3 — that SCC is classified as an
> unreachable GC target and `orgCollectScc` reclaims both objects. `[org]
> selftest/integ/api PASS` (P2–P4) continue to hold. `orgStats` adds
> `scc`/`ownrej`/`sccfreed`.
>
> **Boundary with P6:** 5.3 here is detection + classification + *object-level*
> reclaim of a controlled cycle; integrating the collector with the physical
> allocator (`mm.d:free_phys_page`), the legacy refcount lifecycle, and the live
> graph's complete root set — so the *real* SCM_RIGHTS cycle is reclaimed in
> production — is **P6.2**.

*Why:* enforce I2 (ownership acyclic) and find reference SCCs for GC. *Affected:*
`core/org.d`. *Risks:* global Tarjan latency. *Refactoring:* none. *Performance:* must
be incremental on insert + background full sweep.

- **5.1** — P: Critical · org · Deps: 4.1 · Complexity: Medium · *Desc:* **online
  ownership-cycle prevention** — `edgeAdd(StrongOwn)` runs a bounded DFS in the
  affected component and **rejects** an edge that would close an ownership cycle (I2).
  *Accept:* no StrongOwn cycle can ever be created (fail-closed at insert).
- **5.2** — P: High · org · Deps: 4.1 · Complexity: High · *Desc:* **Tarjan SCC** over
  the full reference graph as a **background, interruptible** job with a per-tick work
  budget; report SCCs. *Accept:* SCCs found in O(V+E); job yields under budget; results
  stamped with epoch.
- **5.3** — P: High · org/gc · Deps: 5.2, 2.3 · Complexity: High · *Desc:* classify
  each SCC: contains only Weak/Observer in-edges from outside ⇒ collectible; reachable
  from a root via strong edges ⇒ live; otherwise unreachable strong-SCC ⇒ **GC target**
  (the SCM_RIGHTS case). *Accept:* the in-flight socket cycle is detected and reclaimed.

## PHASE 6 — Coherence Validation  ✅ DONE

> **Status: invariant checker + quarantine, mark-sweep GC integrated with the
> allocator, and shadow-refcount rebuild — all in `core/org.d`.** This is the
> roadmap's flagged highest-risk phase (a GC bug = UAF), so it is built
> **safety-first**: production runs only the operations that cannot free a live
> object, and the dangerous collect path is proven on controlled cycles.
> **6.1 invariant checker + quarantine:** `orgValidateInvariants(enforce)` checks
> I1 (single owner) and I4 (refcount ≥ strong-in); a breach is **never silent** —
> in enforcing mode `orgQuarantine` flags the object (raising a `[org] SECURITY`
> event), and `edgeAdd` then refuses every edge in/out of it (fail-stop
> containment). The live periodic pass runs it in **report mode** (counting only),
> since quarantining a transiently-skewed live object would itself be a DoS.
> **6.2 mark-sweep GC:** `orgGcStep` nulls dead Weak/Observer edges (I8 — can never
> cause a UAF) on a resumable cursor and refreshes the unreachable-strong **GC
> candidate** count (I3), generational (`age`) + incremental + bounded. The
> **complete root set** is the key safety prerequisite: `orgAddAnchorRoots`
> registers every registry-anchored object (Device/Driver/User/Service/Namespace/
> Endpoint/Window/Vmo/Directory/Linux* …) as a reachability root alongside the
> process leaders, so production has **zero false GC candidates**. The full collect
> path — `orgCollectScc` freeing the SCC's objects **and returning their physical
> pages via `mm.d:free_phys_page`** — is exercised on a constructed cycle, not run
> against live objects.
> **6.3 shadow-refcount rebuild:** `orgShadowRebuild` recomputes every strong-in
> count from a full O(E) edge scan, repairs drift, and quarantines any object whose
> object-manager refcount can't support the recomputed count.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot — now also running the production GC step
> (dead-weak null + candidate count) and report-mode invariant check over the live
> graph with the complete root set — reached Hyprland/Mesa compositor rendering
> with no kernel fault, panic, JHC falloff, OOM, **or any production quarantine**
> (the only `[org] SECURITY` line is the self-test's deliberate one). The one-shot
> self-test logged `[org] gc PASS`: 6.1 an I4 violation is detected and the object
> quarantined + edges refused; 6.2 an unreachable page-backed strong cycle is
> reclaimed (objects freed *and* the page returned to the allocator) and a dead
> weak edge nulled; 6.3 a corrupted strong-in count is detected and repaired.
> `[org] selftest/integ/api/cycle PASS` (P2–P5) all still hold. `orgStats` adds
> `gccand`/`weaknull`/`pagesrec`/`quar`/`secev`.
>
> **Boundary / deferred:** production **auto-collection** of unreachable strong-SCCs
> (vs. the current detect-and-count) is intentionally gated until the P8 validator
> daemon provides budgeted confidence — turning it on now, against any single gap
> in the edge model, would free a live object in a running desktop. Wiring the live
> socket `SCM_RIGHTS` edges (E10, deferred in P3) so production traffic builds real
> reclaimable cycles is likewise unblocked by this GC but sequenced with P10.

*Why:* enforce I1/I3/I4/I8 — the graph never enters an invalid state. *Affected:*
`core/org.d`, allocator (`mm.d`), every create/destroy path. *Risks:* false positives
halting good work. *Refactoring:* hook destroy paths. *Performance:* shadow-refcount
rebuild is O(V+E) — background only.

- **6.1** — P: Critical · org · Deps: P5 · Complexity: Medium · *Desc:* invariant
  checker for I1 (single owner), I4 (no dangling strong / refcount ≥ strong-in). *Accept:*
  any violation raises a security event + quarantines the SCC; never silent.
- **6.2** — P: High · gc · Deps: 5.3, 2.3 · Complexity: High · *Desc:* **mark-sweep GC**
  for unreachable strong-SCCs + dead-weak nulling (I3/I8), generational + incremental,
  bounded per tick; integrates with `mm.d` `free_phys_page` for reclaim. *Accept:* the
  SCM_RIGHTS cycle and orphaned subgraphs are reclaimed; live objects never collected.
- **6.3** — P: High · org · Deps: 6.1 · Complexity: Medium · *Desc:* **shadow-refcount
  rebuild** recovery: mark from roots, diff against stored counts, repair or quarantine.
  *Accept:* an injected refcount corruption is detected and repaired/quarantined.

## PHASE 7 — Security Validation  ✅ DONE

> **Status: I5/I6/I7 enforced — labels and capabilities cannot escalate.**
> Since no MAC label system exists yet, a minimal lattice is introduced on the ORG
> node: a `label` (MAC level, `⊑` = `≤`) and `heldRights` (the authority an object
> may grant downward), both defaulting permissive (`label 0`, `heldRights = all`)
> so existing edges are unaffected until a policy constrains an object.
> **7.1 (I5 at insert):** `edgeAdd(StrongOwn|Cap)` now rejects an edge whose child
> label exceeds the parent's (`label(c) ⊑ label(p)`) or whose granted `rights`
> exceed `heldRights(parent)` — O(1) per edge. Weak/Observer edges are exempt
> (**I6**: reference/observer edges carry no authority).
> **7.2 (I7 revocation closure):** `core/cap.d`'s `capRevoke`/new `capRevokeIn`
> now iterate the forward derive-DAG to a **fixpoint**, so revoking a parent
> capability renders *all* transitively-derived caps (child, grandchild, …)
> unusable — not just the direct children.
> **7.3 (inheritance audit):** `orgLabelAudit` walks **ownership edges only** and
> reports any `label(child) > label(parent)` inversion (post-hoc relabelings the
> insert check can't catch); reference edges are never walked, so they grant
> nothing by construction. Runs in report mode in the live periodic pass.
>
> **Proof:** `make -C src/kernel/d`, `make -B kernel.elf`, and `make hos.iso`
> complete. A headless QEMU smoke boot — now running the edge-add label/rights
> checks and the label audit over the live graph (permissive defaults ⇒ no
> production rejections) — reached Hyprland/Mesa compositor rendering with no
> kernel fault, panic, JHC falloff, or OOM. Two one-shot self-tests logged
> `[org] sec PASS` (a child label *or* right exceeding the parent's is rejected at
> insert; a Weak edge to a high-label object is allowed since it grants nothing;
> a post-hoc ownership label inversion is flagged by the audit) and
> `[cap] revclosure PASS` (on a scratch cap table, revoking a root cap renders a
> derived child *and grandchild* unusable). All P2–P6 proofs still hold. `orgStats`
> adds `lblrej`/`rgtrej`/`lblviol`.
>
> **Note:** the rights subset for capability *delegation* (`capDerive`,
> `SCM_RIGHTS` via `ipcAcceptCap`) was already enforced from OO-P6/Phase-7-IPC; ORG
> P7.1 adds the same guarantee at the graph-edge layer plus the label dimension. A
> full MAC label lattice with compartments (vs. the integer level used here) is
> `SECURITY_ROADMAP.md`/`core/mac.d` work that slots into these same hooks.

*Why:* enforce I5/I6/I7 — labels and capabilities never escalate. *Affected:*
`core/cap.d`, `core/mac.d` (security roadmap), `core/org.d`. *Risks:* perf on every
delegate. *Refactoring:* validate at edge-add. *Performance:* O(1) per edge (lattice
meet); revocation is O(derive-subtree).

- **7.1** — P: Critical · cap/mac · Deps: P2, cap mgr · Complexity: Medium · *Desc:*
  `edgeAdd(Cap|StrongOwn)` checks I5 (`rights(c)⊆rights(p)`, `label(c)⊑label(p)`) and
  rejects escalation. *Accept:* no edge can grant a child more rights/label than parent.
- **7.2** — P: Critical · cap · Deps: 7.1 · Complexity: Medium · *Desc:* **revocation
  closure** (I7): `revoke(cap)` walks derive-edges and kills descendants. *Accept:*
  revoking a parent cap renders all derived caps unusable.
- **7.3** — P: High · mac · Deps: 7.1 · Complexity: Medium · *Desc:* **security
  inheritance audit** — verify labels are monotone along *ownership only*, and that no
  authority flows along Weak/Observer edges. *Accept:* a label violation anywhere in
  the ownership forest is reported; ref edges grant nothing.

## PHASE 8 — Runtime Validator Daemon
*Why:* continuous, budgeted validation without blocking syscalls. *Affected:* new
`core/org_validator.d` (kernel task) + a userspace control object. *Risks:* the
validator becomes an oracle/DoS lever; gate it behind a capability. *Refactoring:*
schedule as a low-priority kernel thread. *Performance:* runs in idle/work-budgeted
slices; must never stall the scheduler.

- **8.1** — P: High · validator · Deps: P5/6/7 · Complexity: High · *Desc:* a kernel
  daemon that cycles {incremental reachability → SCC sweep → invariant check → GC},
  each bounded, epoch-driven (only changed subtrees). *Accept:* steady-state CPU under
  a configured budget; detects an injected violation within N ticks.
- **8.2** — P: Medium · validator · Deps: 8.1 · Complexity: Medium · *Desc:* **audit
  log** of graph events (cycle found, SCC collected, invariant breach, revocation) →
  `core/audit.d` (security roadmap). *Accept:* every validator action is attributable.
- **8.3** — P: Medium · validator · Deps: 8.1, cap mgr · Complexity: Low · *Desc:*
  control surface (query/trigger/quarantine) reachable **only** with a validator
  capability. *Accept:* unprivileged callers cannot drive the validator.

## PHASE 9 — Debugging and Visualization
*Why:* an object graph is unauditable without tooling. *Affected:* `core/org.d`
exporter; a userspace tool. *Risks:* exporting the graph leaks topology (gate by cap).
*Refactoring:* none. *Performance:* export is a budgeted background dump.

- **9.1** — P: Medium · org · Deps: 4.1 · Complexity: Low · *Desc:* serialize the graph
  to a stable format (DOT/JSON: nodes={id,type,label}, edges={kind,rights}). *Accept:*
  a snapshot renders in Graphviz; weak vs strong distinguishable.
- **9.2** — P: Medium · tooling · Deps: 9.1 · Complexity: Medium · *Desc:* userspace
  `orgctl`: dump, highlight SCCs, show reachability/ownership tree, diff snapshots.
  *Accept:* can visualize a deliberately-constructed cycle and its collection.
- **9.3** — P: Low · validator · Deps: 8.1 · Complexity: Low · *Desc:* live counters
  (objects, edges by kind, SCCs, GC reclaimed, validator budget). *Accept:* exported
  via the synthetic fs (`/proc`-style) gated by cap.

## PHASE 10 — Linux Compatibility Layer Integration
*Why:* the Linux layer is a prolific edge creator (fds, SCM_RIGHTS, epoll, fork trees)
and must not bypass ORG. *Affected:* `posix.d`, `kernel_main.d` dispatch,
`LinuxObject` subtree (OO-P12). *Risks:* exact Linux semantics vs ORG rules (e.g.
Linux *allows* the SCM_RIGHTS cycle and GCs it — ORG must match, not forbid). *Refactoring:*
route Linux fd/socket/epoll ops through `edgeAdd`/`edgeRemove`. *Performance:* edge ops
on hot syscalls — keep O(1).

- **10.1** — P: High · linux/fd · Deps: P3, OO-P12 · Complexity: High · *Desc:* make
  `open`/`dup`/`socketpair`/`sendmsg(SCM_RIGHTS)`/`epoll_ctl`/`fork` create/destroy ORG
  edges instead of touching legacy indices directly. *Accept:* a Linux program that
  builds the SCM_RIGHTS cycle is collected by ORG GC, matching Linux behavior.
- **10.2** — P: Medium · linux · Deps: 10.1 · Complexity: Medium · *Desc:* enforce
  epoll **nesting-depth bound** + cap-gate `/dev`, `/proc` object edges. *Accept:*
  unbounded epoll nesting and ambient device edges are rejected.
- **10.3** — P: Medium · linux · Deps: 10.1, P7 · Complexity: Medium · *Desc:* Linux
  pid/uid views derive from Process/User objects + caps; no ambient authority edge.
  *Accept:* a sandboxed Linux process holds only edges to its delegated objects.

## PHASE 11 — Distributed Object Graph Preparation
*Why:* the stated end goal; design the seams now so they're cheap later. *Affected:*
`core/org.d` ref type, `network/`. *Risks:* distributed strong-cycle GC is intractable
— **forbid** cross-node strong cycles by construction. *Refactoring:* widen object ref
to `{nodeId,objId,epoch}`. *Performance:* cross-node ops are message-bound; keep local
ORG unchanged.

- **11.1** — P: Low · org · Deps: P4 · Complexity: Medium · *Desc:* object refs become
  `{nodeId,objId,epoch}`; local ops unchanged when `nodeId==self`. *Accept:* local
  performance unregressed; remote refs representable.
- **11.2** — P: Low · org/net · Deps: 11.1, 2.3 · Complexity: High · *Desc:* cross-node
  edges are **Weak + leased** only; lease expiry = edge death (reference-listing GC).
  *Accept:* a dropped/partitioned peer's remote edges expire and are nulled.
- **11.3** — P: Low · org · Deps: 11.2 · Complexity: Extreme · *Desc:* lazy distributed
  cycle detection (per-node SCC + back-pressure + termination detection) for diagnostics
  only; **no** cross-node strong cycles allowed. *Accept:* a synthetic cross-node weak
  cycle is reported but never leaks (leases reclaim it).

## PHASE 12 — Testing and Verification
*Why:* a graph invariant is worthless unproven; this subsystem is safety-critical
(GC bugs = UAF; validator bugs = false halts). *Affected:* test harness, fault
injection. *Risks:* under-testing the GC/recovery paths. *Refactoring:* add a
deterministic graph-fuzzer. *Performance:* measure validator/GC budgets under load.

- **12.1** — P: Critical · test · Deps: P5/6/7 · Complexity: Medium · *Desc:* unit tests
  per invariant I1–I8 incl. **the SCM_RIGHTS cycle**, socket-pair 2-cycle, epoll nesting,
  parent/child weak. *Accept:* each invariant has a passing positive + failing-injection
  test.
- **12.2** — P: High · test · Deps: 6.2/6.3 · Complexity: High · *Desc:* GC/recovery
  fault injection: corrupt refcounts, sever edges mid-sweep, allocate-under-GC; assert
  no live object freed, no leak. *Accept:* fuzzer runs N iterations with zero UAF/leak.
- **12.3** — P: High · test/perf · Deps: P8 · Complexity: Medium · *Desc:* scale test to
  ≥10⁶ synthetic objects; measure incremental validate/GC budgets and worst-case pause.
  *Accept:* no stop-the-world pause exceeds the configured budget; throughput documented.

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
- **ORG-MVP:** ✅ **Reached** (P2 ✅ + P3 ✅ + P4 ✅ + P5.1 ✅) — every object
  relationship is a typed edge; ownership cycles are impossible by construction (online
  prevention). *Proven:* `[org] cycle PASS` shows `edgeAdd` rejects an ownership cycle;
  the graph is enumerable (`[org] api PASS`).
- **Coherent + safe:** ✅ **Reached** (P5.2/5.3 ✅ + P6 ✅ + P7 ✅) — unreachable strong
  cycles are detected/reclaimed; no rights/label escalation. *Proven:* a page-backed
  strong cycle is detected and reclaimed (objects + physical page) and a corrupted
  refcount repaired (`[org] gc PASS`); an escalation edge is rejected and revocation is
  transitive (`[org] sec PASS`, `[cap] revclosure PASS`); the complete root set gives 0
  false GC candidates in production. Remaining for full production GC: turning on
  auto-collection + live SCM edge wiring, gated on the P8 validator's confidence.
- **Operable:** +P8+P9+P12 — continuous budgeted validation, visualization, scale test
  to 10⁶. *Provable:* validator holds CPU budget and catches injected violations.

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
