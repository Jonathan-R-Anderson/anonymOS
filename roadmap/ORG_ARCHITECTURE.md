# ORG Phase 1 — Architecture (ratified spec)

> Deliverable of **Phase 1** of `OBJECT_REFERENCE_GRAPH_ROADMAP.md` (tasks 1.1–1.3).
> This is the *design* artifact the later ORG phases implement against: the edge
> taxonomy, the invariants reduced to checkable predicates, and the threat model.
> **Grounded in the current `src/kernel/d/` tree** as it stands *after* the Object-OS
> roadmap (Phases 2–13) — not the pre-object-manager codebase the ORG roadmap's
> framing assumed.

---

## 0. Framing correction — the substrate now exists

The ORG roadmap's "Critical framing" opens with *"There is no Object Manager to graph
yet … building ORG before the object header is premature."* **That precondition is now
satisfied.** `OBJECT_OS_ROADMAP.md` Phases 2–13 are implemented:

- **Object Manager** — `core/objmgr.d`: `ObjHeader{id,type,refCount,ownerCap,version_,
  mark,impl}`, central `g_objects[8192]`, `objAlloc/objGet/objRetain/objRelease`, a
  mark-sweep generation (`objBeginSweep/objMark/objSweepType`). (OO-P2/P3.)
- **Capabilities** — `core/cap.d`: `Capability{objId,rights,deriveParent,revoked}`,
  per-process `CapTable`, `capDerive`, `capRevoke` (with derive-child cascade),
  `requireCap`. (OO-P6.)
- **Typed object families** — File/Process/Thread/MemRegion/Vmo/Directory/Device/Driver/
  NetIf/Window/User/Service/Namespace/Endpoint/LinuxProcess(+VFS/Syscall/ELFLoader/
  DeviceAdapter) all carry `objId`s in the central table (OO-P3–P12).

**Consequence for ORG:** edges are *no longer* purely implicit integer indices. Most
endpoints already have a stable `objId`. ORG Phase 2 (`edgeAdd`/adjacency) now extends a
**real** `ObjHeader`, and ORG's ownership root can be a **real** object. The two fields
the ORG roadmap names as its hooks already exist as reserved stubs:
`ObjHeader.ownerCap` (the single owner-capability, currently `0`) and
`ObjHeader.mark` (the GC generation). What is still missing and what ORG P2+ adds: an
**explicit, typed, enumerable edge set** (today the edges are still read by walking
subsystem-specific fields), and **edge-kind tagging**.

This does **not** weaken the roadmap's three blunt truths — they still hold:
1. relationships are still scattered across subsystem fields (no `edgeAdd` chokepoint);
2. ownership and reference are still conflated (nothing tags an edge's kind);
3. the `SCM_RIGHTS` in-flight cycle is still refcount-pinnable and uncollectable.

---

## 1.1 — Edge taxonomy (ratified)

Five edge kinds. Two axes decide everything downstream: **does the edge keep the target
alive** (strong vs. weak), and **does authority/label flow across it** (only ownership
and capability edges carry authority).

| Kind | Keeps target alive? | Carries security (label/rights) down? | May lie on a cycle? | Meaning |
|---|---|---|---|---|
| **StrongOwn** | Yes (the *one* owner) | **Yes** | **Never** (I2 fail-closed) | sole ownership; defines the object *forest*. Destroying the owner destroys/orphans the subtree. |
| **StrongRef** | Yes (counted) | No | Yes (GC-tracked) | non-owning keep-alive (e.g. fd→backend, mapping→Vmo, in-flight SCM fd). |
| **Cap** | Yes (counted) | **Yes (rights only)** | DAG (derive); object→cap must not form ownership cycle | a capability handle → object, with a rights subset. |
| **Weak** | No | No | Yes (broken by nulling) | back-pointer / peer / cache; reads null when target dies (I8). |
| **Observer** | No | No | Yes (+ depth bound) | a watch (epoll); like Weak but additionally **depth-bounded** to stop watch-of-watch blowups. |

**Per-kind rules (the contract Phase 2's `edgeAdd` enforces):**
- *Life:* `refCount(target) ≥ #StrongOwn-in + #StrongRef-in + #Cap-in`. Weak/Observer do
  **not** count (I4, I8).
- *Security:* authority is checked/propagated **only** on StrongOwn and Cap (I5, I6).
  Weak/Observer/StrongRef grant **nothing** — "an object you can see is not an object
  you may use."
- *Cycles:* StrongOwn may never close a cycle (rejected at insert, I2). StrongRef/Cap
  cycles are legal but must be **reachable from a root** or they are GC garbage (I3).
  Weak/Observer cycles are always safe (a weak edge breaks them).
- *Single owner:* exactly one StrongOwn in-edge per non-root object (I1).

### Classification of every relationship in the current code

Each concrete edge in `src/kernel/d/` today, with its kind and the rule it must obey.
(File/line references are to the tree as of this writing.)

| # | Edge (from → to) | Current representation | **Kind** | Rule / notes |
|---|---|---|---|---|
| E1 | Process → Thread | `Task.processObjId` / `objEnsureProcess` ([task.d](../src/kernel/d/core/task.d)) | **StrongOwn** | leader owns its threads; thread death never frees the process. |
| E2 | Process → MemRegion | `AddrRegion.objId`, `Task.regions[]` ([task.d](../src/kernel/d/core/task.d)) | **StrongOwn** | exit tears down regions; already swept by `objReconcileRegions`. |
| E3 | Process → Namespace | `Task.namespaceObjId` ([task.d](../src/kernel/d/core/task.d)) | **StrongOwn** | threads *share* (one owner = leader); fork clones. |
| E4 | Process → CapTable | `Task.capTabId` ([task.d](../src/kernel/d/core/task.d)) | **StrongOwn** | per-process; clone shares, fork narrows. |
| E5 | Child → parent | `Task.parentId`, `parentObjId` ([task.d](../src/kernel/d/core/task.d)) | **Weak** | parent back-edge must not pin the parent; `wait4` reads it, null-safe. |
| E6 | fd handle → object | `Capability{objId,rights}` in `CapTable` ([cap.d](../src/kernel/d/core/cap.d)) | **Cap** | rights-bearing; the authority edge. `requireCap` checks it. |
| E7 | File slot → backend | `File.objId` / `File.backend` ([posix.d](../src/kernel/d/core/syscalls/posix.d)) | **StrongRef** | fd object keeps the socket/pipe/memfd backend alive. |
| E8 | MemRegion → Vmo | `AddrRegion.vmoObjId` (+`vmoRetained`) ([task.d](../src/kernel/d/core/task.d)) | **StrongRef** | shared backing; Vmo never points back (any back-edge is Weak). |
| E9 | Socket ⇄ peer | `LocalSocket.peerId` ([posix.d](../src/kernel/d/core/syscalls/posix.d)) | **Weak** | the 2-cycle; broken on close via `peerClosed`. Must be weak. |
| E10 | Socket → in-flight fd | `LocalSocket.passedFiles[]` + `passedCaps[]` (`IpcCapDesc`) ([posix.d](../src/kernel/d/core/syscalls/posix.d)) | **StrongRef, GC-tracked** | **the canonical leak.** Keeps the passed File alive; can form unreachable cycles ⇒ needs the tracing collector (ORG-P6). |
| E11 | epoll → watched fd | `EpollWatch.watchFd` ([posix.d](../src/kernel/d/core/syscalls/posix.d)) | **Observer** | weak + **nesting-depth bound** (cap at 5, Linux parity). |
| E12 | Directory → child | `RtNode.parent` (`..` computed, not stored) ([posix.d](../src/kernel/d/core/syscalls/posix.d)) | **StrongOwn** | single-parent tree; preserve "no stored `..`". Future binds/hardlinks ⇒ Weak. |
| E13 | Namespace → bound object | `NsBinding{path,targetObjId}` ([namespace.d](../src/kernel/d/core/namespace.d)) | **Cap** (currently un-rights-checked) | name→object; a re-bind of an already-owned object is a **second-class** edge (Weak/Cap), never a second StrongOwn. |
| E14 | Capability → derived cap | `Capability.deriveParent` ([cap.d](../src/kernel/d/core/cap.d)) | **Cap (derive-DAG)** | meet-narrowed rights; `capRevoke` already cascades to children (partial I7). |
| E15 | Driver → Device | `DeviceRecord.driverObjId` ([device.d](../src/kernel/d/core/device.d)) | **StrongOwn** | driver owns its devices. |
| E16 | Device → impl global | `DeviceRecord.impl` (`AHCIDeviceInfo*`/…) ([device.d](../src/kernel/d/core/device.d)) | **Weak** | a raw back-pointer to a legacy global; must read null-safe, grant nothing. |
| E17 | Surface → Window → Output | `WinRec.parentObjId` ([window.d](../src/kernel/d/core/window.d)) | **StrongOwn** (parent) + `ownerObjId` **Cap** | display tree; owner is the cap holder. |
| E18 | Service → Endpoint | `ServiceRec.endpointObjId` ([servicemgr.d](../src/kernel/d/core/servicemgr.d)) | **StrongRef** | service owns its rendezvous queue. |
| E19 | Service A ⇄ Service B | (future, holding each other's endpoint cap) | **Cap/Weak** | mutual-client cycle; never ownership. |
| E20 | LinuxProcess → Process | `LinuxProcRec.processObjId` ([linuxobj.d](../src/kernel/d/core/linuxobj.d)) | **Weak** | a personality *view* of a native object; grants nothing on its own. |

**Objects that must NEVER lie on a cycle (fail-stop):** `g_objects[0]` (the invalid/root
sentinel); the Object-Manager and Capability-Manager roots; every node on the StrongOwn
spanning tree (Process→Thread/MemRegion/Namespace/CapTable, Driver→Device,
Surface→Window→Output, Directory tree); capability *definitions*; future MAC-label /
immutable objects (`IMMUTABLE_ROOTLESS_ROADMAP.md`). **Cycles OK iff a weak edge breaks
them:** E5, E9, E11, E13 (re-bind), E16, E19, E20, and caches.

---

## 1.2 — Formal models as checkable predicates

Let `O` = live objects (`objGet(id) != null`), `E` = the typed edge set
`{(from,to,kind,rights)}`. `strongIn(o)` = StrongOwn+StrongRef+Cap in-edges; `owners(o)`
= StrongOwn in-edges. `roots` = {object-tree root, manager roots}. These are the exact
predicates ORG-P5/P6/P7's validator evaluates.

| Inv | Predicate | Enforcement point | Current status |
|---|---|---|---|
| **I1** Single owner | `∀ o ∈ O\roots: |owners(o)| == 1` | `edgeAdd(StrongOwn)` (P2/P5.1) | implicit (one `processObjId`/`parentObjId` per record) — not yet *checked*. |
| **I2** Ownership acyclic | no SCC of size > 1 in `(O, StrongOwn-edges)` | online DFS at `edgeAdd(StrongOwn)` rejects back-edge (P5.1) | not enforced; today nothing can *add* an ownership cycle because owners are assigned once. |
| **I3** Root reachable | `∀ o ∈ O: reachableFromRoots(o)` over strong edges; else GC, **not leak** | background mark-sweep (P6.2) | `objSweepType` already collects orphaned MemRegion/Process/Thread by impl-pointer + mark; SCM in-flight cycle **not** covered. |
| **I4** No dangling strong | `∀ (f,t,k)∈E, k∈{StrongOwn,StrongRef,Cap}: t∈O` ∧ `refCount(t) ≥ strongIn(t)` | `edgeAdd`/`edgeRemove` + shadow-rebuild (P6.1/6.3) | `capUsable` null-checks `objGet(objId)`; refcount≥strong-in invariant not yet asserted. |
| **I5** Rights/label monotone | `∀ (p,c,Cap|StrongOwn): rights(c) ⊆ rights(p) ∧ label(c) ⊑ label(p)` | `edgeAdd(Cap|StrongOwn)` (P7.1) | `capDerive` already enforces `rights ⊆ parent` (rights half done); labels await MAC. |
| **I6** Edge-kind typing | `∀ e∈E: kind(e) ∈ {StrongOwn,StrongRef,Weak,Cap,Observer}` ∧ authority-rules keyed on kind | the edge type itself (P2.1) | **not yet** — edges are untyped subsystem fields. This is ORG-P2's core add. |
| **I7** Revocation closure | `revoke(cap) ⇒ ∀ d reachable from cap over deriveParent: d.revoked` | `capRevoke` transitive walk (P7.2) | `capRevoke` cascades **one level** (direct children); transitive closure is the P7.2 gap. |
| **I8** Weak coherence | `∀ (f,t,Weak|Observer): weakGet(t) = (t∈O ? t : null)` | `weakGet` epoch-checked (P2.3) | partial: `peerClosed`, `LinuxProcRec` sweep, `winRecByObj` null-check — but no uniform epoch'd `weakGet`. |

**Ownership model (predicate form).** Exactly one owner capability per object:
`ObjHeader.ownerCap` names it; `owners(o) = {p : (p,o,StrongOwn)}` and I1 says
`|owners(o)|=1`. The StrongOwn edges form a forest whose roots are `roots`. Destroy(owner)
⇒ for each StrongOwn child either `destroy(child)` or reparent to a reaper. *Checkable:*
the StrongOwn projection is a forest ⇔ I1 ∧ I2.

**Capability-propagation model (predicate form).** `derive(p, r)` creates child cap `c`
with `rights(c) = rights(p) ⊓ r` (lattice meet ⇒ `rights(c) ⊆ rights(p)`, I5) and a
`deriveParent` edge `c→p`. The derive relation is a DAG. `revoke(p)` sets `revoked` on the
forward-reachable set `{c : p →* c over deriveParent}` (I7). Delegation over IPC
(`SCM_RIGHTS`) **must** create a derive-edge in the receiver's CapTable, never copy a raw
pointer — already true: `sendmsg`→`ipcDelegateCap`, `recvmsg`→`ipcAcceptCap` carry
`{objId,rights}` by value ([posix.d](../src/kernel/d/core/syscalls/posix.d),
[ipc.d](../src/kernel/d/core/ipc.d)).

**Security-inheritance model (predicate form).** Labels move **down StrongOwn edges
only**: `∀ (p,c,StrongOwn): label(c) ⊑ label(p)` (I5). For every other kind,
`label`-authority is `⊥` — reference/observer/weak edges convey no label. *Checkable:* the
audit walks only the StrongOwn forest for label monotonicity and asserts no `label`
function reads a Weak/Observer/StrongRef edge. This is the concrete fix for the roadmap's
framing-weakness #2 ("security inherited downward through *the* hierarchy" is only sound
on the ownership sub-graph).

**Corruption-recovery model.** *Fail-stop* on I1/I2/I4 (ownership): quarantine the
offending SCC, refuse new in-edges, raise a security event — never continue. *Self-heal*
on I3/I8 (reference): mark-sweep, collect unreachable SCCs, null dead weak edges. Recovery
= **shadow-refcount rebuild**: recompute `strongIn(o)` from a root mark, diff against
stored `refCount`; equal ⇒ ok, target-higher ⇒ repair, structurally-impossible ⇒
quarantine.

---

## 1.3 — Threat model (each threat → invariant + mitigating phase)

| Threat | Vector in current code | Violated invariant | Mitigation (ORG phase) | Status today |
|---|---|---|---|---|
| **T1 Cycle-leak DoS** | `SCM_RIGHTS` in-flight `passedFiles[]` (E10): two unix sockets each hold a `File` to the other, both direct fds closed ⇒ unreachable but refcount-pinned (the `net/unix/garbage.c` case). | I3 (root-reachable) | tracing GC for unreachable strong-SCCs — **P5.2/5.3 + P6.2** | **unmitigated** — refcounting cannot collect it; this is the roadmap's headline gap. |
| **T2 Socket-pair pin** | `peerId` mutual edge (E9). | I8 | weak peer edge, null on close — **P3.3** | partially handled (`peerClosed`/`refCount`); formalize as Weak. |
| **T3 epoll watch-bomb** | `EpollWatch.watchFd` (E11), epoll watching epoll. | I8 + resource bound | Observer edge + nesting-depth bound (≤5) — **P3.3 / P10.2** | **unbounded** today (no depth check). |
| **T4 Label escalation via ref edge** | reading an object through a Weak/Observer/StrongRef edge and treating its label/rights as inherited. | I5, I6 | authority keyed on kind; only StrongOwn/Cap propagate — **P7.1/7.3** | structurally prevented in design; not yet *checked* (no labels yet). |
| **T5 Rights escalation on delegation** | a derived cap or `SCM_RIGHTS` handoff granting *more* rights than parent. | I5 | meet-narrowing at `edgeAdd(Cap)` — **P7.1** | **already enforced** (`capDerive` rejects super-set; `ipcAcceptCap` clamps). |
| **T6 Stale revocation** | `capRevoke` only kills direct children; a grandchild cap stays usable. | I7 | transitive revocation closure — **P7.2** | **partial gap** — one-level cascade only. |
| **T7 Ownership cycle / multi-owner** | a future bind/hardlink/reparent makes an object owned by two parents or its own ancestor. | I1, I2 | single-owner check + online cycle rejection — **P5.1 / P6.1** | not possible to *create* yet, not *checked* either. |
| **T8 Dangling strong edge (UAF)** | an edge whose target was freed while `refCount` said live. | I4 | shadow-refcount rebuild + quarantine — **P6.1/6.3** | `objRelease` is underflow-safe + `capUsable` null-checks; no systemic I4 audit. |
| **T9 Validator-as-oracle / DoS** | an unprivileged caller drives the SCC sweep / reads the whole graph to map topology, or pins CPU. | (operational) | validator behind a **validator capability**; work-budgeted background sweep; cap-gated graph export — **P8.3 / P9.1** | n/a yet (no validator). |
| **T10 Dead-weak read** | reading a Weak/Observer edge after the target died returns a stale live pointer. | I8 | epoch-stamped `weakGet` ⇒ null — **P2.3** | partial (ad-hoc null checks per subsystem); no uniform epoch. |

**Threat→phase coverage check:** every threat maps to at least one invariant and one
implementing phase; the two with no current mitigation (**T1**, **T3**) are exactly the
roadmap's flagged "refcounting leaks the cycle" and "epoll nesting" items, and both sit on
the critical path (P5/P6 and P3.3/P10.2). No threat is left unassigned.

---

## Acceptance (Phase 1 tasks)

**Distributed specifics (refs as `{nodeId,objId,epoch}`, weak+leased cross-node edges)**
are deliberately deferred to **ORG-P11** per the roadmap's own risk note ("over-design;
mitigate by deferring distributed specifics").

## Next (ORG Phase 2 — Kernel Data Structures)

Make E1–E20 **explicit, typed, enumerable**: extend `ObjHeader` with `ownerCap` (exists,
wire it), strong in/out counts, and an intrusive adjacency list of `{toId,kind,rights}`;
add `edgeAdd/edgeRemove` as the *only* mutator of relationships; add epoch-stamped
`weakGet`. That is where ORG stops being a spec and starts being code.
