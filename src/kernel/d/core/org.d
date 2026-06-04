// Object Reference Graph — data structures — Phase 2 of
// OBJECT_REFERENCE_GRAPH_ROADMAP.md (see roadmap/ORG_ARCHITECTURE.md for the spec).
//
// Makes object relationships **explicit, typed, and enumerable**: today they are
// scattered subsystem fields (File.objId, LocalSocket.peerId, AddrRegion.vmoObjId,
// Task.parentId, …).  This phase builds the *mechanism* — a typed edge set keyed
// by the central object table — and proves it; rewiring the existing subsystems
// to create their edges through `edgeAdd`/`edgeRemove` is Phase 3.
//
//   2.1 — per-object adjacency (intrusive out-edge list) + strongIn/strongOut
//         counts + `ownerCap` linkage on the real ObjHeader.
//   2.2 — `edgeAdd`/`edgeRemove` as the only relationship mutators; maintain
//         refcounts (strong in/out) + epoch stamps.
//   2.3 — weak references: Weak/Observer edges don't keep targets alive; `weakGet`
//         returns null when the target is dead or its slot was reused.
//
// The adjacency lives in a side table keyed by objId (functionally the object's
// own out-edges) rather than inside `ObjHeader`, to avoid bloating the hot
// 8192-entry header array — the same side-table choice used for the device/window/
// namespace registries.  `ObjHeader.ownerCap` (already reserved) is wired here.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.org;

import core.io; // klog / klog_hex
import core.objmgr : OBJ_MAX, ObjType, objGet, objAlloc, objRelease,
                     g_objFreeNotify;
import core.namespace : nsAlloc, nsBind, nsRelease, nsValidateBindings; // P4.3
import memory.mm : free_phys_page, alloc_phys_page; // P6.2: GC ↔ allocator integration
import core.audit : auditLog, AuditKind; // P8.2: attributable graph events

extern (C) @nogc nothrow:

// Edge taxonomy (ORG_ARCHITECTURE.md §1.1).  Strong = {StrongOwn, StrongRef, Cap}
// keep the target alive; Weak/Observer do not.
enum EdgeKind : ubyte {
    None = 0,
    StrongOwn,   // sole ownership; defines the object forest (security flows here)
    StrongRef,   // non-owning keep-alive (fd→backend, mapping→Vmo, in-flight fd)
    Cap,         // capability handle → object (rights-bearing)
    Weak,        // back-pointer/peer/cache; reads null when target dies
    Observer     // watch (epoll); weak + depth-bounded
}

private bool kindIsStrong(EdgeKind k) {
    return k == EdgeKind.StrongOwn || k == EdgeKind.StrongRef || k == EdgeKind.Cap;
}

enum int ORG_EDGE_MAX = 16384;

struct OrgEdge {
    bool     inUse;
    EdgeKind kind;
    uint     fromId;
    uint     toId;
    uint     rights;
    uint     toGen;   // target slot generation at add time (weak-coherence check)
    int      next;    // next out-edge of fromId, or -1
}

__gshared OrgEdge[ORG_EDGE_MAX] g_orgEdges;
__gshared int[ORG_EDGE_MAX]     g_orgEdgeFree;
__gshared int                   g_orgEdgeFreeTop = -1;

// Per-object adjacency + counts, keyed by objId.
struct OrgNode {
    int  outHead;     // head index into g_orgEdges (-1 = no out-edges)
    uint strongIn;    // # strong in-edges (life count)
    uint strongOut;   // # strong out-edges
    uint strongOwnIn; // # StrongOwn in-edges (must be ≤ 1 — invariant I1)
    uint owner;       // StrongOwn parent objId (0 = none); mirrors ObjHeader.ownerCap
    uint gen;         // slot generation; bumped on free so weak edges go stale
    uint reachMark;   // reachability generation (P4.2 mark-from-roots)
    uint tjIndex;     // Tarjan DFS index (0 = unvisited) (P5.2)
    uint tjLow;       // Tarjan low-link
    uint tjScc;       // SCC representative (root) id this node belongs to
    bool tjOnStack;   // on the Tarjan SCC stack
    bool quarantined; // P6.1: invariant violation — refuse new edges, fail-stop
    uint age;         // P6.2: GC generation age (young objects scanned more often)
    ulong gcPage;     // P6.2: physical page this object backs (freed on collect)
    uint label;       // P7: MAC label/level (⊑ = ≤); monotone down ownership (I5)
    uint heldRights;  // P7: authority this object may grant downward (I5 rights)
}
__gshared OrgNode[OBJ_MAX] g_orgNodes;

__gshared uint  g_orgEpoch        = 1;  // global "edges changed" epoch
__gshared bool  g_orgInited       = false;
__gshared bool  g_orgSelfTested   = false;

__gshared ulong g_orgEdgeAdds     = 0;
__gshared ulong g_orgEdgeRemoves  = 0;
__gshared ulong g_orgEdgesLive    = 0;
__gshared ulong g_orgWeakNullRead = 0;
__gshared ulong g_orgFreeDrops    = 0;

public void orgInit() {
    if (g_orgInited) return;
    g_orgInited = true;
    g_orgEdgeFreeTop = -1;
    for (int i = ORG_EDGE_MAX - 1; i >= 0; --i)
        g_orgEdgeFree[++g_orgEdgeFreeTop] = i;
    foreach (ref n; g_orgNodes) { n.outHead = -1; n.strongIn = 0; n.strongOut = 0;
                                  n.strongOwnIn = 0; n.owner = 0; n.gen = 1;
                                  n.reachMark = 0; n.tjIndex = 0; n.tjLow = 0;
                                  n.tjScc = 0; n.tjOnStack = false;
                                  n.quarantined = false; n.age = 0; n.gcPage = 0;
                                  n.label = 0; n.heldRights = uint.max; }
    g_objFreeNotify = &orgOnFree; // weak coherence: notified when any object frees
}

private int edgeAlloc() {
    if (g_orgEdgeFreeTop < 0) return -1;
    return g_orgEdgeFree[g_orgEdgeFreeTop--];
}

private void edgeFree(int e) {
    g_orgEdges[e] = OrgEdge.init;
    if (g_orgEdgeFreeTop < ORG_EDGE_MAX - 1)
        g_orgEdgeFree[++g_orgEdgeFreeTop] = e;
}

private void bumpEpoch() {
    if (++g_orgEpoch == 0) g_orgEpoch = 1;
}

__gshared ulong g_orgOwnRejectI1 = 0; // StrongOwn edges refused: would give 2nd owner
__gshared ulong g_orgOwnRejectI2 = 0; // StrongOwn edges refused: would close a cycle

// Would a StrongOwn edge from→to close an ownership cycle?  True iff `to` can
// already reach `from` over StrongOwn out-edges.  The ownership graph is kept a
// forest, so this DFS never revisits and terminates; a work-budget overrun
// (impossible in a forest) fails closed.
private bool wouldFormOwnCycle(uint from, uint to) {
    if (from == to) return true; // self-ownership
    int[256] stack;
    int top = -1;
    stack[++top] = cast(int)to;
    int budget = 8192;
    while (top >= 0 && budget-- > 0) {
        uint id = cast(uint)stack[top--];
        for (int c = g_orgNodes[id].outHead; c >= 0; c = g_orgEdges[c].next) {
            auto ed = &g_orgEdges[c];
            if (!ed.inUse || ed.kind != EdgeKind.StrongOwn) continue;
            if (ed.toId == from) return true;
            if (top < cast(int)stack.length - 1) stack[++top] = cast(int)ed.toId;
            else return true; // can't fully verify within bound ⇒ fail closed
        }
    }
    return budget <= 0; // budget exhausted ⇒ fail closed
}

// 2.2 — the ONLY way to relate two objects.  Records a typed edge from→to, links
// it into `from`'s out-list, and (for strong kinds) maintains the life counts.  A
// StrongOwn edge also records the owner on the target (`ObjHeader.ownerCap`).
// Returns true on success; false if an endpoint is dead or the pool is full.
public bool edgeAdd(uint from, uint to, EdgeKind kind, uint rights) {
    orgInit();
    if (from == 0 || to == 0 || kind == EdgeKind.None) return false;
    if (objGet(from) is null || objGet(to) is null) return false;
    // P6.1 — a quarantined object accepts no new edges (fail-stop containment).
    if (g_orgNodes[to].quarantined || g_orgNodes[from].quarantined) {
        ++g_orgQuarantineBlocks;
        return false;
    }

    // P7.1 — I5: authority/label may not increase downward an ownership or
    // capability edge.  `label(c) ⊑ label(p)` (no upward MAC flow) and the granted
    // `rights` must be a subset of what the parent holds.  Reference/observer edges
    // carry no authority, so they are exempt (I6).  Defaults are permissive
    // (label 0, heldRights = all), so existing edges are unaffected until a policy
    // actually constrains an object.
    if (kind == EdgeKind.StrongOwn || kind == EdgeKind.Cap) {
        if (g_orgNodes[to].label > g_orgNodes[from].label) {
            ++g_orgLabelReject;
            return false;
        }
        if ((rights & ~g_orgNodes[from].heldRights) != 0) {
            ++g_orgRightsReject;
            return false;
        }
    }

    // P5.1 — online ownership-cycle prevention (fail-closed at insert): a StrongOwn
    // edge may neither give `to` a second owner (I1) nor close an ownership cycle
    // (I2).  Rejected edges never enter the graph, so the ownership projection is
    // always a forest by construction.
    if (kind == EdgeKind.StrongOwn) {
        if (g_orgNodes[to].strongOwnIn > 0 && g_orgNodes[to].owner != from) {
            ++g_orgOwnRejectI1;
            return false;
        }
        if (wouldFormOwnCycle(from, to)) {
            ++g_orgOwnRejectI2;
            return false;
        }
    }

    int e = edgeAlloc();
    if (e < 0) return false;

    auto ed = &g_orgEdges[e];
    ed.inUse  = true;
    ed.kind   = kind;
    ed.fromId = from;
    ed.toId   = to;
    ed.rights = rights;
    ed.toGen  = g_orgNodes[to].gen;
    ed.next   = g_orgNodes[from].outHead;
    g_orgNodes[from].outHead = e;

    if (kindIsStrong(kind)) {
        ++g_orgNodes[from].strongOut;
        ++g_orgNodes[to].strongIn;
    }
    if (kind == EdgeKind.StrongOwn) {
        ++g_orgNodes[to].strongOwnIn;
        g_orgNodes[to].owner = from;
        auto h = objGet(to);
        if (h !is null) h.ownerCap = from; // wire the reserved header field
    }
    ++g_orgEdgeAdds;
    ++g_orgEdgesLive;
    bumpEpoch();
    return true;
}

// 2.2 — remove the first from→to edge of `kind`.  Maintains counts/epoch.
public bool edgeRemove(uint from, uint to, EdgeKind kind) {
    orgInit();
    if (from == 0 || from >= OBJ_MAX) return false;
    int prev = -1;
    int cur = g_orgNodes[from].outHead;
    while (cur >= 0) {
        auto ed = &g_orgEdges[cur];
        if (ed.inUse && ed.toId == to && ed.kind == kind) {
            if (prev < 0) g_orgNodes[from].outHead = ed.next;
            else          g_orgEdges[prev].next = ed.next;
            if (kindIsStrong(kind)) {
                if (g_orgNodes[from].strongOut > 0) --g_orgNodes[from].strongOut;
                if (g_orgNodes[to].strongIn > 0)    --g_orgNodes[to].strongIn;
            }
            if (kind == EdgeKind.StrongOwn) {
                if (g_orgNodes[to].strongOwnIn > 0) --g_orgNodes[to].strongOwnIn;
                if (g_orgNodes[to].owner == from) g_orgNodes[to].owner = 0;
            }
            edgeFree(cur);
            ++g_orgEdgeRemoves;
            if (g_orgEdgesLive > 0) --g_orgEdgesLive;
            bumpEpoch();
            return true;
        }
        prev = cur;
        cur = ed.next;
    }
    return false;
}

// Notified by objmgr when an object slot frees: drop its out-edges (releasing the
// strong-in counts they held on their targets) and bump its generation so every
// weak in-edge to it now reads stale (I8).
public void orgOnFree(uint id) {
    if (id == 0 || id >= OBJ_MAX || !g_orgInited) return;
    int cur = g_orgNodes[id].outHead;
    while (cur >= 0) {
        auto ed = &g_orgEdges[cur];
        int nxt = ed.next;
        if (ed.inUse && kindIsStrong(ed.kind) &&
            g_orgNodes[ed.toId].strongIn > 0)
            --g_orgNodes[ed.toId].strongIn;
        edgeFree(cur);
        if (g_orgEdgesLive > 0) --g_orgEdgesLive;
        cur = nxt;
    }
    g_orgNodes[id].outHead = -1;
    g_orgNodes[id].strongOut = 0;
    g_orgNodes[id].strongIn = 0;
    g_orgNodes[id].strongOwnIn = 0;
    g_orgNodes[id].owner = 0;
    // Reset transient per-slot state so a reused id starts clean (a stale
    // quarantine/gcPage/label on a recycled slot would be a correctness/safety bug).
    g_orgNodes[id].quarantined = false;
    g_orgNodes[id].gcPage = 0;
    g_orgNodes[id].age = 0;
    g_orgNodes[id].label = 0;
    g_orgNodes[id].heldRights = uint.max;
    if (++g_orgNodes[id].gen == 0) g_orgNodes[id].gen = 1; // stale all weak in-edges
    ++g_orgFreeDrops;
    bumpEpoch();
}

// 2.3 — read a weak/observer edge target.  Returns `to` only if the original
// target is still live (slot allocated AND same generation as when the edge was
// made); otherwise null (0), the I8 "never a stale live pointer" guarantee.
public uint weakGet(uint from, uint to) {
    if (from == 0 || from >= OBJ_MAX) return 0;
    int cur = g_orgNodes[from].outHead;
    while (cur >= 0) {
        auto ed = &g_orgEdges[cur];
        if (ed.inUse && ed.toId == to &&
            (ed.kind == EdgeKind.Weak || ed.kind == EdgeKind.Observer)) {
            if (objGet(to) !is null && g_orgNodes[to].gen == ed.toGen)
                return to;
            ++g_orgWeakNullRead;
            return 0;
        }
        cur = ed.next;
    }
    return 0;
}

// --- enumeration / queries (2.1: out-edges in O(deg)) -------------------------
public uint orgOutDegree(uint id) {
    if (id == 0 || id >= OBJ_MAX) return 0;
    uint n = 0;
    for (int cur = g_orgNodes[id].outHead; cur >= 0; cur = g_orgEdges[cur].next)
        if (g_orgEdges[cur].inUse) ++n;
    return n;
}

public uint orgStrongIn(uint id)  { return (id < OBJ_MAX) ? g_orgNodes[id].strongIn  : 0; }
public uint orgStrongOut(uint id) { return (id < OBJ_MAX) ? g_orgNodes[id].strongOut : 0; }
public uint orgOwner(uint id)     { return (id < OBJ_MAX) ? g_orgNodes[id].owner     : 0; }

// Does `id` have an out-edge of `kind` to `to`?  O(deg).
public bool orgHasEdge(uint from, uint to, EdgeKind kind) {
    if (from == 0 || from >= OBJ_MAX) return false;
    for (int cur = g_orgNodes[from].outHead; cur >= 0; cur = g_orgEdges[cur].next) {
        auto ed = &g_orgEdges[cur];
        if (ed.inUse && ed.toId == to && ed.kind == kind) return true;
    }
    return false;
}

// --- Phase 3 integration helpers ----------------------------------------------
// Subsystems mirror their relationships into the graph through `edgeEnsure` from
// the amortized reconcile passes; `orgPruneDeadOut` keeps an owner's out-edge set
// equal to its *live* relationships as children come and go.

__gshared ulong g_orgEnsureAdds = 0;
__gshared ulong g_orgPruned     = 0;

// True iff a *live, current-generation* from→to edge of `kind` already exists.
private bool hasLiveEdge(uint from, uint to, EdgeKind kind) {
    for (int cur = g_orgNodes[from].outHead; cur >= 0; cur = g_orgEdges[cur].next) {
        auto ed = &g_orgEdges[cur];
        if (ed.inUse && ed.toId == to && ed.kind == kind &&
            objGet(to) !is null && g_orgNodes[to].gen == ed.toGen)
            return true;
    }
    return false;
}

// Idempotent edge creation: add the typed edge only if a live one isn't already
// present.  The single relationship-mutation entry point the reconcile passes use.
public bool edgeEnsure(uint from, uint to, EdgeKind kind, uint rights) {
    if (from == 0 || to == 0 || from >= OBJ_MAX) return false;
    if (objGet(from) is null || objGet(to) is null) return false;
    if (hasLiveEdge(from, to, kind)) return true;
    if (edgeAdd(from, to, kind, rights)) { ++g_orgEnsureAdds; return true; }
    return false;
}

// Remove every out-edge of `from` whose target is dead or whose slot was reused
// (the owner→child edges left dangling when a child object was freed).  Keeps the
// owner's out-set equal to its live children.  Returns #pruned.
public uint orgPruneDeadOut(uint from) {
    if (from == 0 || from >= OBJ_MAX || !g_orgInited) return 0;
    uint pruned = 0;
    int prev = -1;
    int cur = g_orgNodes[from].outHead;
    while (cur >= 0) {
        auto ed = &g_orgEdges[cur];
        int nxt = ed.next;
        bool stale = !ed.inUse || objGet(ed.toId) is null ||
                     g_orgNodes[ed.toId].gen != ed.toGen;
        if (stale) {
            if (prev < 0) g_orgNodes[from].outHead = nxt;
            else          g_orgEdges[prev].next = nxt;
            // The target is dead/reused: only adjust *our* out-count, never the
            // target's in-count (it belongs to a new object now, if any).
            if (ed.inUse && kindIsStrong(ed.kind) && g_orgNodes[from].strongOut > 0)
                --g_orgNodes[from].strongOut;
            edgeFree(cur);
            if (g_orgEdgesLive > 0) --g_orgEdgesLive;
            ++pruned;
            ++g_orgPruned;
            cur = nxt;
            continue;
        }
        prev = cur;
        cur = nxt;
    }
    if (pruned) bumpEpoch();
    return pruned;
}

// --- Invariant audit (I1 single-owner, I4 refcount ≥ strong-in) ----------------
// A budgeted O(V) scan proving the live graph is coherent: every object has at
// most one StrongOwn in-edge, and its object-manager refcount is ≥ its strong
// in-edge count (the legacy refcount is consistent with / derived from the graph).
__gshared ulong g_orgAuditRuns = 0;
__gshared ulong g_orgAuditI1Viol = 0; // multi-owner violations seen (last run)
__gshared ulong g_orgAuditI4Viol = 0; // refcount < strongIn violations (last run)

public bool orgAudit() {
    ++g_orgAuditRuns;
    ulong i1 = 0, i4 = 0;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        auto h = objGet(id);
        if (h is null) continue;
        if (g_orgNodes[id].strongOwnIn > 1) ++i1;        // I1: at most one owner
        if (h.refCount < g_orgNodes[id].strongIn) ++i4;  // I4: refcount ≥ strong-in
    }
    g_orgAuditI1Viol = i1;
    g_orgAuditI4Viol = i4;
    return i1 == 0 && i4 == 0;
}

// === Phase 4 — queryable graph core API ======================================

// --- 4.1 node / edge iteration, degrees, kind filters, epoch ------------------
// All allocation-free, cursor/index based, so callers (validator/GC/exporter) can
// traverse in O(V+E) without touching the hot path.

public uint orgEpoch() { return g_orgEpoch; }

// Iterate live object ids: returns the next live id > `after`, or 0 at the end.
public uint orgNextLiveNode(uint after) {
    for (uint id = (after >= OBJ_MAX ? OBJ_MAX : after) + 1; id < OBJ_MAX; ++id)
        if (objGet(id) !is null) return id;
    return 0;
}

// Out-edge cursor: `orgFirstOutEdge(id)` then `orgNextEdge(h)` until < 0; read with
// the accessors.  Handles are edge-pool indices, stable until that edge is removed.
public int      orgFirstOutEdge(uint id) {
    return (id != 0 && id < OBJ_MAX) ? g_orgNodes[id].outHead : -1;
}
public int      orgNextEdge(int h)    { return (h >= 0 && h < ORG_EDGE_MAX) ? g_orgEdges[h].next : -1; }
public uint     orgEdgeTarget(int h)  { return (h >= 0 && h < ORG_EDGE_MAX) ? g_orgEdges[h].toId : 0; }
public EdgeKind orgEdgeKind(int h)    { return (h >= 0 && h < ORG_EDGE_MAX) ? g_orgEdges[h].kind : EdgeKind.None; }
public uint     orgEdgeRights(int h)  { return (h >= 0 && h < ORG_EDGE_MAX) ? g_orgEdges[h].rights : 0; }

// Out-degree filtered by edge kind (O(deg)).
public uint orgOutDegreeKind(uint id, EdgeKind kind) {
    if (id == 0 || id >= OBJ_MAX) return 0;
    uint n = 0;
    for (int c = g_orgNodes[id].outHead; c >= 0; c = g_orgEdges[c].next)
        if (g_orgEdges[c].inUse && g_orgEdges[c].kind == kind) ++n;
    return n;
}

// In-degree of `to` (O(E) scan — no reverse adjacency; off the hot path).
public uint orgInDegree(uint to) {
    if (to == 0) return 0;
    uint n = 0;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        if (objGet(id) is null) continue;
        for (int c = g_orgNodes[id].outHead; c >= 0; c = g_orgEdges[c].next)
            if (g_orgEdges[c].inUse && g_orgEdges[c].toId == to) ++n;
    }
    return n;
}

// Count live edges of a given kind across the whole graph (O(E); stats/validator).
public uint orgCountKind(EdgeKind kind) {
    uint n = 0;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        if (objGet(id) is null) continue;
        for (int c = g_orgNodes[id].outHead; c >= 0; c = g_orgEdges[c].next)
            if (g_orgEdges[c].inUse && g_orgEdges[c].kind == kind) ++n;
    }
    return n;
}

// --- 4.2 reachability: budgeted, resumable mark-from-roots over strong edges ---
// Roots are an explicit, externally-anchored set (the validator/GC registers the
// scheduler-anchored process objects + manager roots).  An object not marked after
// a full pass is unreachable over strong edges ⇒ a GC candidate (I3) — that is the
// SCM_RIGHTS in-flight cycle, picked up here and collected in P6.

enum int ORG_ROOT_MAX = 256;
__gshared uint[ORG_ROOT_MAX] g_orgRoots;
__gshared int               g_orgRootCount = 0;
__gshared uint              g_orgReachGen  = 0;
__gshared int[OBJ_MAX]      g_orgWork;        // DFS worklist (no heap alloc)
__gshared int               g_orgWorkTop   = -1;
__gshared uint              g_orgReachableCount = 0;
__gshared ulong             g_orgReachRuns = 0;

public void orgClearRoots() { g_orgRootCount = 0; }
public bool orgAddRoot(uint id) {
    if (g_orgRootCount >= ORG_ROOT_MAX || objGet(id) is null) return false;
    g_orgRoots[g_orgRootCount++] = id;
    return true;
}

// Objects anchored by a kernel registry rather than by process ownership — they
// are externally reachable and must be reachability roots, or the GC would see
// them as garbage (P6.2 safety: complete the root set so production has 0 false
// GC candidates).
private bool isAnchorType(ObjType t) {
    switch (t) {
        case ObjType.Device: case ObjType.Driver: case ObjType.NetIf:
        case ObjType.User: case ObjType.Service: case ObjType.Namespace:
        case ObjType.Directory: case ObjType.Endpoint: case ObjType.Window:
        case ObjType.Vmo: case ObjType.LinuxProcess: case ObjType.LinuxVFS:
        case ObjType.LinuxSyscall: case ObjType.LinuxELFLoader:
        case ObjType.LinuxDeviceAdapter:
            return true;
        default: return false;
    }
}

// Register every registry-anchored live object as a root (additive to whatever
// process roots were already registered).  O(V); off the hot path.
public void orgAddAnchorRoots() {
    for (uint id = 1; id < OBJ_MAX; ++id) {
        auto h = objGet(id);
        if (h is null) continue;
        if (isAnchorType(h.type)) orgAddRoot(id);
    }
}

private void reachPush(uint id) {
    if (g_orgNodes[id].reachMark == g_orgReachGen) return;
    g_orgNodes[id].reachMark = g_orgReachGen;
    ++g_orgReachableCount;
    if (g_orgWorkTop < OBJ_MAX - 1) g_orgWork[++g_orgWorkTop] = cast(int)id;
}

// Start a new reachability pass: new generation, seed the worklist with the roots.
public void orgReachBegin() {
    orgInit();
    if (++g_orgReachGen == 0) g_orgReachGen = 1;
    g_orgWorkTop = -1;
    g_orgReachableCount = 0;
    ++g_orgReachRuns;
    foreach (i; 0 .. g_orgRootCount)
        if (objGet(g_orgRoots[i]) !is null) reachPush(g_orgRoots[i]);
}

// Process up to `budget` nodes; marks live strong-edge targets.  Returns true if
// work remains (resumable — the validator calls this in budgeted slices).
public bool orgReachStep(int budget) {
    int done = 0;
    while (g_orgWorkTop >= 0 && done < budget) {
        uint id = cast(uint)g_orgWork[g_orgWorkTop--];
        ++done;
        for (int c = g_orgNodes[id].outHead; c >= 0; c = g_orgEdges[c].next) {
            auto ed = &g_orgEdges[c];
            if (!ed.inUse || !kindIsStrong(ed.kind)) continue; // strong edges only
            uint to = ed.toId;
            if (objGet(to) is null || g_orgNodes[to].gen != ed.toGen) continue;
            reachPush(to);
        }
    }
    return g_orgWorkTop >= 0;
}

// Convenience: run a full pass to completion in `budgetPerStep` slices.
public void orgReachCompute(int budgetPerStep) {
    if (budgetPerStep < 1) budgetPerStep = 1;
    orgReachBegin();
    uint guard = 0;
    while (orgReachStep(budgetPerStep) && ++guard < OBJ_MAX) {}
}

public bool orgReachable(uint id) {
    return id != 0 && id < OBJ_MAX && objGet(id) !is null &&
           g_orgNodes[id].reachMark == g_orgReachGen;
}
public uint orgReachableCount() { return g_orgReachableCount; }

// === 5.2 — Tarjan SCC over the (strong) reference graph =======================
// Iterative (no recursion → no kernel-stack blowup) strongly-connected-component
// computation over strong edges (Weak/Observer never pin, so they can't be part of
// a pinning cycle).  O(V+E); each node is stamped with its SCC representative and
// the run is stamped with the graph epoch.  Runs to completion per call here, off
// the syscall path; the explicit DFS stack makes it straightforward for the P8
// validator to drive in budgeted slices.

__gshared int[OBJ_MAX]  g_tjStack;    // Tarjan SCC stack
__gshared int           g_tjTop = -1;
__gshared int[OBJ_MAX]  g_dfsNode;    // explicit DFS stack: node …
__gshared int[OBJ_MAX]  g_dfsCur;     // … and its current strong-out edge handle
__gshared int           g_dfsTop = -1;
__gshared uint          g_tjIndexCtr = 1;
__gshared uint          g_orgSccCount = 0;   // # non-trivial SCCs (size>1) last run
__gshared uint          g_orgLargestScc = 0;
__gshared uint          g_orgSccEpoch = 0;
__gshared ulong         g_orgTarjanRuns = 0;

private int firstStrongOut(uint id) {
    for (int c = g_orgNodes[id].outHead; c >= 0; c = g_orgEdges[c].next) {
        auto ed = &g_orgEdges[c];
        if (ed.inUse && kindIsStrong(ed.kind) &&
            objGet(ed.toId) !is null && g_orgNodes[ed.toId].gen == ed.toGen)
            return c;
    }
    return -1;
}
private int nextStrongOut(int handle) {
    if (handle < 0) return -1;
    for (int c = g_orgEdges[handle].next; c >= 0; c = g_orgEdges[c].next) {
        auto ed = &g_orgEdges[c];
        if (ed.inUse && kindIsStrong(ed.kind) &&
            objGet(ed.toId) !is null && g_orgNodes[ed.toId].gen == ed.toGen)
            return c;
    }
    return -1;
}

public uint orgTarjanRun() {
    orgInit();
    ++g_orgTarjanRuns;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        if (objGet(id) is null) continue;
        g_orgNodes[id].tjIndex = 0; g_orgNodes[id].tjLow = 0;
        g_orgNodes[id].tjScc = 0;   g_orgNodes[id].tjOnStack = false;
    }
    g_tjTop = -1; g_dfsTop = -1; g_tjIndexCtr = 1;
    uint sccCount = 0, largest = 0;

    for (uint s = 1; s < OBJ_MAX; ++s) {
        if (objGet(s) is null || g_orgNodes[s].tjIndex != 0) continue;
        g_orgNodes[s].tjIndex = g_orgNodes[s].tjLow = g_tjIndexCtr++;
        g_tjStack[++g_tjTop] = cast(int)s; g_orgNodes[s].tjOnStack = true;
        g_dfsNode[++g_dfsTop] = cast(int)s; g_dfsCur[g_dfsTop] = firstStrongOut(s);

        while (g_dfsTop >= 0) {
            uint v = cast(uint)g_dfsNode[g_dfsTop];
            int ec = g_dfsCur[g_dfsTop];
            if (ec >= 0) {
                uint w = g_orgEdges[ec].toId;
                g_dfsCur[g_dfsTop] = nextStrongOut(ec); // advance for next visit
                if (g_orgNodes[w].tjIndex == 0) {
                    g_orgNodes[w].tjIndex = g_orgNodes[w].tjLow = g_tjIndexCtr++;
                    g_tjStack[++g_tjTop] = cast(int)w; g_orgNodes[w].tjOnStack = true;
                    g_dfsNode[++g_dfsTop] = cast(int)w; g_dfsCur[g_dfsTop] = firstStrongOut(w);
                } else if (g_orgNodes[w].tjOnStack) {
                    if (g_orgNodes[w].tjIndex < g_orgNodes[v].tjLow)
                        g_orgNodes[v].tjLow = g_orgNodes[w].tjIndex;
                }
            } else {
                if (g_orgNodes[v].tjLow == g_orgNodes[v].tjIndex) { // SCC root
                    uint size = 0; int member;
                    do {
                        member = g_tjStack[g_tjTop--];
                        g_orgNodes[member].tjOnStack = false;
                        g_orgNodes[member].tjScc = v;
                        ++size;
                    } while (member != cast(int)v);
                    if (size > 1) { ++sccCount; if (size > largest) largest = size; }
                }
                --g_dfsTop;
                if (g_dfsTop >= 0) {
                    uint parent = cast(uint)g_dfsNode[g_dfsTop];
                    if (g_orgNodes[v].tjLow < g_orgNodes[parent].tjLow)
                        g_orgNodes[parent].tjLow = g_orgNodes[v].tjLow;
                }
            }
        }
    }
    g_orgSccCount = sccCount;
    g_orgLargestScc = largest;
    g_orgSccEpoch = g_orgEpoch;
    return sccCount;
}

public uint orgSccOf(uint id)  { return (id != 0 && id < OBJ_MAX) ? g_orgNodes[id].tjScc : 0; }
public uint orgSccCount()      { return g_orgSccCount; }
public uint orgSccEpoch()      { return g_orgSccEpoch; }

// === 5.3 — SCC classification + collection ====================================
// A non-trivial SCC whose members are all *unreachable* from the registered roots
// over strong edges is an unreachable strong-cycle — the SCM_RIGHTS in-flight case
// — and is a GC target.  (Run orgReachCompute() first so reachability is current.)
// Reachable SCCs are live.  An SCC entered only by Weak/Observer edges from outside
// is collectible the same way (those edges don't pin).

public bool orgSccIsGcTarget(uint sccRoot) {
    if (sccRoot == 0) return false;
    uint size = 0;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        if (objGet(id) is null || g_orgNodes[id].tjScc != sccRoot) continue;
        ++size;
        if (orgReachable(id)) return false; // any reachable member ⇒ live SCC
    }
    return size > 1;
}

__gshared ulong g_orgSccCollected = 0; // SCCs collected
__gshared ulong g_orgSccFreed     = 0; // objects freed via SCC collection

// Reclaim an unreachable strong-SCC: release each member (breaking the cycle, which
// drops the internal strong edges via the free-notify path).  Logical reclaim at
// the object level; integrating with the physical allocator (mm.d free_phys_page)
// and the legacy lifecycle is P6.2.  Returns #objects freed.
public uint orgCollectScc(uint sccRoot) {
    if (!orgSccIsGcTarget(sccRoot)) return 0;
    int[64] members;
    int mc = 0;
    for (uint id = 1; id < OBJ_MAX && mc < 64; ++id)
        if (objGet(id) !is null && g_orgNodes[id].tjScc == sccRoot)
            members[mc++] = cast(int)id;
    uint freed = 0;
    for (int i = 0; i < mc; ++i) {
        uint id = cast(uint)members[i];
        if (objGet(id) is null) continue;
        // P6.2 — reclaim any physical page this object backs through the allocator.
        if (g_orgNodes[id].gcPage != 0) {
            free_phys_page(g_orgNodes[id].gcPage);
            g_orgNodes[id].gcPage = 0;
            ++g_orgPagesReclaimed;
        }
        objRelease(id);
        ++freed;
    }
    ++g_orgSccCollected;
    g_orgSccFreed += freed;
    return freed;
}

// Record the physical page an object backs, so GC collection frees it (P6.2).
public void orgSetGcPage(uint id, ulong pageAddr) {
    if (id != 0 && id < OBJ_MAX) g_orgNodes[id].gcPage = pageAddr;
}

// === 6.1 — invariant checker + quarantine + security event ====================
__gshared ulong g_orgSecurityEvents   = 0;
__gshared ulong g_orgQuarantined      = 0; // objects currently quarantined
__gshared ulong g_orgQuarantineBlocks = 0; // edges refused into quarantine

public bool orgIsQuarantined(uint id) {
    return id != 0 && id < OBJ_MAX && g_orgNodes[id].quarantined;
}

// Fail-stop containment for an ownership-invariant breach: quarantine the object
// (no new edges in/out), raise a security event, never silently continue.
public void orgQuarantine(uint id) {
    if (id == 0 || id >= OBJ_MAX || g_orgNodes[id].quarantined) return;
    g_orgNodes[id].quarantined = true;
    ++g_orgQuarantined;
    ++g_orgSecurityEvents;
    auditLog(AuditKind.Quarantine, id, 0); // P8.2: attributable
    klog("[org] SECURITY quarantine obj="); klog_hex(cast(ulong)id); klog("\n");
}

public void orgUnquarantine(uint id) { // used by recovery / tests after repair
    if (id != 0 && id < OBJ_MAX && g_orgNodes[id].quarantined) {
        g_orgNodes[id].quarantined = false;
        if (g_orgQuarantined > 0) --g_orgQuarantined;
    }
}

// Run the I1 (single owner) + I4 (refcount ≥ strong-in) checker.  In enforcing
// mode a violation quarantines the offending object and raises a security event;
// in report mode it only counts (the live periodic pass uses report mode, since
// quarantining a transiently-skewed live object would be its own DoS).
public bool orgValidateInvariants(bool enforce) {
    bool ok = true;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        auto h = objGet(id);
        if (h is null || g_orgNodes[id].quarantined) continue;
        bool viol = (g_orgNodes[id].strongOwnIn > 1) ||      // I1
                    (h.refCount < g_orgNodes[id].strongIn);  // I4
        if (viol) {
            ok = false;
            if (enforce) orgQuarantine(id);
            else ++g_orgSecurityEvents;
        }
    }
    return ok;
}

// === 6.2 — mark-sweep GC: dead-weak nulling + unreachable strong-SCC reclaim ===
// Generational + incremental + bounded.  In production it runs the *safe* half:
// null dead weak/observer edges (can never cause a UAF) and *count* unreachable
// strong objects as GC candidates — it does NOT auto-free live-graph objects,
// because a single gap in the edge model or root set would be a use-after-free in
// a running desktop.  The full collect path (incl. allocator reclaim) is exercised
// on controlled cycles by the self-test; enabling production auto-collection waits
// on the P8 validator's confidence + complete root set.

__gshared ulong g_orgWeakNulled    = 0;
__gshared ulong g_orgGcCandidates  = 0; // unreachable strong objects (last pass)
__gshared ulong g_orgPagesReclaimed = 0;
__gshared uint  g_orgGcCursor      = 0; // resumable sweep cursor (incremental)

// Remove up to `budget` worth of stale weak/observer edges (target dead or slot
// reused).  Resumable via the sweep cursor.  Returns #edges nulled this call.
public uint orgNullDeadWeak(int budget) {
    orgInit();
    uint nulled = 0;
    int scanned = 0;
    uint id = g_orgGcCursor;
    while (scanned < budget) {
        ++id;
        if (id >= OBJ_MAX) id = 1;
        ++scanned;
        if (objGet(id) is null) { if (id == g_orgGcCursor) break; continue; }
        int prev = -1;
        int cur = g_orgNodes[id].outHead;
        while (cur >= 0) {
            auto ed = &g_orgEdges[cur];
            int nxt = ed.next;
            bool weakKind = (ed.kind == EdgeKind.Weak || ed.kind == EdgeKind.Observer);
            bool stale = !ed.inUse || objGet(ed.toId) is null ||
                         g_orgNodes[ed.toId].gen != ed.toGen;
            if (weakKind && stale) {
                if (prev < 0) g_orgNodes[id].outHead = nxt;
                else          g_orgEdges[prev].next = nxt;
                edgeFree(cur);
                if (g_orgEdgesLive > 0) --g_orgEdgesLive;
                ++nulled; ++g_orgWeakNulled;
                cur = nxt;
                continue;
            }
            prev = cur;
            cur = nxt;
        }
        if (id == g_orgGcCursor) break; // wrapped a full lap
    }
    g_orgGcCursor = id;
    return nulled;
}

// Count live objects unreachable from the registered roots over strong edges — the
// GC-candidate set (I3).  Requires orgReachCompute() to have run.  Also ages live
// nodes (generational bookkeeping).  Returns the candidate count.
public uint orgGcScan() {
    uint candidates = 0;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        if (objGet(id) is null) continue;
        if (g_orgNodes[id].age < uint.max) ++g_orgNodes[id].age;
        // Unreachable AND has a strong in-edge (something strong-points at it, so
        // it isn't a freshly-allocated root-to-be) ⇒ a genuine strong-cycle leak.
        if (!orgReachable(id) && g_orgNodes[id].strongIn > 0) ++candidates;
    }
    g_orgGcCandidates = candidates;
    return candidates;
}

// Production-safe GC tick: null dead weak edges (safe) + refresh the candidate
// count (report only).  `budget` bounds the weak sweep per tick.
public void orgGcStep(int budget) {
    orgNullDeadWeak(budget);
    orgGcScan();
}

// === 6.3 — shadow-refcount rebuild recovery ===================================
// Recompute every object's strong in-edge count from a full edge scan (the
// authority), diff against the stored count; repair a drifted count, and quarantine
// an object whose object-manager refcount cannot support the recomputed strong-in
// (a structurally-impossible state).  Reuses g_orgWork as scratch (no concurrent
// reachability during recovery).  Returns #discrepancies found.

__gshared ulong g_orgShadowRuns    = 0;
__gshared ulong g_orgShadowRepairs = 0;
__gshared ulong g_orgShadowQuar    = 0;

public uint orgShadowRebuild() {
    orgInit();
    ++g_orgShadowRuns;
    for (uint id = 0; id < OBJ_MAX; ++id) g_orgWork[id] = 0; // shadow strong-in
    // One O(E) pass: tally strong in-edges to live targets.
    for (uint from = 1; from < OBJ_MAX; ++from) {
        if (objGet(from) is null) continue;
        for (int c = g_orgNodes[from].outHead; c >= 0; c = g_orgEdges[c].next) {
            auto ed = &g_orgEdges[c];
            if (ed.inUse && kindIsStrong(ed.kind) &&
                objGet(ed.toId) !is null && g_orgNodes[ed.toId].gen == ed.toGen)
                ++g_orgWork[ed.toId];
        }
    }
    uint discrep = 0;
    for (uint id = 1; id < OBJ_MAX; ++id) {
        auto h = objGet(id);
        if (h is null) continue;
        uint shadow = cast(uint)g_orgWork[id];
        if (shadow != g_orgNodes[id].strongIn) {
            ++discrep;
            g_orgNodes[id].strongIn = shadow;      // repair the drifted count
            ++g_orgShadowRepairs;
        }
        if (h.refCount < shadow) {                  // structurally impossible ⇒ quarantine
            orgQuarantine(id);
            ++g_orgShadowQuar;
        }
    }
    return discrep;
}

// --- Boot self-test (Phase 2 runtime proof) -----------------------------------
// Builds a tiny graph, checks adjacency + strong counts + owner wiring, then frees
// a strong target and confirms (2.3) the object is freed despite a weak in-edge
// and `weakGet` reads null afterwards.
public void orgSelfTest() {
    if (g_orgSelfTested) return;
    g_orgSelfTested = true;
    orgInit();

    uint a = objAlloc(ObjType.File, null);
    uint b = objAlloc(ObjType.File, null);
    uint c = objAlloc(ObjType.File, null);
    if (a == 0 || b == 0 || c == 0) { klog("[org] selftest FAIL: alloc\n"); return; }

    edgeAdd(a, b, EdgeKind.StrongOwn, 0);  // a owns b
    edgeAdd(a, c, EdgeKind.StrongRef, 0);  // a strong-refs c
    edgeAdd(b, c, EdgeKind.Weak, 0);       // b weakly observes c

    bool counts = (orgOutDegree(a) == 2 && orgStrongOut(a) == 2 &&
                   orgStrongIn(b) == 1 &&                 // only the StrongOwn
                   orgStrongIn(c) == 1 &&                 // StrongRef only; weak excluded
                   orgOwner(b) == a &&
                   weakGet(b, c) == c);                   // c live ⇒ weakGet returns it

    // Drop c's only strong in-edge, then release it.  The weak b→c edge must NOT
    // keep c alive, and weakGet must then read null (I8 / 2.3 acceptance).
    edgeRemove(a, c, EdgeKind.StrongRef);
    bool cHadNoStrongIn = (orgStrongIn(c) == 0);
    objRelease(c);                                        // → orgOnFree(c)
    bool freed = (objGet(c) is null);
    bool weakNull = (weakGet(b, c) == 0);

    bool ok = counts && cHadNoStrongIn && freed && weakNull &&
              orgOutDegree(a) == 1;                       // a→b remains

    // Clean up the self-test objects.
    objRelease(a);
    objRelease(b);

    if (ok) klog("[org] selftest PASS\n");
    else    klog("[org] selftest FAIL: behaviour\n");
}

// ORG P3 proof: fires once the reconcile passes have populated the graph with the
// real subsystem relationships AND the invariant audit (I1/I4) passes over it.
__gshared bool g_orgIntegReported = false;
public void orgIntegReport() {
    if (g_orgIntegReported) return;
    // Wait until the graph is non-trivially populated (ownership/cap edges built).
    if (g_orgEdgesLive < 8) return;
    bool ok = orgAudit();
    if (!ok) return; // keep waiting; a transient mid-reconcile state can show I4 skew
    g_orgIntegReported = true;
    klog("[org] integ PASS edges="); klog_hex(g_orgEdgesLive);
    klog(" I1ok I4ok\n");
}

// --- Phase 4 API self-test (runtime proof) ------------------------------------
// 4.1 iterate/degree/kind-filter; 4.2 budgeted reachability marks a root's strong
// descendants and excludes a disconnected node; 4.3 a namespace binding whose
// target dies is flagged dangling (not a crash).
__gshared bool g_orgApiTested = false;
public void orgApiSelfTest() {
    if (g_orgApiTested) return;
    g_orgApiTested = true;
    orgInit();

    uint r = objAlloc(ObjType.File, null);
    uint a = objAlloc(ObjType.File, null);
    uint b = objAlloc(ObjType.File, null);
    uint d = objAlloc(ObjType.File, null);  // disconnected from r's component
    if (r == 0 || a == 0 || b == 0 || d == 0) { klog("[org] api FAIL: alloc\n"); return; }

    edgeAdd(r, a, EdgeKind.StrongOwn, 7);
    edgeAdd(a, b, EdgeKind.StrongRef, 0);

    // 4.1 — iteration / degree / kind filter.
    int h = orgFirstOutEdge(r);
    bool api41 = (orgOutDegree(r) == 1 &&
                  h >= 0 && orgEdgeTarget(h) == a &&
                  orgEdgeKind(h) == EdgeKind.StrongOwn && orgEdgeRights(h) == 7 &&
                  orgOutDegreeKind(r, EdgeKind.StrongOwn) == 1 &&
                  orgOutDegreeKind(r, EdgeKind.Weak) == 0 &&
                  orgInDegree(a) >= 1 &&
                  orgCountKind(EdgeKind.StrongRef) >= 1 &&
                  orgNextLiveNode(0) != 0);

    // 4.2 — budgeted reachability from r reaches a,b but not d.
    orgClearRoots();
    orgAddRoot(r);
    orgReachCompute(1);                      // 1-node budget per slice ⇒ resumable path
    bool api42 = (orgReachable(r) && orgReachable(a) && orgReachable(b) &&
                  !orgReachable(d) && orgReachableCount() == 3);

    // 4.3 — namespace dangling-name flagging.
    uint baseDangling = nsValidateBindings();
    uint nsd = nsAlloc();
    uint tmp = objAlloc(ObjType.File, null);
    bool bound = (nsd != 0 && tmp != 0 && nsBind(nsd, "/x\0".ptr, tmp, uint.max));
    uint midDangling = nsValidateBindings();  // tmp live ⇒ /x not dangling yet
    objRelease(tmp);                          // kill the bound target
    uint endDangling = nsValidateBindings();  // /x now dangles, flagged not crashed
    bool api43 = (bound && midDangling == baseDangling && endDangling > midDangling);
    if (nsd != 0) nsRelease(nsd);

    objRelease(r); objRelease(a); objRelease(b); objRelease(d);

    if (api41 && api42 && api43) klog("[org] api PASS\n");
    else                         klog("[org] api FAIL: behaviour\n");
}

// --- Phase 5 cycle-detection self-test (runtime proof) ------------------------
// 5.1 an ownership cycle (and a second owner) are rejected at insert; 5.2 a
// strong-ref 2-cycle is found by Tarjan as one SCC; 5.3 that SCC is classified as
// an unreachable GC target and reclaimed.
__gshared bool g_orgCycleTested = false;
public void orgCycleSelfTest() {
    if (g_orgCycleTested) return;
    g_orgCycleTested = true;
    orgInit();

    // 5.1 — ownership-cycle + multi-owner rejection.
    uint o1 = objAlloc(ObjType.File, null);
    uint o2 = objAlloc(ObjType.File, null);
    uint o3 = objAlloc(ObjType.File, null);
    uint o4 = objAlloc(ObjType.File, null);
    if (!o1 || !o2 || !o3 || !o4) { klog("[org] cycle FAIL: alloc\n"); return; }
    bool chain = edgeAdd(o1, o2, EdgeKind.StrongOwn, 0) &&
                 edgeAdd(o2, o3, EdgeKind.StrongOwn, 0);
    bool cycleRej = !edgeAdd(o3, o1, EdgeKind.StrongOwn, 0); // o3→o1 closes o1→o2→o3→o1
    bool ownerRej = !edgeAdd(o4, o2, EdgeKind.StrongOwn, 0); // o2 already owned by o1
    bool p51 = chain && cycleRej && ownerRej;

    // 5.2 / 5.3 — strong-ref 2-cycle detected and reclaimed.
    uint x = objAlloc(ObjType.File, null);
    uint y = objAlloc(ObjType.File, null);
    bool made = (x && y && edgeAdd(x, y, EdgeKind.StrongRef, 0) &&
                 edgeAdd(y, x, EdgeKind.StrongRef, 0));
    orgClearRoots();
    orgAddRoot(o1);            // x,y are NOT reachable from the only root
    orgReachCompute(8);
    orgTarjanRun();
    uint sx = orgSccOf(x);
    bool p52 = made && sx != 0 && sx == orgSccOf(y) && sx != orgSccOf(o1);
    bool p53class = orgSccIsGcTarget(sx) && !orgReachable(x) && !orgReachable(y);
    uint freed = orgCollectScc(sx);
    bool p53reclaim = (freed == 2 && objGet(x) is null && objGet(y) is null);

    // cleanup ownership-test objects (o2 owned by o1; release children first).
    objRelease(o3); objRelease(o2); objRelease(o1); objRelease(o4);

    if (p51 && p52 && p53class && p53reclaim) klog("[org] cycle PASS\n");
    else klog("[org] cycle FAIL: behaviour\n");
}

// --- Phase 6 coherence/GC self-test (runtime proof) ---------------------------
// 6.1 an I4 violation is detected (never silent) and the object is quarantined,
// after which edges into it are refused; 6.2 an unreachable strong cycle backing a
// real physical page is reclaimed (object freed + page returned to the allocator)
// and a dead weak edge is nulled; 6.3 a corrupted strong-in count is detected and
// repaired by the shadow rebuild.
__gshared bool g_orgGcTested = false;
public void orgGcSelfTest() {
    if (g_orgGcTested) return;
    g_orgGcTested = true;
    orgInit();

    // 6.1 — invariant violation detected + quarantine + edge refusal.
    uint a = objAlloc(ObjType.File, null);
    uint live2 = objAlloc(ObjType.File, null);
    if (!a || !live2) { klog("[org] gc FAIL: alloc\n"); return; }
    g_orgNodes[a].strongIn = 5;                 // refCount is 1 ⇒ I4 violation
    bool detected = !orgValidateInvariants(false); // report mode: detects, quarantines no one
    ulong evBefore = g_orgSecurityEvents;
    orgQuarantine(a);
    bool quar = orgIsQuarantined(a) && g_orgSecurityEvents > evBefore;
    bool refused = !edgeAdd(live2, a, EdgeKind.StrongRef, 0); // edge into quarantine refused
    bool p61 = detected && quar && refused;
    g_orgNodes[a].strongIn = 0; orgUnquarantine(a);
    objRelease(a); objRelease(live2);

    // 6.2 — unreachable strong cycle (page-backed) reclaimed + dead-weak nulled.
    uint x = objAlloc(ObjType.File, null);
    uint y = objAlloc(ObjType.File, null);
    bool cyc = (x && y && edgeAdd(x, y, EdgeKind.StrongRef, 0) &&
                edgeAdd(y, x, EdgeKind.StrongRef, 0));
    ulong pg = alloc_phys_page();
    orgSetGcPage(x, pg);
    orgClearRoots();                            // nothing roots x/y
    orgReachCompute(8);
    orgTarjanRun();
    ulong pagesBefore = g_orgPagesReclaimed;
    uint freed = orgCollectScc(orgSccOf(x));
    bool reclaimed = (cyc && freed == 2 && objGet(x) is null && objGet(y) is null &&
                      g_orgPagesReclaimed > pagesBefore);

    uint p = objAlloc(ObjType.File, null);
    uint q = objAlloc(ObjType.File, null);
    bool wk = (p && q && edgeAdd(p, q, EdgeKind.Weak, 0));
    objRelease(q);                              // q dies ⇒ p→q is a dead weak edge
    uint nulled = orgNullDeadWeak(OBJ_MAX);
    bool weakNulled = (wk && nulled >= 1 && orgOutDegree(p) == 0);
    objRelease(p);
    bool p62 = reclaimed && weakNulled;

    // 6.3 — shadow-refcount rebuild detects + repairs a drifted count.
    uint m = objAlloc(ObjType.File, null);
    uint n = objAlloc(ObjType.File, null);
    bool me = (m && n && edgeAdd(m, n, EdgeKind.StrongRef, 0)); // n.strongIn == 1
    g_orgNodes[n].strongIn = 9;                 // corrupt
    uint disc = orgShadowRebuild();
    bool p63 = (me && disc >= 1 && g_orgNodes[n].strongIn == 1);
    edgeRemove(m, n, EdgeKind.StrongRef);
    objRelease(m); objRelease(n);

    if (p61 && p62 && p63) klog("[org] gc PASS\n");
    else                   klog("[org] gc FAIL: behaviour\n");
}

// === Phase 7 — security validation (I5 / I6 / I7.3) ===========================
__gshared ulong g_orgLabelReject = 0; // edges refused: child label > parent (I5)
__gshared ulong g_orgRightsReject = 0; // edges refused: rights exceed parent (I5)
__gshared ulong g_orgLabelViol   = 0; // ownership label-monotonicity violations (last audit)

public void orgSetLabel(uint id, uint label) {
    if (id != 0 && id < OBJ_MAX) g_orgNodes[id].label = label;
}
public uint orgLabel(uint id) { return (id != 0 && id < OBJ_MAX) ? g_orgNodes[id].label : 0; }

public void orgSetHeldRights(uint id, uint rights) {
    if (id != 0 && id < OBJ_MAX) g_orgNodes[id].heldRights = rights;
}
public uint orgHeldRights(uint id) {
    return (id != 0 && id < OBJ_MAX) ? g_orgNodes[id].heldRights : 0;
}

// 7.3 — security-inheritance audit: labels must be monotone along **ownership**
// edges only (`label(child) ⊑ label(parent)`).  Reference/observer edges are not
// walked, so they grant no label authority by construction (I6).  Returns the
// number of StrongOwn edges that violate monotonicity (post-hoc relabelings the
// insert-time check in edgeAdd can't catch).
public uint orgLabelAudit() {
    uint viol = 0;
    for (uint from = 1; from < OBJ_MAX; ++from) {
        if (objGet(from) is null) continue;
        for (int c = g_orgNodes[from].outHead; c >= 0; c = g_orgEdges[c].next) {
            auto ed = &g_orgEdges[c];
            if (!ed.inUse || ed.kind != EdgeKind.StrongOwn) continue;
            if (objGet(ed.toId) is null) continue;
            if (g_orgNodes[ed.toId].label > g_orgNodes[from].label) ++viol;
        }
    }
    g_orgLabelViol = viol;
    return viol;
}

// --- Phase 7 security self-test (runtime proof) -------------------------------
// 7.1 a child label/right exceeding the parent's is rejected at insert; 7.3 a
// post-hoc label inversion along an ownership edge is reported by the audit; ref
// edges carry no authority.  (7.2 transitive revocation is proven in core/cap.d.)
__gshared bool g_orgSecTested = false;
public void orgSecuritySelfTest() {
    if (g_orgSecTested) return;
    g_orgSecTested = true;
    orgInit();

    uint p = objAlloc(ObjType.File, null);
    uint c = objAlloc(ObjType.File, null);
    if (!p || !c) { klog("[org] sec FAIL: alloc\n"); return; }

    // 7.1 label: a more-sensitive child may not be owned by a less-sensitive parent.
    orgSetLabel(p, 2);
    orgSetLabel(c, 5);
    bool labelRej = !edgeAdd(p, c, EdgeKind.StrongOwn, 0);  // 5 ⊑ 2 false ⇒ reject
    orgSetLabel(c, 1);
    bool labelOk = edgeAdd(p, c, EdgeKind.StrongOwn, 0);    // 1 ⊑ 2 ⇒ ok

    // 7.1 rights: a Cap edge may not grant more than the parent holds.
    uint pr = objAlloc(ObjType.File, null);
    uint cr = objAlloc(ObjType.File, null);
    orgSetHeldRights(pr, 0x3);                              // parent holds bits 0,1
    bool rightsRej = !edgeAdd(pr, cr, EdgeKind.Cap, 0x7);   // wants bit 2 too ⇒ reject
    bool rightsOk  =  edgeAdd(pr, cr, EdgeKind.Cap, 0x1);   // subset ⇒ ok

    // I6: a Weak/Observer edge carries no authority — never rejected on label/rights.
    uint hi = objAlloc(ObjType.File, null);
    uint lo = objAlloc(ObjType.File, null);
    orgSetLabel(hi, 9);                                     // "secret" object
    bool weakExempt = edgeAdd(lo, hi, EdgeKind.Weak, 0);    // low may *see* it (no grant)

    // 7.3 audit: relabel after the edge to invert monotonicity → audit flags it.
    uint a1 = objAlloc(ObjType.File, null);
    uint a2 = objAlloc(ObjType.File, null);
    bool oe = edgeAdd(a1, a2, EdgeKind.StrongOwn, 0);       // both label 0 ⇒ ok
    uint baseViol = orgLabelAudit();
    g_orgNodes[a2].label = 9; g_orgNodes[a1].label = 1;     // post-hoc inversion
    uint afterViol = orgLabelAudit();
    bool auditFlags = oe && afterViol > baseViol;

    bool ok = labelRej && labelOk && rightsRej && rightsOk && weakExempt && auditFlags;

    objRelease(p); objRelease(c); objRelease(pr); objRelease(cr);
    objRelease(hi); objRelease(lo); objRelease(a1); objRelease(a2);

    if (ok) klog("[org] sec PASS\n");
    else    klog("[org] sec FAIL: behaviour\n");
}

public void orgStats() {
    klog("[org] edges=");   klog_hex(g_orgEdgesLive);
    klog(" adds=");         klog_hex(g_orgEdgeAdds);
    klog(" ensure=");       klog_hex(g_orgEnsureAdds);
    klog(" removes=");      klog_hex(g_orgEdgeRemoves);
    klog(" pruned=");       klog_hex(g_orgPruned);
    klog(" freedrops=");    klog_hex(g_orgFreeDrops);
    klog(" weaknull=");     klog_hex(g_orgWeakNullRead);
    klog(" audit=");        klog_hex(g_orgAuditRuns);
    klog(" i1v=");          klog_hex(g_orgAuditI1Viol);
    klog(" i4v=");          klog_hex(g_orgAuditI4Viol);
    klog(" roots=");        klog_hex(cast(ulong)g_orgRootCount);
    klog(" reach=");        klog_hex(cast(ulong)g_orgReachableCount);
    klog(" scc=");          klog_hex(cast(ulong)g_orgSccCount);
    klog(" ownrej=");       klog_hex(g_orgOwnRejectI1 + g_orgOwnRejectI2);
    klog(" gccand=");       klog_hex(g_orgGcCandidates);
    klog(" weaknull=");     klog_hex(g_orgWeakNulled);
    klog(" pagesrec=");     klog_hex(g_orgPagesReclaimed);
    klog(" quar=");         klog_hex(g_orgQuarantined);
    klog(" secev=");        klog_hex(g_orgSecurityEvents);
    klog(" lblrej=");       klog_hex(g_orgLabelReject);
    klog(" rgtrej=");       klog_hex(g_orgRightsReject);
    klog(" lblviol=");      klog_hex(g_orgLabelViol);
    klog("\n");
}
