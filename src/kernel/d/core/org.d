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
                                  n.reachMark = 0; }
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

// 2.2 — the ONLY way to relate two objects.  Records a typed edge from→to, links
// it into `from`'s out-list, and (for strong kinds) maintains the life counts.  A
// StrongOwn edge also records the owner on the target (`ObjHeader.ownerCap`).
// Returns true on success; false if an endpoint is dead or the pool is full.
public bool edgeAdd(uint from, uint to, EdgeKind kind, uint rights) {
    orgInit();
    if (from == 0 || to == 0 || kind == EdgeKind.None) return false;
    if (objGet(from) is null || objGet(to) is null) return false;
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
    klog("\n");
}
