// Distributed object graph — preparation — ORG Phase 11 of
// OBJECT_REFERENCE_GRAPH_ROADMAP.md.
//
// Designs the seams for a future federated object graph so they are cheap later,
// without building any networking (that is the real distributed OS, far off):
//
//   11.1  an object reference becomes `OrgRef{nodeId, objId, epoch}`.  Local ops
//         are unchanged when `nodeId == self` (the ref resolves straight to the
//         object); a remote ref is merely *representable* and never resolves into
//         a local pointer.
//   11.2  cross-node edges are **Weak + leased** only — strong cross-node edges are
//         rejected by construction, so there can be no distributed strong cycle to
//         GC.  A lease must be renewed (a peer heartbeat); expiry = edge death, so a
//         dropped/partitioned peer's remote edges are nulled (reference-listing GC).
//   11.3  lazy cross-node cycle *detection* for diagnostics: a weak cycle that spans
//         nodes is reported but never leaks, because the leases that form it expire.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.org_dist;

import core.io; // klog / klog_hex
import core.objmgr : objGet, objAlloc, objRelease, ObjType;
import core.org : EdgeKind;
import core.audit : auditLog, AuditKind;

extern (C) @nogc nothrow:

// This node's id in the (future) federation.  Local objects carry this nodeId.
enum uint ORG_SELF_NODE = 0;

// 11.1 — a federated object reference.
struct OrgRef {
    uint nodeId;
    uint objId;
    uint epoch;
}

public OrgRef orgRefLocal(uint objId) {
    return OrgRef(ORG_SELF_NODE, objId, 0);
}
public OrgRef orgRefMake(uint nodeId, uint objId, uint epoch) {
    return OrgRef(nodeId, objId, epoch);
}
public bool orgRefIsLocal(OrgRef r) { return r.nodeId == ORG_SELF_NODE; }

// Resolve a ref to a live local object, or null when it is remote or dead.  This
// is the only place "is it ours?" is decided, so local performance is unchanged
// (one comparison) and remote refs simply never produce a local pointer.
public bool orgRefResolves(OrgRef r) {
    return orgRefIsLocal(r) && objGet(r.objId) !is null;
}

// --- 11.2 cross-node (Weak + leased) edges ------------------------------------
enum int ORG_REMOTE_MAX = 128;

struct RemoteEdge {
    bool     inUse;
    uint     fromObjId;   // local object holding the remote reference
    OrgRef   to;          // remote target
    EdgeKind kind;        // Weak or Observer only
    ulong    leaseExpiry; // logical tick by which the lease must be renewed
}

// Reference-listing: leases *other* nodes hold to *our* objects (so we know who
// references us — the basis of distributed reachability without global GC).
struct InboundLease {
    bool  inUse;
    uint  localObjId;
    uint  holderNode;
    ulong expiry;
}

__gshared RemoteEdge[ORG_REMOTE_MAX]   g_remoteEdges;
__gshared InboundLease[ORG_REMOTE_MAX] g_inboundLeases;
__gshared ulong g_distTick = 0;        // this node's logical clock

__gshared ulong g_distEdgesAdded   = 0;
__gshared ulong g_distStrongReject = 0; // cross-node strong edges refused
__gshared ulong g_distExpired      = 0; // remote edges nulled by lease expiry
__gshared ulong g_distCyclesSeen   = 0;

private bool kindWeak(EdgeKind k) {
    return k == EdgeKind.Weak || k == EdgeKind.Observer;
}

// Add a cross-node edge.  Rejects any strong kind (no distributed strong cycles)
// and any non-live local source.  Returns the edge index, or -1.
public int orgRemoteEdgeAdd(uint fromObjId, OrgRef to, EdgeKind kind, ulong leaseTicks) {
    if (objGet(fromObjId) is null) return -1;
    if (orgRefIsLocal(to)) return -1;       // not a cross-node edge
    if (!kindWeak(kind)) { ++g_distStrongReject; return -1; } // strong forbidden
    foreach (i, ref e; g_remoteEdges) {
        if (e.inUse) continue;
        e.inUse = true;
        e.fromObjId = fromObjId;
        e.to = to;
        e.kind = kind;
        e.leaseExpiry = g_distTick + (leaseTicks == 0 ? 1 : leaseTicks);
        ++g_distEdgesAdded;
        return cast(int)i;
    }
    return -1;
}

public bool orgRemoteEdgeLive(int idx) {
    if (idx < 0 || idx >= ORG_REMOTE_MAX) return false;
    auto e = &g_remoteEdges[idx];
    return e.inUse && e.leaseExpiry > g_distTick && objGet(e.fromObjId) !is null;
}

// Renew a lease (a peer heartbeat extends the edge's life).
public bool orgRemoteRenew(int idx, ulong leaseTicks) {
    if (idx < 0 || idx >= ORG_REMOTE_MAX || !g_remoteEdges[idx].inUse) return false;
    g_remoteEdges[idx].leaseExpiry = g_distTick + (leaseTicks == 0 ? 1 : leaseTicks);
    return true;
}

// Record that `holderNode` holds a lease to our `localObjId` (reference-listing).
public int orgInboundLeaseAdd(uint localObjId, uint holderNode, ulong leaseTicks) {
    if (objGet(localObjId) is null) return -1;
    foreach (i, ref l; g_inboundLeases) {
        if (l.inUse) continue;
        l.inUse = true;
        l.localObjId = localObjId;
        l.holderNode = holderNode;
        l.expiry = g_distTick + (leaseTicks == 0 ? 1 : leaseTicks);
        return cast(int)i;
    }
    return -1;
}

public uint orgInboundLeaseCount(uint localObjId) {
    uint n = 0;
    foreach (ref l; g_inboundLeases)
        if (l.inUse && l.localObjId == localObjId && l.expiry > g_distTick) ++n;
    return n;
}

// Advance the logical clock by `dticks` and reclaim every remote edge / inbound
// lease whose lease has expired (reference-listing GC).  Returns #reclaimed.  In
// production (no peers) there are no remote edges, so this is a no-op.
public uint orgDistTick(ulong dticks) {
    g_distTick += (dticks == 0 ? 1 : dticks);
    uint reclaimed = 0;
    foreach (ref e; g_remoteEdges) {
        if (e.inUse && (e.leaseExpiry <= g_distTick || objGet(e.fromObjId) is null)) {
            e = RemoteEdge.init; ++reclaimed; ++g_distExpired;
        }
    }
    foreach (ref l; g_inboundLeases)
        if (l.inUse && (l.expiry <= g_distTick || objGet(l.localObjId) is null)) {
            l = InboundLease.init; ++reclaimed;
        }
    return reclaimed;
}

// 11.3 — lazy cross-node cycle detection (diagnostics only): a weak cycle spans
// nodes when we hold a remote edge to node N and node N holds a lease back to one
// of our objects.  Report it; it cannot leak because both ends are leased.
public bool orgDetectCrossNodeCycle() {
    bool found = false;
    foreach (ref e; g_remoteEdges) {
        if (!e.inUse) continue;
        foreach (ref l; g_inboundLeases) {
            if (l.inUse && l.holderNode == e.to.nodeId) {
                found = true;
                ++g_distCyclesSeen;
                auditLog(AuditKind.CycleFound, l.localObjId, e.to.nodeId);
            }
        }
    }
    return found;
}

// --- self-test (runtime proof) ------------------------------------------------
// 11.1 a local ref resolves and a remote ref is representable but does not; 11.2 a
// leased remote weak edge survives within its lease, expires (is nulled) once the
// lease lapses without renewal, and a strong cross-node edge is rejected; 11.3 a
// synthetic cross-node weak cycle is reported and then reclaimed by lease expiry.
__gshared bool g_distTested = false;
public void orgDistSelfTest() {
    if (g_distTested) return;
    g_distTested = true;

    uint a = objAlloc(ObjType.File, null);
    if (a == 0) { klog("[dist] selftest FAIL: alloc\n"); return; }

    // 11.1
    OrgRef lr = orgRefLocal(a);
    OrgRef rr = orgRefMake(7, 99, 1);
    bool p111 = orgRefIsLocal(lr) && orgRefResolves(lr) &&
                !orgRefIsLocal(rr) && !orgRefResolves(rr);

    // 11.2
    int e = orgRemoteEdgeAdd(a, orgRefMake(7, 100, 1), EdgeKind.Weak, 3);
    bool added = (e >= 0 && orgRemoteEdgeLive(e));
    orgDistTick(2);                       // within lease (2 < 3)
    bool alive = orgRemoteEdgeLive(e);
    orgDistTick(2);                       // total 4 > 3 ⇒ expired + nulled
    bool expired = !orgRemoteEdgeLive(e);
    bool strongRej = (orgRemoteEdgeAdd(a, orgRefMake(7, 101, 1), EdgeKind.StrongRef, 3) < 0);
    bool p112 = added && alive && expired && strongRej;

    // 11.3
    int e2 = orgRemoteEdgeAdd(a, orgRefMake(8, 200, 1), EdgeKind.Weak, 2);
    orgInboundLeaseAdd(a, 8, 2);          // node 8 references us back
    bool cycle = orgDetectCrossNodeCycle();
    orgDistTick(3);                       // leases lapse
    bool reclaimed = (!orgRemoteEdgeLive(e2) && orgInboundLeaseCount(a) == 0);
    bool p113 = (e2 >= 0 && cycle && reclaimed);

    objRelease(a);

    if (p111 && p112 && p113) klog("[dist] selftest PASS\n");
    else                      klog("[dist] selftest FAIL\n");
}

public void orgDistStats() {
    klog("[dist] node=");   klog_hex(cast(ulong)ORG_SELF_NODE);
    klog(" tick=");         klog_hex(g_distTick);
    klog(" radded=");       klog_hex(g_distEdgesAdded);
    klog(" expired=");      klog_hex(g_distExpired);
    klog(" strongrej=");    klog_hex(g_distStrongReject);
    klog(" cycles=");       klog_hex(g_distCyclesSeen);
    klog("\n");
}
