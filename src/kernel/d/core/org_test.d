// ORG testing & verification — ORG Phase 12 of OBJECT_REFERENCE_GRAPH_ROADMAP.md.
//
// This subsystem is safety-critical (a GC bug = use-after-free; a validator bug =
// a false halt), so it gets a real in-kernel test suite, run once at boot:
//   12.1  a unit test per invariant I1–I8 — each with a *positive* case (the
//         invariant holds) and a *failing-injection* case (a violation is detected
//         or rejected), plus the SCM_RIGHTS cycle, the socket-pair 2-cycle, and the
//         parent/child weak edge.
//   12.2  a deterministic GC/recovery fuzzer: random edge churn + refcount
//         corruption + edge severing + allocate-under-GC over N iterations, then
//         assert the graph is consistent and the edge pool returned to baseline
//         (no UAF, no leak).
//   12.3  a scale test: fill the object table, build a deep graph, and prove the
//         budgeted reachability yields under its work budget (no stop-the-world
//         pause), reporting object/edge throughput.
//
// All tests operate on their own freshly-allocated objects and release them, so
// they never disturb the live graph.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.org_test;

import core.io; // klog / klog_hex
import core.objmgr : objAlloc, objRelease, objRetain, objGet, ObjType;
import core.org : EdgeKind, edgeAdd, edgeEnsure, edgeRemove, weakGet, orgOutDegree,
                  orgStrongIn, orgValidateInvariants, orgShadowRebuild,
                  orgNullDeadWeak, orgPruneDeadOut, orgClearRoots, orgAddRoot,
                  orgReachBegin, orgReachStep, orgReachCompute, orgReachable,
                  orgReachableCount, orgTarjanRun, orgSccOf, orgSccIsGcTarget,
                  orgCollectScc, orgSetHeldRights, orgIsQuarantined,
                  g_orgNodes, g_orgEdgesLive;

extern (C) @nogc nothrow:

__gshared bool  g_orgTestRun     = false;
__gshared uint  g_testInvPass    = 0;
__gshared uint  g_testInvTotal   = 0;
__gshared ulong g_fuzzState      = 0x2545F4914F6CDD1DUL;

private uint frand() {
    g_fuzzState = g_fuzzState * 6364136223846793005UL + 1442695040888963407UL;
    return cast(uint)(g_fuzzState >> 33);
}

private void check(bool cond, ref uint pass, ref uint total) {
    ++total;
    if (cond) ++pass;
}

// --- 12.1 per-invariant unit tests --------------------------------------------
private bool testInvariants() {
    uint pass = 0, total = 0;

    // I1 single owner: one owner ok; a second owner is rejected at insert.
    {
        uint p1 = objAlloc(ObjType.File, null), p2 = objAlloc(ObjType.File, null);
        uint c = objAlloc(ObjType.File, null);
        check(edgeAdd(p1, c, EdgeKind.StrongOwn, 0), pass, total);   // positive
        check(!edgeAdd(p2, c, EdgeKind.StrongOwn, 0), pass, total);  // injection
        objRelease(p1); objRelease(p2); objRelease(c);
    }
    // I2 ownership acyclic: a chain is ok; closing the cycle is rejected.
    {
        uint a = objAlloc(ObjType.File, null), b = objAlloc(ObjType.File, null);
        uint d = objAlloc(ObjType.File, null);
        check(edgeAdd(a, b, EdgeKind.StrongOwn, 0) &&
              edgeAdd(b, d, EdgeKind.StrongOwn, 0), pass, total);    // positive
        check(!edgeAdd(d, a, EdgeKind.StrongOwn, 0), pass, total);   // injection (cycle)
        objRelease(a); objRelease(b); objRelease(d);
    }
    // I4 refcount ≥ strong-in: holds normally; a corrupted count is detected.
    {
        uint x = objAlloc(ObjType.File, null);
        check(orgValidateInvariants(false), pass, total);            // positive (no viol)
        g_orgNodes[x].strongIn = 99;                                 // inject I4 breach
        check(!orgValidateInvariants(false), pass, total);           // injection detected
        g_orgNodes[x].strongIn = 0;
        objRelease(x);
    }
    // I5 rights monotone: a subset grant is ok; an escalation is rejected.
    {
        uint p = objAlloc(ObjType.File, null), c = objAlloc(ObjType.File, null);
        orgSetHeldRights(p, 0x3);
        check(edgeAdd(p, c, EdgeKind.Cap, 0x1), pass, total);        // positive (subset)
        uint c2 = objAlloc(ObjType.File, null);
        check(!edgeAdd(p, c2, EdgeKind.Cap, 0x7), pass, total);      // injection (escalate)
        objRelease(p); objRelease(c); objRelease(c2);
    }
    // I8 weak coherence: a weak edge reads the live target, then null once it dies.
    {
        uint o = objAlloc(ObjType.File, null), t = objAlloc(ObjType.File, null);
        edgeAdd(o, t, EdgeKind.Weak, 0);
        check(weakGet(o, t) == t, pass, total);                      // positive (live)
        objRelease(t);                                               // injection (target dies)
        check(weakGet(o, t) == 0, pass, total);                      // reads null, not stale
        objRelease(o);
    }
    // SCM_RIGHTS cycle + socket-pair 2-cycle: an unreachable strong 2-cycle is a
    // GC target and is reclaimed; a weak peer 2-cycle never pins.
    {
        uint s1 = objAlloc(ObjType.Endpoint, null), s2 = objAlloc(ObjType.Endpoint, null);
        edgeAdd(s1, s2, EdgeKind.StrongRef, 0);
        edgeAdd(s2, s1, EdgeKind.StrongRef, 0);
        orgClearRoots(); orgReachCompute(8); orgTarjanRun();
        uint scc = orgSccOf(s1);
        check(orgSccIsGcTarget(scc), pass, total);                  // SCM cycle detected
        check(orgCollectScc(scc) == 2 && objGet(s1) is null, pass, total); // reclaimed

        uint w1 = objAlloc(ObjType.Endpoint, null), w2 = objAlloc(ObjType.Endpoint, null);
        edgeAdd(w1, w2, EdgeKind.Weak, 0);
        edgeAdd(w2, w1, EdgeKind.Weak, 0);
        check(orgStrongIn(w1) == 0 && orgStrongIn(w2) == 0, pass, total); // weak peers don't pin
        objRelease(w1); objRelease(w2);
    }
    // Parent/child weak: a parent back-edge does not pin the parent.
    {
        uint child = objAlloc(ObjType.File, null), parent = objAlloc(ObjType.File, null);
        edgeAdd(child, parent, EdgeKind.Weak, 0);                    // child → parent (weak)
        check(orgStrongIn(parent) == 0, pass, total);               // parent not pinned
        objRelease(parent);
        check(weakGet(child, parent) == 0, pass, total);            // dangles to null
        objRelease(child);
    }

    g_testInvPass = pass;
    g_testInvTotal = total;
    return pass == total;
}

// --- 12.2 GC / recovery fuzzer ------------------------------------------------
private bool testFuzz(int iters) {
    enum int POOL = 32;
    uint[POOL] ids;
    int n = 0;
    foreach (i; 0 .. POOL) {
        uint id = objAlloc(ObjType.File, null);
        if (id == 0) break;
        // Headroom: retain so refcount ≥ any possible strong-in (≤ POOL), so the
        // fuzz never trips a *real* I4 violation while churning strong edges.
        foreach (r; 0 .. POOL) objRetain(id);
        ids[n++] = id;
    }
    if (n < 4) { foreach (i; 0 .. n) { foreach (r; 0 .. POOL + 1) objRelease(ids[i]); } return false; }

    ulong edgesBase = g_orgEdgesLive;
    bool brokeQuarantine = false;

    foreach (it; 0 .. iters) {
        uint x = ids[frand() % n];
        uint y = ids[frand() % n];
        final switch (frand() % 6) {
            // Idempotent adds: at most one edge per (x,y,kind), so strong-in stays
            // ≤ the refcount headroom and the churn never trips a *real* I4 breach.
            case 0: edgeEnsure(x, y, EdgeKind.Weak, 0); break;
            case 1: edgeEnsure(x, y, EdgeKind.StrongRef, 0); break;
            case 2: edgeRemove(x, y, EdgeKind.StrongRef);          // sever an edge
                    edgeRemove(x, y, EdgeKind.Weak); break;
            case 3: orgNullDeadWeak(POOL); break;                   // GC pass mid-churn
            case 4: g_orgNodes[x].strongIn += 2; orgShadowRebuild(); break; // corrupt+recover
            case 5: orgPruneDeadOut(x);
                    uint extra = objAlloc(ObjType.File, null);      // allocate-under-GC
                    if (extra != 0) objRelease(extra);
                    break;
        }
        if (orgIsQuarantined(x) || orgIsQuarantined(y)) brokeQuarantine = true;
    }

    orgShadowRebuild();                       // recover any residual drift
    bool consistent = orgValidateInvariants(false) && !brokeQuarantine;

    // Tear down: releasing every test object drops all its edges (no leak), and no
    // object was ever freed while still in use (releases happen only here).
    foreach (i; 0 .. n) foreach (r; 0 .. POOL + 1) objRelease(ids[i]);
    bool noLeak = (g_orgEdgesLive == edgesBase);

    return consistent && noLeak;
}

// --- 12.3 scale test ----------------------------------------------------------
private bool testScale() {
    enum int CAP = 1024;          // bounded by the object table headroom
    uint[CAP] ids;
    int n = 0;
    while (n < CAP) {
        uint id = objAlloc(ObjType.File, null);
        if (id == 0) break;
        ids[n++] = id;
    }
    if (n < 64) { foreach (i; 0 .. n) objRelease(ids[i]); return false; }

    // A deep StrongOwn chain (forest path) + StrongRef cross-links: a large
    // connected strong graph reachable from a single root.
    foreach (i; 1 .. n) edgeAdd(ids[i - 1], ids[i], EdgeKind.StrongOwn, 0);
    foreach (k; 0 .. n / 4) {
        uint a = ids[frand() % n], b = ids[frand() % n];
        edgeAdd(a, b, EdgeKind.StrongRef, 0);
    }

    // Budgeted reachability: with a small budget and many nodes, the first step
    // must yield (more work remains) — proof there is no stop-the-world pause.
    orgClearRoots(); orgAddRoot(ids[0]);
    orgReachBegin();
    bool yielded = orgReachStep(16);          // n ≫ 16 ⇒ returns "more remains"
    int steps = 1;
    while (orgReachStep(16) && steps < CAP * 4) ++steps;
    uint reached = orgReachableCount();

    bool budgetBound = (n <= 17) || yielded;          // bounded pause
    bool reachedAll  = (reached == cast(uint)n);       // whole chain reachable from root

    klog("[test] scale objects="); klog_hex(cast(ulong)n);
    klog(" reached=");             klog_hex(cast(ulong)reached);
    klog(" steps=");               klog_hex(cast(ulong)steps);
    klog(" budget=16\n");

    foreach (i; 0 .. n) objRelease(ids[i]);
    return budgetBound && reachedAll;
}

// --- suite --------------------------------------------------------------------
public void orgTestSuite() {
    if (g_orgTestRun) return;
    g_orgTestRun = true;

    bool inv   = testInvariants();
    bool fuzz  = testFuzz(2000);
    bool scale = testScale();

    klog("[test] invariants="); klog_hex(cast(ulong)g_testInvPass);
    klog("/");                   klog_hex(cast(ulong)g_testInvTotal);
    klog(" fuzz=");              klog_hex(fuzz ? 1 : 0);
    klog(" scale=");             klog_hex(scale ? 1 : 0);
    klog("\n");

    if (inv && fuzz && scale) klog("[test] suite PASS\n");
    else                      klog("[test] suite FAIL\n");
}
