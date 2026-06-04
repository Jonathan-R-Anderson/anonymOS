// Untyped → typed memory — IMMUTABLE_ROOTLESS_ROADMAP §1.4.
//
// Makes RAM a **delegated, accountable capability** instead of ambient: an
// `Untyped` object is a budget of physical pages; allocating (retyping) consumes
// from it, and a task with no untyped capability (or an exhausted one) cannot
// allocate.  Budgets sub-divide parent→child (a child can never get more than its
// parent holds) — the seL4 untyped-retype / Genode resource-from-parent model, and
// the fix for §G mistake #3 ("ambient allocation").
//
// In the additive, desktop-safe spirit of the prior phases this lands with a
// generous per-process budget and the public physical allocator wired through
// `untypedRetype`: a task with no selected Untyped object is denied once the boot
// gate is enabled.  The self-test proves denial on a small sandbox budget while
// the production budget stays large enough for the current desktop guest.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.untyped;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;

extern (C) @nogc nothrow:

enum int   UNTYPED_MAX = 128;
enum uint  UNTYPED_CAP_HANDLE = 1024; // outside the Linux fd range 0..1023
// Generous per-process / root budget (pages).  4 GiB worth at 4 KiB pages — large
// enough that the live accounting never denies in a 512 MiB guest, while the gate
// is real (a sandbox created with a small budget is denied; see the self-test).
enum ulong UNTYPED_PROC_PAGES = 0x100000;

struct UntypedRec {
    bool  inUse;
    uint  objId;        // ObjType.Untyped
    uint  parentObjId;  // untyped this was sub-divided from (0 = root / no parent)
    bool  parentReserved;
    ulong total;        // budget, in pages
    ulong used;         // pages retyped (consumed) or reserved by children
}

__gshared UntypedRec[UNTYPED_MAX] g_untyped;
__gshared uint  g_rootUntyped     = 0;
__gshared bool  g_untypedInited    = false;
__gshared bool  g_untypedSelfTested = false;

__gshared ulong g_untypedCreated   = 0;
__gshared ulong g_untypedRetyped   = 0;  // successful retypes (pages)
__gshared ulong g_untypedDenied    = 0;  // allocations refused (no/insufficient budget)
__gshared ulong g_untypedReleased  = 0;

private UntypedRec* byObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref u; g_untyped)
        if (u.inUse && u.objId == objId) return &u;
    return null;
}

// Create an untyped budget of `pages`, sub-divided from `parentObjId` when
// `reserve` is set (the parent's free budget is charged, and a child may never
// exceed it).  `parentObjId == 0` creates a root/unparented budget.  Returns the
// new object id, or 0 on exhaustion / over-subscription.
public uint untypedCreate(uint parentObjId, ulong pages, bool reserve) {
    UntypedRec* parent = null;
    if (parentObjId != 0) {
        parent = byObj(parentObjId);
        if (parent is null) return 0;
        if (pages > parent.total) { ++g_untypedDenied; return 0; }
        if (reserve && parent.total - parent.used < pages) { ++g_untypedDenied; return 0; }
    }
    foreach (ref u; g_untyped) {
        if (u.inUse) continue;
        uint id = objAlloc(ObjType.Untyped, cast(void*)&u);
        if (id == 0) return 0;
        u = UntypedRec.init;
        u.inUse = true;
        u.objId = id;
        u.parentObjId = parentObjId;
        u.parentReserved = reserve && parent !is null;
        u.total = pages;
        u.used = 0;
        if (reserve && parent !is null) parent.used += pages; // narrowing reservation
        ++g_untypedCreated;
        return id;
    }
    return 0;
}

// Strict sub-allocation: a child budget reserved from (and never exceeding) parent.
public uint untypedSubdivide(uint parentObjId, ulong pages) {
    return untypedCreate(parentObjId, pages, true);
}

public void untypedRootInit() {
    if (g_untypedInited) return;
    g_untypedInited = true;
    g_rootUntyped = untypedCreate(0, UNTYPED_PROC_PAGES * UNTYPED_MAX, false);
}

// THE ALLOCATION GATE: retype `pages` out of `untypedObjId` into a typed
// allocation.  A null/absent untyped (no capability) or an over-budget request is
// **refused** — this is "no ambient allocation".  Returns true on success.
public bool untypedRetype(uint untypedObjId, ulong pages) {
    auto u = byObj(untypedObjId);
    if (u is null) { ++g_untypedDenied; return false; }        // no cap ⇒ no memory
    if (u.total - u.used < pages) { ++g_untypedDenied; return false; }
    u.used += pages;
    g_untypedRetyped += pages;
    return true;
}

// Return `pages` to a budget (a typed object was freed).
public void untypedRelease(uint untypedObjId, ulong pages) {
    auto u = byObj(untypedObjId);
    if (u is null) return;
    if (pages > u.used) pages = u.used;
    u.used -= pages;
    g_untypedReleased += pages;
}

// Recompute live usage (used by the per-process accounting reconcile) — sets
// `used` directly, clamped to the budget; off the hot path.
public void untypedSetUsed(uint untypedObjId, ulong pages) {
    auto u = byObj(untypedObjId);
    if (u is null) return;
    u.used = (pages > u.total) ? u.total : pages;
}

// Destroy an untyped budget, returning any reservation to its parent.
public void untypedDestroy(uint untypedObjId) {
    auto u = byObj(untypedObjId);
    if (u is null) return;
    if (u.parentObjId != 0 && u.parentReserved) {
        auto parent = byObj(u.parentObjId);
        if (parent !is null && parent.used >= u.total) parent.used -= u.total;
    }
    objRelease(u.objId);
    *u = UntypedRec.init;
}

public ulong untypedAvail(uint objId) { auto u = byObj(objId); return (u is null) ? 0 : u.total - u.used; }
public ulong untypedTotal(uint objId) { auto u = byObj(objId); return (u is null) ? 0 : u.total; }
public ulong untypedUsed(uint objId)  { auto u = byObj(objId); return (u is null) ? 0 : u.used; }

// A generous per-process budget (a child of root by lineage; not hard-reserved, so
// processes don't starve each other — an over-commit model, like Linux), used for
// the live memory accounting.
public uint untypedCreateProcess(uint parentUntyped) {
    uint p = (parentUntyped != 0 && byObj(parentUntyped) !is null) ? parentUntyped : g_rootUntyped;
    return untypedCreate(p, UNTYPED_PROC_PAGES, false);
}

// --- self-test (runtime proof) ------------------------------------------------
// The budget mechanism: a child is sub-divided from a parent and may not exceed
// it; retype consumes the budget and is **denied** past it; a task with no untyped
// capability cannot allocate at all (no ambient allocation); release returns pages.
public void untypedSelfTest() {
    if (g_untypedSelfTested) return;
    g_untypedSelfTested = true;
    untypedRootInit();

    uint root = untypedCreate(0, 100, false);
    if (root == 0) { klog("[untyped] selftest FAIL: root\n"); return; }

    uint child = untypedSubdivide(root, 30);              // reserve 30 of 100
    bool sub = (child != 0 && untypedTotal(child) == 30 && untypedUsed(root) == 30);
    bool overSub = (untypedSubdivide(root, 1000) == 0);   // can't exceed parent's 70 left

    bool r1 = untypedRetype(child, 20);                   // consume 20 of 30
    bool deny = !untypedRetype(child, 20);                // only 10 left ⇒ refused
    bool ambient = !untypedRetype(0, 1);                  // no untyped cap ⇒ refused
    untypedRelease(child, 20);                            // give the 20 back
    bool released = (untypedAvail(child) == 30);

    bool ok = sub && overSub && r1 && deny && ambient && released;

    untypedDestroy(child);
    untypedDestroy(root);

    if (ok) klog("[untyped] selftest PASS\n");
    else    klog("[untyped] selftest FAIL: behaviour\n");
}

public void untypedStats() {
    klog("[untyped] objs="); klog_hex(cast(ulong)objCountType(ObjType.Untyped));
    klog(" created=");       klog_hex(g_untypedCreated);
    klog(" retyped=");       klog_hex(g_untypedRetyped);
    klog(" denied=");        klog_hex(g_untypedDenied);
    klog(" released=");      klog_hex(g_untypedReleased);
    klog(" rootavail=");     klog_hex(untypedAvail(g_rootUntyped));
    klog("\n");
}
