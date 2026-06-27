// Domain writable overlay — DM6.2 of roadmap/domain_manager.md.
//
// A running domain layers a WRITABLE overlay over its immutable template/base:
//
//     immutable base Generation (lower)  →  writable overlay (upper)  →  merged view
//
// The overlay is backed by the REAL content-addressed store (core/store.d): a copy-up
// write is a `storePut` (dedup'd, immutable StoreObject); a snapshot/commit is a
// `genCreate` (an immutable Generation parented on the previous one).  Because every
// Generation + StoreObject is content-addressed and immutable, **commit can never mutate
// the existing template** — it produces a NEW base Generation whose parent is the old one;
// the old base and any snapshot are untouched.  That immutability is the security invariant
// the overlay must hold, and content-addressing gives it for free.
//
// DM6.2 is the overlay CONTROL plane (create / write-copyup / snapshot / restore / discard /
// commit) proven against the real store.  The DATA plane — hooking actual `rtCreate` file
// writes into `overlayWrite` (copy-up at the rtfs level) — is the remaining DM6 integration.
//
// Kernel constraints: -betterC, plain structs, __gshared fixed tables, @nogc nothrow.
module core.overlay;

import core.objmgr : ObjType, objAlloc, objRelease, objGet;
import core.store  : storePut, genCreate, genNumber, genParent, genCount, genEntry;
import core.io     : klog, klog_hex;

extern (C) @nogc nothrow:

enum int OVL_MAX     = 8;     // concurrent domain overlays
enum int OVL_ENTRIES = 8;     // copy-up StoreObjects per overlay (== GEN_ENTRY_MAX)

struct OverlayRec {
    bool inUse;
    uint objId;                  // ObjType.Overlay
    uint domObjId;               // the domain this overlay belongs to
    uint baseGen;                // the immutable template/base Generation (the lower layer)
    uint lastSnap;               // most recent snapshot Generation (lineage parent)
    uint count;                  // number of copy-up entries (writable changes)
    uint[OVL_ENTRIES] entries;   // StoreObject ids of the writable changes
}
__gshared OverlayRec[OVL_MAX] g_overlays;
__gshared bool g_ovlSelfTested = false;

private OverlayRec* ovlByDom(uint domObjId) {
    if (domObjId == 0) return null;
    foreach (ref o; g_overlays) if (o.inUse && o.domObjId == domObjId) return &o;
    return null;
}

// Create a writable overlay over `baseGen` for a domain.  baseGen 0 ⟹ allocate a fresh empty
// base Generation (a domain with no template content yet).  Idempotent per domain.
public uint overlayCreate(uint domObjId, uint baseGen) {
    if (domObjId == 0) return 0;
    if (auto ex = ovlByDom(domObjId)) return ex.objId;
    foreach (ref o; g_overlays) if (!o.inUse) {
        const uint id = objAlloc(ObjType.Overlay, cast(void*)&o);
        if (id == 0) return 0;
        o = OverlayRec.init;
        o.inUse = true;
        o.objId = id;
        o.domObjId = domObjId;
        o.baseGen = (baseGen != 0) ? baseGen : genCreate(0, null, 0);   // fresh empty base
        return id;
    }
    return 0;
}

public void overlayDestroy(uint domObjId) {
    auto o = ovlByDom(domObjId);
    if (o is null) return;
    objRelease(o.objId);
    *o = OverlayRec.init;
}

// A copy-up write: store the content (content-addressed, dedup'd) + track it as a change.
public bool overlayWrite(uint domObjId, const(ubyte)* data, uint len) {
    auto o = ovlByDom(domObjId);
    if (o is null || o.count >= OVL_ENTRIES) return false;
    const uint so = storePut(data, len);
    if (so == 0) return false;
    o.entries[o.count++] = so;
    return true;
}

public uint overlayChangeCount(uint domObjId) { auto o = ovlByDom(domObjId); return o is null ? 0 : o.count; }
public uint overlayBaseGen(uint domObjId)     { auto o = ovlByDom(domObjId); return o is null ? 0 : o.baseGen; }

// Inspect diff: the i-th changed StoreObject of the overlay (the pending changes vs the base).
public uint overlayEntryAt(uint domObjId, uint i) {
    auto o = ovlByDom(domObjId);
    return (o is null || i >= o.count) ? 0 : o.entries[i];
}

// Validate before commit: an overlay is committable iff it has at least one change and every
// change is still a live StoreObject (none dropped/garbage-collected).  Empty ⟹ nothing to fold.
public bool overlayValidate(uint domObjId) {
    auto o = ovlByDom(domObjId);
    if (o is null || o.count == 0) return false;
    foreach (i; 0 .. o.count)
        if (o.entries[i] == 0 || objGet(o.entries[i]) is null) return false;
    return true;
}

// Snapshot: freeze the current overlay as an immutable Generation (parent = the previous
// snapshot, so snapshots form a lineage).  Returns the snapshot Generation id.
public uint overlaySnapshot(uint domObjId) {
    auto o = ovlByDom(domObjId);
    if (o is null) return 0;
    const uint snap = genCreate(o.lastSnap, o.entries.ptr, o.count);
    if (snap != 0) o.lastSnap = snap;
    return snap;
}

// Discard: drop the writable changes (revert to the template/base — an empty overlay).
public void overlayDiscard(uint domObjId) {
    auto o = ovlByDom(domObjId);
    if (o !is null) o.count = 0;
}

// Restore the overlay's changes from a snapshot Generation.
public bool overlayRestore(uint domObjId, uint snapGen) {
    auto o = ovlByDom(domObjId);
    if (o is null) return false;
    const uint n = genCount(snapGen);
    if (n > OVL_ENTRIES) return false;
    foreach (uint i; 0 .. n) o.entries[i] = genEntry(snapGen, i);
    o.count = n;
    return true;
}

// Commit: fold the overlay into a NEW base Generation (parent = the current base).  The OLD
// base + its StoreObjects are content-addressed + immutable → never mutated.  The domain's
// base advances to the new Generation and the overlay is cleared.  Returns the new base.
public uint overlayCommit(uint domObjId) {
    auto o = ovlByDom(domObjId);
    if (o is null) return 0;
    if (!overlayValidate(domObjId)) return 0;        // validate before commit (deny-by-default)
    const uint newBase = genCreate(o.baseGen, o.entries.ptr, o.count);
    if (newBase == 0) return 0;
    o.baseGen = newBase;
    o.count = 0;
    return newBase;
}

// DM6.2 boot proof: exercise the full overlay control plane against the real store and assert
// the immutability invariant — a commit creates a NEW base Generation parented on the old one;
// the old base + the snapshot are UNCHANGED (content-addressing guarantees it).
public void overlaySelfTest() {
    if (g_ovlSelfTested) return;
    g_ovlSelfTested = true;

    const uint dom = 0x0D000001;                       // a fake domain id token (never deref'd)
    const uint base = genCreate(0, null, 0);           // an empty "template" base generation
    const uint ov = overlayCreate(dom, base);
    bool ok = (ov != 0) && (overlayBaseGen(dom) == base);

    static immutable ubyte[3] a = ['f','o','o'];
    static immutable ubyte[3] b = ['b','a','r'];
    ok = ok && overlayWrite(dom, a.ptr, 3) && overlayWrite(dom, b.ptr, 3);
    ok = ok && (overlayChangeCount(dom) == 2);
    ok = ok && overlayValidate(dom) && (overlayEntryAt(dom, 0) != 0);   // inspect-diff + validate-before-commit

    const uint snap = overlaySnapshot(dom);            // immutable snapshot of the 2 changes
    ok = ok && (snap != 0) && (genCount(snap) == 2);

    static immutable ubyte[4] c = ['b','a','z','!'];
    ok = ok && overlayWrite(dom, c.ptr, 4) && (overlayChangeCount(dom) == 3);
    overlayDiscard(dom);                               // revert to base (empty)
    ok = ok && (overlayChangeCount(dom) == 0) && (genCount(snap) == 2);   // snapshot untouched
    ok = ok && !overlayValidate(dom);                  // an empty overlay is NOT committable

    ok = ok && overlayRestore(dom, snap) && (overlayChangeCount(dom) == 2);
    ok = ok && overlayValidate(dom);                   // restored ⟹ committable again

    const uint oldBase = overlayBaseGen(dom);
    const uint newBase = overlayCommit(dom);
    ok = ok && (newBase != 0) && (newBase != oldBase)
            && (genParent(newBase) == oldBase)         // lineage: new version parents the old
            && (genCount(newBase) == 2)                // the overlay's changes folded into the new base
            && (genCount(oldBase) == 0)                // ★ the OLD base is UNCHANGED (immutable)
            && (overlayChangeCount(dom) == 0);         // overlay cleared after commit

    overlayDestroy(dom);
    if (ok) klog("[overlay] selftest PASS (write/snapshot/discard/restore/inspect-diff/validate/commit; commit never mutates the base)\n");
    else    klog("[overlay] selftest FAIL\n");
}
