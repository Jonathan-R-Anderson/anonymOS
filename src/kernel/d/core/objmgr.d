// Object Manager — Phase 2 of roadmap/OBJECT_OS_ROADMAP.md.
//
// Introduces the common `Object` header + a central object table that all
// subsystems will eventually adopt (files, processes, memory regions, devices,
// ...).  In this phase it is ADDITIVE and not on the dispatch path: it mirrors
// the existing fd layer so we can prove "every fd is an entry in g_objects"
// before any behaviour is routed through `g_objOps` (that is Phase 5).
//
// Constraints: kernel is built `-betterC` (ldc2, no druntime/GC/exceptions) —
// plain structs, __gshared fixed tables, function pointers, @nogc nothrow.
// File is named objmgr.d (module core.objmgr) rather than object.d to avoid any
// ambiguity with D's special root `object` module.
module core.objmgr;

import core.io; // klog / klog_hex

extern (C) @nogc nothrow:

// Every kind of thing that can become an object.  Order is stable (ids are
// persisted nowhere yet, but treat additions as append-only).  `Count` is the
// sentinel = number of real types, used to size the method-table array.
enum ObjType : uint {
    Invalid = 0,
    File,
    Process,
    Thread,
    MemRegion,
    Vmo,
    Directory,
    Device,
    Driver,
    NetIf,
    Window,
    User,
    Service,
    Namespace,
    Capability,
    Endpoint,
    LinuxProcess,
    LinuxVFS,           // Phase 12: Linux VFS view object
    LinuxSyscall,       // Phase 12: Linux syscall translator object
    LinuxELFLoader,     // Phase 12: Linux ELF-loader object
    LinuxDeviceAdapter, // Phase 12: native Device → /dev/* adapter object
    Untyped,            // IMMUTABLE_ROOTLESS §1.4: untyped-memory capability
    Admin,              // IMMUTABLE_ROOTLESS §3.2: typed admin authority object
    Count
}

// The common object header.  `impl` points at the subsystem payload that backs
// this object (e.g. a `File` slot, a `Task`, an `AddrRegion`) — what used to be
// the per-instance `void* backend`.  `ownerCap`/`version_` are hooks for the
// capability owner (Phase 6) and version history; unused but reserved now.
struct ObjHeader {
    uint    id;        // dense index into g_objects (0 == the invalid object)
    ObjType type;
    uint    refCount;  // 0 == free slot
    uint    ownerCap;  // capability id of owner (Phase 6); 0 for now
    uint    version_;  // metadata / version-history hook
    uint    mark;      // mark-sweep generation (Phase 3 reconcile; ORG-roadmap GC)
    void*   impl;      // subsystem payload
}

enum int OBJ_MAX = 8192;
__gshared ObjHeader[OBJ_MAX] g_objects;

// Free-list stack of available slot indices (ids 1..OBJ_MAX-1; id 0 is the
// reserved "invalid" object so a 0 handle always means "none").
__gshared uint[OBJ_MAX] g_objFree;
__gshared int           g_objFreeTop = -1;
__gshared bool          g_objInited  = false;

__gshared ulong g_objAllocTotal = 0;
__gshared ulong g_objFreeTotal  = 0;
__gshared uint  g_objLive        = 0;
__gshared uint  g_objPeak        = 0;

// ORG hook (OBJECT_REFERENCE_GRAPH_ROADMAP.md P2): when an object slot is freed,
// the Object Reference Graph layer is notified so it can drop the object's
// out-edges and stale its weak in-edges.  Set by core/org.d at init; null until
// then (objmgr must not depend on org — this avoids the import cycle).
__gshared void function(uint id) @nogc nothrow g_objFreeNotify = null;

private void objInit() {
    if (g_objInited) return;
    g_objInited = true;
    g_objects[0] = ObjHeader.init;          // id 0 = invalid sentinel
    g_objFreeTop = -1;
    for (int i = OBJ_MAX - 1; i >= 1; --i)  // hand out low ids first
        g_objFree[++g_objFreeTop] = cast(uint)i;
}

// Per-type method table.  Phase 5 routes fd/file behaviour through these
// methods; null slots mean "operation not implemented for this object type".
alias ObjReadFn  = long function(ObjHeader*, void*, ulong) @nogc nothrow;
alias ObjWriteFn = long function(ObjHeader*, const(void)*, ulong) @nogc nothrow;
alias ObjCloseFn = long function(ObjHeader*) @nogc nothrow;
alias ObjStatFn  = long function(ObjHeader*, ulong) @nogc nothrow;
alias ObjIoctlFn = long function(ObjHeader*, ulong, ulong) @nogc nothrow;
alias ObjMmapFn  = long function(ObjHeader*, ulong, ulong*, ulong*, uint*, bool*) @nogc nothrow;
struct ObjOps {
    ObjReadFn  read;
    ObjWriteFn write;
    ObjCloseFn close;
    ObjStatFn  stat;
    ObjIoctlFn ioctl;
    ObjMmapFn  mmap;
}
__gshared ObjOps[ObjType.Count] g_objOps;

// Phase 5: count of I/O operations actually serviced through the g_objOps method
// table (rather than the legacy switch).  Runtime proof that behaviour flows
// through the object model; printed by objStats().
__gshared ulong g_objOpsDispatch = 0;

// Allocate a new object of `type` backed by `impl`.  Returns its id, or 0 if the
// table is full (callers tolerate 0 = "untracked" — nothing depends on the
// object table for behaviour in Phase 2).
public uint objAlloc(ObjType t, void* impl) {
    objInit();
    if (g_objFreeTop < 0) return 0;
    uint id = g_objFree[g_objFreeTop--];
    auto h = &g_objects[id];
    h.id       = id;
    h.type     = t;
    h.refCount = 1;
    h.ownerCap = 0;
    h.version_ = 0;
    h.mark     = 0;
    h.impl     = impl;
    ++g_objAllocTotal;
    ++g_objLive;
    if (g_objLive > g_objPeak) g_objPeak = g_objLive;
    return id;
}

public ObjHeader* objGet(uint id) {
    if (id == 0 || id >= OBJ_MAX) return null;
    auto h = &g_objects[id];
    return (h.refCount == 0) ? null : h;
}

public void objRetain(uint id) {
    auto h = objGet(id);
    if (h !is null) ++h.refCount;
}

// Drop a reference; frees the slot at refcount 0.  Idempotent / underflow-safe so
// a stray double-release (possible while the object table is still a best-effort
// mirror) can never corrupt the kernel.
public void objRelease(uint id) {
    auto h = objGet(id);
    if (h is null) return;
    if (--h.refCount == 0) {
        h.type = ObjType.Invalid;
        h.impl = null;
        if (g_objFreeTop < OBJ_MAX - 1)
            g_objFree[++g_objFreeTop] = id;
        ++g_objFreeTotal;
        if (g_objLive > 0) --g_objLive;
        if (g_objFreeNotify !is null) g_objFreeNotify(id); // ORG P2: drop edges
    }
}

// Number of live objects of a given type (linear scan; only used by stats/sweep,
// never on a hot path).
public uint objCountType(ObjType t) {
    uint n = 0;
    for (uint i = 1; i < OBJ_MAX; ++i)
        if (g_objects[i].refCount != 0 && g_objects[i].type == t) ++n;
    return n;
}

// --- Mark-sweep reconciliation support (Phase 3) ---------------------------
// Subsystems whose backing slots are NOT address-stable (e.g. AddrRegion moves
// under swap-remove / whole-Task fork copies) cannot be mirrored by the simple
// impl-pointer check alone: a moved slot orphans its old object.  A mark-sweep
// pass over one ObjType reclaims exactly those orphans.  Generation never reuses
// 0 so a freshly-objAlloc'd object (mark==0) is never mistaken for "marked".
__gshared uint g_objMarkGen = 1;

public void objBeginSweep() {
    if (++g_objMarkGen == 0) g_objMarkGen = 1; // skip 0 on wrap
}

public void objMark(uint id) {
    auto h = objGet(id);
    if (h !is null) h.mark = g_objMarkGen;
}

// Free every live object of type `t` not marked in the current generation.
public void objSweepType(ObjType t) {
    for (uint i = 1; i < OBJ_MAX; ++i) {
        auto h = &g_objects[i];
        if (h.refCount != 0 && h.type == t && h.mark != g_objMarkGen)
            objRelease(i);
    }
}

public void objStats() {
    klog("[obj] live="); klog_hex(cast(ulong)g_objLive);
    klog(" peak=");      klog_hex(cast(ulong)g_objPeak);
    klog(" alloc=");     klog_hex(g_objAllocTotal);
    klog(" freed=");     klog_hex(g_objFreeTotal);
    klog(" file=");      klog_hex(cast(ulong)objCountType(ObjType.File));
    klog(" mem=");       klog_hex(cast(ulong)objCountType(ObjType.MemRegion));
    klog(" vmo=");       klog_hex(cast(ulong)objCountType(ObjType.Vmo));
    klog(" proc=");      klog_hex(cast(ulong)objCountType(ObjType.Process));
    klog(" thread=");    klog_hex(cast(ulong)objCountType(ObjType.Thread));
    klog(" admin=");     klog_hex(cast(ulong)objCountType(ObjType.Admin));
    klog(" opdisp=");    klog_hex(g_objOpsDispatch);
    klog("\n");
}
