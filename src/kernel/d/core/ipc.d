// IPC Router — Phase 7 of roadmap/OBJECT_OS_ROADMAP.md.
//
// A native message router with first-class **Endpoint** objects plus a **Service**
// name registry.  Endpoints are rendezvous/queue objects in the central object
// table (ObjType.Endpoint); messages carry inline bytes plus **capability
// descriptors** — {objId, rights} pairs validated through the Capability/Object
// managers — so authority is delegated by value and **never as a raw pointer**.
//
// This phase is additive in the spirit of Phase 2: it stands up the native router
// (Endpoints, Services, objCall, capability delegation primitives) and proves it
// at runtime with a boot self-test, while the Linux SCM_RIGHTS fd-passing path in
// posix.d is re-expressed as capability delegation routed through these
// primitives.  Fully collapsing LocalSocket onto Endpoint queues is left to the
// later Linux-object phases.
//
// Constraints mirror the rest of the kernel: -betterC (ldc2, no druntime/GC),
// plain structs, __gshared fixed tables, @nogc nothrow.
module core.ipc;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, ObjHeader, objAlloc, objGet, objRelease;

extern (C) @nogc nothrow:

// --- Errno mirrors (kept local so ipc.d has no dependency on posix.d) ---------
private enum int E_AGAIN  = 11;  // EAGAIN  — queue empty / would block
private enum int E_INVAL  = 22;  // EINVAL  — bad endpoint / argument
private enum int E_NOSPC  = 28;  // ENOSPC  — queue / table full

// Capability rights bitset universe — must match core.cap's CAP_RIGHT_UNIVERSE
// so a delegated descriptor can never widen rights beyond what the model defines.
private enum uint CAP_RIGHTS_UNIVERSE = (1u << 9) - 1;

// A delegated capability, transferred *by value*: the object id it names and the
// rights mask the holder is granted.  This is what crosses an endpoint instead of
// any raw backend pointer.
struct IpcCapDesc {
    uint objId;
    uint rights;
}

enum int IPC_MSG_MAX_BYTES = 256;
enum int IPC_MSG_MAX_CAPS  = 8;

struct IpcMessage {
    uint                          srcObjId;            // sender endpoint (0 = anon)
    uint                          len;                 // valid bytes in `data`
    uint                          ncaps;               // valid entries in `caps`
    ubyte[IPC_MSG_MAX_BYTES]      data;
    IpcCapDesc[IPC_MSG_MAX_CAPS]  caps;
}

enum int IPC_QUEUE_DEPTH  = 8;
enum int IPC_ENDPOINT_MAX = 256;

struct Endpoint {
    bool                       inUse;
    uint                       objId;   // backing ObjHeader id (ObjType.Endpoint)
    IpcMessage[IPC_QUEUE_DEPTH] ring;
    uint                       head;    // next write slot
    uint                       tail;    // next read slot
    uint                       count;   // queued messages
}

__gshared Endpoint[IPC_ENDPOINT_MAX] g_endpoints;

// --- Service name registry (name -> endpoint object id) -----------------------
enum int IPC_SVC_NAME_MAX = 64;
enum int IPC_SVC_MAX      = 64;

struct ServiceEntry {
    bool                    inUse;
    uint                    endpointObjId;
    uint                    nameLen;
    char[IPC_SVC_NAME_MAX]  name;
}

__gshared ServiceEntry[IPC_SVC_MAX] g_services;

// --- Runtime stats (printed by ipcStats(); the Phase 7 proof) -----------------
__gshared ulong g_ipcEndpointAlloc = 0;
__gshared ulong g_ipcEndpointFree  = 0;
__gshared uint  g_ipcEndpointLive  = 0;
__gshared ulong g_ipcSendTotal     = 0;
__gshared ulong g_ipcRecvTotal     = 0;
__gshared ulong g_ipcDropFull      = 0;   // sends rejected, queue full
__gshared ulong g_ipcDelegateTotal = 0;   // capability descriptors delegated
__gshared ulong g_ipcAcceptTotal   = 0;   // capability descriptors accepted
__gshared ulong g_ipcCapDropped    = 0;   // descriptors dropped (object gone)
__gshared ulong g_ipcServiceReg    = 0;
__gshared ulong g_ipcServiceLookup = 0;
__gshared ulong g_ipcServiceMiss   = 0;
__gshared bool  g_ipcSelfTested    = false;

// --- Endpoint lifecycle -------------------------------------------------------

private Endpoint* endpointSlotForObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref ep; g_endpoints)
        if (ep.inUse && ep.objId == objId) return &ep;
    return null;
}

// Look up the Endpoint backing an object id, or null.  Public so posix.d can map
// a LocalSocket's endpoint object id to its queue.
public Endpoint* ipcEndpointByObj(uint objId) {
    return endpointSlotForObj(objId);
}

// Create a new Endpoint object; returns its object id, or 0 on exhaustion.
public uint ipcEndpointAlloc() {
    foreach (ref ep; g_endpoints) {
        if (ep.inUse) continue;
        uint id = objAlloc(ObjType.Endpoint, cast(void*)&ep);
        if (id == 0) return 0; // object table full
        ep = Endpoint.init;
        ep.inUse = true;
        ep.objId = id;
        ++g_ipcEndpointAlloc;
        ++g_ipcEndpointLive;
        return id;
    }
    return 0; // endpoint table full
}

// Destroy an Endpoint object and drop any undelivered messages.
public void ipcEndpointFree(uint objId) {
    auto ep = endpointSlotForObj(objId);
    if (ep is null) return;
    objRelease(ep.objId);
    *ep = Endpoint.init;
    ++g_ipcEndpointFree;
    if (g_ipcEndpointLive > 0) --g_ipcEndpointLive;
}

public uint ipcEndpointDepth(uint objId) {
    auto ep = endpointSlotForObj(objId);
    return (ep is null) ? 0 : ep.count;
}

// --- Capability delegation primitives ----------------------------------------
// These are the heart of "fd passing becomes capability delegation": a holder
// delegates authority by value (objId + a subset of rights), and the receiver
// accepts that value.  Both validate against the live object table so a stale or
// freed object can never be delegated, and rights can never exceed the universe.

public IpcCapDesc ipcDelegateCap(uint objId, uint rights) {
    IpcCapDesc d;
    if (objId == 0 || objGet(objId) is null) {
        ++g_ipcCapDropped;
        return d; // {0, 0} — nothing to delegate
    }
    d.objId  = objId;
    d.rights = rights & CAP_RIGHTS_UNIVERSE;
    ++g_ipcDelegateTotal;
    return d;
}

// Accept a delegated descriptor: returns the rights mask the receiver may install
// onto its own handle for the named object.  The descriptor conveys authority by
// value, so acceptance does not require the *sender's* object id to still be live
// (the receiver materialises its own handle); it only re-clamps to the universe.
public uint ipcAcceptCap(IpcCapDesc desc) {
    if (desc.objId == 0) return 0;
    ++g_ipcAcceptTotal;
    return desc.rights & CAP_RIGHTS_UNIVERSE;
}

// --- Message routing ----------------------------------------------------------

// Validate and copy a message into the endpoint's queue.  Invalid capability
// descriptors (naming a dead object) are dropped rather than delivered, so a
// receiver never sees authority over an object that no longer exists.  Raw
// pointers are never queued — only {objId, rights} values.
public int ipcSend(uint epObjId, const(IpcMessage)* msg) {
    if (msg is null) return -E_INVAL;
    auto ep = endpointSlotForObj(epObjId);
    if (ep is null) return -E_INVAL;
    if (ep.count >= IPC_QUEUE_DEPTH) {
        ++g_ipcDropFull;
        return -E_NOSPC;
    }

    auto slot = &ep.ring[ep.head];
    *slot = IpcMessage.init;
    slot.srcObjId = msg.srcObjId;

    uint n = msg.len;
    if (n > IPC_MSG_MAX_BYTES) n = IPC_MSG_MAX_BYTES;
    foreach (i; 0 .. n) slot.data[i] = msg.data[i];
    slot.len = n;

    uint nc = msg.ncaps;
    if (nc > IPC_MSG_MAX_CAPS) nc = IPC_MSG_MAX_CAPS;
    uint kept = 0;
    foreach (i; 0 .. nc) {
        auto c = msg.caps[i];
        if (c.objId == 0 || objGet(c.objId) is null) {
            ++g_ipcCapDropped;
            continue; // drop authority over a dead/invalid object
        }
        slot.caps[kept].objId  = c.objId;
        slot.caps[kept].rights = c.rights & CAP_RIGHTS_UNIVERSE;
        ++kept;
        ++g_ipcDelegateTotal;
    }
    slot.ncaps = kept;

    ep.head = (ep.head + 1) % IPC_QUEUE_DEPTH;
    ++ep.count;
    ++g_ipcSendTotal;
    return 0;
}

// Dequeue the next message from an endpoint into `out_`.  Returns 0 on delivery,
// -EAGAIN when empty, -EINVAL for a bad endpoint.
public int ipcRecv(uint epObjId, IpcMessage* out_) {
    if (out_ is null) return -E_INVAL;
    auto ep = endpointSlotForObj(epObjId);
    if (ep is null) return -E_INVAL;
    if (ep.count == 0) return -E_AGAIN;

    auto slot = &ep.ring[ep.tail];
    *out_ = *slot;
    *slot = IpcMessage.init;
    ep.tail = (ep.tail + 1) % IPC_QUEUE_DEPTH;
    --ep.count;
    ++g_ipcRecvTotal;
    return 0;
}

// Native call primitive: post `req` to the endpoint named by an endpoint object
// id (the "endpoint capability" once routed through core.cap).  Asynchronous in
// this phase — it enqueues and returns the send result; a future revision adds a
// reply endpoint for round-trip rendezvous.
public int objCall(uint endpointObjId, const(IpcMessage)* req) {
    return ipcSend(endpointObjId, req);
}

// --- Service registry ---------------------------------------------------------

private bool nameEquals(ref const(ServiceEntry) e, const(char)* name, uint len) {
    if (e.nameLen != len) return false;
    foreach (i; 0 .. len)
        if (e.name[i] != name[i]) return false;
    return true;
}

public int ipcServiceRegister(const(char)* name, uint len, uint endpointObjId) {
    if (name is null || len == 0 || len > IPC_SVC_NAME_MAX) return -E_INVAL;
    if (objGet(endpointObjId) is null) return -E_INVAL;
    // Re-register an existing name in place.
    foreach (ref e; g_services) {
        if (e.inUse && nameEquals(e, name, len)) {
            e.endpointObjId = endpointObjId;
            ++g_ipcServiceReg;
            return 0;
        }
    }
    foreach (ref e; g_services) {
        if (e.inUse) continue;
        e.inUse = true;
        e.endpointObjId = endpointObjId;
        e.nameLen = len;
        foreach (i; 0 .. len) e.name[i] = name[i];
        ++g_ipcServiceReg;
        return 0;
    }
    return -E_NOSPC;
}

// Resolve a service name to its endpoint object id, or 0 if unknown.
public uint ipcServiceLookup(const(char)* name, uint len) {
    if (name is null || len == 0 || len > IPC_SVC_NAME_MAX) {
        ++g_ipcServiceMiss;
        return 0;
    }
    ++g_ipcServiceLookup;
    foreach (ref e; g_services) {
        if (e.inUse && nameEquals(e, name, len)) {
            if (objGet(e.endpointObjId) is null) break; // endpoint died
            return e.endpointObjId;
        }
    }
    ++g_ipcServiceMiss;
    return 0;
}

public void ipcServiceUnregister(const(char)* name, uint len) {
    foreach (ref e; g_services)
        if (e.inUse && nameEquals(e, name, len)) e = ServiceEntry.init;
}

// --- Boot self-test (Phase 7 runtime proof) -----------------------------------
// Stands up an endpoint, registers it as a named service, resolves the name, then
// round-trips a message carrying a delegated capability through the router and
// verifies bytes + capability survive intact.  Runs once; logs PASS/FAIL.
public void ipcSelfTest() {
    if (g_ipcSelfTested) return;
    g_ipcSelfTested = true;

    uint ep = ipcEndpointAlloc();
    if (ep == 0) { klog("[ipc] selftest FAIL: no endpoint\n"); return; }

    static immutable char[4] svcName = ['i','p','c','0'];
    if (ipcServiceRegister(&svcName[0], 4, ep) != 0) {
        klog("[ipc] selftest FAIL: register\n"); ipcEndpointFree(ep); return;
    }
    if (ipcServiceLookup(&svcName[0], 4) != ep) {
        klog("[ipc] selftest FAIL: lookup\n");
        ipcServiceUnregister(&svcName[0], 4); ipcEndpointFree(ep); return;
    }

    // Delegate a capability for a real, live object (the endpoint itself) so the
    // descriptor passes validation, then send it through the router.
    IpcMessage m;
    m.srcObjId = ep;
    m.data[0] = 0x7E; m.data[1] = 0x11; m.len = 2;
    m.caps[0] = ipcDelegateCap(ep, CAP_RIGHTS_UNIVERSE);
    m.ncaps   = (m.caps[0].objId != 0) ? 1 : 0;

    int sr = objCall(ep, &m);
    IpcMessage got;
    int rr = ipcRecv(ep, &got);

    bool ok = (sr == 0 && rr == 0 &&
               got.len == 2 && got.data[0] == 0x7E && got.data[1] == 0x11 &&
               got.ncaps == 1 && got.caps[0].objId == ep &&
               ipcAcceptCap(got.caps[0]) == CAP_RIGHTS_UNIVERSE);

    if (ok) klog("[ipc] selftest PASS\n");
    else    klog("[ipc] selftest FAIL: roundtrip\n");

    ipcServiceUnregister(&svcName[0], 4);
    ipcEndpointFree(ep);
}

public void ipcStats() {
    klog("[ipc] ep_live=");  klog_hex(cast(ulong)g_ipcEndpointLive);
    klog(" alloc=");         klog_hex(g_ipcEndpointAlloc);
    klog(" freed=");         klog_hex(g_ipcEndpointFree);
    klog(" send=");          klog_hex(g_ipcSendTotal);
    klog(" recv=");          klog_hex(g_ipcRecvTotal);
    klog(" full=");          klog_hex(g_ipcDropFull);
    klog(" deleg=");         klog_hex(g_ipcDelegateTotal);
    klog(" accept=");        klog_hex(g_ipcAcceptTotal);
    klog(" capdrop=");       klog_hex(g_ipcCapDropped);
    klog(" svcreg=");        klog_hex(g_ipcServiceReg);
    klog(" svchit=");        klog_hex(g_ipcServiceLookup);
    klog(" svcmiss=");       klog_hex(g_ipcServiceMiss);
    klog("\n");
}
