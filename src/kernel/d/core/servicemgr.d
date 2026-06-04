// Service objects + Service Manager — Phase 10 of roadmap/OBJECT_OS_ROADMAP.md.
//
// A native Service Manager (the object identity of PID1/init) that registers
// **Service** objects.  Each service is reachable by holding its endpoint
// capability (Phase 7 IPC) and runs under a least-privilege authority set that is
// a *subset* of the manager's — the object-model expression of "PID1 holds a
// minimal cap set; each service gets an endpoint cap + a narrowed cap table."
//
// In the additive spirit of the earlier phases this stands up the Service object
// graph, endpoint wiring, and rights-narrowing invariant with a boot self-test;
// actually re-spawning userspace daemons as Process objects bound to these
// narrowed tables is the init rework the rootless roadmap drives, and the object
// plumbing for it exists now.  A real per-service capability table is not carved
// out of the 64 task-indexed tables here (MAX_TASKS == CAPTAB_COUNT); the service
// instead records the rights subset it is entitled to, enforced as a subset of
// the manager's authority.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.servicemgr;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objCountType;
import core.ipc : ipcEndpointAlloc, ipcServiceRegister, ipcServiceLookup;
import core.user : USER_RIGHT_ALL;

extern (C) @nogc nothrow:

enum int SVC_MAX      = 32;
enum int SVC_NAME_MAX = 32;

struct ServiceRec {
    bool inUse;
    uint objId;            // ObjType.Service
    uint endpointObjId;    // its IPC Endpoint (the endpoint capability target)
    uint rights;           // least-privilege authority subset (⊆ manager rights)
    uint ownerUserObjId;   // User the service runs as
    uint nameLen;
    char[SVC_NAME_MAX] name;
}

__gshared ServiceRec[SVC_MAX] g_svcs;

// The Service Manager (PID1/init) identity and the full authority set it holds.
__gshared uint g_svcManagerObjId = 0;
__gshared uint g_svcManagerEndpoint = 0;
__gshared uint g_svcManagerRights = 0;

__gshared ulong g_svcRegTotal   = 0;
__gshared ulong g_svcDenyTotal   = 0;   // registrations rejected (rights not a subset)
__gshared bool  g_svcInited      = false;
__gshared bool  g_svcSelfTested  = false;

private uint svcStrLen(const(char)* s) {
    if (s is null) return 0;
    uint n = 0;
    while (s[n] != 0 && n < SVC_NAME_MAX) ++n;
    return n;
}

private bool svcNameEq(ref const(ServiceRec) e, const(char)* name, uint len) {
    if (e.nameLen != len) return false;
    foreach (i; 0 .. len) if (e.name[i] != name[i]) return false;
    return true;
}

// Stand up the Service Manager identity holding `managerRights` (the full
// authority set PID1 starts with) and its own endpoint.  Idempotent.
public void serviceManagerInit(uint managerRights) {
    if (g_svcInited) return;
    g_svcInited = true;
    g_svcManagerRights = managerRights & USER_RIGHT_ALL;
    g_svcManagerEndpoint = ipcEndpointAlloc();
    g_svcManagerObjId = objAlloc(ObjType.Service, null);
}

// Register a service running under `ownerUserObjId` with authority `rightsSubset`.
// The subset is clamped to the manager's rights (a service can never hold more
// authority than the manager that spawned it) and the service is given its own
// IPC endpoint, registered by name so a holder of the endpoint cap can reach it.
// Returns the Service object id, or 0 on failure.
public uint serviceRegister(const(char)* name, uint ownerUserObjId,
                            uint rightsSubset) {
    uint len = svcStrLen(name);
    if (len == 0 || !g_svcInited) return 0;

    // Least privilege: the granted set is the intersection with the manager's.
    uint granted = rightsSubset & g_svcManagerRights;
    if (granted != rightsSubset) ++g_svcDenyTotal; // requested more than allowed

    // Re-register in place if the name already exists.
    foreach (ref s; g_svcs)
        if (s.inUse && svcNameEq(s, name, len)) {
            s.rights = granted;
            s.ownerUserObjId = ownerUserObjId;
            return s.objId;
        }

    foreach (ref s; g_svcs) {
        if (s.inUse) continue;
        uint ep = ipcEndpointAlloc();
        if (ep == 0) return 0;
        uint id = objAlloc(ObjType.Service, cast(void*)&s);
        if (id == 0) return 0;
        s = ServiceRec.init;
        s.inUse = true;
        s.objId = id;
        s.endpointObjId = ep;
        s.rights = granted;
        s.ownerUserObjId = ownerUserObjId;
        s.nameLen = len;
        foreach (i; 0 .. len) s.name[i] = name[i];
        ipcServiceRegister(name, len, ep); // name → endpoint (Phase 7 registry)
        ++g_svcRegTotal;
        return id;
    }
    return 0;
}

public uint serviceLookup(const(char)* name) {
    uint len = svcStrLen(name);
    foreach (ref s; g_svcs)
        if (s.inUse && svcNameEq(s, name, len)) return s.objId;
    return 0;
}

public ServiceRec* serviceByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref s; g_svcs)
        if (s.inUse && s.objId == objId) return &s;
    return null;
}

// True iff every registered service holds authority ⊆ the manager's (the
// least-privilege invariant).
public bool serviceRightsInvariant() {
    foreach (ref s; g_svcs)
        if (s.inUse && (s.rights & ~g_svcManagerRights) != 0) return false;
    return true;
}

// --- proof --------------------------------------------------------------------
public void serviceSelfTest() {
    if (g_svcSelfTested || !g_svcInited) return;
    g_svcSelfTested = true;

    // A service that asks for full authority is clamped to the manager's set; one
    // that asks for a strict subset keeps exactly that.
    uint full = serviceRegister("svc-test-full\0".ptr, 0, USER_RIGHT_ALL);
    uint min  = serviceRegister("svc-test-min\0".ptr, 0, 1u /*LOGIN only*/);

    auto sf = serviceByObj(full);
    auto sm = serviceByObj(min);

    bool ok = (full != 0 && min != 0 && full != min &&
               sf !is null && sm !is null &&
               objGet(full) !is null && objGet(min) !is null &&
               sf.endpointObjId != 0 && sm.endpointObjId != sf.endpointObjId &&
               (sf.rights & ~g_svcManagerRights) == 0 &&     // clamped to manager
               sm.rights == (1u & g_svcManagerRights) &&     // exact narrow subset
               ipcServiceLookup("svc-test-min\0".ptr, 12) == sm.endpointObjId &&
               serviceRightsInvariant());

    if (ok) klog("[svc] selftest PASS\n");
    else    klog("[svc] selftest FAIL\n");
}

public void serviceStats() {
    klog("[svc] reg=");     klog_hex(g_svcRegTotal);
    klog(" svcobj=");       klog_hex(cast(ulong)objCountType(ObjType.Service));
    klog(" mgrrights=");    klog_hex(cast(ulong)g_svcManagerRights);
    klog(" deny=");         klog_hex(g_svcDenyTotal);
    klog(" invariant=");    klog_hex(serviceRightsInvariant() ? 1 : 0);
    klog("\n");
}
