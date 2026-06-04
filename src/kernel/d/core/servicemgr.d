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
// IMMUTABLE_ROOTLESS_ROADMAP §5 (Service management) extends this module:
//   §5.1 capability broker — dependency edges + dependency-ordered start
//        (serviceAddDep / serviceStartAll) and endpoint-cap brokering into a
//        client cap table (serviceBrokerEndpoint), atop the existing per-service
//        rights narrowing.
//   §5.2 move in-kernel services out — each service has a ServiceDomain and a
//        migration (serviceMigrateToUser) that drops ambient kernel authority and
//        clamps to an explicit subset; serviceMigrateNext orders the extraction
//        FS-first, display-last.  (The object/authority plumbing lands here; the
//        actual code-relocation of the in-kernel fs/net/display servers is the
//        remaining work this drives.)
//   §5.3 versioned services — a service pins a content-addressed store hash
//        (StoreObject, §4.1) and a Generation (§4.4); an upgrade is a new pinned
//        hash + version bump tied to a new generation (serviceUpgrade).
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.servicemgr;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objCountType;
import core.ipc : ipcEndpointAlloc, ipcServiceRegister, ipcServiceLookup,
                  ipcServiceGrantTo;
import core.user : USER_RIGHT_ALL, USER_RIGHT_LOGIN, USER_RIGHT_SPAWN;
import core.store : storePut, storeRoot, storeLen, genCreate, genActive,
                    Digest256; // IR-P5.3: pin services to content-addressed store hashes
import core.cap : CAP_INVALID, CAPTAB_COUNT, capTableClear, capLiveCount,
                  CAP_RIGHT_CALL;

extern (C) @nogc nothrow:

enum int SVC_MAX      = 32;
enum int SVC_NAME_MAX = 32;
enum int SVC_DEP_MAX  = 4;    // start-dependencies recorded per service (§5.1)

// IR-P5.2: where a service runs.  Today most "services" (fs/net/display) live
// in-kernel with ambient authority; migrating them to user space is the rootless
// goal — FS first, display last.  A migrated service holds only the explicit cap
// subset it was handed (no ambient kernel reach).
enum ServiceDomain : uint {
    InKernel  = 0,   // ambient authority (the current reality)
    UserSpace = 1,   // least-privilege, explicit caps only
}

// IR-P5.2: migration ordering class — lower migrates earlier ("do FS first,
// display last").  Used only to order the incremental kernel-service extraction.
enum SVC_MIG_FS      = 0;
enum SVC_MIG_NET     = 1;
enum SVC_MIG_DISPLAY = 2;
enum SVC_MIG_NONE    = 0xffff_ffff; // not a migratable in-kernel service

struct ServiceRec {
    bool inUse;
    uint objId;            // ObjType.Service
    uint endpointObjId;    // its IPC Endpoint (the endpoint capability target)
    uint rights;           // least-privilege authority subset (⊆ manager rights)
    uint ownerUserObjId;   // User the service runs as
    uint nameLen;
    char[SVC_NAME_MAX] name;
    // --- IR-P5.1: dependency-ordered start -----------------------------------
    uint depCount;
    uint[SVC_DEP_MAX] deps; // Service objIds that must start before this one
    bool started;
    // --- IR-P5.2: kernel → user-space migration ------------------------------
    ServiceDomain domain;
    bool   ambient;         // holds ambient kernel authority (true while InKernel)
    uint   migClass;        // SVC_MIG_* extraction order (SVC_MIG_NONE if N/A)
    // --- IR-P5.3: versioned services (pinned store hash) ---------------------
    uint   storeObjId;      // pinned content-addressed StoreObject (the version's bits)
    uint   version_;        // monotonic version (bumped on upgrade)
    uint   genObjId;        // Generation this version belongs to (§4.4)
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
        // §5.2 defaults: a freshly registered service starts in-kernel holding
        // ambient authority and is not (yet) classed for extraction.
        s.domain   = ServiceDomain.InKernel;
        s.ambient  = true;
        s.migClass = SVC_MIG_NONE;
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

// =============================================================================
// §5.1 — dependency-ordered start + endpoint-cap brokering
// =============================================================================
__gshared ulong g_svcStartTotal   = 0;
__gshared ulong g_svcUnstarted    = 0;   // services left unstarted (cycle/missing dep)
__gshared ulong g_svcBrokerTotal  = 0;   // endpoint caps brokered into clients

// Record that `svcObjId` must not start before `depObjId`.  Both must exist; a
// service may declare up to SVC_DEP_MAX dependencies.  Returns false on overflow
// or unknown ids (a self-dependency is rejected — it would never be startable).
public bool serviceAddDep(uint svcObjId, uint depObjId) {
    auto s = serviceByObj(svcObjId);
    auto d = serviceByObj(depObjId);
    if (s is null || d is null || svcObjId == depObjId) return false;
    if (s.depCount >= SVC_DEP_MAX) return false;
    foreach (i; 0 .. s.depCount) if (s.deps[i] == depObjId) return true; // already
    s.deps[s.depCount++] = depObjId;
    return true;
}

private bool depsSatisfied(ref const(ServiceRec) s) {
    foreach (i; 0 .. s.depCount) {
        auto d = serviceByObj(s.deps[i]);
        if (d is null || !d.started) return false;
    }
    return true;
}

// Dependency-ordered start (a bounded topological pass): repeatedly start every
// not-yet-started service whose dependencies are all started, until no further
// progress is possible.  Returns the number started this call; any service still
// unstarted afterwards has an unsatisfiable dependency (missing or a cycle) and is
// counted in g_svcUnstarted — never started out of order.
public uint serviceStartAll() {
    uint started = 0;
    bool progress = true;
    while (progress) {
        progress = false;
        foreach (ref s; g_svcs) {
            if (!s.inUse || s.started) continue;
            if (!depsSatisfied(s)) continue;
            s.started = true;
            ++started;
            ++g_svcStartTotal;
            progress = true;
        }
    }
    foreach (ref s; g_svcs)
        if (s.inUse && !s.started) ++g_svcUnstarted;
    return started;
}

public bool serviceStarted(uint svcObjId) {
    auto s = serviceByObj(svcObjId);
    return s !is null && s.started;
}

// Broker the service's endpoint capability into a client cap table at `handle`,
// granting `rights` (CALL is always included).  This is the Genode "session to a
// service" hand-off: a client can only reach a service it was brokered an endpoint
// cap for.  Returns the installed handle, or CAP_INVALID on failure.
public uint serviceBrokerEndpoint(int tableId, uint svcObjId, uint handle, uint rights) {
    auto s = serviceByObj(svcObjId);
    if (s is null || s.endpointObjId == 0) return CAP_INVALID;
    uint h = ipcServiceGrantTo(tableId, s.name.ptr, s.nameLen, handle, rights);
    if (h != CAP_INVALID) ++g_svcBrokerTotal;
    return h;
}

// =============================================================================
// §5.2 — move in-kernel services out (incremental, FS-first)
// =============================================================================
__gshared ulong g_svcMigratedTotal = 0;

// Mark a service as an in-kernel server eligible for extraction, with its order
// class (SVC_MIG_FS earliest, SVC_MIG_DISPLAY latest).
public bool serviceSetMigClass(uint svcObjId, uint migClass) {
    auto s = serviceByObj(svcObjId);
    if (s is null) return false;
    s.migClass = migClass;
    return true;
}

// Extract a service to user space: drop its ambient kernel authority and clamp it
// to the explicit `keepRights` subset (⊆ what it already held — never widened).
// After this the service is a least-privilege user-space server.  Idempotent-safe.
public bool serviceMigrateToUser(uint svcObjId, uint keepRights) {
    auto s = serviceByObj(svcObjId);
    if (s is null) return false;
    s.rights  = s.rights & keepRights;       // narrow only
    s.ambient = false;                       // no more ambient kernel reach
    s.domain  = ServiceDomain.UserSpace;
    ++g_svcMigratedTotal;
    return true;
}

// The next in-kernel service that should be extracted: the lowest migClass still
// running InKernel ("do FS first, display last").  Returns its objId, or 0 if no
// classed in-kernel service remains.
public uint serviceMigrateNext() {
    uint best = 0;
    uint bestClass = SVC_MIG_NONE;
    foreach (ref s; g_svcs) {
        if (!s.inUse || s.domain != ServiceDomain.InKernel) continue;
        if (s.migClass == SVC_MIG_NONE) continue;
        if (best == 0 || s.migClass < bestClass) { best = s.objId; bestClass = s.migClass; }
    }
    return best;
}

public ServiceDomain serviceDomain(uint svcObjId) {
    auto s = serviceByObj(svcObjId);
    return s is null ? ServiceDomain.InKernel : s.domain;
}

// =============================================================================
// §5.3 — versioned services (a service = a pinned content-addressed store hash)
// =============================================================================
__gshared ulong g_svcUpgradeTotal = 0;

// Pin a service to a store object (its on-store bits) and the generation it
// belongs to, setting version 1.  A service with no pinned hash is "unversioned".
public bool serviceSetVersion(uint svcObjId, uint storeObjId, uint genObjId) {
    auto s = serviceByObj(svcObjId);
    if (s is null || storeObjId == 0) return false;
    s.storeObjId = storeObjId;
    s.genObjId   = genObjId;
    if (s.version_ == 0) s.version_ = 1;
    return true;
}

// Upgrade a service to a new pinned store hash (a new generation): bump its
// version and repin.  Pinning the *same* hash is a no-op (no version churn).
// Returns the new version, or 0 on failure.
public uint serviceUpgrade(uint svcObjId, uint newStoreObjId, uint newGenObjId) {
    auto s = serviceByObj(svcObjId);
    if (s is null || newStoreObjId == 0) return 0;
    if (s.storeObjId == newStoreObjId) return s.version_; // identical bits ⇒ no upgrade
    s.storeObjId = newStoreObjId;
    s.genObjId   = newGenObjId;
    ++s.version_;
    ++g_svcUpgradeTotal;
    return s.version_;
}

public uint serviceVersion(uint svcObjId)    { auto s = serviceByObj(svcObjId); return s is null ? 0 : s.version_; }
public uint servicePinnedObj(uint svcObjId)  { auto s = serviceByObj(svcObjId); return s is null ? 0 : s.storeObjId; }
public uint serviceGeneration(uint svcObjId) { auto s = serviceByObj(svcObjId); return s is null ? 0 : s.genObjId; }

// The content digest (store hash) a service is pinned to.
public Digest256 servicePinnedHash(uint svcObjId) {
    auto s = serviceByObj(svcObjId);
    return s is null ? Digest256.init : storeRoot(s.storeObjId);
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

// --- IR-P5 proof: dependency-ordered start, migration, versioning -------------
__gshared bool g_svc5SelfTested = false;

private bool p5DepOrder() {                 // §5.1 dependency-ordered start + broker
    uint fs   = serviceRegister("p5-fs\0".ptr,   0, USER_RIGHT_ALL);
    uint net  = serviceRegister("p5-net\0".ptr,  0, USER_RIGHT_ALL);
    uint disp = serviceRegister("p5-disp\0".ptr, 0, USER_RIGHT_ALL);
    if (fs == 0 || net == 0 || disp == 0) return false;
    // net needs fs; disp needs net  ⇒  start order must be fs, net, disp.
    if (!serviceAddDep(net, fs))  return false;
    if (!serviceAddDep(disp, net)) return false;
    if (!serviceAddDep(disp, disp)) {} // self-dep rejected (returns false; ignored)

    serviceStartAll();
    bool started = serviceStarted(fs) && serviceStarted(net) && serviceStarted(disp);
    // Every started service's dependencies were started before it (the invariant a
    // topological order guarantees).
    bool ordered = true;
    foreach (ref s; g_svcs)
        if (s.inUse && s.started && !depsSatisfied(s)) ordered = false;

    // A dependency cycle is never started.
    uint ca = serviceRegister("p5-cyca\0".ptr, 0, USER_RIGHT_ALL);
    uint cb = serviceRegister("p5-cycb\0".ptr, 0, USER_RIGHT_ALL);
    serviceAddDep(ca, cb);
    serviceAddDep(cb, ca);
    serviceStartAll();
    bool cycleHeld = !serviceStarted(ca) && !serviceStarted(cb);

    // §5.1 broker: hand fs's endpoint cap into a scratch client table.
    int st = CAPTAB_COUNT - 2;
    capTableClear(st);
    uint h = serviceBrokerEndpoint(st, fs, 50, CAP_RIGHT_CALL);
    bool brokered = (h != CAP_INVALID && capLiveCount(st) == 1);
    capTableClear(st);

    return started && ordered && cycleHeld && brokered;
}

private bool p5Migration() {                // §5.2 FS-first extraction + narrowing
    uint fs   = serviceLookup("p5-fs\0".ptr);
    uint disp = serviceLookup("p5-disp\0".ptr);
    serviceSetMigClass(fs,   SVC_MIG_FS);
    serviceSetMigClass(disp, SVC_MIG_DISPLAY);
    bool fsFirst   = (serviceMigrateNext() == fs);          // FS before display
    uint before    = serviceByObj(fs).rights;
    bool wasKernel = (serviceDomain(fs) == ServiceDomain.InKernel);
    bool migrated  = serviceMigrateToUser(fs, USER_RIGHT_LOGIN);
    auto sfs       = serviceByObj(fs);
    bool narrowed  = (sfs.rights == (before & USER_RIGHT_LOGIN) &&
                      sfs.rights != before &&               // strictly fewer rights
                      !sfs.ambient &&                        // ambient authority dropped
                      sfs.domain == ServiceDomain.UserSpace);
    bool dispNext  = (serviceMigrateNext() == disp);        // display now the next
    return fsFirst && wasKernel && migrated && narrowed && dispNext;
}

private bool p5Versioning() {               // §5.3 pinned store hash + upgrade
    static immutable ubyte[6] v1 = ['f','s',' ','v','1','\0'];
    static immutable ubyte[6] v2 = ['f','s',' ','v','2','\0'];
    uint o1 = storePut(v1.ptr, 5);
    uint o2 = storePut(v2.ptr, 5);
    uint g1 = genCreate(0,  &o1, 1);
    uint g2 = genCreate(g1, &o2, 1);
    uint fs = serviceLookup("p5-fs\0".ptr);
    if (o1 == 0 || o2 == 0 || o1 == o2 || g1 == 0 || g2 == 0 || fs == 0) return false;

    bool pinned = serviceSetVersion(fs, o1, g1) &&
                  serviceVersion(fs) == 1 && servicePinnedObj(fs) == o1 &&
                  serviceGeneration(fs) == g1;
    uint nv = serviceUpgrade(fs, o2, g2);                   // new bits ⇒ new version
    Digest256 h1 = storeRoot(o1);
    Digest256 h2 = servicePinnedHash(fs);
    bool upgraded = (nv == 2 && servicePinnedObj(fs) == o2 &&
                     serviceGeneration(fs) == g2 &&
                     (h2.w[0] != h1.w[0] || h2.w[1] != h1.w[1])); // hash changed
    bool idempotent = (serviceUpgrade(fs, o2, g2) == 2);   // same bits ⇒ no churn
    return pinned && upgraded && idempotent;
}

public void servicePhase5SelfTest() {
    if (g_svc5SelfTested || !g_svcInited) return;
    g_svc5SelfTested = true;

    bool dep = p5DepOrder();
    bool mig = p5Migration();
    bool ver = p5Versioning();

    if (dep && mig && ver) {
        klog("[svc5] selftest PASS\n");
    } else {
        klog("[svc5] selftest FAIL:");
        if (!dep) klog(" deporder");
        if (!mig) klog(" migrate");
        if (!ver) klog(" version");
        klog("\n");
    }
}

public void serviceStats() {
    klog("[svc] reg=");     klog_hex(g_svcRegTotal);
    klog(" svcobj=");       klog_hex(cast(ulong)objCountType(ObjType.Service));
    klog(" mgrrights=");    klog_hex(cast(ulong)g_svcManagerRights);
    klog(" deny=");         klog_hex(g_svcDenyTotal);
    klog(" invariant=");    klog_hex(serviceRightsInvariant() ? 1 : 0);
    klog(" started=");      klog_hex(g_svcStartTotal);
    klog(" broker=");       klog_hex(g_svcBrokerTotal);
    klog(" migrated=");     klog_hex(g_svcMigratedTotal);
    klog(" upgrade=");      klog_hex(g_svcUpgradeTotal);
    klog("\n");
}
