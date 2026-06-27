// Domain model — DM0 (data model + RAM registry) of roadmap/domain_manager.md.
//
// A *domain* is a complete reusable OS environment.  DM0 makes it a first-class
// kernel object (ObjType.Domain) that references an Identity (the security
// domain carrying color / ceiling / net / clip in core/identity.d).  Later
// milestones give a domain a JSON manifest (DM1), a restricted namespace (DM2),
// real launch-into-domain (DM3), a lifecycle state machine (DM4), on-disk
// persistence with a perpetuation policy (DM5), and an immutable template + a
// writable overlay (DM6).
//
// DM0 is ONLY the data model + registry + boot seeding: it links the 7 compiled-in
// identities to 7 RAM domains so the GUI/CLI have live data.  No persistence, no
// restriction, no lifecycle transitions yet.  This module mirrors core/identity.d
// deliberately (same -betterC constraints: ldc2, no GC/druntime/exceptions, plain
// structs, __gshared fixed tables, @nogc nothrow, -O0).
module core.domain;

import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.identity : identityById, identityByName;
import core.io : klog, klog_hex;

extern (C) @nogc nothrow:

alias DomainId = uint;   // objId of an ObjType.Domain

// Lifecycle states — the §4 state machine.  DM0 only ever uses Defined; the
// transitions land in DM4.
enum DomainState : uint { Defined = 0, Starting, Running, Paused, Stopping, Failed }

// Perpetuation policy (the brief's choice of what survives reboot); honored by DM5.
enum ubyte PERSIST_EPHEMERAL = 0;  // nothing persists (fresh every boot)
enum ubyte PERSIST_HOME_ONLY = 1;  // only /Domains/<name>/Home survives
enum ubyte PERSIST_FULL      = 2;  // the full domain segment survives

// --- the domain object --------------------------------------------------------
enum int DOM_NAME_MAX = 24;
struct DomainRec {
    bool          inUse;
    bool          running;        // DM4: Running state mirror
    bool          paused;         // DM4: Paused state mirror
    DomainId      objId;          // ObjType.Domain
    uint          templateObjId;  // immutable Template referenced (0 = none yet, DM6)
    uint          identityObjId;  // the IdentityRec (color / ceiling / net / clip)
    uint          nsObjId;        // restricted namespace, 0 until started (DM2/DM3)
    uint          overlayObjId;   // writable overlay, 0 until started (DM6)
    ulong         manifestLba;    // on-disk manifest blob, 0 = RAM-only (DM1/DM5)
    uint          manifestLen;
    ubyte         persistMode;    // PERSIST_*
    DomainState   state;
    uint          nameLen;
    char[DOM_NAME_MAX] name;      // "System","Personal",… (mirrors the identity name)
    ulong         policyEpoch;    // signed-mutation counter (mirrors IdentityRec)
}

// --- fixed registry (deny-by-default; small fixed table, like the identities) --
enum int DOM_MAX = 32;
public __gshared DomainRec[DOM_MAX] g_domains;
public __gshared bool g_domFrozen = false;     // registry immutable after policy load (DM1)

__gshared ulong g_domCreateTotal   = 0;
__gshared bool  g_domDefaultsInited = false;
__gshared bool  g_domSelfTested     = false;

private int domCstrLen(const(char)* s) {
    if (s is null) return 0;
    int n = 0;
    while (n < DOM_NAME_MAX && s[n] != 0) ++n;
    return n;
}
private bool domNameEq(ref const(DomainRec) e, const(char)* name) {
    const int n = domCstrLen(name);
    if (e.nameLen != cast(uint)n) return false;
    foreach (i; 0 .. n) if (e.name[i] != name[i]) return false;
    return true;
}
private void domCopyName(ref DomainRec e, const(char)* name) {
    const int n = domCstrLen(name);
    foreach (i; 0 .. n) e.name[i] = name[i];
    e.nameLen = cast(uint)n;
}

// Resolve a domain object id to its record (or null).
public DomainRec* domainById(DomainId id) {
    if (id == 0) return null;
    foreach (ref e; g_domains) if (e.inUse && e.objId == id) return &e;
    return null;
}

// Resolve a name to its domain object id (0 = none).  Names are unique.
public DomainId domainByName(const(char)* name) {
    if (name is null || name[0] == 0) return 0;
    foreach (ref e; g_domains) if (e.inUse && domNameEq(e, name)) return e.objId;
    return 0;
}

public uint domainCount() {
    uint n = 0;
    foreach (ref e; g_domains) if (e.inUse) ++n;
    return n;
}

// Create a Domain object linked to an identity (and optionally a template).
// Refused after freeze, on an empty/too-long or duplicate name, or an unknown
// identity (deny-by-default).  Returns the new object id, or 0.
public DomainId domainCreate(const(char)* name, uint identityObjId, uint templateObjId) {
    if (g_domFrozen) return 0;                                  // read-only after policy load
    const int nl = domCstrLen(name);
    if (nl == 0 || nl >= DOM_NAME_MAX) return 0;
    if (identityObjId != 0 && identityById(identityObjId) is null) return 0;  // identity must be live
    if (domainByName(name) != 0) return 0;                      // unique name
    foreach (ref e; g_domains) if (!e.inUse) {
        e = DomainRec.init;
        e.inUse = true;
        e.identityObjId = identityObjId;
        e.templateObjId = templateObjId;
        e.persistMode   = PERSIST_EPHEMERAL;
        e.state         = DomainState.Defined;
        domCopyName(e, name);
        const uint oid = objAlloc(ObjType.Domain, cast(void*)&e);
        if (oid == 0) { e = DomainRec.init; return 0; }
        e.objId = oid;
        ++g_domCreateTotal;
        return oid;
    }
    return 0;                                                   // table full
}

public void domainFreeze() { g_domFrozen = true; }              // registry immutable

private void mkBootDomain(const(char)* name) {
    const uint idobj = identityByName(name);                    // link domain → identity (0 if absent)
    domainCreate(name, idobj, 0);
}

// Seed one RAM domain per compiled-in identity (the same 7 the GUI mirrors), so
// the domain object tree / CLI have live data.  Must run AFTER identityInitDefaults
// (the identities must exist to link).  No persistence (DM5), no restricted ns (DM2).
public void domainInitDefaults() {
    if (g_domDefaultsInited) return;
    g_domDefaultsInited = true;
    mkBootDomain("System\0".ptr);
    mkBootDomain("Personal\0".ptr);
    mkBootDomain("Work\0".ptr);
    mkBootDomain("Banking\0".ptr);
    mkBootDomain("Development\0".ptr);
    mkBootDomain("Untrusted\0".ptr);
    mkBootDomain("Disposable\0".ptr);
}

// Human-readable state name (for the /objects/domains/<name>/meta render, DM0.d).
public immutable(char)* domainStateName(DomainState s) {
    final switch (s) {
        case DomainState.Defined:  return "Defined\0".ptr;
        case DomainState.Starting: return "Starting\0".ptr;
        case DomainState.Running:  return "Running\0".ptr;
        case DomainState.Paused:   return "Paused\0".ptr;
        case DomainState.Stopping: return "Stopping\0".ptr;
        case DomainState.Failed:   return "Failed\0".ptr;
    }
}

// klog a domain's name (or "?") — used by the domain dump / stats.
public void domainNamePrint(DomainId id) {
    auto r = domainById(id);
    if (r is null) { klog("?"); return; }
    foreach (i; 0 .. r.nameLen) {
        char[2] c; c[0] = r.name[i]; c[1] = 0;
        klog(c.ptr);
    }
}

// One-shot boot proof (DM0 outcome): create/lookup; duplicate name, unknown
// identity, and post-freeze mutation all refused.
public void domainSelfTest() {
    if (g_domSelfTested) return;
    g_domSelfTested = true;

    const uint sysId = identityByName("System\0".ptr);
    const DomainId d = domainCreate("SelftestDom\0".ptr, sysId, 0);
    bool ok = (d != 0);
    auto r = domainById(d);
    ok = ok && (r !is null) && (r.objId == d) && (r.state == DomainState.Defined);
    ok = ok && (r.identityObjId == sysId);
    ok = ok && (domainByName("SelftestDom\0".ptr) == d);
    ok = ok && (domainByName("Nonexistent\0".ptr) == 0);
    // duplicate name refused
    ok = ok && (domainCreate("SelftestDom\0".ptr, sysId, 0) == 0);
    // unknown identity refused
    ok = ok && (domainCreate("BadId\0".ptr, 0x7fffffff, 0) == 0);
    // mutation after freeze refused (toggle for the test, then restore)
    const bool wasFrozen = g_domFrozen;
    g_domFrozen = true;
    ok = ok && (domainCreate("AfterFreeze\0".ptr, sysId, 0) == 0);
    g_domFrozen = wasFrozen;

    // clean up the throwaway domain
    if (r !is null) { objRelease(r.objId); *r = DomainRec.init; }

    if (ok) klog("[domain] selftest PASS\n");
    else    klog("[domain] selftest FAIL\n");
}

public void domainStats() {
    klog("[domain] count=");  klog_hex(cast(ulong)domainCount());
    klog(" created=");        klog_hex(g_domCreateTotal);
    klog(" frozen=");         klog_hex(g_domFrozen ? 1 : 0);
    klog(" domobj=");         klog_hex(cast(ulong)objCountType(ObjType.Domain));
    klog("\n");
}
