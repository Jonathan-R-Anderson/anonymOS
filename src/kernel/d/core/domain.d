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
import core.identity : identityById, identityByName, IdentityRec,
                       DEVCLASS_INPUT, DEVCLASS_GPU, DEVCLASS_CAMERA,
                       DEVCLASS_MIC, DEVCLASS_AUDIO, DEVCLASS_USB;  // DM8/DM10.7 device policy
import core.namespace : nsAllocRestricted, nsBind, nsBindDeny, nsRootDir,
                        nsResolveCheck, nsRelease;     // DOMAIN_MANAGER DM2
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_STAT;  // DOMAIN_MANAGER DM2
import core.objstore : objstoreMounted, objstoreInstallDomain,
                       objstoreDomainAt, objstoreDomainCount;     // DOMAIN_MANAGER DM5
import core.overlay : overlayCreate, overlayDestroy, overlaySnapshot, overlayCommit,
                      overlayDiscard, overlayRestore;            // DOMAIN_MANAGER DM6.2
import core.io : klog, klog_hex;
import core.pkgrepo : pkgInstallByName, pkgRemoveByName, pkgApplyProfile;   // DOMAIN_MANAGER DM7/DM11
import core.template_bundle : templatePublish;                             // DOMAIN_MANAGER DM12: export verb

extern (C) @nogc nothrow:

alias DomainId = uint;   // objId of an ObjType.Domain

// Lifecycle states — the §4 state machine.  DM0 only ever uses Defined; the
// transitions land in DM4.
enum DomainState : uint { Defined = 0, Starting, Running, Paused, Stopping, Failed }

// Perpetuation policy (the brief's choice of what survives reboot); honored by DM5.
enum ubyte PERSIST_EPHEMERAL = 0;  // nothing persists (fresh every boot)
enum ubyte PERSIST_HOME_ONLY = 1;  // only /Domains/<name>/Home survives
enum ubyte PERSIST_FULL      = 2;  // the full domain segment survives

// DM11: per-domain Linux-compat distribution + package manager.  The musl-fit subset is real
// (native object store / BusyBox / Nix-static / Alpine-apk); full glibc distros are modeled but
// out of scope (need glibc-loader support).  A non-native domain gets a RO /linux compat root.
enum ubyte DISTRO_NATIVE = 0, DISTRO_BUSYBOX = 1, DISTRO_NIX = 2, DISTRO_ALPINE = 3;
enum ubyte PKGMGR_NATIVE = 0, PKGMGR_BUSYBOX = 1, PKGMGR_NIX = 2, PKGMGR_APK = 3;

// --- the domain object --------------------------------------------------------
enum int DOM_NAME_MAX = 24;
struct DomainRec {
    bool          inUse;
    bool          running;        // DM4: Running state mirror
    bool          paused;         // DM4: Paused state mirror
    bool          isTemplate;     // DM6: an immutable Template (a running domain references one)
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
    uint          allowedDevices; // DM8/DM10.7: per-domain §7 device mask (seeded from the identity, GUI-toggled)
    uint          devInit;        // 0 until allowedDevices is seeded (distinguishes "deny all" from "unset")
    ubyte         distro;         // DM11: DISTRO_* Linux-compat root selector
    ubyte         pkgMgr;         // DM11: PKGMGR_* package manager for this domain
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
    if (n < DOM_NAME_MAX) e.name[n] = 0;   // always NUL-terminate (renamed/rehydrated records)
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
        auto idr0 = identityById(identityObjId);                 // DM10.7: seed the per-domain device mask
        e.allowedDevices = (idr0 !is null) ? idr0.allowedDevices : 0;
        e.devInit = 1;
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

// DM6: mark a domain as an immutable Template (a running domain references one).
public void domainSetTemplate(uint domObjId) {
    auto d = domainById(domObjId);
    if (d !is null) d.isTemplate = true;
}
public bool domainIsTemplate(uint domObjId) {
    auto d = domainById(domObjId);
    return d !is null && d.isTemplate;
}

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

// DOMAIN_MANAGER DM2: build the domain's RESTRICTED namespace from a default-deny policy.
// The domain sees ONLY: /Domains/<name>/Home (rw), /tmp (rw), /Shared (ro) — with /Shared/Private
// and /System explicitly denied, and EVERYTHING ELSE deny-by-default (no "/" binding).  DM2.3 will
// override this default from the manifest's filesystemAccess.  Stores + returns the nsObjId.
public uint domainBuildNamespace(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null) return 0;
    const uint ns = nsAllocRestricted();
    if (ns == 0) return 0;
    const uint root = nsRootDir();   // a live Directory object = the allow-binding target (the gate only
                                     // needs target!=0 + rights; the rtfs resolver handles the real file)
    const uint RW = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_STAT;
    const uint RO = CAP_RIGHT_READ | CAP_RIGHT_STAT;

    // /Domains/<name>/Home (rw) — the domain's private home
    char[64] home = void;
    size_t hp = 0;
    immutable string pre = "/Domains/";
    foreach (c; pre) home[hp++] = c;
    foreach (i; 0 .. d.nameLen) if (hp < home.length - 8) home[hp++] = d.name[i];
    immutable string suf = "/Home";
    foreach (c; suf) home[hp++] = c;
    home[hp] = 0;
    nsBind(ns, home.ptr, root, RW);

    nsBind(ns, "/tmp\0".ptr,    root, RW);
    nsBind(ns, "/Shared\0".ptr, root, RO);
    nsBindDeny(ns, "/Shared/Private\0".ptr);   // a hole inside the allowed /Shared (deny-override)
    nsBindDeny(ns, "/System\0".ptr);           // explicit deny (also covered by deny-by-default)

    // DM3: the compositor socket, so a CONFINED process can actually put a window on screen.
    //
    // Without this a domain-bound GUI app dies at connect() and the whole confinement feature
    // is limited to console programs.  Exposing it does not weaken the identity model: the
    // compositor is trusted, and it stamps a window's identity from the OWNING PROCESS at
    // winRegister time rather than from anything the client sends, so a confined app still
    // cannot spoof its border colour or its label.  Bound as narrowly as possible -- the exact
    // socket path, not /run and not /run/user.
    nsBind(ns, "/run/user/1000/wayland-0\0".ptr, root, RW);

    // DM11: a non-native domain mounts its distro's Linux compat root at /linux (READ-only).
    if (d.distro != DISTRO_NATIVE) nsBind(ns, "/linux\0".ptr, root, RO);

    d.nsObjId = ns;
    return ns;
}

// DM11 — per-domain distribution / package-manager selection.  Setting the distro re-mounts the
// RO /linux compat root and defaults the package manager to match; switching re-roots at runtime.
public ubyte domainDistro(uint domObjId) { auto d = domainById(domObjId); return d is null ? 0 : d.distro; }
public ubyte domainPkgMgr(uint domObjId) { auto d = domainById(domObjId); return d is null ? 0 : d.pkgMgr; }

public bool domainSetDistro(uint domObjId, ubyte distro) {
    auto d = domainById(domObjId);
    if (d is null) return false;
    d.distro = distro;
    d.pkgMgr = (distro == DISTRO_BUSYBOX) ? PKGMGR_BUSYBOX :
               (distro == DISTRO_NIX)     ? PKGMGR_NIX :
               (distro == DISTRO_ALPINE)  ? PKGMGR_APK : PKGMGR_NATIVE;
    if (d.nsObjId == 0) domainBuildNamespace(domObjId);
    if (distro != DISTRO_NATIVE && d.nsObjId != 0)
        nsBind(d.nsObjId, "/linux\0".ptr, nsRootDir(), CAP_RIGHT_READ | CAP_RIGHT_STAT);  // RO re-root
    ++d.policyEpoch;
    return true;
}
public bool domainSetPkgMgr(uint domObjId, ubyte pm) {
    auto d = domainById(domObjId);
    if (d is null) return false;
    d.pkgMgr = pm; ++d.policyEpoch; return true;
}
public ubyte distroByName(const(char)* n) {
    if (verbEq(n,"busybox")) return DISTRO_BUSYBOX;
    if (verbEq(n,"nix"))     return DISTRO_NIX;
    if (verbEq(n,"alpine"))  return DISTRO_ALPINE;
    return DISTRO_NATIVE;
}
public ubyte pkgMgrByName(const(char)* n) {
    if (verbEq(n,"busybox")) return PKGMGR_BUSYBOX;
    if (verbEq(n,"nix"))     return PKGMGR_NIX;
    if (verbEq(n,"apk"))     return PKGMGR_APK;
    return PKGMGR_NATIVE;
}
public const(char)* distroName(ubyte d) {
    return d==DISTRO_BUSYBOX ? "busybox\0".ptr : d==DISTRO_NIX ? "nix\0".ptr :
           d==DISTRO_ALPINE  ? "alpine\0".ptr  : "native\0".ptr;
}
public const(char)* pkgMgrName(ubyte p) {
    return p==PKGMGR_BUSYBOX ? "busybox\0".ptr : p==PKGMGR_NIX ? "nix\0".ptr :
           p==PKGMGR_APK     ? "apk\0".ptr     : "native\0".ptr;
}

// DM2/DM10: ensure every (non-template) domain has a restricted namespace, so the GUI's
// Filesystem RuntimeView shows a real policy for each.  Idempotent: skips domains that already
// have one (e.g. the manifest-policy domains built by configboot's TAG_FS_POLICY).
public void domainBuildAllNamespaces() {
    foreach (ref e; g_domains)
        if (e.inUse && e.nsObjId == 0 && !e.isTemplate)
            domainBuildNamespace(e.objId);
}

// DM10.7 — per-domain §7 device policy (the GUI Permissions/peripherals tab).  The mask is seeded
// from the identity at create and then GUI-toggled per domain.  Unseeded ⟹ unrestricted (safety).
// DM9: least-privilege merge — the EFFECTIVE device mask is the INTERSECTION of the domain's own
// mask and every template it inherits from (the templateObjId chain).  A child can only narrow.
public uint domainEffectiveDevices(uint domObjId) {
    uint mask = 0xFFFFFFFFu;
    uint cur = domObjId; int guard = 0;
    while (cur != 0 && guard++ < 16) {
        auto d = domainById(cur);
        if (d is null) break;
        if (d.devInit) mask &= d.allowedDevices;     // intersect this link's policy
        cur = d.templateObjId;                       // walk up the inheritance chain
    }
    return mask;
}
// DM9: true if the domain DECLARES device access its template chain denies (an escalation).
public bool domainDeviceEscalates(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null || d.templateObjId == 0) return false;
    const uint parent = domainEffectiveDevices(d.templateObjId);
    return (d.allowedDevices & ~parent) != 0;        // a bit the parent chain lacks
}
public bool domainDeviceAllowed(uint domObjId, uint devClass) {
    auto d = domainById(domObjId);
    if (d is null || devClass == 0) return true;
    if (!d.devInit) return true;
    return (domainEffectiveDevices(domObjId) & devClass) == devClass;   // DM9: enforce the merged chain
}
public uint domainDeviceMask(uint domObjId) { auto d = domainById(domObjId); return d is null ? 0 : d.allowedDevices; }
public bool domainSetDevice(uint domObjId, uint devClass, bool on) {
    auto d = domainById(domObjId);
    if (d is null || devClass == 0) return false;
    if (on) d.allowedDevices |= devClass; else d.allowedDevices &= ~devClass;
    d.devInit = 1; ++d.policyEpoch;
    return true;
}
public uint domainDeviceClassByName(const(char)* n) {
    if (verbEq(n, "input"))  return DEVCLASS_INPUT;
    if (verbEq(n, "gpu"))    return DEVCLASS_GPU;
    if (verbEq(n, "camera")) return DEVCLASS_CAMERA;
    if (verbEq(n, "mic"))    return DEVCLASS_MIC;
    if (verbEq(n, "audio"))  return DEVCLASS_AUDIO;
    if (verbEq(n, "usb"))    return DEVCLASS_USB;
    // DEVCLASS_NET was the one class with no name here, which made the whole per-domain
    // network control dead: "devon Work net" resolved to 0, and domainSetDevice() bails on
    // `devClass == 0`, so it silently returned false.  The bit itself (identity.d:87) is real
    // and IS checked by netProviderConnectGate(), so this one line is what connects the
    // control surface to the enforcement that already existed.
    if (verbEq(n, "net"))    return DEVCLASS_NET;
    return 0;
}

// DM10.7 — runtime filesystem bindings (the GUI Filesystem tab: grant/deny a REAL path to a
// domain).  An allow binding resolves to the live backing (nsRootDir), so it grants the domain
// access to that actual filesystem path; deny overrides on longest-prefix.  Idempotent ns build.
public bool domainFsBindAllow(uint domObjId, const(char)* path, bool rw) {
    auto d = domainById(domObjId);
    if (d is null || path is null || path[0] != '/') return false;
    if (d.nsObjId == 0) domainBuildNamespace(domObjId);
    const uint rights = rw ? (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_STAT)
                           : (CAP_RIGHT_READ | CAP_RIGHT_STAT);
    const bool ok = nsBind(d.nsObjId, path, nsRootDir(), rights);
    if (ok) ++d.policyEpoch;
    return ok;
}
public bool domainFsBindDeny(uint domObjId, const(char)* path) {
    auto d = domainById(domObjId);
    if (d is null || path is null || path[0] != '/') return false;
    if (d.nsObjId == 0) domainBuildNamespace(domObjId);
    const bool ok = nsBindDeny(d.nsObjId, path);
    if (ok) ++d.policyEpoch;
    return ok;
}

// DM10.3 — the control-write EXECUTOR.  Parses a "verb name [arg]" command (the action panels
// will write this to a control path; the native HOSQ_DOMAIN_* verbs can call it too) and invokes
// the matching lifecycle/overlay op.  NON-ESCALATING by construction: every verb is an existing
// capability-gated operation on a NAMED, already-declared domain — an unknown verb or an unknown
// domain is a no-op (deny-by-default).  Returns true on a recognized + successful command.
private bool verbEq(const(char)* v, string lit) {
    size_t i = 0;
    for (; i < lit.length; ++i) if (v[i] != lit[i]) return false;
    return v[i] == 0;   // exact match (the buffer is NUL-padded)
}

// DM3: launch a program INTO a domain.
//
// This is the piece the whole domain model was waiting on.  domainEnterTask()/domainBindTaskNs()
// have existed since DM3 but had NO caller outside a boot self-test, so no running process ever
// carried a domainObjId -- which meant every fsrw/fsdeny/devon/devoff policy the GUI can set was
// being evaluated against nothing, and the namespace confinement in namespaceCheckOpen() never
// applied to a real task.  domain.d:630 said as much: "launch into it is DM3 (domainEnterTask
// via HOSQ_DOMAIN_SPAWN, run from here later)".
//
// The actual task creation lives in kernel_main.d (allocTask/execveTask/untypedCreateProcess are
// not reachable from here, and importing kernel_main would be a cycle -- it already imports us),
// so kernel_main registers a hook at boot and this module just calls it.  Same pattern as the
// ICMP raw tap in network/icmp.d.
alias DomainSpawnFn = extern(C) bool function(uint domObjId, const(char)* prog);
private __gshared DomainSpawnFn g_domainSpawnHook = null;
public void domainSetSpawnHook(DomainSpawnFn fn) { g_domainSpawnHook = fn; }

// DM13: the same hook trick for the per-task native->linux ratchet.  core.task imports THIS
// module (domainBindTaskNs calls domainById), so we cannot import core.task back -- kernel_main
// imports both and registers the bridge.  `linux` != 0 requests the drop; the callee refuses
// linux -> native.
alias DomainModeFn = extern(C) bool function(int linuxMode);
private __gshared DomainModeFn g_domainModeHook = null;
public void domainSetModeHook(DomainModeFn fn) { g_domainModeHook = fn; }
public bool domainSpawnInto(uint domObjId, const(char)* prog) {
    if (g_domainSpawnHook is null) { klog("[domain] spawn: no launcher registered\n"); return false; }
    if (domObjId == 0 || prog is null || prog[0] == 0) return false;
    return g_domainSpawnHook(domObjId, prog);
}
public bool domainControlWrite(const(char)* cmd, size_t len) {
    if (cmd is null || len == 0) return false;
    char[160] buf = void;
    const size_t n = len < buf.length - 1 ? len : buf.length - 1;
    foreach (i; 0 .. n) buf[i] = cmd[i];
    buf[n] = 0;
    // tokenize into verb / name / arg over whitespace
    char[16]           verb = 0;
    char[DOM_NAME_MAX] name = 0;
    char[96]           arg  = 0;   // wide enough for a filesystem path
    size_t pos = 0, tok = 0, vi = 0;
    while (pos < n) {
        const char c = buf[pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            if (vi > 0) { ++tok; vi = 0; if (tok > 2) break; }
            ++pos; continue;
        }
        if      (tok == 0) { if (vi < verb.length - 1) verb[vi++] = c; }
        else if (tok == 1) { if (vi < name.length - 1) name[vi++] = c; }
        else               { if (vi < arg.length  - 1) arg [vi++] = c; }
        ++pos;
    }
    const uint id = domainByName(name.ptr);
    bool ok = false;
    if      (verbEq(verb.ptr, "ping"))     ok = true;                                      // path self-test, no side effect
    else if (verbEq(verb.ptr, "start"))    ok = (id != 0) && domainStart(id);
    else if (verbEq(verb.ptr, "stop"))     ok = (id != 0) && domainShutdown(id);
    else if (verbEq(verb.ptr, "pause"))    ok = (id != 0) && domainPause(id);
    else if (verbEq(verb.ptr, "resume"))   ok = (id != 0) && domainResume(id);
    else if (verbEq(verb.ptr, "snapshot")) ok = (id != 0) && (domainSnapshot(id) != 0);
    else if (verbEq(verb.ptr, "commit"))   ok = (id != 0) && (domainCommit(id)   != 0);
    else if (verbEq(verb.ptr, "clone"))    ok = (id != 0) && (arg[0] != 0) && (domainClone(id, arg.ptr) != 0);
    // DM7: package manager verbs — "install <domain> <pkg>" / "uninstall <domain> <pkg>"
    else if (verbEq(verb.ptr, "install"))   ok = (name[0] != 0) && (arg[0] != 0) && (pkgInstallByName(name.ptr, arg.ptr) == 0);
    else if (verbEq(verb.ptr, "uninstall")) ok = (name[0] != 0) && (arg[0] != 0) && (pkgRemoveByName(name.ptr, arg.ptr) == 0);
    // DM10.7: peripheral device toggles — "devon/devoff <domain> <gpu|audio|camera|mic|usb|input>"
    else if (verbEq(verb.ptr, "devon"))     ok = (id != 0) && domainSetDevice(id, domainDeviceClassByName(arg.ptr), true);
    else if (verbEq(verb.ptr, "devoff"))    ok = (id != 0) && domainSetDevice(id, domainDeviceClassByName(arg.ptr), false);
    // DM10.7: filesystem path access — "fsro/fsrw/fsdeny <domain> <path>" (real backing paths)
    else if (verbEq(verb.ptr, "fsro"))      ok = (id != 0) && domainFsBindAllow(id, arg.ptr, false);
    else if (verbEq(verb.ptr, "fsrw"))      ok = (id != 0) && domainFsBindAllow(id, arg.ptr, true);
    else if (verbEq(verb.ptr, "fsdeny"))    ok = (id != 0) && domainFsBindDeny(id, arg.ptr);
    else if (verbEq(verb.ptr, "delete"))    ok = (id != 0) && domainDelete(id);   // DM10.7: GUI Delete button
    // DM11: distro / package-manager / profile — "distro <domain> <busybox|nix|alpine|native>" etc.
    else if (verbEq(verb.ptr, "distro"))    ok = (id != 0) && domainSetDistro(id, distroByName(arg.ptr));
    else if (verbEq(verb.ptr, "pkgmgr"))    ok = (id != 0) && domainSetPkgMgr(id, pkgMgrByName(arg.ptr));
    else if (verbEq(verb.ptr, "profile"))   ok = (name[0] != 0) && (arg[0] != 0) && (pkgApplyProfile(name.ptr, arg.ptr) >= 1);
    else if (verbEq(verb.ptr, "export"))    ok = (id != 0) && (templatePublish(id) == 0);   // DM12: publish as a signed template
    // GUI toolbar: from-scratch Create + instantiate-from-template (Import)
    // DM3: "spawn <domain> <program>" — run a program confined to the domain.  This is the only
    // verb that produces a task actually carrying domainObjId, so it is what makes every other
    // policy verb (fsro/fsrw/fsdeny, devon/devoff) take effect on a live process.
    else if (verbEq(verb.ptr, "spawn"))     ok = (id != 0) && (arg[0] != 0) && domainSpawnInto(id, arg.ptr);
    // DM13: "mode self <native|linux>" ratchets the CALLING task (linux -> native is refused,
    // and the mode is inherited by every child).  "mode <domain> <native|linux>" sets what
    // future `spawn`s into that domain start as, which is the domain's distro axis:
    // DISTRO_NATIVE is the native personality, anything else is a Linux one.
    else if (verbEq(verb.ptr, "mode")) {
        const bool wantLinux = verbEq(arg.ptr, "linux");
        if (verbEq(name.ptr, "self"))
            ok = (g_domainModeHook !is null) && g_domainModeHook(wantLinux ? 1 : 0);
        else
            ok = (id != 0) && domainSetDistro(id, wantLinux ? DISTRO_BUSYBOX : DISTRO_NATIVE);
    }
    else if (verbEq(verb.ptr, "create"))    ok = (name[0] != 0) && (domainCreate(name.ptr, identityByName(arg.ptr), 0) != 0);
    else if (verbEq(verb.ptr, "fromtpl"))   { const uint tp = domainByName(arg.ptr);
                                              ok = (name[0] != 0) && (tp != 0) && (domainCreate(name.ptr, domainById(tp).identityObjId, tp) != 0); }
    else { klog("[domain] control: unknown verb '"); klog(verb.ptr); klog("'\n"); return false; }
    klog("[domain] control: "); klog(verb.ptr); klog(" "); klog(name.ptr); klog(ok ? " -> OK\n" : " -> FAIL\n");
    return ok;
}

// DM10.3 boot proof: drive a domain through its lifecycle purely via parsed control strings —
// the same entry point the action panels / HOSQ verbs use — and assert the state transitions +
// deny-by-default for an unknown verb and an unknown domain.  Leaves the domain Defined (clean).
private __gshared bool g_domCtlProofDone = false;
public void domainControlProof() {
    if (g_domCtlProofDone) return;
    g_domCtlProofDone = true;
    const uint id = domainByName("DevSandbox\0".ptr);
    if (id == 0) { klog("[domain] control proof SKIP (no DevSandbox)\n"); return; }
    auto d = domainById(id);
    bool ok = domainControlWrite("ping DevSandbox".ptr, 15);
    ok = ok && domainControlWrite("start DevSandbox".ptr, 16)   && (d.state == DomainState.Running);
    ok = ok && domainControlWrite("pause DevSandbox".ptr, 16)   && (d.state == DomainState.Paused);
    ok = ok && domainControlWrite("resume DevSandbox".ptr, 17)  && (d.state == DomainState.Running);
    ok = ok &&  domainControlWrite("snapshot DevSandbox".ptr, 19);             // overlay exists after start
    ok = ok && domainControlWrite("stop DevSandbox".ptr, 15)    && (d.state == DomainState.Defined);
    // clone — the 3-token parse (verb name newname); a new domain appears, then clean it up
    ok = ok && domainControlWrite("clone DevSandbox DevSandboxCl".ptr, 29) && (domainByName("DevSandboxCl\0".ptr) != 0);
    { const uint cl = domainByName("DevSandboxCl\0".ptr); if (cl != 0) domainDelete(cl); }
    ok = ok && (domainByName("DevSandboxCl\0".ptr) == 0);                     // cleanup leaves the registry clean
    ok = ok && !domainControlWrite("frobnicate DevSandbox".ptr, 21);          // unknown verb → denied
    ok = ok && !domainControlWrite("start Nonexistent".ptr, 17);              // unknown domain → denied
    // DM10.7: device toggle + filesystem-path binding via the control path
    const uint devDom = domainByName("Development\0".ptr);
    ok = ok && domainControlWrite("devoff Development gpu".ptr, 22) && !domainDeviceAllowed(devDom, DEVCLASS_GPU);
    ok = ok && domainControlWrite("devon Development gpu".ptr, 21)  &&  domainDeviceAllowed(devDom, DEVCLASS_GPU);
    ok = ok && domainControlWrite("fsrw Development /host/projects".ptr, 31);     // grant a real path rw
    ok = ok && domainControlWrite("fsdeny Development /host/projects/key".ptr, 37); // deny a sub-path
    // GUI toolbar: from-scratch create + instantiate-from-template (both clean up after)
    ok = ok && domainControlWrite("create CtlNew Personal".ptr, 22) && (domainByName("CtlNew\0".ptr) != 0);
    ok = ok && domainControlWrite("fromtpl CtlInst DevTemplate".ptr, 27) && (domainByName("CtlInst\0".ptr) != 0);
    { const uint a = domainByName("CtlNew\0".ptr);  if (a) domainDelete(a); }
    { const uint c = domainByName("CtlInst\0".ptr); if (c) domainDelete(c); }
    klog(ok ? "[domain] control proof PASS (lifecycle/clone/create/fromtpl + devon/devoff + fsrw/fsdeny via parse+exec; unknown denied)\n"
            : "[domain] control proof FAIL\n");
}

// DM11 boot proof: a domain's distro selects a RO /linux compat root; switching the distro re-roots
// and the package manager follows.  Leaves Development on the Nix distro (a sensible dev default).
__gshared bool g_distroProofDone = false;
public void domDistroProof() {
    if (g_distroProofDone) return;
    g_distroProofDone = true;
    const uint dev = domainByName("Development\0".ptr);
    if (dev == 0) { klog("[domain] distro proof SKIP (no Development)\n"); return; }
    bool ok = domainSetDistro(dev, DISTRO_BUSYBOX) && (domainDistro(dev) == DISTRO_BUSYBOX)
              && (domainPkgMgr(dev) == PKGMGR_BUSYBOX);
    // /linux resolves READ-only in the domain ns (read granted, write denied)
    const(char)* rest; uint rights; bool denied;
    auto d = domainById(dev);
    const uint t = (d !is null && d.nsObjId != 0)
                   ? nsResolveCheck(d.nsObjId, "/linux/bin\0".ptr, rest, rights, denied) : 0;
    ok = ok && (t != 0) && ((rights & CAP_RIGHT_READ) != 0) && ((rights & CAP_RIGHT_WRITE) == 0);
    // switching the distro re-roots /linux and the package manager follows
    ok = ok && domainSetDistro(dev, DISTRO_NIX) && (domainPkgMgr(dev) == PKGMGR_NIX);
    klog(ok ? "[domain] distro proof PASS (busybox -> /linux RO; switch to nix re-roots + pkgMgr follows)\n"
            : "[domain] distro proof FAIL\n");
}

// DM9 boot proof: a 3-level template chain (Base ← Dev ← Leaf).  The effective device mask is the
// intersection along the chain; a child can NARROW (accepted) but DECLARING access the parent
// denies is an escalation (detected + still denied by the merge).  Leaves no domains behind.
__gshared bool g_inheritProofDone = false;
public void domInheritProof() {
    if (g_inheritProofDone) return;
    g_inheritProofDone = true;
    const uint pid = identityByName("Personal\0".ptr);
    if (pid == 0) { klog("[domain] inherit proof SKIP (no Personal)\n"); return; }
    const uint baseId = domainCreate("InhBase\0".ptr, pid, 0);
    const uint devId  = domainCreate("InhDev\0".ptr,  pid, baseId);   // extends Base
    const uint leafId = domainCreate("InhLeaf\0".ptr, pid, devId);    // extends Dev
    bool ok = (baseId != 0) && (devId != 0) && (leafId != 0);
    if (ok) {
        domainById(baseId).allowedDevices = DEVCLASS_INPUT | DEVCLASS_GPU | DEVCLASS_AUDIO;
        domainById(devId).allowedDevices  = DEVCLASS_INPUT | DEVCLASS_GPU;            // narrows (drops AUDIO)
        domainById(leafId).allowedDevices = DEVCLASS_INPUT | DEVCLASS_GPU;
        ok = ok && (domainEffectiveDevices(leafId) == (DEVCLASS_INPUT | DEVCLASS_GPU)); // = intersection
        ok = ok && !domainDeviceEscalates(devId) && !domainDeviceEscalates(leafId);     // narrowing is fine
        // a child that DECLARES AUDIO (its parent dropped it) → escalation, and the merge still denies it
        domainById(leafId).allowedDevices = DEVCLASS_INPUT | DEVCLASS_GPU | DEVCLASS_AUDIO;
        ok = ok && domainDeviceEscalates(leafId);
        ok = ok && ((domainEffectiveDevices(leafId) & DEVCLASS_AUDIO) == 0);
        ok = ok && !domainDeviceAllowed(leafId, DEVCLASS_AUDIO);                         // enforced at the gate
    }
    if (leafId) domainDelete(leafId);
    if (devId)  domainDelete(devId);
    if (baseId) domainDelete(baseId);
    klog(ok ? "[domain] inherit proof PASS (least-privilege merge: effective=intersection; narrow OK, escalation denied+detected)\n"
            : "[domain] inherit proof FAIL\n");
}

// DOMAIN_MANAGER DM2 boot proof: build a real domain's restricted namespace and resolve several
// paths through it exactly as namespaceCheckOpen would, asserting the policy holds.
__gshared bool g_domNsProofDone = false;
public void domainNsProof() {
    if (g_domNsProofDone) return;
    g_domNsProofDone = true;
    const uint dev = domainByName("Development\0".ptr);
    const uint ns = domainBuildNamespace(dev);
    if (ns == 0) { klog("[domain] ns proof FAIL: build\n"); return; }
    const(char)* rest; uint rights; bool denied;
    bool ok = true;
    // (1) the domain's own home — allowed, with WRITE
    const uint t1 = nsResolveCheck(ns, "/Domains/Development/Home/notes\0".ptr, rest, rights, denied);
    ok = ok && (t1 != 0) && ((rights & CAP_RIGHT_WRITE) != 0) && !denied;
    // (2) an unbound path — deny-by-default (no "/" mount)
    const uint t2 = nsResolveCheck(ns, "/etc/passwd\0".ptr, rest, rights, denied);
    ok = ok && (t2 == 0) && !denied;
    // (3) /Shared — allowed read-only (READ, not WRITE)
    const uint t3 = nsResolveCheck(ns, "/Shared/readme\0".ptr, rest, rights, denied);
    ok = ok && (t3 != 0) && ((rights & CAP_RIGHT_WRITE) == 0) && !denied;
    // (4) /Shared/Private — denied, overriding the /Shared allow
    const uint t4 = nsResolveCheck(ns, "/Shared/Private/secret\0".ptr, rest, rights, denied);
    ok = ok && (t4 == 0) && denied;
    // (5) /System — denied
    const uint t5 = nsResolveCheck(ns, "/System/Kernel\0".ptr, rest, rights, denied);
    ok = ok && (t5 == 0) && denied;
    if (ok) klog("[domain] ns proof PASS: Development restricted view (home rw, /Shared ro, Private+/System+unbound denied)\n");
    else    klog("[domain] ns proof FAIL: behaviour\n");
}

// DOMAIN_MANAGER DM2.3 boot proof: a domain whose namespace was built from its manifest
// filesystemAccess (by configboot's TAG_FS_POLICY/TAG_FS_BIND) enforces exactly that policy.
// Runs AFTER configBootApply (the manifest domain + its ns must exist).
__gshared bool g_domFsManifestProofDone = false;
public void domFsManifestProof() {
    if (g_domFsManifestProofDone) return;
    g_domFsManifestProofDone = true;
    auto d = domainById(domainByName("DevSandbox\0".ptr));
    if (d is null || d.nsObjId == 0) { klog("[domain] fs manifest proof SKIP (no DevSandbox ns)\n"); return; }
    const uint ns = d.nsObjId;
    const(char)* rest; uint rights; bool denied;
    bool ok = true;
    // readWrite /Domains/DevSandbox/Home → allowed, WRITE
    const uint t1 = nsResolveCheck(ns, "/Domains/DevSandbox/Home/x\0".ptr, rest, rights, denied);
    ok = ok && (t1 != 0) && ((rights & CAP_RIGHT_WRITE) != 0) && !denied;
    // readWrite /Shared/Projects → allowed, WRITE
    const uint t2 = nsResolveCheck(ns, "/Shared/Projects/build\0".ptr, rest, rights, denied);
    ok = ok && (t2 != 0) && ((rights & CAP_RIGHT_WRITE) != 0) && !denied;
    // deny /Shared/Projects/secrets → denied, overriding the /Shared/Projects rw allow
    const uint t3 = nsResolveCheck(ns, "/Shared/Projects/secrets/key\0".ptr, rest, rights, denied);
    ok = ok && (t3 == 0) && denied;
    // readOnly /System/Templates → allowed READ but not WRITE
    const uint t4 = nsResolveCheck(ns, "/System/Templates/dev\0".ptr, rest, rights, denied);
    ok = ok && (t4 != 0) && ((rights & CAP_RIGHT_READ) != 0) && ((rights & CAP_RIGHT_WRITE) == 0) && !denied;
    // an unbound path → deny-by-default
    const uint t5 = nsResolveCheck(ns, "/etc/passwd\0".ptr, rest, rights, denied);
    ok = ok && (t5 == 0) && !denied;
    if (ok) klog("[domain] fs manifest proof PASS: DevSandbox ns from manifest (Home+Projects rw, /System/Templates ro, secrets denied, unbound deny-by-default)\n");
    else    klog("[domain] fs manifest proof FAIL\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// DOMAIN_MANAGER DM4 — lifecycle state machine + operations (the §4 state machine).
// Registry/state operations (no task spawning — Start's actual launch-into-domain is
// DM3's HOSQ_DOMAIN_SPAWN); these are the verbs' kernel side.  Deny-by-default; a bad
// transition returns false.  States: Defined ⇄ Running ⇄ Paused; Delete from any.
// ─────────────────────────────────────────────────────────────────────────────

// Defined → Running.  Ensures the domain has a restricted ns (DM2); the actual app
// launch into it is DM3 (domainEnterTask via HOSQ_DOMAIN_SPAWN, run from here later).
public bool domainStart(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null || d.state != DomainState.Defined) return false;
    if (d.nsObjId == 0) domainBuildNamespace(domObjId);          // DM2 restricted view
    if (d.overlayObjId == 0) d.overlayObjId = overlayCreate(domObjId, 0); // DM6.2 writable overlay
    d.state = DomainState.Running; d.running = true; d.paused = false;
    return true;
}

// DM6.2 — domain-level overlay ops (the kernel side of HOSQ_DOMAIN_{SNAPSHOT,RESTORE,COMMIT,DISCARD}).
public uint domainSnapshot(uint domObjId)              { return overlaySnapshot(domObjId); }
public bool domainRestore(uint domObjId, uint snapGen) { return overlayRestore(domObjId, snapGen); }
public void domainDiscard(uint domObjId)               { overlayDiscard(domObjId); }
// Commit folds the overlay into a NEW base version (never mutating the old) and bumps the domain epoch.
public uint domainCommit(uint domObjId) {
    const uint newBase = overlayCommit(domObjId);
    if (newBase != 0) { auto d = domainById(domObjId); if (d !is null) ++d.policyEpoch; }
    return newBase;
}
public bool domainShutdown(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null || (d.state != DomainState.Running && d.state != DomainState.Paused)) return false;
    d.state = DomainState.Defined; d.running = false; d.paused = false;
    return true;
}
public bool domainPause(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null || d.state != DomainState.Running) return false;
    d.state = DomainState.Paused; d.paused = true;
    return true;
}
public bool domainResume(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null || d.state != DomainState.Paused) return false;
    d.state = DomainState.Running; d.paused = false;
    return true;
}

// Clone a domain's config (identity / template / persist) into a NEW Defined domain.
// The clone's restricted ns is (re)built lazily on Start.  Returns the new objId, or 0.
public uint domainClone(uint srcObjId, const(char)* newName) {
    auto s = domainById(srcObjId);
    if (s is null) return 0;
    const uint id = domainCreate(newName, s.identityObjId, s.templateObjId);
    if (id == 0) return 0;
    auto n = domainById(id);
    if (n !is null) n.persistMode = s.persistMode;
    return id;
}

public bool domainRename(uint domObjId, const(char)* newName) {
    if (g_domFrozen) return false;
    auto d = domainById(domObjId);
    if (d is null || d.isTemplate) return false;   // DM6: templates are immutable
    const int nl = domCstrLen(newName);
    if (nl == 0 || nl >= DOM_NAME_MAX) return false;
    if (domainByName(newName) != 0) return false;     // unique name
    domCopyName(*d, newName);
    return true;
}

// Delete a domain: release its restricted namespace + the object, free the registry slot.
public bool domainDelete(uint domObjId) {
    if (g_domFrozen) return false;
    auto d = domainById(domObjId);
    if (d is null) return false;
    if (d.nsObjId != 0) { nsRelease(d.nsObjId); d.nsObjId = 0; }
    overlayDestroy(domObjId);   // DM6.2: release the writable overlay
    objRelease(d.objId);
    *d = DomainRec.init;
    return true;
}

// DM4 boot proof: exercise the full lifecycle on a throwaway clone.
__gshared bool g_domLifecycleProofDone = false;
public void domainLifecycleProof() {
    if (g_domLifecycleProofDone) return;
    g_domLifecycleProofDone = true;
    const uint dev = domainByName("Development\0".ptr);
    auto dr = domainById(dev);
    bool ok = (dev != 0) && (dr !is null);

    const uint clone = domainClone(dev, "Dev2Test\0".ptr);
    auto cr = domainById(clone);
    ok = ok && (clone != 0) && (cr !is null) && (cr.identityObjId == dr.identityObjId)
            && (cr.state == DomainState.Defined);
    // state machine
    ok = ok && domainStart(clone)   && (domainById(clone).state == DomainState.Running)
            && (domainById(clone).overlayObjId != 0);                // DM6.2: start creates a writable overlay
    ok = ok && !domainStart(clone);                                  // not from Running
    ok = ok && domainPause(clone)   && (domainById(clone).state == DomainState.Paused);
    ok = ok && !domainResume(dev);                                   // dev is Defined → can't resume
    ok = ok && domainResume(clone)  && (domainById(clone).state == DomainState.Running);
    ok = ok && domainShutdown(clone)&& (domainById(clone).state == DomainState.Defined);
    // rename + delete
    ok = ok && domainRename(clone, "Dev3Test\0".ptr)
            && (domainByName("Dev3Test\0".ptr) == clone) && (domainByName("Dev2Test\0".ptr) == 0);
    ok = ok && domainDelete(clone) && (domainByName("Dev3Test\0".ptr) == 0);

    if (ok) klog("[domain] lifecycle proof PASS: clone/start/pause/resume/shutdown/rename/delete + bad transitions rejected\n");
    else    klog("[domain] lifecycle proof FAIL\n");
}

// DOMAIN_MANAGER DM5: recreate persisted domains from the on-disk store.  Run AFTER the
// identities + the seed/manifest domains exist (so identity links resolve + names dedup).
// The domain DEFINITION survives reboot; the writable overlay+home reload is DM6.
public void domainRehydrateFromDisk() {
    if (!objstoreMounted()) return;
    uint n = 0;
    foreach (i; 0 .. 32) {
        const(char)* nm; const(char)* idn; uint persist;
        if (!objstoreDomainAt(i, nm, idn, persist)) continue;
        if (domainByName(nm) != 0) continue;          // already present (seed/manifest)
        const uint idobj = (idn[0] != 0) ? identityByName(idn) : 0;
        const uint id = domainCreate(nm, idobj, 0);
        auto d = domainById(id);
        if (d !is null) { d.persistMode = cast(ubyte)persist; ++n; }
    }
    if (n != 0) { klog("[domain] rehydrated "); klog_hex(cast(ulong)n); klog(" domain(s) from disk\n"); }
}

// DOMAIN_MANAGER DM5 boot proof (2-boot): boot 1 creates + persists "PersistProbe"; on a
// reboot of the SAME disk it is rehydrated (by domainRehydrateFromDisk, before this runs) → PASS.
__gshared bool g_domPersistProofDone = false;
public void domainPersistProof() {
    if (g_domPersistProofDone) return;
    g_domPersistProofDone = true;
    if (!objstoreMounted()) { klog("[domain] persist proof SKIP (no disk)\n"); return; }
    if (domainByName("PersistProbe\0".ptr) != 0) {
        klog("[domain] persist proof PASS: PersistProbe rehydrated from disk across reboot\n");
        return;
    }
    const uint id = domainCreate("PersistProbe\0".ptr, identityByName("Personal\0".ptr), 0);
    if (id == 0) { klog("[domain] persist proof FAIL: create\n"); return; }
    auto d = domainById(id);
    if (d !is null) d.persistMode = PERSIST_FULL;
    const bool ok = objstoreInstallDomain("PersistProbe", "Personal", "", PERSIST_FULL);
    klog(ok ? "[domain] persist proof: PersistProbe created + persisted to disk (boot 1 -- reboot to verify)\n"
            : "[domain] persist proof FAIL: objstoreInstallDomain\n");
}

// DOMAIN_MANAGER DM6 boot proof: a manifest type=template entry becomes an immutable Template,
// and a domain that names it links to it (templateObjId).
__gshared bool g_domTemplateProofDone = false;
public void domainTemplateProof() {
    if (g_domTemplateProofDone) return;
    g_domTemplateProofDone = true;
    const uint tpl = domainByName("DevTemplate\0".ptr);
    const uint dom = domainByName("DevSandbox\0".ptr);
    if (tpl == 0 || dom == 0) { klog("[domain] template proof SKIP (no DevTemplate/DevSandbox)\n"); return; }
    bool ok = domainIsTemplate(tpl);                        // DevTemplate is a template
    auto dd = domainById(dom);
    ok = ok && (dd !is null) && (dd.templateObjId == tpl);  // DevSandbox references it
    ok = ok && !domainIsTemplate(dom);                      // DevSandbox is a domain, not a template
    ok = ok && !domainRename(tpl, "Renamed\0".ptr);         // a template is immutable → rename refused
    if (ok) klog("[domain] template proof PASS: DevTemplate immutable template + DevSandbox references it\n");
    else    klog("[domain] template proof FAIL\n");
}

public void domainStats() {
    klog("[domain] count=");  klog_hex(cast(ulong)domainCount());
    klog(" created=");        klog_hex(g_domCreateTotal);
    klog(" frozen=");         klog_hex(g_domFrozen ? 1 : 0);
    klog(" domobj=");         klog_hex(cast(ulong)objCountType(ObjType.Domain));
    klog("\n");
}
