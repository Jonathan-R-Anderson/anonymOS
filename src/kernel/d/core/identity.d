// Identity / Security-Domain model — Phase 1 (data model) of
// roadmap/IDENTITY_DOMAIN_ROADMAP.md.
//
// A Qubes-style *identity* (security domain) is a first-class object
// (ObjType.Identity): every user-facing process is labelled with one, windows
// are bordered with the identity's color by the trusted compositor, and
// isolation is enforced by the existing capability + object + namespace
// substrate — not Unix uids or VMs.  Deny-by-default; the capability is always
// the authority (there is no ambient "current identity" global).
//
// Phase 1 is *only* the data model: the typed records, enums and fixed tables.
// No registry logic, validation, policy, or enforcement yet — those land in
// later phases (Identity Manager §2, namespaces §4, IPC §5, GUI §6, …).  Keeping
// the first slice to declarations matches the roadmap's "do not over-build."
//
// Kernel build constraints (hard): -betterC (ldc2, no GC/druntime/exceptions),
// plain structs, __gshared fixed-size tables, @nogc nothrow, -O0.
module core.identity;

import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.cap : CAP_RIGHT_UNIVERSE, CAP_RIGHT_ADMIN_ALL, CAP_RIGHT_ALL,
                  CAP_RIGHT_ADMIN_IDENTITY, CAPTAB_COUNT,
                  capLiveCount, capTableClear, capTableCloneNarrowing;
import core.admin : adminInstallCapIn, adminRequireIn; // §3 identity-transition cap
import core.audit : auditLog, AuditKind;               // §H identity decisions
import core.namespace : nsAlloc, nsRelease;
import core.io : klog, klog_hex;

extern (C) @nogc nothrow:

// --- identifiers (all are object ids; 0 = none) ------------------------------
alias IdentityId   = uint;   // objId of an ObjType.Identity
alias NamespaceId  = uint;   // objId of an ObjType.Namespace (core/namespace.d)
alias GuiContextId = uint;   // objId grouping an identity's windows/surfaces
alias IdentityColor = uint;  // packed 0xAARRGGBB, drawn by the trusted compositor

// Trust levels — higher = more trusted; used only as default-flow hints (e.g. a
// "down-trust" clipboard rule), never as an ambient authority check.
enum ubyte TRUST_SYSTEM    = 100;
enum ubyte TRUST_BANKING   = 80;
enum ubyte TRUST_WORK      = 60;
enum ubyte TRUST_PERSONAL  = 50;
enum ubyte TRUST_DEV       = 40;
enum ubyte TRUST_UNTRUSTED = 10;
enum ubyte TRUST_DISPOSABLE = 5;

enum NetPolicy : ubyte { None = 0, NAT, VPN, Tor, LocalOnly, Disposable }
enum ClipPolicy : ubyte { Deny = 0, AskApproval, AllowSameIdentity, AllowDownTrust }
enum GuiPolicy : uint {
    BorderAlways        = 1,
    TitleLabel          = 2,
    NoScreenshotAcrossId = 4,
    NoGlobalGrab        = 8,
}

// --- the identity object (immutable once `active`) ---------------------------
enum int ID_NAME_MAX = 24;
struct IdentityRec {
    bool          inUse;
    bool          active;        // once true: immutable except via signed txn (§9)
    bool          disposable;    // §8 throwaway domain
    IdentityId    objId;         // ObjType.Identity
    uint          templateId;    // disposable: the template it was cloned from (else 0)
    uint          nameLen;
    char[ID_NAME_MAX] name;      // "System","Personal","Work","Banking",…
    IdentityColor color;         // border color (compositor-drawn)
    ubyte         trust;         // TRUST_*
    uint          rightsCeiling; // max cap rights any process in this identity may hold
    NamespaceId   nsTemplate;    // object-tree root / namespace template cloned per process
    uint          objRootObjId;  // /identities/<name> Directory object
    uint          allowedDevices;// bitmask of brokered device classes (§7)
    NetPolicy     net;
    ClipPolicy    clip;
    uint          gui;           // GuiPolicy flags
    ulong         policyEpoch;   // bumped by each signed policy transaction (§9)
}

// --- §7 brokered device classes (the bits in IdentityRec.allowedDevices) ------
// DOMAIN_MANAGER DM8: a domain's identity may only open device nodes whose class bit is set.
// allowedDevices == 0 ⟹ no brokered devices (deny-by-default); all seeded identities set it.
enum uint DEVCLASS_INPUT  = 1u << 0;   // /dev/input/event* (keyboard/mouse)
enum uint DEVCLASS_GPU    = 1u << 1;   // /dev/dri/* (DRM/KMS)
enum uint DEVCLASS_CAMERA = 1u << 2;   // /dev/video*
enum uint DEVCLASS_MIC    = 1u << 3;   // /dev/snd/* capture
enum uint DEVCLASS_AUDIO  = 1u << 4;   // /dev/snd/* playback
enum uint DEVCLASS_USB    = 1u << 5;   // /dev/bus/usb/*
enum uint DEVCLASS_NET    = 1u << 6;   // WiFi/network via the cap-gated LKL provider socket
enum uint DEVCLASS_ALL    = DEVCLASS_INPUT | DEVCLASS_GPU | DEVCLASS_CAMERA |
                            DEVCLASS_MIC | DEVCLASS_AUDIO | DEVCLASS_USB | DEVCLASS_NET;

// DM8: true iff the identity may open the given device class.  An unknown identity fails OPEN
// (returns true) — only a *known* identity with the bit clear denies, so non-identity kernel
// paths are never blocked.
public bool identityDeviceAllowed(IdentityId idObj, uint devClass) {
    if (idObj == 0 || devClass == 0) return true;
    auto r = identityById(idObj);
    if (r is null) return true;
    return (r.allowedDevices & devClass) == devClass;
}

// --- per-identity allow-lists (deny-by-default; small fixed tables) ----------
// 0 brokerSvcObjId = direct allow; non-zero = the brokered service the pair routes through.
struct IpcPairRule { bool inUse; IdentityId from, to; uint brokerSvcObjId; }
// A cap-wrapped cross-identity object share (audited; rights ⊆ owner's).
struct ShareRule   { bool inUse; IdentityId owner; uint objId; uint rights; IdentityId grantee; }

// --- fixed registry tables (capacity chosen small; deny-by-default) ----------
// Logic that fills these (identityCreate/validate/freeze, rule install) is Phase 2+.
enum int ID_MAX          = 32;   // distinct identities
enum int ID_IPC_RULES_MAX = 64;  // cross-identity IPC allow-list entries
enum int ID_SHARE_RULES_MAX = 64;// cross-identity object-share entries

// Names are identity-prefixed because the -betterC `extern (C)` blanket exports
// module globals as flat C symbols (so `g_ids` would clash with core/secipc.d).
public __gshared IdentityRec[ID_MAX]           g_identities;
public __gshared IpcPairRule[ID_IPC_RULES_MAX]  g_idIpcRules;
public __gshared ShareRule[ID_SHARE_RULES_MAX]  g_idShareRules;
public __gshared bool g_idFrozen = false;      // registry immutable after policy load (§2)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 — Identity Manager (roadmap §2): registry, create-from-defaults,
// lookup by id/name, validation, rights-ceiling, read-only after freeze.
// There is NO ambient "current identity" anywhere — authority is always the cap;
// these are registry accessors only.
// ─────────────────────────────────────────────────────────────────────────────

__gshared ulong g_idCreateTotal    = 0;
__gshared bool  g_idDefaultsInited = false;
__gshared bool  g_idSelfTested     = false;

private int idCstrLen(const(char)* s) {
    if (s is null) return 0;
    int n = 0;
    while (n < ID_NAME_MAX && s[n] != 0) ++n;
    return n;
}
private bool idNameEq(ref const(IdentityRec) e, const(char)* name) {
    const int n = idCstrLen(name);
    if (e.nameLen != cast(uint)n) return false;
    foreach (i; 0 .. n) if (e.name[i] != name[i]) return false;
    return true;
}
private void idCopyName(ref IdentityRec e, const(char)* name) {
    const int n = idCstrLen(name);
    foreach (i; 0 .. n) e.name[i] = name[i];
    e.nameLen = cast(uint)n;
}

// Resolve an identity object id to its record (or null).  No global "current".
public IdentityRec* identityById(IdentityId id) {
    if (id == 0) return null;
    foreach (ref e; g_identities) if (e.inUse && e.objId == id) return &e;
    return null;
}

// Resolve a name to its identity object id (0 = none).  Names are unique.
public IdentityId identityByName(const(char)* name) {
    if (name is null || name[0] == 0) return 0;
    foreach (ref e; g_identities) if (e.inUse && idNameEq(e, name)) return e.objId;
    return 0;
}

public uint identityCount() {
    uint n = 0;
    foreach (ref e; g_identities) if (e.inUse) ++n;
    return n;
}

// Create an Identity object.  Refused after freeze, on a duplicate name, a zero
// color (a border color is mandatory), or a ceiling that exceeds the universe.
public IdentityId identityCreate(const(char)* name, IdentityColor color, ubyte trust,
                                 uint ceiling, NamespaceId nsTemplate,
                                 NetPolicy net, ClipPolicy clip, uint gui) {
    if (g_idFrozen) return 0;                            // read-only after policy load
    const int nl = idCstrLen(name);
    if (nl == 0 || nl >= ID_NAME_MAX) return 0;
    if (color == 0) return 0;                            // border color is mandatory
    if ((ceiling & ~CAP_RIGHT_UNIVERSE) != 0) return 0;  // ceiling ⊆ universe
    if (identityByName(name) != 0) return 0;             // unique name
    foreach (ref e; g_identities) if (!e.inUse) {
        e = IdentityRec.init;
        e.inUse = true;
        e.color = color; e.trust = trust; e.rightsCeiling = ceiling;
        e.nsTemplate = nsTemplate; e.net = net; e.clip = clip; e.gui = gui;
        idCopyName(e, name);
        const uint oid = objAlloc(ObjType.Identity, cast(void*)&e);
        if (oid == 0) { e = IdentityRec.init; return 0; }
        e.objId = oid;
        ++g_idCreateTotal;
        return oid;
    }
    return 0;                                            // table full
}

// Make an identity immutable (mutation after this requires a signed policy txn, §9).
public void identityActivate(IdentityId id) {
    auto r = identityById(id);
    if (r !is null) r.active = true;
}

// Structural validity: ceiling ⊆ universe, a color set, a name, and a live ns template.
public bool identityValidate(IdentityId id) {
    auto r = identityById(id);
    if (r is null) return false;
    if (r.color == 0) return false;
    if ((r.rightsCeiling & ~CAP_RIGHT_UNIVERSE) != 0) return false;
    if (r.nameLen == 0) return false;
    if (objGet(r.nsTemplate) is null) return false;      // ns template must be live
    return true;
}

public void identityFreeze() { g_idFrozen = true; }      // registry immutable

// One boot identity: a private ns template (Phase 4 clones it per process), the
// record, then activate (immutable).
private void mkBootIdentity(const(char)* name, IdentityColor color, ubyte trust,
                            uint ceiling, NetPolicy net, ClipPolicy clip, uint gui,
                            bool disposable, uint allowedDevices) {
    const NamespaceId ns = nsAlloc();
    const IdentityId id = identityCreate(name, color, trust, ceiling, ns, net, clip, gui);
    auto r = identityById(id);
    if (r !is null) {
        r.disposable = disposable;
        r.allowedDevices = allowedDevices;    // DM8: §7 device policy (set before activation)
        identityActivate(id);
    }
}

// Compiled-in default identities (the declarative policy file is Phase 9).  Colors
// / trust / net / clip / gui mirror roadmap §F.  System is the only identity whose
// ceiling includes admin caps.
public void identityInitDefaults() {
    if (g_idDefaultsInited) return;
    g_idDefaultsInited = true;
    enum uint CEIL_FULL = CAP_RIGHT_UNIVERSE;                          // System only
    enum uint CEIL_USER = CAP_RIGHT_UNIVERSE & ~CAP_RIGHT_ADMIN_ALL;   // no admin caps
    enum uint GUI_BASE  = cast(uint)(GuiPolicy.BorderAlways | GuiPolicy.TitleLabel);
    enum uint GUI_WORK  = GUI_BASE | cast(uint)GuiPolicy.NoScreenshotAcrossId;
    enum uint GUI_BANK  = GUI_WORK | cast(uint)GuiPolicy.NoGlobalGrab;
    // DM8 §7 device policy: all get INPUT+GPU (a window needs both); higher trust adds peripherals.
    enum uint DEV_FULL = DEVCLASS_ALL;
    enum uint DEV_HOME = DEVCLASS_INPUT | DEVCLASS_GPU | DEVCLASS_AUDIO | DEVCLASS_CAMERA | DEVCLASS_MIC | DEVCLASS_USB | DEVCLASS_NET;
    enum uint DEV_WORK = DEVCLASS_INPUT | DEVCLASS_GPU | DEVCLASS_AUDIO | DEVCLASS_USB | DEVCLASS_NET;   // no camera/mic
    enum uint DEV_LOCK = DEVCLASS_INPUT | DEVCLASS_GPU;                                    // no cam/mic/usb/audio/net
    // DEV_LOCK plus the network class.  DEVCLASS_NET used to gate only the AF_UNIX connect to
    // the LKL provider socket, where "no NET" sensibly meant "may not manage the WiFi
    // provider".  Now that sys_socket() consults the same bit, it means "may not use IP at
    // all" -- and Banking/Untrusted/Disposable each declare a NetPolicy (VPN/Tor/Disposable)
    // that PRESUMES working network, so leaving them on DEV_LOCK would deny the very traffic
    // their policy exists to route.  The split is: the device bit decides whether you may
    // open a socket, NetPolicy decides where the packets are allowed to go.
    enum uint DEV_LOCKNET = DEV_LOCK | DEVCLASS_NET;
    mkBootIdentity("System\0".ptr,     0xFF808080, TRUST_SYSTEM,     CEIL_FULL, NetPolicy.NAT,        ClipPolicy.AllowDownTrust,    GUI_BASE, false, DEV_FULL);
    mkBootIdentity("Personal\0".ptr,   0xFF2E7D32, TRUST_PERSONAL,   CEIL_USER, NetPolicy.NAT,        ClipPolicy.AskApproval,       GUI_BASE, false, DEV_HOME);
    mkBootIdentity("Work\0".ptr,       0xFF1565C0, TRUST_WORK,       CEIL_USER, NetPolicy.VPN,        ClipPolicy.AllowSameIdentity, GUI_WORK, false, DEV_WORK);
    mkBootIdentity("Banking\0".ptr,    0xFFFFD600, TRUST_BANKING,    CEIL_USER, NetPolicy.VPN,        ClipPolicy.Deny,              GUI_BANK, false, DEV_LOCKNET);
    mkBootIdentity("Development\0".ptr,0xFF6A1B9A, TRUST_DEV,        CEIL_USER, NetPolicy.LocalOnly,  ClipPolicy.AskApproval,       GUI_BASE, false, DEV_FULL);
    mkBootIdentity("Untrusted\0".ptr,  0xFFB71C1C, TRUST_UNTRUSTED,  CEIL_USER, NetPolicy.Tor,        ClipPolicy.Deny,              GUI_BASE, false, DEV_LOCKNET);
    mkBootIdentity("Disposable\0".ptr, 0xFFFF6D00, TRUST_DISPOSABLE, CEIL_USER, NetPolicy.Disposable, ClipPolicy.Deny,              GUI_BASE, true,  DEV_LOCKNET);
}

// One-shot boot proof (roadmap §2 outcome): create/lookup/validate; duplicate name,
// over-universe ceiling, missing color, and post-freeze mutation all refused.
public void identitySelfTest() {
    if (g_idSelfTested) return;
    g_idSelfTested = true;

    const uint ns = nsAlloc();
    const IdentityId id = identityCreate("SelftestId\0".ptr, 0xFF123456, TRUST_WORK,
                                         CAP_RIGHT_UNIVERSE & ~CAP_RIGHT_ADMIN_ALL, ns,
                                         NetPolicy.NAT, ClipPolicy.AskApproval,
                                         cast(uint)(GuiPolicy.BorderAlways | GuiPolicy.TitleLabel));
    bool ok = (id != 0);
    auto r = identityById(id);
    ok = ok && (r !is null) && (r.objId == id) && (r.color == 0xFF123456);
    ok = ok && (identityByName("SelftestId\0".ptr) == id);
    ok = ok && (identityByName("Nonexistent\0".ptr) == 0);
    ok = ok && identityValidate(id);
    // duplicate name refused
    ok = ok && (identityCreate("SelftestId\0".ptr, 0xFF654321, TRUST_DEV,
                               CAP_RIGHT_ALL, ns, NetPolicy.None, ClipPolicy.Deny, 0) == 0);
    // ceiling exceeding the universe refused
    ok = ok && (identityCreate("BadCeil\0".ptr, 0xFFABCDEF, TRUST_DEV,
                               0xFFFFFFFF, ns, NetPolicy.None, ClipPolicy.Deny, 0) == 0);
    // missing border color refused
    ok = ok && (identityCreate("NoColor\0".ptr, 0, TRUST_DEV,
                               CAP_RIGHT_ALL, ns, NetPolicy.None, ClipPolicy.Deny, 0) == 0);
    // mutation after freeze refused (toggle for the test, then restore)
    const bool wasFrozen = g_idFrozen;
    g_idFrozen = true;
    ok = ok && (identityCreate("AfterFreeze\0".ptr, 0xFF222222, TRUST_DEV,
                               CAP_RIGHT_ALL, ns, NetPolicy.None, ClipPolicy.Deny, 0) == 0);
    g_idFrozen = wasFrozen;

    // clean up the throwaway identity + its ns template
    if (r !is null) { objRelease(r.objId); *r = IdentityRec.init; }
    nsRelease(ns);

    if (ok) klog("[identity] selftest PASS\n");
    else    klog("[identity] selftest FAIL\n");
}

public void identityStats() {
    klog("[identity] count=");  klog_hex(cast(ulong)identityCount());
    klog(" created=");          klog_hex(g_idCreateTotal);
    klog(" frozen=");           klog_hex(g_idFrozen ? 1 : 0);
    klog(" idobj=");            klog_hex(cast(ulong)objCountType(ObjType.Identity));
    klog("\n");
}

// klog an identity's name (or "?") — used by the idps process-identity dump.
public void identityNamePrint(IdentityId id) {
    auto r = identityById(id);
    if (r is null) { klog("?"); return; }
    foreach (i; 0 .. r.nameLen) {
        char[2] c; c[0] = r.name[i]; c[1] = 0;
        klog(c.ptr);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 — Process-Manager integration (roadmap §3): identity inheritance is
// done by fork/clone in kernel_main.d; here is the privileged transition gate and
// its compiled-in launch rules (the declarative policy file is §9).  Deny-by-
// default; every denial is audited.
// ─────────────────────────────────────────────────────────────────────────────

struct LaunchRule { bool inUse; IdentityId from, to; }
enum int ID_LAUNCH_RULES_MAX = 32;
public __gshared LaunchRule[ID_LAUNCH_RULES_MAX] g_idLaunchRules;
__gshared bool g_idLaunchInited = false;

private void addLaunchRule(const(char)* fromName, const(char)* toName) {
    const IdentityId f = identityByName(fromName);
    const IdentityId t = identityByName(toName);
    if (f == 0 || t == 0) return;
    foreach (ref r; g_idLaunchRules)
        if (!r.inUse) { r.inUse = true; r.from = f; r.to = t; return; }
}

// Compiled-in launch rules (roadmap §F): System may launch into every other
// identity; Development may launch a Disposable.  Must run after the identities
// exist (called from kernel_main.d right after identityInitDefaults()).
public void identityInitLaunchRules() {
    if (g_idLaunchInited) return;
    g_idLaunchInited = true;
    addLaunchRule("System\0".ptr, "Personal\0".ptr);
    addLaunchRule("System\0".ptr, "Work\0".ptr);
    addLaunchRule("System\0".ptr, "Banking\0".ptr);
    addLaunchRule("System\0".ptr, "Development\0".ptr);
    addLaunchRule("System\0".ptr, "Untrusted\0".ptr);
    addLaunchRule("System\0".ptr, "Disposable\0".ptr);
    addLaunchRule("Development\0".ptr, "Disposable\0".ptr);
}

public bool policyLaunchAllowed(IdentityId from, IdentityId to) {
    foreach (ref r; g_idLaunchRules)
        if (r.inUse && r.from == from && r.to == to) return true;
    return false;
}

// The transition gate: a child may move into a DIFFERENT identity only if the
// launcher's cap table holds CAP_RIGHT_ADMIN_IDENTITY *and* a launch rule permits
// parent→target.  Same identity = inherit (always allowed).  Untrusted may never
// transition.  Default-deny; denials are audited (subject=target, detail=parent).
public bool identityCanTransition(IdentityId parentId, IdentityId targetId, int capTabId) {
    if (!identityValidate(targetId)) {
        auditLog(AuditKind.IdTransitionDeny, targetId, parentId); return false;
    }
    if (targetId == parentId) return true;                 // inherit — no transition
    auto p = identityById(parentId);
    if (p !is null && p.trust == TRUST_UNTRUSTED) {        // Untrusted → anything denied
        auditLog(AuditKind.IdTransitionDeny, targetId, parentId); return false;
    }
    if (!adminRequireIn(capTabId, CAP_RIGHT_ADMIN_IDENTITY)) {
        auditLog(AuditKind.IdTransitionDeny, targetId, parentId); return false;
    }
    if (!policyLaunchAllowed(parentId, targetId)) {
        auditLog(AuditKind.IdTransitionDeny, targetId, parentId); return false;
    }
    return true;
}

__gshared bool g_idProcSelfTested = false;

// One-shot proof (roadmap §3 outcome): same-identity inherit allowed; a cross-
// identity transition is refused without the admin cap, refused without a launch
// rule, refused from Untrusted; and a cap table narrowed to a no-admin ceiling
// loses the identity admin cap (cap set ⊆ ceiling).
public void idprocSelfTest() {
    if (g_idProcSelfTested) return;
    g_idProcSelfTested = true;

    const IdentityId sys  = identityByName("System\0".ptr);
    const IdentityId work = identityByName("Work\0".ptr);
    const IdentityId bank = identityByName("Banking\0".ptr);
    const IdentityId untr = identityByName("Untrusted\0".ptr);
    if (sys == 0 || work == 0 || bank == 0 || untr == 0) {
        klog("[idproc] selftest FAIL: ids\n"); return;
    }

    const int st = CAPTAB_COUNT - 3;   // spare (admin uses -2, cap/ipc use -1)
    const int dt = CAPTAB_COUNT - 4;
    if (capLiveCount(st) != 0 || capLiveCount(dt) != 0) {
        klog("[idproc] selftest SKIP\n"); return;
    }

    bool ok = true;
    ok = ok && identityCanTransition(work, work, st);          // inherit (no cap needed)
    ok = ok && !identityCanTransition(sys, work, st);          // no admin cap → denied
    ok = ok && adminInstallCapIn(st, CAP_RIGHT_ADMIN_IDENTITY);
    ok = ok && identityCanTransition(sys, work, st);           // cap + launch rule → allowed
    ok = ok && !identityCanTransition(work, bank, st);         // no launch rule → denied
    ok = ok && !identityCanTransition(untr, work, st);         // Untrusted → denied

    // cap set ⊆ ceiling: narrowing the admin-holding table to a no-admin ceiling
    // must strip the identity admin cap.
    capTableCloneNarrowing(st, dt, CAP_RIGHT_UNIVERSE & ~CAP_RIGHT_ADMIN_ALL);
    ok = ok && !adminRequireIn(dt, CAP_RIGHT_ADMIN_IDENTITY);

    capTableClear(dt);
    capTableClear(st);

    if (ok) klog("[idproc] selftest PASS\n");
    else    klog("[idproc] selftest FAIL\n");
}
