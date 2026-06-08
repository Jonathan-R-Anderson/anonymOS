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
import core.cap : CAP_RIGHT_UNIVERSE, CAP_RIGHT_ADMIN_ALL, CAP_RIGHT_ALL;
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
                            bool disposable) {
    const NamespaceId ns = nsAlloc();
    const IdentityId id = identityCreate(name, color, trust, ceiling, ns, net, clip, gui);
    auto r = identityById(id);
    if (r !is null) { r.disposable = disposable; identityActivate(id); }
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
    mkBootIdentity("System\0".ptr,     0xFF808080, TRUST_SYSTEM,     CEIL_FULL, NetPolicy.NAT,        ClipPolicy.AllowDownTrust,    GUI_BASE, false);
    mkBootIdentity("Personal\0".ptr,   0xFF2E7D32, TRUST_PERSONAL,   CEIL_USER, NetPolicy.NAT,        ClipPolicy.AskApproval,       GUI_BASE, false);
    mkBootIdentity("Work\0".ptr,       0xFF1565C0, TRUST_WORK,       CEIL_USER, NetPolicy.VPN,        ClipPolicy.AllowSameIdentity, GUI_WORK, false);
    mkBootIdentity("Banking\0".ptr,    0xFFFFD600, TRUST_BANKING,    CEIL_USER, NetPolicy.VPN,        ClipPolicy.Deny,              GUI_BANK, false);
    mkBootIdentity("Development\0".ptr,0xFF6A1B9A, TRUST_DEV,        CEIL_USER, NetPolicy.LocalOnly,  ClipPolicy.AskApproval,       GUI_BASE, false);
    mkBootIdentity("Untrusted\0".ptr,  0xFFB71C1C, TRUST_UNTRUSTED,  CEIL_USER, NetPolicy.Tor,        ClipPolicy.Deny,              GUI_BASE, false);
    mkBootIdentity("Disposable\0".ptr, 0xFFFF6D00, TRUST_DISPOSABLE, CEIL_USER, NetPolicy.Disposable, ClipPolicy.Deny,              GUI_BASE, true);
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
