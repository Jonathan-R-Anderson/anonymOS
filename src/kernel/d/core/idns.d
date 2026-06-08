// Identity Namespace Manager — Phase 4 of roadmap/IDENTITY_DOMAIN_ROADMAP.md.
//
// Builds a per-identity *object-tree view* on top of core/namespace.d: each
// identity owns a private object-root (a Directory) bound at /identities/<name>,
// and a process in that identity gets its OWN clone of the identity's namespace
// template with that root bound RW.  Nothing of one identity's root is reachable
// from another's (deny-by-default); a cross-identity object is reachable only
// through an explicit, cap-wrapped, audited ShareRule.
//
// Kernel build constraints (hard): -betterC (ldc2, no GC/druntime/exceptions),
// plain structs, __gshared fixed-size tables, @nogc nothrow, -O0.
module core.idns;

import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.namespace : nsAlloc, nsClone, nsBind, nsResolve, nsResolveWithRights,
                        nsRelease, nsRootDir;
import core.identity : IdentityId, NamespaceId, IdentityRec, ShareRule,
                       identityById, identityCreate, identityByName,
                       g_identities, ID_MAX, g_idShareRules, ID_SHARE_RULES_MAX,
                       NetPolicy, ClipPolicy, GuiPolicy, TRUST_WORK;
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE,
                  CAP_RIGHT_UNIVERSE, CAP_RIGHT_ADMIN_ALL;
import core.audit : auditLog, AuditKind;
import core.io : klog, klog_hex;

extern (C) @nogc nothrow:

__gshared ulong g_idnsCloneTotal = 0;
__gshared ulong g_idnsShareTotal = 0;
__gshared bool  g_idnsRootsInited = false;
__gshared bool  g_idnsSelfTested  = false;

// Build "/identities/<name>" (null-terminated) into buf.
private void idnsRootPath(ref char[64] buf, ref const(IdentityRec) r) {
    static immutable string pfx = "/identities/";
    int n = 0;
    foreach (c; pfx) buf[n++] = c;
    foreach (i; 0 .. r.nameLen) if (n < 62) buf[n++] = r.name[i];
    buf[n] = 0;
}

// Build "/shared/<objId-decimal>" (null-terminated) into buf.
private void idnsSharedPath(ref char[40] buf, uint objId) {
    static immutable string pfx = "/shared/";
    int n = 0;
    foreach (c; pfx) buf[n++] = c;
    char[10] tmp; int t = 0;
    if (objId == 0) tmp[t++] = '0';
    else { uint v = objId; while (v > 0) { tmp[t++] = cast(char)('0' + v % 10); v /= 10; } }
    while (t > 0) buf[n++] = tmp[--t];
    buf[n] = 0;
}

// Ensure each live identity has a private object-root Directory.  Idempotent;
// run once at boot after identityInitDefaults().  (The /identities/<name> binding
// itself is added per-process by idnsForIdentity so rebinds never leak.)
public void idnsInitRoots() {
    if (g_idnsRootsInited) return;
    g_idnsRootsInited = true;
    foreach (ref e; g_identities) {
        if (!e.inUse) continue;
        if (e.objRootObjId == 0 || objGet(e.objRootObjId) is null)
            e.objRootObjId = objAlloc(ObjType.Directory, null);
    }
}

// A private namespace for a process in identity `id`: clone the identity's
// template, then bind its object-root RW at /identities/<name>.  Returns 0 on
// failure.  Rebinds in the clone never affect other processes (namespace.d clone
// semantics).
public NamespaceId idnsForIdentity(IdentityId id) {
    auto r = identityById(id);
    if (r is null) return 0;
    if (r.objRootObjId == 0 || objGet(r.objRootObjId) is null)
        r.objRootObjId = objAlloc(ObjType.Directory, null);
    NamespaceId ns = nsClone(r.nsTemplate);
    if (ns == 0) return 0;
    char[64] p; idnsRootPath(p, *r);
    nsBind(ns, p.ptr, r.objRootObjId, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
    ++g_idnsCloneTotal;
    return ns;
}

// True iff `path` resolves to a specifically-bound object in this namespace —
// not merely the global rtfs-root fallback.  This is the "nothing reachable
// across identities unless explicitly bound" check.
public bool idnsVisible(NamespaceId taskNs, const(char)* path) {
    const(char)* rest;
    uint obj = nsResolve(taskNs, path, rest);
    return obj != 0 && obj != nsRootDir();
}

// ── cross-identity object shares (deny-by-default) ───────────────────────────
private ShareRule* idnsShareRuleFind(IdentityId owner, uint objId, IdentityId grantee) {
    foreach (ref s; g_idShareRules)
        if (s.inUse && s.owner == owner && s.objId == objId && s.grantee == grantee)
            return &s;
    return null;
}

// Install a ShareRule (the policy authority does this; here for tests/§9 reuse).
public bool idnsShareRuleAdd(IdentityId owner, uint objId, IdentityId grantee, uint rights) {
    if (idnsShareRuleFind(owner, objId, grantee) !is null) return true;
    foreach (ref s; g_idShareRules)
        if (!s.inUse) {
            s.inUse = true; s.owner = owner; s.objId = objId;
            s.rights = rights; s.grantee = grantee;
            return true;
        }
    return false;
}

// Grant a cross-identity object share: requires a matching ShareRule and the
// requested rights ⊆ the rule's rights, then binds a cap-wrapped /shared/<obj>
// into the grantee identity's template (its future processes inherit it).
// Denials/grants are audited.
public bool idnsShare(IdentityId owner, uint objId, IdentityId grantee, uint rights) {
    auto rule = idnsShareRuleFind(owner, objId, grantee);
    if (rule is null || (rights & rule.rights) != rights) {
        auditLog(AuditKind.IdNsDeny, objId, grantee);
        return false;
    }
    auto g = identityById(grantee);
    if (g is null || objGet(objId) is null) {
        auditLog(AuditKind.IdNsDeny, objId, grantee);
        return false;
    }
    char[40] sp; idnsSharedPath(sp, objId);
    if (!nsBind(g.nsTemplate, sp.ptr, objId, rights)) return false;
    ++g_idnsShareTotal;
    auditLog(AuditKind.IdShare, objId, grantee);
    return true;
}

// One-shot proof (roadmap §4 outcome): two throwaway identities get disjoint
// object-roots; A's root is invisible to B; a shared object becomes reachable by
// B only after an authorized share (and stays invisible to A).  Self-contained:
// everything created here is released, leaving the real registry untouched.
public void idnsSelfTest() {
    if (g_idnsSelfTested) return;
    g_idnsSelfTested = true;

    enum uint CEIL = CAP_RIGHT_UNIVERSE & ~CAP_RIGHT_ADMIN_ALL;
    enum uint GUI  = cast(uint)(GuiPolicy.BorderAlways | GuiPolicy.TitleLabel);

    NamespaceId tplA = nsAlloc(), tplB = nsAlloc();
    IdentityId a = identityCreate("idnsA\0".ptr, 0xFF112233, TRUST_WORK, CEIL, tplA,
                                  NetPolicy.None, ClipPolicy.Deny, GUI);
    IdentityId b = identityCreate("idnsB\0".ptr, 0xFF445566, TRUST_WORK, CEIL, tplB,
                                  NetPolicy.None, ClipPolicy.Deny, GUI);
    auto ra = identityById(a), rb = identityById(b);
    if (a == 0 || b == 0 || ra is null || rb is null) { klog("[idns] selftest FAIL: create\n"); return; }
    ra.objRootObjId = objAlloc(ObjType.Directory, null);
    rb.objRootObjId = objAlloc(ObjType.Directory, null);

    NamespaceId nsA = idnsForIdentity(a);
    NamespaceId nsB = idnsForIdentity(b);

    bool ok = (nsA != 0 && nsB != 0 && ra.objRootObjId != 0 && rb.objRootObjId != 0);
    // disjoint roots: each sees its own, not the other's
    ok = ok &&  idnsVisible(nsA, "/identities/idnsA\0".ptr);
    ok = ok && !idnsVisible(nsB, "/identities/idnsA\0".ptr);   // A's root invisible to B
    ok = ok &&  idnsVisible(nsB, "/identities/idnsB\0".ptr);
    ok = ok && !idnsVisible(nsA, "/identities/idnsB\0".ptr);
    // resolution of A's path in A's ns lands on A's object-root
    {
        const(char)* rest;
        ok = ok && (nsResolve(nsA, "/identities/idnsA/x\0".ptr, rest) == ra.objRootObjId);
        ok = ok && (nsResolve(nsB, "/identities/idnsA/x\0".ptr, rest) != ra.objRootObjId);
    }

    // share gating: an object owned by A, shared to B
    uint shObj = objAlloc(ObjType.Directory, null);
    char[40] sp; idnsSharedPath(sp, shObj);
    ok = ok && !idnsShare(a, shObj, b, CAP_RIGHT_READ);        // no rule → denied
    ok = ok && idnsShareRuleAdd(a, shObj, b, CAP_RIGHT_READ);
    ok = ok && !idnsShare(a, shObj, b, CAP_RIGHT_READ | CAP_RIGHT_WRITE); // rights ⊄ rule → denied
    ok = ok && idnsShare(a, shObj, b, CAP_RIGHT_READ);         // authorized → granted
    {
        NamespaceId nsB2 = idnsForIdentity(b);                 // fresh B ns (after share)
        const(char)* rest; uint rr;
        ok = ok && (nsResolveWithRights(nsB2, sp.ptr, rest, rr) == shObj);
        ok = ok && ((rr & CAP_RIGHT_READ) == CAP_RIGHT_READ);
        ok = ok && (nsResolve(nsA, sp.ptr, rest) != shObj);    // A never gets the share
        nsRelease(nsB2);
    }

    // teardown — leave the registry exactly as found
    nsRelease(nsA); nsRelease(nsB);
    objRelease(shObj);
    objRelease(ra.objRootObjId); objRelease(rb.objRootObjId);
    objRelease(a); objRelease(b);
    foreach (ref s; g_idShareRules)
        if (s.inUse && s.owner == a) s = ShareRule.init;
    *ra = IdentityRec.init; *rb = IdentityRec.init;
    nsRelease(tplA); nsRelease(tplB);

    if (ok) klog("[idns] selftest PASS\n");
    else    klog("[idns] selftest FAIL\n");
}

public void idnsStats() {
    klog("[idns] clones=");  klog_hex(g_idnsCloneTotal);
    klog(" shares=");        klog_hex(g_idnsShareTotal);
    klog(" rootsInit=");     klog_hex(g_idnsRootsInited ? 1 : 0);
    klog("\n");
}
