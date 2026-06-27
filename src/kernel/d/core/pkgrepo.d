// Software repository + package manager — DM7 of roadmap/domain_manager.md.
//
// A *repository* is a catalog of installable native packages; the *package manager* installs a
// package INTO a domain, **cap-gated** (the package's required capability rights must be ⊆ the
// target domain's identity rights-ceiling — deny-by-default) and **scoped** to that domain
// (tracked per-domain).  This is the infrastructure the brief's "automatically install required
// software … subject to policy approval" rides on.  On-disk persistence reuses objstore.d
// (ObjAppEntry, the F4 app store) so an installed package survives reboot (DM5) and is cap-gated
// again on launch.
//
// Kernel constraints: -betterC, plain structs, __gshared fixed tables, @nogc nothrow.
module core.pkgrepo;

import core.identity : identityById, IdentityRec;
import core.domain   : domainById, domainByName, DomainId;
import core.objstore : objstoreMounted, objstoreInstallApp;
import core.cap      : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_STAT, CAP_RIGHT_MMAP,
                       CAP_RIGHT_EXEC, CAP_RIGHT_ADMIN_MOUNT, CAP_RIGHT_ADMIN_INSPECT;
import core.io       : klog, klog_hex;

extern (C) @nogc nothrow:

enum int PKG_NAME_MAX = 32;
enum int PKG_REPO_MAX = 16;   // catalog capacity
enum int PKG_DOM_MAX  = 32;   // domains tracked (one PkgDomState each)

// install() result codes (0 = installed).
enum int PKG_OK            =  0;
enum int PKG_ERR_NOPKG     = -1;   // unknown package
enum int PKG_ERR_NODOMAIN  = -2;   // unknown domain
enum int PKG_ERR_NOIDENT   = -3;   // domain has no live identity
enum int PKG_ERR_CEILING   = -4;   // package caps exceed the domain ceiling (EPERM)
enum int PKG_ERR_FULL      = -5;   // per-domain install table full

struct PkgRepoEntry {
    bool   inUse;
    uint   nameLen;
    char[PKG_NAME_MAX] name;
    char[12] ver;
    uint   sizeKb;
    uint   requiredCaps;       // capability rights the package needs — must be ⊆ domain ceiling
    bool   signed;             // signature verified (the trusted catalog is seeded signed)
}
__gshared PkgRepoEntry[PKG_REPO_MAX] g_pkgRepo;
__gshared uint g_pkgRepoCount = 0;
__gshared bool g_pkgSeeded = false;

// Per-domain installed set: a bitmask over the catalog, keyed by domain objId.
struct PkgDomState { bool inUse; uint domObjId; uint installedMask; }
__gshared PkgDomState[PKG_DOM_MAX] g_pkgDom;

// ── catalog helpers ───────────────────────────────────────────────────────────
private void pkgSetName(ref PkgRepoEntry e, const(char)* s) {
    uint i = 0;
    while (s[i] != 0 && i < PKG_NAME_MAX - 1) { e.name[i] = s[i]; ++i; }
    e.name[i] = 0; e.nameLen = i;
}
private void pkgSetVer(ref PkgRepoEntry e, const(char)* s) {
    uint i = 0; while (s[i] != 0 && i < 11) { e.ver[i] = s[i]; ++i; } e.ver[i] = 0;
}
private bool pkgNameEq(ref const(PkgRepoEntry) e, const(char)* name) {
    uint i = 0;
    for (; i < e.nameLen; ++i) if (e.name[i] != name[i]) return false;
    return name[i] == 0;
}

private void pkgAdd(const(char)* name, const(char)* ver, uint sizeKb, uint reqCaps) {
    if (g_pkgRepoCount >= PKG_REPO_MAX) return;
    auto e = &g_pkgRepo[g_pkgRepoCount++];
    *e = PkgRepoEntry.init;
    e.inUse = true;
    pkgSetName(*e, name);
    pkgSetVer(*e, ver);
    e.sizeKb = sizeKb;
    e.requiredCaps = reqCaps;
    e.signed = true;             // the built-in catalog is trusted/signed
}

// Seed the built-in repository catalog.  Most packages need only user caps (installable in any
// domain); the two admin-cap packages can only land in a System-ceiling domain.
public void pkgRepoSeed() {
    if (g_pkgSeeded) return;
    g_pkgSeeded = true;
    enum uint USER = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_STAT | CAP_RIGHT_MMAP | CAP_RIGHT_EXEC;
    pkgAdd("hello\0".ptr,          "1.0\0".ptr,        64u, CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
    pkgAdd("text-editor\0".ptr,    "2.1\0".ptr,      2048u, USER);
    pkgAdd("web-browser\0".ptr,    "118.0\0".ptr,   51200u, USER);
    pkgAdd("media-player\0".ptr,   "4.4\0".ptr,      8192u, USER);
    pkgAdd("dev-toolchain\0".ptr,  "14\0".ptr,      30720u, USER | CAP_RIGHT_ADMIN_MOUNT);    // mounts build dirs → admin
    pkgAdd("system-monitor\0".ptr, "1.2\0".ptr,       512u, CAP_RIGHT_READ | CAP_RIGHT_STAT | CAP_RIGHT_ADMIN_INSPECT);
    klog("[pkg] repository seeded ("); klog_hex(g_pkgRepoCount); klog(" packages)\n");
}

public uint pkgRepoCount() { return g_pkgRepoCount; }
public PkgRepoEntry* pkgRepoAt(uint i) { return (i < g_pkgRepoCount && g_pkgRepo[i].inUse) ? &g_pkgRepo[i] : null; }

public int pkgRepoFindByName(const(char)* name) {
    foreach (uint i; 0 .. g_pkgRepoCount)
        if (g_pkgRepo[i].inUse && pkgNameEq(g_pkgRepo[i], name)) return cast(int)i;
    return -1;
}

private PkgDomState* pkgDomFor(uint domObjId, bool create) {
    foreach (ref s; g_pkgDom) if (s.inUse && s.domObjId == domObjId) return &s;
    if (!create) return null;
    foreach (ref s; g_pkgDom) if (!s.inUse) { s.inUse = true; s.domObjId = domObjId; s.installedMask = 0; return &s; }
    return null;
}

public uint pkgInstalledMask(uint domObjId) { auto s = pkgDomFor(domObjId, false); return s is null ? 0 : s.installedMask; }
public bool pkgIsInstalled(uint domObjId, uint repoIdx) { return (pkgInstalledMask(domObjId) & (1u << repoIdx)) != 0; }

// Install a catalog package into a domain.  Deny-by-default cap-gate: the package's required caps
// must be ⊆ the target domain's identity rights-ceiling, else PKG_ERR_CEILING (the brief's
// "package exceeding the domain ceiling → EPERM").  On success it is tracked per-domain and, if
// the object store is mounted, persisted as an identity-scoped ObjAppEntry (cap-gated on launch).
public int pkgRepoInstall(uint repoIdx, uint domObjId) {
    if (repoIdx >= g_pkgRepoCount || !g_pkgRepo[repoIdx].inUse) return PKG_ERR_NOPKG;
    auto d = domainById(domObjId);
    if (d is null) return PKG_ERR_NODOMAIN;
    auto id = identityById(d.identityObjId);
    if (id is null) return PKG_ERR_NOIDENT;

    auto pkg = &g_pkgRepo[repoIdx];
    if ((pkg.requiredCaps & ~id.rightsCeiling) != 0) {     // caps ⊄ ceiling → deny
        klog("[pkg] install DENIED (ceiling): "); klog(pkg.name.ptr); klog("\n");
        return PKG_ERR_CEILING;
    }
    auto st = pkgDomFor(domObjId, true);
    if (st is null) return PKG_ERR_FULL;
    st.installedMask |= (1u << repoIdx);

    // best-effort persistence: an identity-scoped app entry, cap-gated to the package's caps.
    if (objstoreMounted())
        objstoreInstallApp(pkg.name[0 .. pkg.nameLen], id.name[0 .. id.nameLen],
                           pkg.requiredCaps, null, null, null, null);
    klog("[pkg] installed "); klog(pkg.name.ptr); klog(" into domain objId "); klog_hex(domObjId); klog("\n");
    return PKG_OK;
}

public int pkgRepoRemove(uint repoIdx, uint domObjId) {
    if (repoIdx >= g_pkgRepoCount) return PKG_ERR_NOPKG;
    auto st = pkgDomFor(domObjId, false);
    if (st is null || (st.installedMask & (1u << repoIdx)) == 0) return PKG_ERR_NOPKG;
    st.installedMask &= ~(1u << repoIdx);
    return PKG_OK;
}

// Convenience for the control-write verbs: install/uninstall by (domainName, packageName).
public int pkgInstallByName(const(char)* domainName, const(char)* pkgName) {
    const int idx = pkgRepoFindByName(pkgName);
    if (idx < 0) return PKG_ERR_NOPKG;
    const DomainId dom = domainByName(domainName);
    if (dom == 0) return PKG_ERR_NODOMAIN;
    return pkgRepoInstall(cast(uint)idx, dom);
}
public int pkgRemoveByName(const(char)* domainName, const(char)* pkgName) {
    const int idx = pkgRepoFindByName(pkgName);
    if (idx < 0) return PKG_ERR_NOPKG;
    const DomainId dom = domainByName(domainName);
    if (dom == 0) return PKG_ERR_NODOMAIN;
    return pkgRepoRemove(cast(uint)idx, dom);
}

// ── DM11: package profiles — reusable bundles of catalog packages (the brief's profiles) ──────
private bool pkgStrEq(const(char)* a, string lit) {
    size_t i = 0;
    for (; i < lit.length; ++i) if (a[i] != lit[i]) return false;
    return a[i] == 0;
}
private int profilePkgs(const(char)* p, ref const(char)*[4] dst) {
    if (pkgStrEq(p, "minimal"))     { dst[0] = "hello\0".ptr; return 1; }
    if (pkgStrEq(p, "development")) { dst[0] = "text-editor\0".ptr; dst[1] = "dev-toolchain\0".ptr; return 2; }
    if (pkgStrEq(p, "office"))      { dst[0] = "text-editor\0".ptr; return 1; }
    if (pkgStrEq(p, "research"))    { dst[0] = "text-editor\0".ptr; dst[1] = "web-browser\0".ptr; return 2; }
    if (pkgStrEq(p, "media"))       { dst[0] = "media-player\0".ptr; return 1; }
    return -1;
}
// Install a named profile's packages into a domain (each still cap-gated to the domain ceiling).
// Returns the count successfully installed, or -1 for an unknown profile.
public int pkgApplyProfile(const(char)* domainName, const(char)* profile) {
    const(char)*[4] dst;
    const int n = profilePkgs(profile, dst);
    if (n < 0) return -1;
    int installed = 0;
    foreach (i; 0 .. n) if (pkgInstallByName(domainName, dst[i]) == PKG_OK) ++installed;
    klog("[pkg] profile applied: "); klog(profile); klog("\n");
    return installed;
}

// DM7 boot proof: cap-gated per-domain install/remove.  A user-cap package installs into any
// domain; an admin-cap package is DENIED in a user-ceiling domain but installs in System.
__gshared bool g_pkgProofDone = false;
public void pkgRepoSelfTest() {
    if (g_pkgProofDone) return;
    g_pkgProofDone = true;
    pkgRepoSeed();

    const int hello = pkgRepoFindByName("hello\0".ptr);
    const int sysmon = pkgRepoFindByName("system-monitor\0".ptr);
    const DomainId devDom  = domainByName("Development\0".ptr);
    const DomainId bankDom = domainByName("Banking\0".ptr);
    const DomainId sysDom  = domainByName("System\0".ptr);

    bool ok = (hello >= 0) && (sysmon >= 0) && devDom && bankDom && sysDom;
    // user-cap package installs into a user-ceiling domain + is tracked
    ok = ok && (pkgRepoInstall(cast(uint)hello, devDom) == PKG_OK);
    ok = ok && pkgIsInstalled(devDom, cast(uint)hello);
    ok = ok && !pkgIsInstalled(bankDom, cast(uint)hello);                       // scoped: not in Banking
    // admin-cap package DENIED in a user-ceiling domain (caps exceed ceiling)
    ok = ok && (pkgRepoInstall(cast(uint)sysmon, bankDom) == PKG_ERR_CEILING);
    ok = ok && !pkgIsInstalled(bankDom, cast(uint)sysmon);
    // …but installs in the System (full-ceiling) domain
    ok = ok && (pkgRepoInstall(cast(uint)sysmon, sysDom) == PKG_OK);
    ok = ok && pkgIsInstalled(sysDom, cast(uint)sysmon);
    // remove clears the per-domain bit
    ok = ok && (pkgRepoRemove(cast(uint)hello, devDom) == PKG_OK) && !pkgIsInstalled(devDom, cast(uint)hello);
    // DM11: a package profile installs its bundle (cap-gated) into a domain
    ok = ok && (pkgApplyProfile("Development\0".ptr, "minimal\0".ptr) >= 1) && pkgIsInstalled(devDom, cast(uint)hello);
    pkgRepoRemove(cast(uint)hello, devDom);   // cleanup

    klog(ok ? "[pkg] repo proof PASS (cap-gated install/remove + profile apply; admin pkg EACCES in user domain, OK in System)\n"
            : "[pkg] repo proof FAIL\n");
}
