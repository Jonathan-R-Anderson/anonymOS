// Application DELEGATION — which domain may run which application (2026-09-27; enforced 2026-09-28).
//
// A grant ("port") gives a DOMAIN the right to run its own isolated INSTANCE of an application.  When a
// delegated app is launched it is CONFINED into that domain (its own identity, its own /Domains/<name>/
// private data, its own capability ceiling), sharing only the read-only executable bytes -- so each
// domain gets a genuinely separate instance, not a shared session.  System (the trusted admin domain,
// which owns the Domain Manager) can always run everything and is where applications are delegated
// out from.
//
// appgate: this table is no longer a GUI hint.  execveTask asks appPortAllowed() on every exec
// (core.appreg decides where the image lands, this table decides whether that domain may run it), so a
// domain that was not delegated an application cannot launch it by any route.  Only the Domain Manager
// (in System) can change the table -- the port/unport verbs are authorized in core.domain.
//
// Grants survive reboot (objstore, keyed by domain NAME because objIds are not stable across boots) and
// start from core.appreg's defaults for a domain that has never had a record.  Before appGrantsInit()
// runs at boot, the seed/scrub hooks leave the store alone: the boot proofs create and delete throwaway
// domains, and must neither write the table nor have their defaults clobber the user's saved choices.
//
// Kernel constraints: -betterC, plain structs, __gshared fixed tables, @nogc nothrow.
module core.appport;

import core.domain : domainById, domainByName, domainSystemId, domainSessionId, g_domains, DOM_MAX,
                     DOM_NAME_MAX;
import core.appreg : AppRegEntry, appRegAppAt, appRegDefaultGranted, appRegIsDelegable, appRegLabel;
import core.objstore : objstoreMounted, objstoreSaveGrants, objstoreLoadGrants;
import core.io     : klog, klog_dec;

extern (C) @nogc nothrow:

// Apps tracked (registry apps, objstore store:<n> apps, installed pkg:<n> packages): the table grows in
// chunks as apps are delegated -- no cap.  Records never move, so a record pointer stays valid.
enum int APPPORT_CHUNK = 64;
enum int APPPORT_DOMS_MAX = 32;    // == DOM_MAX: an app can be delegated to every domain
enum int APPPORT_NAME_MAX = 72;    // >= "store:" + the objstore's 64-byte app names

enum int APPPORT_OK        =  0;
enum int APPPORT_ERR_NODOM = -2;   // unknown domain name
enum int APPPORT_ERR_FULL  = -5;   // app table / per-app domain list full

struct AppPortRec {
    bool inUse;
    char[APPPORT_NAME_MAX] app;             // appid, e.g. "wl-files" or "store:notes" (NUL-terminated)
    uint appLen;
    uint nDoms;
    uint[APPPORT_DOMS_MAX] doms;            // allowed domain objIds
}
private __gshared AppPortRec*[4096] g_appPortChunk;
private __gshared uint g_appPortCap = 0;      // records allocated (a multiple of APPPORT_CHUNK)
private AppPortRec* apRec(uint i) { return &g_appPortChunk[i / APPPORT_CHUNK][i % APPPORT_CHUNK]; }
private bool apGrow() {
    import memory.mm : alloc_phys_pages;
    import core.exports : phys_to_virt;
    const uint c = g_appPortCap / APPPORT_CHUNK;
    if (c >= g_appPortChunk.length) return false;
    const ulong phys = alloc_phys_pages((APPPORT_CHUNK * AppPortRec.sizeof + 4095) / 4096);
    if (phys == 0) return false;
    auto recs = cast(AppPortRec*)phys_to_virt(phys);
    foreach (i; 0 .. APPPORT_CHUNK) recs[i] = AppPortRec.init;
    g_appPortChunk[c] = recs;
    g_appPortCap += APPPORT_CHUNK;
    return true;
}

// True once the boot-time load/seed has run; before that the lifecycle hooks do not touch the store.
__gshared bool g_appGrantsReady = false;

private bool aStrEq(const(char)* a, const(char)* b) {
    if (a is null || b is null) return false;
    for (uint i = 0;; ++i) { if (a[i] != b[i]) return false; if (a[i] == 0) return true; }
}
private void aSetName(ref AppPortRec e, const(char)* s) {
    uint i = 0;
    while (s[i] != 0 && i < APPPORT_NAME_MAX - 1) { e.app[i] = s[i]; ++i; }
    e.app[i] = 0; e.appLen = i;
}
// Find (or optionally create) the record for appid.
private AppPortRec* appRecFor(const(char)* appid, bool create) {
    if (appid is null || appid[0] == 0) return null;
    foreach (i; 0 .. g_appPortCap) { auto e = apRec(i); if (e.inUse && aStrEq(e.app.ptr, appid)) return e; }
    if (!create) return null;
    foreach (i; 0 .. g_appPortCap) { auto e = apRec(i); if (!e.inUse) { e.inUse = true; aSetName(*e, appid); e.nDoms = 0; return e; } }
    const uint first = g_appPortCap;                 // every record is in use: add a chunk
    if (!apGrow()) return null;
    auto e = apRec(first);
    e.inUse = true; aSetName(*e, appid); e.nDoms = 0;
    return e;
}

// Grant/revoke by objId (the name-keyed verbs below and the lifecycle hooks share these).
private int grantById(const(char)* appid, uint dom) {
    if (dom == 0) return APPPORT_ERR_NODOM;
    auto e = appRecFor(appid, true);
    if (e is null) return APPPORT_ERR_FULL;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == dom) return APPPORT_OK;      // already granted
    if (e.nDoms >= APPPORT_DOMS_MAX) return APPPORT_ERR_FULL;
    e.doms[e.nDoms++] = dom;
    return APPPORT_OK;
}
private bool revokeById(const(char)* appid, uint dom) {
    auto e = appRecFor(appid, false);
    if (e is null) return false;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == dom) {
        e.doms[i] = e.doms[e.nDoms - 1]; --e.nDoms;      // swap-remove
        if (e.nDoms == 0) e.inUse = false;               // no domains left -> free the slot
        return true;
    }
    return false;
}

// Grant domain <domainName> the right to run app <appid>.  Idempotent.
public int appPortAdd(const(char)* appid, const(char)* domainName) {
    const uint dom = domainByName(domainName);
    if (dom == 0) return APPPORT_ERR_NODOM;
    const int r = grantById(appid, dom);
    if (r == APPPORT_OK) { klog("[appport] port granted\n"); appGrantsPersist(); }
    return r;
}

// Revoke domain <domainName>'s right to run app <appid> (clean removal -- just drops the entry).
public int appPortRemove(const(char)* appid, const(char)* domainName) {
    const uint dom = domainByName(domainName);
    if (dom == 0) return APPPORT_ERR_NODOM;
    if (revokeById(appid, dom)) { klog("[appport] port revoked\n"); appGrantsPersist(); }
    return APPPORT_OK;
}

// May domain <domObjId> run app <appid>?  System is always allowed (the admin/distribution domain).
public bool appPortAllowed(uint domObjId, const(char)* appid) {
    if (domObjId == 0) return false;
    if (domObjId == domainSystemId()) return true;
    auto e = appRecFor(appid, false);
    if (e is null) return false;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == domObjId) return true;
    return false;
}

// GUI enumeration (rendered into /config/apps.json by hoscall.d).
public uint appPortCount() { uint n = 0; foreach (i; 0 .. g_appPortCap) if (apRec(i).inUse) ++n; return n; }
public AppPortRec* appPortAt(uint idx) {
    uint n = 0;
    foreach (i; 0 .. g_appPortCap) { auto e = apRec(i); if (e.inUse) { if (n == idx) return e; ++n; } }
    return null;
}
// Is `appid` granted to domain objId `dom` (no System shortcut -- for rendering)?
public bool appPortHas(const(char)* appid, uint dom) {
    auto e = appRecFor(appid, false);
    if (e is null) return false;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == dom) return true;
    return false;
}

// ── lifecycle: seed / clone / scrub ────────────────────────────────────────────────────────────

private bool isGrantTarget(uint dom) {
    auto d = domainById(dom);
    return d !is null && !d.isTemplate && dom != domainSystemId();
}

private uint seedDefaults(uint dom) {
    auto d = domainById(dom);
    if (d is null) return 0;
    char[DOM_NAME_MAX + 1] nm = 0;
    foreach (i; 0 .. d.nameLen) if (i < DOM_NAME_MAX) nm[i] = d.name[i];
    const bool isSession = (dom == domainSessionId());
    uint n = 0;
    for (uint i = 0;; ++i) {
        auto e = appRegAppAt(i);
        if (e is null) break;
        if (appRegDefaultGranted(e, nm.ptr, isSession) && grantById(e.appId.ptr, dom) == APPPORT_OK) ++n;
    }
    return n;
}

// A domain was just created at runtime (create / fromtpl): give it the registry defaults.
public void appGrantsSeedDomain(uint dom) {
    if (!g_appGrantsReady || !isGrantTarget(dom)) return;
    seedDefaults(dom);
    appGrantsPersist();
}

// A domain was cloned: the clone may run exactly what its source could.
public void appGrantsCloneDomain(uint srcDom, uint dstDom) {
    if (!g_appGrantsReady || !isGrantTarget(dstDom)) return;
    foreach (api_; 0 .. g_appPortCap) {
        auto e = apRec(api_);
        if (!e.inUse) continue;
        foreach (i; 0 .. e.nDoms) if (e.doms[i] == srcDom) { grantById(e.app.ptr, dstDom); break; }
    }
    appGrantsPersist();
}

// A domain is being deleted: forget everything it was delegated.  RAM always (the objId is about to be
// reused); the store only once the table is live.
public void appGrantsScrubDomain(uint dom) {
    if (dom == 0) return;
    foreach (api_; 0 .. g_appPortCap) {
        auto e = apRec(api_);
        if (!e.inUse) continue;
        foreach (i; 0 .. e.nDoms) if (e.doms[i] == dom) {
            e.doms[i] = e.doms[e.nDoms - 1]; --e.nDoms;
            if (e.nDoms == 0) e.inUse = false;
            break;
        }
    }
    if (g_appGrantsReady) appGrantsPersist();
}

// ── persistence ───────────────────────────────────────────────────────────────────────────────
// Text, so it is inspectable and tolerant of registry changes between releases:
//   "HOSGRNT1\n" then one "<Domain>\t<app>,<app>,...\n" per non-System domain ("-" = none).
// A domain with no line has never been seeded and gets the defaults.

enum uint GRANTS_BUF_MAX = 3584;           // == one objstore grants slot (7 sectors)
private __gshared char[GRANTS_BUF_MAX] g_grantsBuf;

private void bput(ref uint p, const(char)* s, uint n) {
    foreach (i; 0 .. n) if (p < GRANTS_BUF_MAX) g_grantsBuf[p++] = s[i];
}

public void appGrantsPersist() {
    if (!g_appGrantsReady || !objstoreMounted()) return;
    uint p = 0;
    bput(p, "HOSGRNT1\n".ptr, 9);
    const uint sys = domainSystemId();
    foreach (ref d; g_domains) {
        if (!d.inUse || d.isTemplate || d.objId == sys) continue;
        uint nl = 0;
        while (nl < d.nameLen && nl < DOM_NAME_MAX && d.name[nl] != 0) ++nl;   // never persist a NUL
        bput(p, d.name.ptr, nl);
        bput(p, "\t".ptr, 1);
        uint k = 0;
        foreach (api_; 0 .. g_appPortCap) {
            auto e = apRec(api_);
            if (!e.inUse) continue;
            bool has = false;
            foreach (i; 0 .. e.nDoms) if (e.doms[i] == d.objId) { has = true; break; }
            if (!has) continue;
            if (k++ > 0) bput(p, ",".ptr, 1);
            bput(p, e.app.ptr, e.appLen);
        }
        if (k == 0) bput(p, "-".ptr, 1);
        bput(p, "\n".ptr, 1);
    }
    if (p >= GRANTS_BUF_MAX) { klog("[appgate] grants: table too large to persist\n"); return; }
    if (!objstoreSaveGrants(cast(const(ubyte)*)g_grantsBuf.ptr, p))
        klog("[appgate] grants: persist FAILED\n");
}

// Parse the persisted table.  Returns the number of domain records applied; marks each in `seen`.
private uint loadGrants(uint len, ref bool[DOM_MAX] seen) {
    if (len < 9) return 0;
    immutable string magic = "HOSGRNT1\n";
    foreach (i; 0 .. magic.length) if (g_grantsBuf[i] != magic[i]) return 0;
    uint recs = 0;
    uint p = 9;
    const uint sys = domainSystemId();
    while (p < len) {
        // domain name up to TAB
        char[DOM_NAME_MAX + 1] dn = 0; uint dl = 0;
        while (p < len && g_grantsBuf[p] != '\t' && g_grantsBuf[p] != '\n') {
            if (dl < DOM_NAME_MAX) dn[dl++] = g_grantsBuf[p];
            ++p;
        }
        if (p >= len || g_grantsBuf[p] != '\t') { while (p < len && g_grantsBuf[p] != '\n') ++p; ++p; continue; }
        ++p;   // TAB
        const uint dom = domainByName(dn.ptr);
        int slot = -1;
        foreach (i, ref d; g_domains) if (d.inUse && d.objId == dom) { slot = cast(int)i; break; }
        const bool apply = dom != 0 && dom != sys && slot >= 0 && !g_domains[slot].isTemplate;
        // comma-separated app ids up to NL
        while (p < len && g_grantsBuf[p] != '\n') {
            char[APPPORT_NAME_MAX] an = 0; uint al = 0;
            while (p < len && g_grantsBuf[p] != ',' && g_grantsBuf[p] != '\n') {
                if (al < APPPORT_NAME_MAX - 1) an[al++] = g_grantsBuf[p];
                ++p;
            }
            if (p < len && g_grantsBuf[p] == ',') ++p;
            if (apply && al > 0 && !(al == 1 && an[0] == '-') && appRegIsDelegable(an.ptr))
                grantById(an.ptr, dom);
        }
        ++p;   // NL
        if (apply) { seen[slot] = true; ++recs; }
    }
    return recs;
}

// Boot: load the saved table (if the store has one), then give every domain that has no record the
// registry defaults, then persist once.  Called after the last boot-time domain mutation and before
// the first user program runs.
public void appGrantsInit() {
    if (g_appGrantsReady) return;
    // Anything the boot proofs left in the table is stale: start clean.
    foreach (i; 0 .. g_appPortCap) *apRec(i) = AppPortRec.init;
    bool[DOM_MAX] seen = false;
    uint loaded = 0;
    bool corrupt = false;
    if (objstoreMounted()) {
        const int n = objstoreLoadGrants(cast(ubyte*)g_grantsBuf.ptr, GRANTS_BUF_MAX);
        if (n < 0) corrupt = true;
        else if (n > 0) loaded = loadGrants(cast(uint)n, seen);
    }
    uint seeded = 0;
    const uint sys = domainSystemId();
    foreach (i, ref d; g_domains) {
        if (!d.inUse || d.isTemplate || d.objId == sys || seen[i]) continue;
        // A corrupt table fails CLOSED: every domain starts with nothing and the user re-delegates
        // from the Domain Manager, rather than silently regaining apps that had been revoked.
        if (!corrupt) seeded += seedDefaults(d.objId);
    }
    g_appGrantsReady = true;
    klog("[appgate] grants: "); klog_dec(loaded); klog(" domain record(s) loaded, ");
    klog_dec(seeded); klog(corrupt ? " default grant(s) seeded (store CORRUPT: failing closed)\n"
                                   : " default grant(s) seeded\n");
    appGrantsPersist();
}

// ── denial feedback ───────────────────────────────────────────────────────────────────────────
// The last few refused launches, rendered as /config/appgate.json so the top bar can tell the user
// why a window did not open (a refused exec is otherwise silent: launchers _exit in the child).

enum int APPGATE_RING = 8;
struct AppgateDeny {
    uint seq;
    char[32] image;
    char[APPPORT_NAME_MAX] app;
    char[40] label;                         // the app's display name ("Terminal"), or the image
    char[DOM_NAME_MAX + 1] domain;
}
__gshared AppgateDeny[APPGATE_RING] g_appgateDeny;
__gshared uint g_appgateDenySeq = 0;

private void cpyz(char* dst, size_t cap, const(char)* src) {
    size_t i = 0;
    if (src !is null) while (src[i] != 0 && i < cap - 1) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}

public void appgateNoteDeny(const(char)* image, const(char)* appId, uint domObjId) {
    ++g_appgateDenySeq;
    auto r = &g_appgateDeny[g_appgateDenySeq % APPGATE_RING];
    r.seq = g_appgateDenySeq;
    cpyz(r.image.ptr, r.image.length, image);
    cpyz(r.app.ptr, r.app.length, appId);
    cpyz(r.label.ptr, r.label.length, appId !is null ? appRegLabel(appId) : image);
    auto d = domainById(domObjId);
    uint k = 0;
    if (d !is null) foreach (i; 0 .. d.nameLen) if (k < DOM_NAME_MAX) r.domain[k++] = d.name[i];
    r.domain[k] = 0;
}
