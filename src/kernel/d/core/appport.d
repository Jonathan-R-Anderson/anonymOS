// Cross-domain application PORTING — the Software Center distribution feature (2026-09-27).
//
// A "port" grants a DOMAIN the right to run its own isolated INSTANCE of an app.  When a ported app
// is launched it is CONFINED into that domain (its own identity, its own /Domains/<name>/ private
// data, its own capability ceiling), sharing only the read-only executable bytes — so each domain
// gets a genuinely separate instance, not a shared session, without copying the binary per domain
// (the user chose the lighter "isolated instance" model over a byte copy).  System (the trusted
// admin domain) is always allowed and is where apps are installed from the Software Center and then
// distributed outward.  Deselecting a domain clears its entry — a clean, leak-free removal.
//
// Kernel constraints: -betterC, plain structs, __gshared fixed tables, @nogc nothrow.
module core.appport;

import core.domain : domainById, domainByName;
import core.io     : klog;

extern (C) @nogc nothrow:

enum int APPPORT_APPS_MAX = 32;    // distinct apps tracked
enum int APPPORT_DOMS_MAX = 24;    // domains an app can be ported to (>= live domain count)
enum int APPPORT_NAME_MAX = 48;

enum int APPPORT_OK        =  0;
enum int APPPORT_ERR_NODOM = -2;   // unknown domain name
enum int APPPORT_ERR_FULL  = -5;   // app table / per-app domain list full

struct AppPortRec {
    bool inUse;
    char[APPPORT_NAME_MAX] app;             // appid, e.g. "wl-software" (NUL-terminated)
    uint appLen;
    uint nDoms;
    uint[APPPORT_DOMS_MAX] doms;            // allowed domain objIds
}
__gshared AppPortRec[APPPORT_APPS_MAX] g_appPort;

private bool aStrEq(const(char)* a, const(char)* b) {
    for (uint i = 0;; ++i) { if (a[i] != b[i]) return false; if (a[i] == 0) return true; }
}
private void aSetName(ref AppPortRec e, const(char)* s) {
    uint i = 0;
    while (s[i] != 0 && i < APPPORT_NAME_MAX - 1) { e.app[i] = s[i]; ++i; }
    e.app[i] = 0; e.appLen = i;
}
// Find (or optionally create) the record for appid.
private AppPortRec* appRecFor(const(char)* appid, bool create) {
    foreach (ref e; g_appPort) if (e.inUse && aStrEq(e.app.ptr, appid)) return &e;
    if (!create) return null;
    foreach (ref e; g_appPort) if (!e.inUse) { e.inUse = true; aSetName(e, appid); e.nDoms = 0; return &e; }
    return null;
}
private uint systemObjId() { return domainByName("System\0".ptr); }

// Grant domain <domainName> the right to run app <appid>.  Idempotent.
public int appPortAdd(const(char)* appid, const(char)* domainName) {
    const uint dom = domainByName(domainName);
    if (dom == 0) return APPPORT_ERR_NODOM;
    auto e = appRecFor(appid, true);
    if (e is null) return APPPORT_ERR_FULL;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == dom) return APPPORT_OK;    // already ported
    if (e.nDoms >= APPPORT_DOMS_MAX) return APPPORT_ERR_FULL;
    e.doms[e.nDoms++] = dom;
    klog("[appport] port granted\n");
    return APPPORT_OK;
}

// Revoke domain <domainName>'s right to run app <appid> (clean removal — just drops the entry).
public int appPortRemove(const(char)* appid, const(char)* domainName) {
    const uint dom = domainByName(domainName);
    if (dom == 0) return APPPORT_ERR_NODOM;
    auto e = appRecFor(appid, false);
    if (e is null) return APPPORT_OK;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == dom) {
        e.doms[i] = e.doms[e.nDoms - 1]; --e.nDoms;      // swap-remove
        if (e.nDoms == 0) e.inUse = false;               // no domains left → free the slot
        klog("[appport] port revoked\n");
        return APPPORT_OK;
    }
    return APPPORT_OK;
}

// May domain <domObjId> run app <appid>?  System is always allowed (the admin/distribution domain).
public bool appPortAllowed(uint domObjId, const(char)* appid) {
    if (domObjId != 0 && domObjId == systemObjId()) return true;
    auto e = appRecFor(appid, false);
    if (e is null) return false;
    foreach (i; 0 .. e.nDoms) if (e.doms[i] == domObjId) return true;
    return false;
}

// GUI enumeration (rendered into /config/apps.json by hoscall.d).
public uint appPortCount() { uint n = 0; foreach (ref e; g_appPort) if (e.inUse) ++n; return n; }
public AppPortRec* appPortAt(uint idx) {
    uint n = 0;
    foreach (ref e; g_appPort) if (e.inUse) { if (n == idx) return &e; ++n; }
    return null;
}
