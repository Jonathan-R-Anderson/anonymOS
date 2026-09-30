// Software Center back end — the kernel half of src/util/wl-software.c.
//
// The GUI browses a catalog aggregated from the real package indexes of every major Linux
// distribution (scripts/pack-software-catalog.py -> software.blob).  Browsing needs nothing from
// the kernel; INSTALLING does, because an install crosses two trust boundaries this OS takes
// seriously: the network (the bytes come from outside) and the domain's capability ceiling (the
// package lands in one identity's filesystem, not "the system").  So the GUI does not fetch
// anything itself: it writes a request to /config/software.action and reads the verdict back from
// /config/software.status, exactly like the installer's install.action/install.progress pair.
//
// The verdict is deliberately explicit rather than optimistic.  Four things can be true:
//   * the package manager is not one this system can execute (glibc distro packages on a musl
//     personality) -> refused, with what to run on a machine that can;
//   * there is no network -> refused, naming what to do about it;
//   * the network is up -> the fetch is handed to the userspace helper (hos-pkg-fetch) under the
//     LKL socket shim, and the status reports what it did;
//   * the catalog's own built-in package set (core.pkgrepo) -> installed straight into the
//     active domain, cap-gated, which is the path that has always worked here.
//
// Kernel constraints: -betterC, @nogc nothrow, __gshared fixed buffers, no allocation.
module core.software;

import core.io : klog, klog_hex;

@nogc nothrow:

enum size_t SW_STATUS_MAX = 192;
enum size_t SW_ARG_MAX    = 96;

__gshared char[SW_STATUS_MAX] g_swStatus;
__gshared uint g_swStatusLen = 0;
__gshared uint g_swRequests  = 0;

// Install completion.  The fetch+unpack is asynchronous (hos-pkg-fetch runs in userspace and takes
// as long as the download does), so the control-write only ARMS the install; the kernel supervisor
// loop calls softwarePoll(), which watches for the fetcher's /run/pkg/<name>.{done,fail} markers and
// then performs the one cap-gated step userspace cannot — placing the files — and writes the real
// verdict.  One install is tracked at a time (the Software Center issues them one click at a time).
__gshared char[128] g_swPendName;
__gshared uint      g_swPendLen    = 0;
__gshared bool      g_swPendActive = false;
__gshared uint      g_swPollTick   = 0;
// The domain that requested the install (captured at request time, when the CURRENT task is the
// requesting app).  The placement runs later in the supervisor (dom 0), so it must be told which
// domain to install INTO — otherwise a per-domain-private .apk lands nowhere the requester can see.
__gshared uint      g_swPendDom    = 0;

private void swSet(string kind, const(char)[] a = null, const(char)[] b = null,
                   const(char)[] c = null, const(char)[] d = null) {
    uint n = 0;
    void put(const(char)[] s) {
        foreach (ch; s) { if (n + 1 < SW_STATUS_MAX) g_swStatus[n++] = ch; }
    }
    put(kind);
    put(a); put(b); put(c); put(d);
    g_swStatus[n] = 0;
    g_swStatusLen = n;
}

private bool swEq(const(char)* s, uint len, string lit) {
    if (len != lit.length) return false;
    foreach (i, ch; lit) if (s[i] != ch) return false;
    return true;
}

// Copy one space-delimited token starting at `pos`; returns its length and advances `pos`.
private uint swToken(const(char)* cmd, size_t len, ref size_t pos, char[] dst) {
    while (pos < len && (cmd[pos] == ' ' || cmd[pos] == '\t')) ++pos;
    uint n = 0;
    while (pos < len && cmd[pos] != ' ' && cmd[pos] != '\t' && cmd[pos] != '\n' && cmd[pos] != '\r') {
        if (n + 1 < dst.length) dst[n++] = cmd[pos];
        ++pos;
    }
    dst[n] = 0;
    return n;
}

// Is a usable network up?  Either the LKL provider's DHCP lease marker (the Wi-Fi path; kernel_main.d's
// udhcpc supervisor latches on the same file) or the in-kernel wired stack with an address.
private bool swNetworkUp() {
    import core.syscalls.posix : linux_sys_access, nativeNetUp;
    if (linux_sys_access(cast(ulong)"/run/wifi/dhcp-ok\0".ptr, 0) == 0) return true;
    // ...or the in-kernel stack: a wired NIC with an address, over which the fetcher now speaks
    // TCP directly (network/tcp.d) -- no LKL provider needed.
    return nativeNetUp();
}

// The control-write endpoint: "install <pkgmgr> <name> <baseurl>".
public bool softwareControlWrite(const(char)* cmd, size_t len) {
    if (cmd is null || len == 0) return false;
    ++g_swRequests;
    size_t pos = 0;
    char[SW_ARG_MAX] verb = void, mgr = void, name = void, url = void;
    const uint vl = swToken(cmd, len, pos, verb[]);
    if (!swEq(verb.ptr, vl, "install")) {
        swSet("refused unknown verb (expected: install <pkgmgr> <name> <url>)");
        return false;
    }
    const uint ml = swToken(cmd, len, pos, mgr[]);
    const uint nl = swToken(cmd, len, pos, name[]);
    swToken(cmd, len, pos, url[]);
    if (ml == 0 || nl == 0) {
        swSet("refused malformed request (expected: install <pkgmgr> <name> <url>)");
        return false;
    }

    klog("[software] install request: "); klog(mgr.ptr); klog(" "); klog(name.ptr); klog("\n");

    // 1. Only apk packages are executable here: Alpine builds against musl, which is the libc this
    //    Linux personality implements.  Everything else is a catalog entry, and saying so is more
    //    useful than a generic failure.
    if (!swEq(mgr.ptr, ml, "apk")) {
        swSet("refused ", mgr[0 .. ml],
              " packages are built against glibc; this system's Linux layer is musl (Alpine/apk). "
              ~ "The catalog entry is complete, but it cannot be installed here.");
        return false;
    }

    // 2. The bytes have to come from somewhere.
    if (!swNetworkUp()) {
        swSet("refused no network: connect Wi-Fi from Quick Settings (SUPER+S), then try ",
              name[0 .. nl], " again. The catalog itself is offline and always browsable.");
        return false;
    }

    // 3. Plan the install: the package and every dependency it is missing, dependencies FIRST.
    //    The dependency names come from the image's catalog (resolved at build time from the
    //    repository's own index), never from the mirror or the request, and each is pinned and
    //    verified exactly like the package itself.  What the OS already provides (its libc, busybox,
    //    the base layout) and what is already installed are skipped.
    {
        import core.syscalls.posix : softwareCallerDomain;
        import core.domain : domainSystemId;
        g_swQN = 0; g_swQPos = 0; g_swVisitN = 0;
        g_swTargetLen = 0;
        for (uint i = 0; i < nl && i + 1 < g_swTarget.length; ++i) g_swTarget[g_swTargetLen++] = name[i];
        g_swTarget[g_swTargetLen] = 0;
        uint ul = 0;
        for (; url[ul] != 0 && ul + 1 < g_swTargetUrl.length; ++ul) g_swTargetUrl[ul] = url[ul];
        g_swTargetUrl[ul] = 0;
        if (!swPlan(g_swTarget.ptr, 0) || g_swQN == 0) {
            swSet("refused ", name[0 .. nl], " cannot be installed: a dependency is not in this image's catalog",
                  " (or the dependency tree is too large).");
            return false;
        }
        // Capture the requesting domain BEFORE any spawn: spawning the fetcher makes it the current
        // task, so reading it afterwards always answered "domain 0".  appgate: the Software Center
        // runs in the System domain, and an install made from System is SYSTEM-WIDE (the shared
        // base) -- which domains may then run it is the Domain Manager's delegation.
        const uint reqDom = softwareCallerDomain();
        g_swPendDom = (reqDom == domainSystemId()) ? 0 : reqDom;
        klog("[software] plan for "); klog(g_swTarget.ptr); klog(":");
        foreach (i; 0 .. g_swQN) { klog(" "); klog(g_swQ[i].ptr); }
        klog("\n");
    }
    return swStartNext();
}

// ── the install queue ──────────────────────────────────────────────────────────────────────────
enum int SW_Q_MAX = 32;
enum int SW_DEPTH_MAX = 10;
__gshared char[48][SW_Q_MAX] g_swQ;           // packages to install, in order (dependencies first)
__gshared uint g_swQN = 0, g_swQPos = 0;
__gshared char[48][SW_Q_MAX * 2] g_swVisit;   // names being / already planned (cycle guard)
__gshared uint g_swVisitN = 0;
__gshared char[512][SW_DEPTH_MAX + 1] g_swDepBuf;   // per-depth dependency lists (no stack growth)
__gshared char[48] g_swTarget;                // what the user asked for
__gshared uint g_swTargetLen = 0;
__gshared char[SW_ARG_MAX] g_swTargetUrl;

private bool swNameEq(const(char)* a, const(char)* b) {
    size_t i = 0;
    for (; a[i] != 0 && b[i] != 0; ++i) if (a[i] != b[i]) return false;
    return a[i] == b[i];
}

// Provided by the OS itself: its musl is the loader every program already uses, busybox supplies the
// shell and core utilities, and the base layout is the root filesystem.  Installing Alpine's copies
// would shadow the system's own (and placement refuses most of those paths anyway).
private bool swBaseProvided(const(char)* n) {
    static immutable string[12] base = ["musl", "busybox", "busybox-binsh", "alpine-baselayout",
        "alpine-baselayout-data", "alpine-keys", "alpine-release", "apk-tools", "libc-utils",
        "musl-utils", "scanelf", "ssl_client"];
    foreach (b; base) {
        size_t i = 0;
        for (; i < b.length && n[i] == b[i]; ++i) {}
        if (i == b.length && n[i] == 0) return true;
    }
    return false;
}

private bool swVisited(const(char)* n) {
    foreach (i; 0 .. g_swVisitN) if (swNameEq(g_swVisit[i].ptr, n)) return true;
    return false;
}

// Post-order walk of the dependency graph from the catalog: every missing dependency is queued
// before the package that needs it.
private bool swPlan(const(char)* name, int depth) {
    import core.syscalls.posix : softwareCatalogDeps, softwarePkgInstalled;
    if (depth > SW_DEPTH_MAX) return false;
    if (swVisited(name)) return true;                 // queued already, or a cycle: fine either way
    if (depth > 0 && (swBaseProvided(name) || softwarePkgInstalled(name))) return true;
    if (g_swVisitN >= g_swVisit.length) return false;
    {   size_t k = 0;
        for (; name[k] != 0 && k + 1 < 48; ++k) g_swVisit[g_swVisitN][k] = name[k];
        g_swVisit[g_swVisitN][k] = 0; ++g_swVisitN; }
    char* deps = g_swDepBuf[depth].ptr;
    if (!softwareCatalogDeps(name, deps, g_swDepBuf[depth].length)) return false;
    size_t p = 0;
    while (deps[p] != 0) {
        while (deps[p] == ' ') ++p;
        if (deps[p] == 0) break;
        char[48] dep = 0; size_t dl = 0;
        while (deps[p] != 0 && deps[p] != ' ') { if (dl + 1 < dep.length) dep[dl++] = deps[p]; ++p; }
        dep[dl] = 0;
        if (!swPlan(dep.ptr, depth + 1)) return false;
        deps = g_swDepBuf[depth].ptr;                  // (same buffer; deeper levels use their own)
    }
    if (g_swQN >= SW_Q_MAX) return false;
    size_t k = 0;
    for (; name[k] != 0 && k + 1 < 48; ++k) g_swQ[g_swQN][k] = name[k];
    g_swQ[g_swQN][k] = 0;
    ++g_swQN;
    return true;
}

private uint swLen(const(char)* s) { uint n = 0; while (s[n] != 0) ++n; return n; }

// Pin + fetch the next queued package.
private bool swStartNext() {
    import core.kernel_main : softwareSpawnFetcher;
    import core.syscalls.posix : softwareCatalogPin;
    const(char)* nm = g_swQ[g_swQPos].ptr;
    const uint nl = swLen(nm);
    const bool isTarget = swNameEq(nm, g_swTarget.ptr);
    char[64] pver = 0, psum = 0;
    char[SW_ARG_MAX] pbase = 0;
    if (!softwareCatalogPin(nm, isTarget ? g_swTargetUrl.ptr : null, pver.ptr, pver.length,
                            psum.ptr, psum.length, pbase.ptr, pbase.length)) {
        swSet("refused ", nm[0 .. nl],
              " cannot be verified: this image's catalog has no checksum for it, so a download could not be checked.");
        g_swPendActive = false;
        return false;
    }
    klog("[software] pinned "); klog(nm); klog(" "); klog(pver.ptr);
    klog(" control="); klog(psum.ptr); klog("\n");
    if (!softwareSpawnFetcher("apk\0".ptr, nm, pbase.ptr, pver.ptr, psum.ptr)) {
        swSet("refused could not start the package fetcher (hos-pkg-fetch is not staged in this image)");
        g_swPendActive = false;
        return false;
    }
    // Clear any stale markers from a previous install of the same package BEFORE arming the poll,
    // so softwarePoll() cannot fire on an old .done while this fetch is still running.
    swClearMarkers(nm, nl);
    g_swPendLen = 0;
    for (uint i = 0; i < nl && i + 1 < g_swPendName.length; ++i) { g_swPendName[i] = nm[i]; ++g_swPendLen; }
    g_swPendName[g_swPendLen] = 0;
    g_swPendActive = true;
    if (g_swQN > 1) {
        char[24] prog = 0; uint pl = 0;
        void pnum(uint v) { if (v >= 10) pnum(v / 10); prog[pl++] = cast(char)('0' + v % 10); }
        pnum(g_swQPos + 1); foreach (ch; " of ") prog[pl++] = ch; pnum(g_swQN);
        swSet("busy installing ", nm[0 .. nl], isTarget ? " (" : " for ",
              isTarget ? prog[0 .. pl] : g_swTarget[0 .. g_swTargetLen],
              isTarget ? ") from the Alpine mirror; watch Logs, filter 'pkg'." : " -- a dependency; watch Logs, filter 'pkg'.");
    } else {
        swSet("busy fetching ", nm[0 .. nl], " from the Alpine mirror (hos-pkg-fetch); watch Logs, filter 'pkg'.");
    }
    return true;
}

// Build "/run/pkg/<name><suffix>" (NUL-terminated) into dst; used to probe/clear the fetcher markers.
private uint swMarkerPath(char[] dst, const(char)* name, uint nameLen, string suffix) {
    uint n = 0;
    foreach (ch; "/run/pkg/") if (n + 1 < dst.length) dst[n++] = ch;
    for (uint i = 0; i < nameLen && n + 1 < dst.length; ++i) dst[n++] = name[i];
    foreach (ch; suffix)       if (n + 1 < dst.length) dst[n++] = ch;
    if (n < dst.length) dst[n] = 0;
    return n;
}

// Remove any leftover completion markers for `name` (a re-install of the same package must not see
// the previous run's .done/.fail).
private void swClearMarkers(const(char)* name, uint nameLen) {
    import core.syscalls.posix : linux_sys_unlink;
    char[160] p = void;
    swMarkerPath(p[], name, nameLen, ".done"); linux_sys_unlink(cast(ulong)p.ptr);
    swMarkerPath(p[], name, nameLen, ".fail"); linux_sys_unlink(cast(ulong)p.ptr);
}

// Kernel supervisor hook: when an install is armed, watch for the fetcher's completion marker and,
// on .done, do the cap-gated placement into the REQUESTING domain and report the real verdict; on
// .fail, report the failure.  Throttled.  softwareApkTryComplete impersonates g_swPendDom so the
// domain-private marker + staged files are visible (per DM6.2 isolation) and the install lands in
// that domain — not the shared base.
public void softwarePoll() {
    if (!g_swPendActive) return;
    if ((g_swPollTick++ % 30) != 0) return;
    import core.syscalls.posix : softwareApkTryComplete;
    const int rc = softwareApkTryComplete(g_swPendName.ptr, g_swPendDom);
    if (rc >= 0) {
        g_swPendActive = false;
        ++g_swQPos;
        if (g_swQPos < g_swQN) { swStartNext(); return; }     // next package in the plan
        if (g_swQN > 1) {
            char[8] nd = 0; uint l = 0; uint v = g_swQN - 1;
            if (v >= 10) nd[l++] = cast(char)('0' + v / 10);
            nd[l++] = cast(char)('0' + v % 10);
            swSet("ok installed ", g_swTarget[0 .. g_swTargetLen], " and ", nd[0 .. l],
                  " dependencies into this domain's filesystem (see Logs, filter 'pkg').");
        } else {
            swSet("ok installed ", g_swPendName[0 .. g_swPendLen],
                  " into this domain's filesystem (see Logs, filter 'pkg').");
        }
    } else if (rc == -2) {
        const bool dep = !swNameEq(g_swPendName.ptr, g_swTarget.ptr);
        swSet("refused could not fetch or unpack ", g_swPendName[0 .. g_swPendLen],
              dep ? " (a dependency of " : "", dep ? g_swTarget[0 .. g_swTargetLen] : "",
              dep ? "; see Logs, filter 'pkg')." : " (see Logs, filter 'pkg').");
        g_swPendActive = false;
    }
    // rc == -1: still pending — keep polling.
}

// Report the catalog at boot: its presence (and size) is the difference between a Software Center
// that lists 73k packages and one that can only say it has none, so it belongs in the log next to
// the other one-line facts about what this image carries.
public void softwareCatalogReport() {
    import core.syscalls.posix : softwareCatalogModule;
    ulong bytes = softwareCatalogModule();
    if (bytes == 0) {
        klog("[software] no catalog module in this image; the Software Center will have nothing to list\n");
        return;
    }
    klog("[software] catalog module: 0x"); klog_hex(bytes);
    klog(" bytes, served at /config/software.catalog\n");
}

// The read side of /config/software.status.  Empty until the first request, so a GUI that polls
// before anything happened shows its own default text rather than a stale kernel line.
public uint softwareStatus(char* dst, uint cap) {
    uint n = 0;
    while (n < g_swStatusLen && n + 1 < cap) { dst[n] = g_swStatus[n]; ++n; }
    if (n < cap) dst[n] = 0;
    return n;
}
