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

// Is a usable network up?  The LKL provider owns the NIC and the DHCP lease marker is what the
// rest of the system already treats as "we have an address" (kernel_main.d's udhcpc supervisor
// latches on the same file), so this asks the same question rather than inventing a second answer.
private bool swNetworkUp() {
    import core.syscalls.posix : linux_sys_access, unixSocketListenerReady;
    if (linux_sys_access(cast(ulong)"/run/wifi/dhcp-ok\0".ptr, 0) == 0) return true;
    return false;
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

    // 3. Network is up: hand the fetch to the userspace helper, which speaks HTTP through the LKL
    //    socket shim (the kernel has no HTTP client and should not grow one).  The helper writes
    //    its own progress into /run/pkg/<name>.log; the status here reports the hand-off honestly
    //    rather than claiming an install that has not finished.
    {
        import core.kernel_main : softwareSpawnFetcher;
        if (softwareSpawnFetcher(mgr.ptr, name.ptr, url.ptr)) {
            swSet("busy fetching ", name[0 .. nl],
                  " from the Alpine mirror (hos-pkg-fetch); watch Logs, filter 'pkg'.");
            return true;
        }
        swSet("refused could not start the package fetcher (hos-pkg-fetch is not staged in this image)");
        return false;
    }
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
