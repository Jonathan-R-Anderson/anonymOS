// Application registry + launch policy ("appgate"), 2026-09-28.
//
// The rule this enforces, in the user's words: the System domain owns the Domain Manager; the
// Domain Manager is THE interface through which applications are delegated out to other domains;
// and a domain that has not been delegated an application cannot launch it.
//
// Two halves.  This module is the static half: a table that classifies every program image the OS
// can exec (execveTask only runs boot modules and objstore apps, so the whole universe is known at
// build time), plus the pure decision function execveTask asks on EVERY exec -- where does this
// image land, and may it run there.  The dynamic half -- which domain has been delegated which
// application -- is the grant table in core.appport, written only by the Domain Manager.
//
// Why a table rather than the old SYSTEM_PROGS allowlist + "hos-*" prefix: that list answered one
// question (confine or not) by NAME, for any caller, so a confined process could exec its way out
// of its domain just by running a listed image, and nothing ever asked whether the domain was
// allowed to run the program at all.  Placement now follows the CALLER first (a domain's processes
// stay in that domain -- the sticky rule) and the image second.
//
// Keep one row per line: tests/appgate/check_registry.py parses this table to prove every staged
// executable, keybind, .desktop Exec= and kernel spawn target is classified.
//
// Kernel constraints: -betterC, plain structs, static immutable tables, @nogc nothrow.
module core.appreg;

extern (C) @nogc nothrow:

enum AppCls : ubyte {
    Unregistered = 0,   // not in the table: denied outside System (fail closed, logged)
    App,                // an application: always allowed in System, elsewhere only where delegated
    SystemOnly,         // owned by System, never delegable: the Domain Manager, developer tools
    Runtime,            // plumbing any domain may exec: shells, busybox applets, the daemons it hosts
    Infra,              // unconfined system infrastructure: stays domain 0 when launched from domain 0,
                        // refused inside any non-System domain
    Noexec,             // not a program (the dynamic loader, guest kernels, scripts): ENOEXEC for all
}

// Where a launch from the SHARED DESKTOP lands -- i.e. from an unconfined domain-0 caller such as
// Hyprland, the top bar or the app grid.  A launch from inside a domain always stays in that domain.
enum AppHost : ubyte {
    Session = 0,        // the session domain (the desktop's user domain), subject to its grants
    System  = 1,        // the System domain: administration tools open there
}

// Initial grant for a delegable app on a domain that has no persisted grant record yet.
enum AppDef : ubyte {
    None    = 0,        // System only until the Domain Manager delegates it
    Session = 1,        // the session domain, so the desktop works out of the box
    Named   = 2,        // one named domain (defDomain)
}

enum : ubyte {
    AF_DELEGABLE = 1,   // the Domain Manager may delegate it to other domains
    AF_CHROME    = 2,   // desktop chrome (bar, grid, popups): an INFRA image the desktop may start
    AF_DESKTOP   = 4,   // the app grid may launch it (see the wl-overview rule in appgateDecide)
}

struct AppRegEntry {
    string  image;      // boot-module basename, == execveTask's execName
    string  appId;      // delegation key (the Domain Manager's DMAPPS exec basename); null if none
    AppCls  cls;
    AppHost host;
    AppDef  def;
    string  defDomain;  // AppDef.Named only
    ubyte   flags;
}

private enum AppCls  APP = AppCls.App, SYS = AppCls.SystemOnly, RUN = AppCls.Runtime,
                     INF = AppCls.Infra, NOX = AppCls.Noexec;
private enum AppHost SES = AppHost.Session, SYH = AppHost.System;
private enum AppDef  DNO = AppDef.None, DSE = AppDef.Session, DNM = AppDef.Named;
private enum ubyte   DLG = AF_DELEGABLE, CHR = AF_CHROME, DSK = AF_DESKTOP;

// ── The registry ──────────────────────────────────────────────────────────────────────────────
// image, appId, class, host, default grant, default domain, flags.  ONE ROW PER LINE.
static immutable AppRegEntry[] g_appReg = [
    // Applications the Domain Manager delegates.  The Terminal is several images (the launcher
    // wrapper and the terminal emulators it or the DM may start), all delegated as one app.
    AppRegEntry("hos-wifiterm",      "hos-wifiterm",  APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-term",           "hos-wifiterm",  APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("gl-term",           "hos-wifiterm",  APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("hos-term",          "hos-wifiterm",  APP, SES, DSE, null, DLG | DSK),
    // ratty (orhun/ratty, scripts/build-ratty.sh): one more emulator of the same Terminal app.
    AppRegEntry("ratty",             "hos-wifiterm",  APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-files",          "wl-files",      APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-editor",         "wl-editor",     APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-calc",           "wl-calc",       APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-imgview",        "wl-imgview",    APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-clocks",         "wl-clocks",     APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-calendar",       "wl-calendar",   APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-chars",          "wl-chars",      APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("wl-screenshot",     "wl-screenshot", APP, SES, DSE, null, DLG | DSK),
    AppRegEntry("kuml",              "kuml",          APP, SES, DNM, "Development", DLG | DSK),
    // Compatibility runtimes (src/util/hos-compat.c, docs/COMPAT.md): one launcher per foreign
    // platform, delegable to any domain.  Granted the app AND the runtime installed there (Wine
    // from the Software Center; Darling/Waydroid built by scripts/build-*.sh), the domain runs
    // Windows/macOS/Android software as its own -- isolated and badged like everything else.
    AppRegEntry("hos-compat",        "hos-compat",    APP, SES, DNO, null, DLG | DSK),
    AppRegEntry("hos-wine",          "hos-wine",      APP, SES, DNO, null, DLG | DSK),
    AppRegEntry("hos-darling",       "hos-darling",   APP, SES, DNO, null, DLG | DSK),
    AppRegEntry("hos-waydroid",      "hos-waydroid",  APP, SES, DNO, null, DLG | DSK),
    // Virtual Machines: System-hosted from the desktop, and delegable -- a domain granted it (plus
    // Virtualization in its Permissions, i.e. DEVCLASS_VIRT for /dev/kvm) runs its own hypervisor.
    AppRegEntry("wl-vmm",            "wl-vmm",        APP, SYH, DNO, null, DLG | DSK),
    AppRegEntry("cloud-hypervisor",  "wl-vmm",        APP, SYH, DNO, null, DLG),
    // Administration apps: they drive /config (catalog, logs, every process), so they belong to
    // System and are not delegable -- a delegated instance could not reach what it needs.
    AppRegEntry("wl-software",       "wl-software",   APP, SYH, DNO, null, DSK),
    AppRegEntry("wl-sysmon",         "wl-sysmon",     APP, SYH, DNO, null, DSK),
    AppRegEntry("wl-logview",        "wl-logview",    APP, SYH, DNO, null, DSK),

    // Owned by System, never delegable.  The Domain Manager first: it is the delegation authority.
    AppRegEntry("wl-domain-manager", "wl-domain-manager", SYS, SYH, DNO, null, DSK),
    AppRegEntry("store-app",         null, SYS, SYH, DNO, null, 0),   // the seed image / a re-exec that lost its app
    AppRegEntry("gtk3-widget-factory", null, SYS, SYH, DNO, null, 0),
    AppRegEntry("gtk3-demo",         null, SYS, SYH, DNO, null, 0),
    AppRegEntry("gtk-hello",         null, SYS, SYH, DNO, null, 0),
    AppRegEntry("hog",               null, SYS, SYH, DNO, null, 0),
    AppRegEntry("wl-cairo-demo",     null, SYS, SYH, DNO, null, 0),
    AppRegEntry("gl-wl-test",        null, SYS, SYH, DNO, null, 0),
    AppRegEntry("hello-gui",         null, SYS, SYH, DNO, null, 0),
    AppRegEntry("hello-wl",          null, SYS, SYH, DNO, null, 0),
    AppRegEntry("wl-shm-demo",       null, SYS, SYH, DNO, null, 0),
    AppRegEntry("wl-probe",          null, SYS, SYH, DNO, null, 0),
    AppRegEntry("compositor",        null, SYS, SYH, DNO, null, 0),
    AppRegEntry("test-drm",          null, SYS, SYH, DNO, null, 0),
    AppRegEntry("display-info",      null, SYS, SYH, DNO, null, 0),
    AppRegEntry("drm-gpu-test",      null, SYS, SYH, DNO, null, 0),
    AppRegEntry("drm-gl-test",       null, SYS, SYH, DNO, null, 0),
    AppRegEntry("hos-thread-test",   null, SYS, SYH, DNO, null, 0),
    AppRegEntry("hos-nettest",       null, SYS, SYH, DNO, null, 0),
    AppRegEntry("scp-test",          null, SYS, SYH, DNO, null, 0),
    AppRegEntry("hos-http-upload",   null, SYS, SYH, DNO, null, 0),
    AppRegEntry("nmcli",             null, SYS, SYH, DNO, null, 0),
    AppRegEntry("wpa_cli",           null, SYS, SYH, DNO, null, 0),
    AppRegEntry("rabbiit-node",    null, SYS, SYH, DNO, null, 0),
    AppRegEntry("weston",            null, SYS, SYH, DNO, null, 0),
    AppRegEntry("weston-desktop-shell", null, SYS, SYH, DNO, null, 0),
    AppRegEntry("weston-keyboard",   null, SYS, SYH, DNO, null, 0),
    AppRegEntry("weston-terminal",   null, SYS, SYH, DNO, null, 0),
    AppRegEntry("dyntest",           null, SYS, SYH, DNO, null, 0),

    // Runtime plumbing: allowed in every domain, placed where it is launched from.  The daemons keep
    // the session placement they have always had when an infrastructure launcher starts them.
    AppRegEntry("busybox",           null, RUN, SES, DNO, null, 0),
    AppRegEntry("-sh",               null, RUN, SES, DNO, null, 0),   // a byte-identical busybox copy
    AppRegEntry("busybox-dyn",       null, RUN, SES, DNO, null, 0),
    AppRegEntry("zsh",               null, RUN, SES, DNO, null, 0),
    AppRegEntry("hos-sh",            null, RUN, SES, DNO, null, 0),
    AppRegEntry("bsdtar",            null, RUN, SES, DNO, null, 0),
    AppRegEntry("unsquashfs",        null, RUN, SES, DNO, null, 0),
    AppRegEntry("mke2fs",            null, RUN, SES, DNO, null, 0),
    AppRegEntry("gpgv",              null, RUN, SES, DNO, null, 0),
    AppRegEntry("dbus-daemon",       null, RUN, SES, DNO, null, 0),
    AppRegEntry("dbus-send",         null, RUN, SES, DNO, null, 0),
    AppRegEntry("dropbear",          null, RUN, SES, DNO, null, 0),
    AppRegEntry("ssh",               null, RUN, SES, DNO, null, 0),
    AppRegEntry("scp",               null, RUN, SES, DNO, null, 0),
    AppRegEntry("lkl-boot",          null, RUN, SES, DNO, null, 0),
    AppRegEntry("wpa_supplicant",    null, RUN, SES, DNO, null, 0),
    AppRegEntry("NetworkManager",    null, RUN, SES, DNO, null, 0),
    AppRegEntry("udhcpc-script",     null, RUN, SES, DNO, null, 0),
    AppRegEntry("xid-test",          null, RUN, SES, DNO, null, 0),   // the 4.1 negative control spawns it INTO a domain
    AppRegEntry("hos-wifi",          null, RUN, SES, DNO, null, 0),

    // Unconfined infrastructure.  The desktop chrome first (the only INFRA the app grid may start).
    AppRegEntry("Hyprland",          null, INF, SES, DNO, null, CHR),
    AppRegEntry("wl-layer-bar",      null, INF, SES, DNO, null, CHR),
    AppRegEntry("wl-overview",       null, INF, SES, DNO, null, CHR | DSK),
    AppRegEntry("wl-dock",           null, INF, SES, DNO, null, CHR),        // the launcher bar + drawer
    AppRegEntry("wl-welcome",        null, INF, SES, DNO, null, CHR | DSK),  // the first-boot overlay
    AppRegEntry("wl-quicksettings",  null, INF, SES, DNO, null, CHR | DSK),
    AppRegEntry("wl-wifi-menu",      null, INF, SES, DNO, null, CHR | DSK),
    AppRegEntry("wl-wallpaper",      null, INF, SES, DNO, null, CHR),
    AppRegEntry("idle",              null, INF, SES, DNO, null, 0),
    AppRegEntry("calamares",         null, INF, SES, DNO, null, 0),   // the installer (built as wl-installer)
    AppRegEntry("hos-pkg-fetch",     null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-vm-fetch",      null, INF, SES, DNO, null, 0),   // the firewall image download
    AppRegEntry("hos-dbus-launch",   null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-sshd-launch",   null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-wpa-launch",    null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-wpa-agent",     null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-udhcpc-launch", null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-nm-launch",     null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-wifi-agent",    null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-nmcli-test",    null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-log-upload",    null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-netlaunch",     null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-attest-deploy", null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-ethsign",       null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-ethsign-dyn",   null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-dbus-test",     null, INF, SES, DNO, null, 0),
    AppRegEntry("inotify-test",      null, INF, SES, DNO, null, 0),
    AppRegEntry("hos-wl-trace",      null, INF, SES, DNO, null, 0),

    // Never a program.  The loader runs only as a PT_INTERP; exec'ing it directly would let any
    // caller run an arbitrary module under an unconfined loader image.
    AppRegEntry("ld-musl-x86_64.so.1", null, NOX, SES, DNO, null, 0),
    AppRegEntry("guest-hello.elf",   null, NOX, SES, DNO, null, 0),
    AppRegEntry("wifi-diag.sh",      null, NOX, SES, DNO, null, 0),
];

// Display names for the application ids, so a refusal can say "Terminal", not "hos-wifiterm".
struct AppLabel { string appId; string label; }
static immutable AppLabel[] g_appLabels = [
    AppLabel("hos-wifiterm",      "Terminal"),
    AppLabel("wl-files",          "Files"),
    AppLabel("wl-editor",         "Text Editor"),
    AppLabel("wl-calc",           "Calculator"),
    AppLabel("wl-imgview",        "Image Viewer"),
    AppLabel("wl-clocks",         "Clocks"),
    AppLabel("wl-calendar",       "Calendar"),
    AppLabel("wl-chars",          "Characters"),
    AppLabel("wl-screenshot",     "Screenshot"),
    AppLabel("kuml",              "kUML"),
    AppLabel("wl-software",       "Software Center"),
    AppLabel("wl-vmm",            "Virtual Machines"),
    AppLabel("wl-sysmon",         "System Monitor"),
    AppLabel("wl-logview",        "Logs"),
    AppLabel("wl-domain-manager", "Domain Manager"),
];

// The objstore app row: /objects/apps/<name>/executable runs under execName "store-app", and its
// grant key is "store:<name>" (never a boot-module appId -- see appgateStoreKey).
static immutable AppRegEntry g_appRegStore =
    AppRegEntry("store-app", null, APP, SES, DNO, null, DLG | DSK);

// ── lookups ───────────────────────────────────────────────────────────────────────────────────

private bool regEqC(string lit, const(char)* s) {
    if (s is null) return false;
    size_t i = 0;
    for (; i < lit.length; ++i) if (s[i] != lit[i]) return false;
    return s[i] == 0;
}

private bool regEqS(string a, string b) {
    if (a.length != b.length) return false;
    foreach (i; 0 .. a.length) if (a[i] != b[i]) return false;
    return true;
}

// Exact basename match, no prefix rules.  null = unregistered.
public const(AppRegEntry)* appRegLookup(const(char)* image) {
    if (image is null || image[0] == 0) return null;
    foreach (ref e; g_appReg) if (regEqC(e.image, image)) return &e;
    return null;
}

public const(AppRegEntry)* appRegStoreEntry() { return &g_appRegStore; }

// Every program of an INSTALLED package (Software Center) is classified by this one row; its grant
// key is "pkg:<name>".  An application, hosted by System (an install is system-wide, made by the
// administrator), delegable: the Domain Manager ports a package to a domain like any application.
static immutable AppRegEntry g_appRegPkg =
    AppRegEntry("installed-package", null, APP, SYH, DNO, null, DLG);
public const(AppRegEntry)* appRegPkgEntry() { return &g_appRegPkg; }

// "pkg:<name>" of a package that is actually installed.
public bool appRegIsPkgKey(const(char)* appId) {
    import core.syscalls.posix : softwarePkgInstalled;
    return appId !is null && appId[0] == 'p' && appId[1] == 'k' && appId[2] == 'g' && appId[3] == ':'
        && softwarePkgInstalled(appId + 4);
}

// A row's grant key as a C string (table literals are NUL-terminated), or null.
public const(char)* appRegKey(const(AppRegEntry)* e) {
    return (e is null || e.appId is null) ? null : e.appId.ptr;
}

// The first row that carries this appId (the app's canonical row).
public const(AppRegEntry)* appRegByAppId(const(char)* appId) {
    if (appId is null || appId[0] == 0) return null;
    foreach (ref e; g_appReg) if (e.appId !is null && regEqC(e.appId, appId)) return &e;
    return null;
}

// A display name for an appId (the appId itself when it has none), as a C string.
public const(char)* appRegLabel(const(char)* appId) {
    if (appId is null) return null;
    foreach (ref l; g_appLabels) if (regEqC(l.appId, appId)) return l.label.ptr;
    return appId;
}

// "store:<name>" -- an objstore application's grant key.
public bool appRegIsStoreKey(const(char)* key) {
    return key !is null && key[0] == 's' && key[1] == 't' && key[2] == 'o' && key[3] == 'r'
        && key[4] == 'e' && key[5] == ':' && key[6] != 0;
}

// May the Domain Manager delegate `appId` to another domain?
public bool appRegIsDelegable(const(char)* appId) {
    if (appRegIsStoreKey(appId)) return true;
    if (appRegIsPkgKey(appId)) return true;
    auto e = appRegByAppId(appId);
    return e !is null && e.cls == AppCls.App && (e.flags & AF_DELEGABLE) != 0;
}

// Enumerate each APP-class appId once (for /config/apps.json): idx 0..n-1, null past the end.
public const(AppRegEntry)* appRegAppAt(uint idx) {
    uint n = 0;
    foreach (i, ref e; g_appReg) {
        if (e.cls != AppCls.App || e.appId is null) continue;
        bool seen = false;
        foreach (j; 0 .. i) {
            auto p = &g_appReg[j];
            if (p.cls == AppCls.App && p.appId !is null && regEqS(p.appId, e.appId)) { seen = true; break; }
        }
        if (seen) continue;
        if (n == idx) return &e;
        ++n;
    }
    return null;
}

// Should a domain that has no persisted grant record start out with this app?
public bool appRegDefaultGranted(const(AppRegEntry)* e, const(char)* domainName, bool isSession) {
    if (e is null || e.cls != AppCls.App || (e.flags & AF_DELEGABLE) == 0) return false;
    if (e.def == AppDef.Session) return isSession;
    if (e.def == AppDef.Named)   return e.defDomain !is null && regEqC(e.defDomain, domainName);
    return false;
}

// ── the decision ──────────────────────────────────────────────────────────────────────────────

enum AppVerdict : ubyte { Allow = 0, Deny = 1, Noexec = 2 }

struct AppDecision {
    uint       target;    // domain objId the image will run in (0 = unconfined)
    AppVerdict verdict;
}

alias AppGrantedFn = bool function(uint domObjId, const(char)* appId) @nogc nothrow;

// Pure placement + permission decision for one exec.
//   callerDom   the task's domain BEFORE the exec (0 = unconfined: kernel spawn, Hyprland child, infra)
//   parentImage the image the task ran before the exec (null = a fresh kernel spawn)
//   reg         the image's row (null = unregistered)
//   grantKey    reg's appId, or "store:<name>" for an objstore app
//   sys / sess  the System and session domain objIds (0 when absent)
public AppDecision appgateDecide(uint callerDom, const(char)* parentImage, const(AppRegEntry)* reg,
                                 const(char)* grantKey, uint sys, uint sess, AppGrantedFn granted) {
    AppDecision d;
    const AppCls cls = (reg is null) ? AppCls.Unregistered : reg.cls;
    if (cls == AppCls.Noexec) { d.verdict = AppVerdict.Noexec; d.target = callerDom; return d; }

    // Launched from INSIDE a domain: it stays in that domain (a domain's processes cannot exec their
    // way out), and it runs only if that domain may run it.  System may run everything.
    if (callerDom != 0) {
        d.target = callerDom;
        bool ok;
        if (sys != 0 && callerDom == sys)  ok = true;
        else if (cls == AppCls.Runtime)   ok = true;
        else if (cls == AppCls.App)       ok = grantKey !is null && granted !is null && granted(callerDom, grantKey);
        else                              ok = false;   // SystemOnly / Infra / Unregistered
        d.verdict = ok ? AppVerdict.Allow : AppVerdict.Deny;
        return d;
    }

    // Launched from the shared desktop / infrastructure (domain 0).
    const uint home = (sess != 0) ? sess : sys;          // never 0 when a System domain exists
    // A runtime helper started by unconfined SYSTEM infrastructure -- a service launcher, or a daemon
    // it started (hos-udhcpc-launch -> busybox-dyn udhcpc -> udhcpc-script) -- is part of that
    // service and stays unconfined with it.  Launched by the desktop chrome (a keybind, the bar) it is
    // the user's, and lands in the session domain like before.  (Measured: DHCP placed in the
    // session domain could not read /libnshim.so, so its AF_PACKET socket fell through to the
    // native kernel -- "udhcpc: socket: Protocol not supported" -- and no lease ever came.)
    const(AppRegEntry)* par = (parentImage !is null) ? appRegLookup(parentImage) : null;
    const bool serviceParent = par !is null && (par.flags & AF_CHROME) == 0
                               && (par.cls == AppCls.Infra || par.cls == AppCls.Runtime);
    switch (cls) {
        case AppCls.Infra:      d.target = 0;   break;
        case AppCls.SystemOnly: d.target = sys; break;
        case AppCls.App:        d.target = (reg.host == AppHost.System) ? sys : home; break;
        case AppCls.Runtime:    d.target = serviceParent ? 0 : home; break;
        default:                d.target = home; break;  // Unregistered
    }
    bool ok;
    if (d.target == 0 || (sys != 0 && d.target == sys)) ok = (cls != AppCls.Unregistered) || d.target == sys || sys == 0;
    else if (cls == AppCls.Runtime) ok = true;
    else if (cls == AppCls.App)     ok = grantKey !is null && granted !is null && granted(d.target, grantKey);
    else                            ok = false;
    // The launchers (the app grid, the dock's drawer) exec whatever an Exec= line in
    // /usr/share/applications says, and packages can add .desktop files -- so their children are
    // limited to what a launcher tile legitimately is: a desktop-flagged image (applications, the
    // Domain Manager, desktop chrome) or any application proper -- App class, which always runs
    // confined in a domain that was granted it (an installed package is one).  Anything else (a
    // service launcher, a developer tool with attacker-chosen arguments) is refused rather than
    // started in domain 0/System.
    if (parentImage !is null && (regEqC("wl-overview", parentImage) || regEqC("wl-dock", parentImage))
        && (reg is null || ((reg.flags & AF_DESKTOP) == 0 && reg.cls != AppCls.App)))
        ok = false;
    d.verdict = ok ? AppVerdict.Allow : AppVerdict.Deny;
    return d;
}

// ── boot self-test ────────────────────────────────────────────────────────────────────────────

private __gshared uint g_stSys = 0x100, g_stSess = 0x200, g_stWork = 0x300;
private bool stGranted(uint dom, const(char)* appId) {
    // Personal (sess) has the Terminal and Files; Work has only Files.
    if (dom == g_stSess) return regEqC("hos-wifiterm", appId) || regEqC("wl-files", appId);
    if (dom == g_stWork) return regEqC("wl-files", appId);
    return false;
}

private __gshared uint g_stBad = 0;
private __gshared void function(const(char)* what) @nogc nothrow g_stFail = null;
private void expect(const(char)* what, bool cond) {
    if (cond) return;
    ++g_stBad;
    if (g_stFail !is null) g_stFail(what);
}

// Returns the number of failed cases (0 = PASS); reports each failure through `fail`.
public uint appgateSelfTestCases(void function(const(char)* what) @nogc nothrow fail) {
    g_stBad = 0;
    g_stFail = fail;
    const sys = g_stSys, sess = g_stSess, work = g_stWork;

    auto dm    = appRegLookup("wl-domain-manager\0".ptr);
    auto files = appRegLookup("wl-files\0".ptr);
    auto term  = appRegLookup("wl-term\0".ptr);
    auto sw    = appRegLookup("wl-software\0".ptr);
    auto bb    = appRegLookup("busybox\0".ptr);
    auto netl  = appRegLookup("hos-netlaunch\0".ptr);
    auto bar   = appRegLookup("wl-layer-bar\0".ptr);
    auto ldso  = appRegLookup("ld-musl-x86_64.so.1\0".ptr);
    auto qs    = appRegLookup("wl-quicksettings\0".ptr);
    expect("registry rows present", dm !is null && files !is null && term !is null && sw !is null
                                    && bb !is null && netl !is null && bar !is null && ldso !is null && qs !is null);
    if (g_stBad) return g_stBad;
    AppDecision r;

    r = appgateDecide(0, null, dm, dm.appId.ptr, sys, sess, &stGranted);
    expect("DM from the desktop runs in System", r.verdict == AppVerdict.Allow && r.target == sys);
    r = appgateDecide(sess, "zsh\0".ptr, dm, dm.appId.ptr, sys, sess, &stGranted);
    expect("DM refused inside Personal", r.verdict == AppVerdict.Deny);
    r = appgateDecide(sys, "zsh\0".ptr, dm, dm.appId.ptr, sys, sess, &stGranted);
    expect("DM allowed inside System", r.verdict == AppVerdict.Allow && r.target == sys);
    r = appgateDecide(0, "Hyprland\0".ptr, files, files.appId.ptr, sys, sess, &stGranted);
    expect("Files from the desktop -> session (granted)", r.verdict == AppVerdict.Allow && r.target == sess);
    r = appgateDecide(work, "zsh\0".ptr, term, term.appId.ptr, sys, sess, &stGranted);
    expect("Terminal refused in Work (not delegated)", r.verdict == AppVerdict.Deny && r.target == work);
    r = appgateDecide(work, "zsh\0".ptr, files, files.appId.ptr, sys, sess, &stGranted);
    expect("Files allowed in Work (delegated)", r.verdict == AppVerdict.Allow && r.target == work);
    r = appgateDecide(0, "Hyprland\0".ptr, sw, sw.appId.ptr, sys, sess, &stGranted);
    expect("Software Center from the desktop -> System", r.verdict == AppVerdict.Allow && r.target == sys);
    r = appgateDecide(sess, "zsh\0".ptr, sw, sw.appId.ptr, sys, sess, &stGranted);
    expect("Software Center refused in Personal", r.verdict == AppVerdict.Deny);
    r = appgateDecide(work, "zsh\0".ptr, bb, null, sys, sess, &stGranted);
    expect("busybox (runtime) allowed anywhere, stays put", r.verdict == AppVerdict.Allow && r.target == work);
    r = appgateDecide(0, null, netl, null, sys, sess, &stGranted);
    expect("service launcher from the kernel stays unconfined", r.verdict == AppVerdict.Allow && r.target == 0);
    r = appgateDecide(sess, "zsh\0".ptr, netl, null, sys, sess, &stGranted);
    expect("service launcher refused inside Personal (no escape)", r.verdict == AppVerdict.Deny);
    r = appgateDecide(sess, "zsh\0".ptr, bar, null, sys, sess, &stGranted);
    expect("desktop chrome refused inside Personal (no escape)", r.verdict == AppVerdict.Deny);
    r = appgateDecide(0, "Hyprland\0".ptr, ldso, null, sys, sess, &stGranted);
    expect("loader direct exec refused even from domain 0", r.verdict == AppVerdict.Noexec);
    r = appgateDecide(sess, "zsh\0".ptr, null, null, sys, sess, &stGranted);
    expect("unregistered image refused in Personal", r.verdict == AppVerdict.Deny);
    r = appgateDecide(sys, "zsh\0".ptr, null, null, sys, sess, &stGranted);
    expect("unregistered image allowed in System", r.verdict == AppVerdict.Allow && r.target == sys);
    r = appgateDecide(0, "wl-overview\0".ptr, netl, null, sys, sess, &stGranted);
    expect("app grid cannot start a service launcher", r.verdict == AppVerdict.Deny);
    r = appgateDecide(0, "wl-overview\0".ptr, qs, null, sys, sess, &stGranted);
    expect("app grid may open quick settings (chrome)", r.verdict == AppVerdict.Allow && r.target == 0);
    r = appgateDecide(0, "wl-overview\0".ptr, dm, dm.appId.ptr, sys, sess, &stGranted);
    expect("app grid may open the Domain Manager (System)", r.verdict == AppVerdict.Allow && r.target == sys);
    r = appgateDecide(0, "hos-netlaunch\0".ptr, bb, null, sys, sess, &stGranted);
    expect("a service's runtime helper stays unconfined", r.verdict == AppVerdict.Allow && r.target == 0);
    r = appgateDecide(0, "Hyprland\0".ptr, bb, null, sys, sess, &stGranted);
    expect("a keybind's runtime program lands in the session", r.verdict == AppVerdict.Allow && r.target == sess);
    // Delegation keys.
    expect("DM is not delegable", !appRegIsDelegable("wl-domain-manager\0".ptr));
    expect("Software Center is not delegable", !appRegIsDelegable("wl-software\0".ptr));
    expect("Files is delegable", appRegIsDelegable("wl-files\0".ptr));
    expect("store:<n> keys are delegable", appRegIsDelegable("store:notes\0".ptr));
    expect("a bogus appId is not delegable", !appRegIsDelegable("wl-nonexistent\0".ptr));
    return g_stBad;
}
