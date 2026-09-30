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
                       DEVCLASS_MIC, DEVCLASS_AUDIO, DEVCLASS_USB,
                       DEVCLASS_NET, DEVCLASS_POWER, DEVCLASS_VIRT;  // DM8/DM10.7 device policy
                       // DEVCLASS_NET was missing from this list, which is exactly why
                       // domainDeviceClassByName() had no "net" case: the name could not be
                       // resolved here, so per-domain network control was unreachable.
import core.namespace : nsAllocRestricted, nsBind, nsBindDeny, nsRootDir,
                        nsResolveCheck, nsRelease;     // DOMAIN_MANAGER DM2
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_STAT;  // DOMAIN_MANAGER DM2
import core.objstore : objstoreMounted, objstoreInstallDomain, objstoreRemoveDomain,
                       objstoreDomainAt, objstoreDomainCount;     // DOMAIN_MANAGER DM5
import core.overlay : overlayCreate, overlayDestroy, overlaySnapshot, overlayCommit,
                      overlayDiscard, overlayRestore;            // DOMAIN_MANAGER DM6.2
import core.io : klog, klog_hex;
import core.pkgrepo : pkgInstallByName, pkgRemoveByName, pkgApplyProfile;   // DOMAIN_MANAGER DM7/DM11
import core.appport : appPortAdd, appPortRemove, appGrantsSeedDomain, appGrantsCloneDomain,
                      appGrantsScrubDomain;   // appgate: the grant table the Domain Manager edits
import core.appreg : appRegIsDelegable;       // appgate: which appIds may be delegated at all
import core.install_config : installConfigDomains; // installer-chosen domain set (which domains exist)
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

    // If the installer recorded which domains should exist (install.json "domains"), seed EXACTLY
    // those instead of the hardcoded set — this is what makes the installer's domain selection
    // actually take effect on the installed system (previously it was ignored and these 7 always
    // won).  System is always present (the admin domain); duplicate names in the list are harmless
    // (domainCreate rejects them).  Empty selection ⟹ fall back to the built-in set below.
    char[512] sel = void;
    const uint selLen = installConfigDomains(sel[]);
    if (selLen > 0) {
        mkBootDomain("System\0".ptr);
        char[DOM_NAME_MAX] nm = void;
        uint j = 0;
        foreach (i; 0 .. selLen + 1) {
            const char c = (i < selLen) ? sel[i] : ',';
            if (c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                if (j > 0) { nm[j] = 0; mkBootDomain(nm.ptr); j = 0; }
            } else if (j < DOM_NAME_MAX - 1) {
                nm[j++] = c;
            }
        }
        klog("[domain] seeded from install.json domain selection\n");
        return;
    }

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
    // ...and the name Hyprland really listens on.  libwayland takes the first free name, which is
    // wayland-1 here (connect() aliases wayland-0 to it, see findUnixListener), and every program
    // Hyprland launches inherits WAYLAND_DISPLAY=wayland-1 -- with only wayland-0 bound, a confined
    // app launched from a keybind died at wl_display_connect (measured: wl-term and wl-sysmon
    // exit(1) right after start).  Same compositor, same trust argument as above.
    nsBind(ns, "/run/user/1000/wayland-1\0".ptr, root, RW);

    // The PTY pair, so a confined terminal can actually host a shell.  Verified the hard way:
    // the first successful confined spawn got as far as "G4TERM: open /dev/ptmx: No such file
    // or directory" -- the namespace was doing its job and denying an unbound path, but a
    // terminal with no pty cannot run anything.  /dev/pts/N is where the slave appears.
    //
    // This is a capability every domain needs to be useful at all, and it grants nothing
    // outside the domain: a pty is a private channel between the terminal and its own child.
    nsBind(ns, "/dev/ptmx\0".ptr, root, RW);
    nsBind(ns, "/dev/pts\0".ptr,  root, RW);

    // DM11: a non-native domain mounts its distro's Linux compat root at /linux (READ-only).
    if (d.distro != DISTRO_NATIVE) nsBind(ns, "/linux\0".ptr, root, RO);

    // appgate: the read-only RUNTIME, so a program the Domain Manager delegates here can actually
    // start.  Every application is a dynamic executable: the loader opens its libraries under /lib and
    // /usr/lib and the apps read /usr/share (fonts, themes) and /etc -- none of which this default-deny
    // view granted, so "delegated" meant "refused by the loader" (measured: dbus-daemon confined in the
    // session domain died with "Error loading shared library libdbus-1.so.3").  Reads stay an allow
    // LIST (these trees, not "/"): /home, /config, /objects, /run, /proc and every other domain's data
    // remain unreachable.  Writes are unchanged: only Home and /tmp.
    nsBind(ns, "/usr\0".ptr,       root, RO);
    nsBind(ns, "/lib\0".ptr,       root, RO);
    nsBind(ns, "/etc\0".ptr,       root, RO);
    nsBind(ns, "/bin\0".ptr,       root, RO);
    nsBind(ns, "/sbin\0".ptr,      root, RO);
    nsBind(ns, "/compat\0".ptr,    root, RO);
    nsBind(ns, "/system\0".ptr,    root, RO);   // the shell's function library (/system/shell/...)
    nsBind(ns, "/var/cache\0".ptr, root, RO);   // font caches
    nsBind(ns, "/vm-alpine.vmlinuz\0".ptr, root, RO);  // the Virtual Machines app's bundled guest
    nsBind(ns, "/vm-alpine.initrd\0".ptr,  root, RO);
    nsBind(ns, "/vm-firmware.fd\0".ptr,    root, RO);   // UEFI for firmware-booted guests (OPNsense)
    nsBind(ns, "/libnshim.so\0".ptr, root, RO); // the network shim (LD_PRELOAD) -- TCP/IP is the LKL's
    // ...minus the secrets that live in /etc (explicit deny overrides the shorter allow).
    nsBindDeny(ns, "/etc/shadow\0".ptr);
    nsBindDeny(ns, "/etc/wpa_supplicant\0".ptr);          // Wi-Fi keys
    nsBindDeny(ns, "/etc/NetworkManager\0".ptr);
    nsBindDeny(ns, "/etc/ssh\0".ptr);                     // host keys
    nsBindDeny(ns, "/etc/dropbear\0".ptr);
    nsBindDeny(ns, "/etc/hypr\0".ptr);                    // the compositor's config: never a domain's to touch
    // The device nodes every program writes to or reads from.  Brokered devices (/dev/dri) are still
    // gated per domain by deviceClassGate; these binds only make the path resolvable.
    nsBind(ns, "/dev/null\0".ptr,    root, RW);
    nsBind(ns, "/dev/zero\0".ptr,    root, RW);
    nsBind(ns, "/dev/full\0".ptr,    root, RW);
    nsBind(ns, "/dev/tty\0".ptr,     root, RW);
    nsBind(ns, "/dev/shm\0".ptr,     root, RW);   // POSIX shm: rtfs keeps each domain's objects private
    nsBind(ns, "/dev/dri\0".ptr,     root, RW);
    nsBind(ns, "/dev/kvm\0".ptr,     root, RW);   // VMs: usable only where Virtualization is enabled
    nsBind(ns, "/dev/urandom\0".ptr, root, RO);
    nsBind(ns, "/dev/random\0".ptr,  root, RO);

    // System is the trusted administrative identity (TRUST_SYSTEM / CEIL_FULL).  Confining it to a
    // per-domain sandbox contradicts its role: the user runs System precisely to inspect and TWEAK
    // the system's configuration (the Hyprland/desktop config, /etc, the live domain control files).
    // So System — and ONLY System — additionally gets read-visibility of the whole tree plus RW on
    // the configuration locations.  The more-specific RW bindings override the "/" RO the same way
    // /Shared/Private's deny overrides /Shared above (longest-prefix wins).  Every other domain
    // stays default-deny.
    bool isSystem = (d.nameLen >= 6 && d.name.length >= 7);
    if (isSystem) { static immutable string sysn = "System";
                    foreach (i; 0 .. 6) if (d.name[i] != sysn[i]) { isSystem = false; break; }
                    // accept "System" exactly, tolerating a trailing NUL in nameLen (6 or 7)
                    if (isSystem && d.nameLen > 6 && d.name[6] != 0) isSystem = false; }
    if (isSystem) {
        klog("[domain] System namespace: granting config-file access (/home/user/.config, /etc, /config)\n");
        nsBind(ns, "/\0".ptr,                   root, RO);   // browse the whole system read-only
        nsBind(ns, "/home/user/.config\0".ptr,  root, RW);   // Hyprland + app config (general.lua, colors, …)
        nsBind(ns, "/etc\0".ptr,                root, RW);   // system configuration
        nsBind(ns, "/config\0".ptr,             root, RW);   // live domain/system control (domains.json, …)
        nsBind(ns, "/desktop.conf\0".ptr,       root, RW);   // desktop autostart/config
        nsBind(ns, "/display.conf\0".ptr,       root, RW);
        // appgate: System now RUNS things (the Domain Manager, Software Center, VMs) rather than only
        // being browsed, so the device nodes they write must be writable here too ("/" above is RO).
        // The runtime denies above do not apply to the administration domain.
        nsBind(ns, "/etc/shadow\0".ptr,         root, RO);
        nsBind(ns, "/etc/wpa_supplicant\0".ptr, root, RO);
        nsBind(ns, "/etc/NetworkManager\0".ptr, root, RO);
        nsBind(ns, "/etc/ssh\0".ptr,            root, RO);
        nsBind(ns, "/etc/dropbear\0".ptr,       root, RO);
        nsBind(ns, "/etc/hypr\0".ptr,           root, RW);
    }

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
    // VIRT: the explicit /dev/kvm grant ("devon <domain> virt").  This is the ONLY
    // way a non-System task gets /dev/kvm: no default identity mask includes the bit.
    if (verbEq(n, "virt"))   return DEVCLASS_VIRT;
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
// Returns 0 on success or a negative errno (-13 EACCES = the domain may not run that program).
alias DomainSpawnFn = extern(C) long function(uint domObjId, const(char)* prog) @nogc nothrow;
private __gshared DomainSpawnFn g_domainSpawnHook = null;
public void domainSetSpawnHook(DomainSpawnFn fn) { g_domainSpawnHook = fn; }

// appgate: how many live tasks are bound to a domain (kernel_main owns the task table and core.task
// imports this module, so the count comes back through a hook).  A domain with running programs
// cannot be deleted: its objId would be reused LIFO and those tasks' next exec would stick them
// into whatever domain is created next.
alias DomainBusyFn = extern(C) uint function(uint domObjId) @nogc nothrow;
private __gshared DomainBusyFn g_domainBusyHook = null;
public void domainSetBusyHook(DomainBusyFn fn) { g_domainBusyHook = fn; }
// appgate: told when a domain is deleted, before its objId is released (rtfs tombstones its
// private files so a later domain that reuses the objId cannot read them).
alias DomainGoneFn = extern(C) void function(uint domObjId) @nogc nothrow;
private __gshared DomainGoneFn g_domainGoneHook = null;
public void domainSetGoneHook(DomainGoneFn fn) { g_domainGoneHook = fn; }

// appgate: the System domain's objId (0 if there is none).  System owns the Domain Manager and is the
// only domain that may run every program, so this is asked on every exec and every rtfs lookup by
// an unconfined task -- cached.  Safe to cache: System can be neither deleted nor renamed (below),
// so once resolved the objId stays valid.
private __gshared uint g_sysDomCache = 0;
public uint domainSystemId() {
    if (g_sysDomCache != 0 && domainById(g_sysDomCache) !is null) return g_sysDomCache;
    g_sysDomCache = domainByName("System\0".ptr);
    return g_sysDomCache;
}

// DM13: the same hook trick for the per-task native->linux ratchet.  core.task imports THIS
// module (domainBindTaskNs calls domainById), so we cannot import core.task back -- kernel_main
// imports both and registers the bridge.  `linux` != 0 requests the drop; the callee refuses
// linux -> native.
alias DomainModeFn = extern(C) bool function(int linuxMode) @nogc nothrow;
private __gshared DomainModeFn g_domainModeHook = null;
public void domainSetModeHook(DomainModeFn fn) { g_domainModeHook = fn; }

// "reboot|poweroff System": reboot/power off the machine.  The action lives in core.syscalls.posix
// (rebootNow), which this module cannot import (cycle), so kernel_main registers a bridge.  Gated
// by the System-only name check in domainControlWrite + the fsPerm-gated control write.
alias DomainRebootFn = extern(C) bool function(int poweroff) @nogc nothrow;
private __gshared DomainRebootFn g_domainRebootHook = null;
public void domainSetRebootHook(DomainRebootFn fn) { g_domainRebootHook = fn; }
public long domainSpawnInto(uint domObjId, const(char)* prog) {
    if (g_domainSpawnHook is null) { klog("[domain] spawn: no launcher registered\n"); return -22; }
    if (domObjId == 0 || prog is null || prog[0] == 0) return -22;
    auto d = domainById(domObjId);
    if (d is null) return -2;
    if (d.isTemplate) return -6;          // ENXIO: a template is a definition, nothing runs in it
    return g_domainSpawnHook(domObjId, prog);
}
// Kernel-context entry (boot proofs, internal callers): fully authorized.
public bool domainControlWrite(const(char)* cmd, size_t len) {
    return domainControlWriteFrom(0, null, true, cmd, len) == 0;
}

// appgate: who may issue a domain-control verb.
//
// The Domain Manager is THE interface that delegates applications and edits domain policy, and the
// System domain owns it -- so the verbs that change policy are accepted only from the Domain Manager
// image running in the System domain.  Keying on the image and not merely on "a System task" matters:
// other administration apps also run in System (Software Center, VMs, logs), and a parsing flaw in
// any of them must not turn into the power to delegate apps or delete domains.  Domain-0 callers
// (the compositor, the bar, the kernel's service launchers) are refused too: the compositor runs
// arbitrary Lua from its IPC socket and config, so "unconfined" is not the same as "authorized".
private enum : int { AUTH_ANY = 0, AUTH_POWER, AUTH_SPAWN, AUTH_DM }

private bool domIsDmImage(const(char)* img) {
    if (img is null) return false;
    immutable string dm = "wl-domain-manager";
    size_t i = 0;
    for (; i < dm.length; ++i) if (img[i] != dm[i]) return false;
    return img[i] == 0;
}

// Parse + authorize + execute one "verb name [arg]" command.
//   callerDom    the writing task's domain (0 = unconfined)
//   callerImage  the writing task's exec image (g_taskExecName), for the Domain Manager check
//   kernelCtx    true for in-kernel callers (boot proofs): always authorized
// Returns 0 on success, or a negative errno: -1 EPERM (not authorized), -2 ENOENT (unknown domain),
// -6 ENXIO (template), -13 EACCES (the target domain may not run that program), -16 EBUSY (programs
// still running in the domain), -22 EINVAL (malformed / failed).
public long domainControlWriteFrom(uint callerDom, const(char)* callerImage, bool kernelCtx,
                                   const(char)* cmd, size_t len) {
    if (cmd is null || len == 0) return -22;
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

    // ── authority ────────────────────────────────────────────────────────────────────────────
    const uint sys = domainSystemId();
    const bool selfName = verbEq(name.ptr, "self");
    int need;
    if      (verbEq(verb.ptr, "ping"))                              need = AUTH_ANY;
    else if (verbEq(verb.ptr, "mode") && selfName)                  need = AUTH_ANY;
    else if (verbEq(verb.ptr, "reboot") || verbEq(verb.ptr, "poweroff")) need = AUTH_POWER;
    else if (verbEq(verb.ptr, "spawn"))                             need = AUTH_SPAWN;
    else                                                            need = AUTH_DM;
    const bool isDm = kernelCtx || (callerDom != 0 && callerDom == sys && domIsDmImage(callerImage));
    // "spawn self <prog>" runs a program in the caller's OWN domain (e.g. the VM app starting its
    // hypervisor).  A domain can never spawn into another domain; only the Domain Manager can.
    const uint id = (selfName && need == AUTH_SPAWN) ? callerDom : domainByName(name.ptr);
    bool authorized;
    switch (need) {
        case AUTH_ANY:   authorized = true; break;
        case AUTH_POWER: authorized = kernelCtx || (callerDom != 0 && callerDom == sys); break;
        case AUTH_SPAWN: authorized = isDm || (callerDom != 0 && id == callerDom); break;
        default:         authorized = isDm; break;          // AUTH_DM
    }
    if (!authorized) {
        static __gshared uint g_authDenyN = 0;
        if (g_authDenyN < 24) {
            ++g_authDenyN;
            klog("[appgate] authority DENY '"); klog(verb.ptr); klog(" "); klog(name.ptr);
            klog("' from "); klog(callerImage !is null ? callerImage : "?".ptr);
            klog(" (domain "); klog_hex(callerDom); klog(")\n");
        }
        return -1;   // EPERM
    }

    long rc = 0;
    bool ok = false;
    if      (verbEq(verb.ptr, "ping"))     ok = true;                                      // path self-test, no side effect
    else if (verbEq(verb.ptr, "start"))    ok = (id != 0) && domainStart(id);
    else if (verbEq(verb.ptr, "stop"))     ok = (id != 0) && domainShutdown(id);
    else if (verbEq(verb.ptr, "pause"))    ok = (id != 0) && domainPause(id);
    else if (verbEq(verb.ptr, "resume"))   ok = (id != 0) && domainResume(id);
    else if (verbEq(verb.ptr, "snapshot")) ok = (id != 0) && (domainSnapshot(id) != 0);
    else if (verbEq(verb.ptr, "commit"))   ok = (id != 0) && (domainCommit(id)   != 0);
    else if (verbEq(verb.ptr, "clone")) {
        const uint nid = (id != 0 && arg[0] != 0) ? domainClone(id, arg.ptr) : 0;
        ok = nid != 0;
        if (ok) appGrantsCloneDomain(id, nid);         // a clone can run what its source could
    }
    // DM7: package manager verbs — "install <domain> <pkg>" / "uninstall <domain> <pkg>"
    else if (verbEq(verb.ptr, "install"))   ok = (name[0] != 0) && (arg[0] != 0) && (pkgInstallByName(name.ptr, arg.ptr) == 0);
    else if (verbEq(verb.ptr, "uninstall")) ok = (name[0] != 0) && (arg[0] != 0) && (pkgRemoveByName(name.ptr, arg.ptr) == 0);
    // Delegation — "port <domain> <app>" / "unport <domain> <app>": grant/revoke <domain> the right to
    // run its OWN isolated instance of <app> (confined into that domain).  System can always run
    // everything, so it is never a target; only delegable applications can be ported.
    else if (verbEq(verb.ptr, "port")) {
        auto td = domainById(id);
        if (id == 0)                                      rc = -2;
        else if (id == sys || td.isTemplate)              rc = -22;
        else if (arg[0] == 0 || !appRegIsDelegable(arg.ptr)) rc = -22;
        else ok = (appPortAdd(arg.ptr, name.ptr) == 0);
    }
    else if (verbEq(verb.ptr, "unport")) {
        if (id == 0) rc = -2;
        else ok = (arg[0] != 0) && (appPortRemove(arg.ptr, name.ptr) == 0);
    }
    // DM10.7: peripheral device toggles — "devon/devoff <domain> <gpu|audio|camera|mic|usb|input>"
    else if (verbEq(verb.ptr, "devon"))     ok = (id != 0) && domainSetDevice(id, domainDeviceClassByName(arg.ptr), true);
    else if (verbEq(verb.ptr, "devoff"))    ok = (id != 0) && domainSetDevice(id, domainDeviceClassByName(arg.ptr), false);
    // DM10.7: filesystem path access — "fsro/fsrw/fsdeny <domain> <path>" (real backing paths)
    else if (verbEq(verb.ptr, "fsro"))      ok = (id != 0) && domainFsBindAllow(id, arg.ptr, false);
    else if (verbEq(verb.ptr, "fsrw"))      ok = (id != 0) && domainFsBindAllow(id, arg.ptr, true);
    else if (verbEq(verb.ptr, "fsdeny"))    ok = (id != 0) && domainFsBindDeny(id, arg.ptr);
    else if (verbEq(verb.ptr, "delete")) {  // DM10.7: GUI Delete button (domainDelete forgets any persisted entry)
        if (id == 0)                                                   rc = -2;
        else if (id == sys)                                            rc = -1;    // System owns the DM
        else if (g_domainBusyHook !is null && g_domainBusyHook(id) != 0) rc = -16; // programs still running
        else ok = domainDelete(id);
    }
    // Power: "reboot System" / "poweroff System" — only the System domain may power the machine
    // (mirrors the DEVCLASS_POWER authority on the syscall path).  Never returns on success.
    else if (verbEq(verb.ptr, "reboot") || verbEq(verb.ptr, "poweroff"))
        ok = verbEq(name.ptr, "System") && (g_domainRebootHook !is null)
             && g_domainRebootHook(verbEq(verb.ptr, "poweroff") ? 1 : 0);
    // DM11: distro / package-manager / profile — "distro <domain> <busybox|nix|alpine|native>" etc.
    else if (verbEq(verb.ptr, "distro"))    ok = (id != 0) && domainSetDistro(id, distroByName(arg.ptr));
    else if (verbEq(verb.ptr, "pkgmgr"))    ok = (id != 0) && domainSetPkgMgr(id, pkgMgrByName(arg.ptr));
    else if (verbEq(verb.ptr, "profile"))   ok = (name[0] != 0) && (arg[0] != 0) && (pkgApplyProfile(name.ptr, arg.ptr) >= 1);
    else if (verbEq(verb.ptr, "export"))    ok = (id != 0) && (templatePublish(id) == 0);   // DM12: publish as a signed template
    // GUI toolbar: from-scratch Create + instantiate-from-template (Import)
    // DM3: "spawn <domain> <program>" — run a program confined to the domain.  This is the only
    // verb that produces a task actually carrying domainObjId, so it is what makes every other
    // policy verb (fsro/fsrw/fsdeny, devon/devoff) take effect on a live process.  appgate: the
    // program runs only if the domain may run it (EACCES otherwise).
    else if (verbEq(verb.ptr, "spawn")) {
        if (id == 0)          rc = -2;
        else if (arg[0] == 0) rc = -22;
        else { rc = domainSpawnInto(id, arg.ptr); ok = (rc == 0); }
    }
    // DM13: "mode self <native|linux>" ratchets the CALLING task (linux -> native is refused,
    // and the mode is inherited by every child).  "mode <domain> <native|linux>" sets what
    // future `spawn`s into that domain start as, which is the domain's distro axis:
    // DISTRO_NATIVE is the native personality, anything else is a Linux one.
    else if (verbEq(verb.ptr, "mode")) {
        const bool wantLinux = verbEq(arg.ptr, "linux");
        if (selfName)
            ok = (g_domainModeHook !is null) && g_domainModeHook(wantLinux ? 1 : 0);
        else
            ok = (id != 0) && domainSetDistro(id, wantLinux ? DISTRO_BUSYBOX : DISTRO_NATIVE);
    }
    else if (verbEq(verb.ptr, "create")) {
        const uint nid = (name[0] != 0) ? domainCreate(name.ptr, identityByName(arg.ptr), 0) : 0;
        ok = nid != 0;
        // Persist the new domain's definition so a domain created from the GUI survives reboot
        // (DM5 rehydrate).  Best-effort: if the store is unavailable it just stays session-only.
        if (ok) objstoreInstallDomain(name[0 .. domCstrLen(name.ptr)],
                                      arg[0 .. domCstrLen(arg.ptr)], "", PERSIST_EPHEMERAL);
        if (ok) appGrantsSeedDomain(nid);
    }
    else if (verbEq(verb.ptr, "fromtpl"))   { const uint tp = domainByName(arg.ptr);
                                              const uint nid = ((name[0] != 0) && (tp != 0))
                                                  ? domainCreate(name.ptr, domainById(tp).identityObjId, tp) : 0;
                                              ok = nid != 0;
                                              if (ok) appGrantsSeedDomain(nid); }
    else { klog("[domain] control: unknown verb '"); klog(verb.ptr); klog("'\n"); return -22; }
    if (ok) rc = 0;
    else if (rc == 0) rc = (id == 0 && name[0] != 0 && !selfName && need != AUTH_ANY
                            && !verbEq(verb.ptr, "create") && !verbEq(verb.ptr, "fromtpl")
                            && !verbEq(verb.ptr, "install") && !verbEq(verb.ptr, "uninstall")
                            && !verbEq(verb.ptr, "profile")) ? -2 : -22;
    klog("[domain] control: "); klog(verb.ptr); klog(" "); klog(name.ptr); klog(ok ? " -> OK\n" : " -> FAIL\n");
    return rc;
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
    // Power authority (reboot/poweroff): System only.  The Development check guards the safety
    // invariant that DEVCLASS_POWER was NOT folded into DEV_FULL/DEVCLASS_ALL.
    ok = ok &&  domainDeviceAllowed(domainByName("System\0".ptr),     DEVCLASS_POWER);   // System may power off
    ok = ok && !domainDeviceAllowed(domainByName("Untrusted\0".ptr),  DEVCLASS_POWER);   // untrusted may NOT
    ok = ok && !domainDeviceAllowed(domainByName("Development\0".ptr), DEVCLASS_POWER);   // DEV_FULL must NOT imply POWER
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
    // (2) an unbound path — deny-by-default (no "/" mount): the user's base home is not a domain's
    const uint t2 = nsResolveCheck(ns, "/home/user/.ssh/id_rsa\0".ptr, rest, rights, denied);
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
    // (6) appgate: the read-only runtime -- libraries readable, never writable
    const uint t6 = nsResolveCheck(ns, "/usr/lib/libc.so\0".ptr, rest, rights, denied);
    ok = ok && (t6 != 0) && ((rights & CAP_RIGHT_READ) != 0) && ((rights & CAP_RIGHT_WRITE) == 0) && !denied;
    // (7) ...but /etc's secrets stay closed
    const uint t7 = nsResolveCheck(ns, "/etc/shadow\0".ptr, rest, rights, denied);
    ok = ok && (t7 == 0) && denied;
    // (8) /dev/null is writable (shells redirect to it)
    const uint t8 = nsResolveCheck(ns, "/dev/null\0".ptr, rest, rights, denied);
    ok = ok && (t8 != 0) && ((rights & CAP_RIGHT_WRITE) != 0) && !denied;
    if (ok) klog("[domain] ns proof PASS: Development restricted view (home rw, /Shared ro, runtime ro, Private+/System+secrets+unbound denied)\n");
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
    // appgate: System's authority is keyed on its identity -- it cannot be renamed away (nor can
    // another domain take its name, which domainByName below already refuses while it exists).
    if (domObjId == domainSystemId()) return false;
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
    // appgate: the System domain owns the Domain Manager; deleting it (and re-creating a domain with
    // the same name) would hand its authority to whatever took the name.  Never allowed.
    if (domObjId == domainSystemId()) {
        klog("[appgate] refusing to delete the System domain\n");
        return false;
    }
    // appgate: forget what the domain was delegated, and tombstone its private files, before the
    // objId goes back to the allocator (objIds are reused LIFO).
    appGrantsScrubDomain(domObjId);
    if (g_domainGoneHook !is null) g_domainGoneHook(domObjId);
    // DM5: forget any persisted definition first, so a domain deleted at runtime does not reappear
    // on the next boot via domainRehydrateFromDisk.  No-op for a seed/manifest/clone domain that was
    // never persisted.  Done here (not just in the GUI verb) so every delete path stays consistent.
    if (d.nameLen > 0 && d.nameLen <= DOM_NAME_MAX) objstoreRemoveDomain(d.name[0 .. d.nameLen]);
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

// ── ROADMAP 4.0: the session domain ───────────────────────────────────────────────────────────
//
// Spawned applications must not inherit the KERNEL's identity.  Task 0 carries System, and having
// every desktop app run as System is the same category of wrong as the pid-hash border: a label
// that is present, plausible, and describes the wrong thing.  An app should carry the identity of
// the domain it lives under.
//
// Nothing designated which domain the desktop session is, so this states a rule rather than
// inventing a field: the SESSION DOMAIN is the first non-template, non-SYSTEM-trust domain in the
// registry.  Domains are created in declarative-config order (configboot.d), so the config author
// chooses it by ordering; templates are skipped because a template is a definition rather than
// something to run in.
//
// The system-trust exclusion is not a refinement, it is the whole point.  Measured: the first
// non-template domain is the System domain, whose identity is the SAME object task 0 carries
// (sessionDomain=0x45 sessionIdentity=0x31 task0Identity=0x31).  Selecting it produced applications
// labelled System -- exactly the outcome this change exists to prevent, arrived at by a longer
// route.  An application lives under a user-facing domain; the system domain is where the kernel
// lives.
//
// Returns 0 when no domain qualifies, and callers fall back to their existing behaviour: a system
// with no domains configured must still boot a desktop.
public DomainId domainSessionId() @nogc nothrow {
    import core.identity : identityById, TRUST_SYSTEM;
    foreach (ref e; g_domains) {
        if (!e.inUse || e.isTemplate) continue;
        if (e.identityObjId == 0) continue;              // a domain with no identity labels nothing
        auto idr = identityById(e.identityObjId);
        if (idr is null || idr.trust >= TRUST_SYSTEM) continue;   // the kernel's domain, not an app's
        return e.objId;
    }
    return 0;
}

// The session domain's identity, or 0.  Kept separate from domainBindTaskNs(), which also clones
// the domain's RESTRICTED namespace -- that confines the task, and confining the compositor and
// installer is a much larger change than labelling them correctly.  Identity first, confinement
// with the policy engine.
public uint domainSessionIdentity() @nogc nothrow {
    const DomainId d = domainSessionId();
    if (d == 0) return 0;
    auto rec = domainById(d);
    return (rec is null) ? 0 : rec.identityObjId;
}
