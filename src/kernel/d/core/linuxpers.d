// Linux compatibility as capability objects — IMMUTABLE_ROOTLESS_ROADMAP §7.
//
// The §12 LinuxObject subtree (`core/linuxobj.d`) already demoted the Linux
// personality to a gated object subtree.  This phase makes the personality
// *resolve through objects and capabilities* rather than an ambient global tree:
//
//   §7.1 personality → object/cap ops — a Linux path op resolves through the
//        calling app's Namespace + the binding's rights (not a global `/`); the
//        op→right table records what authority each Linux syscall family needs
//        (open→READ/WRITE, mmap→MMAP, socket→CALL) so the translation is explicit.
//   §7.2 per-app ephemeral root + private volume (Qubes AppVM) — each Linux app
//        gets its OWN namespace whose "/" is a fresh *ephemeral* Directory (writes
//        are disposable) plus a persistent private volume at "/private"; it cannot
//        see or mutate the real system root, and `/usr` stays read-only.
//   §7.3 capability-gated /proc · /sys · /dev — these synthetic trees are NOT bound
//        by default; an app reaches them only after being granted a binding with
//        the matching rights (a cap), so device/proc access is no longer ambient.
//
// This is the personality wiring on top of the native namespace/store/cap layers;
// the existing posix.d syscall bodies remain the implementation the translator
// delegates to.  Constraints mirror the rest of the kernel: -betterC, plain
// structs, __gshared fixed tables, @nogc nothrow.
module core.linuxpers;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.namespace : nsClone, nsBind, nsResolveWithRights, nsRoot, nsRelease;
import core.store : storeMountSystem;
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_MMAP, CAP_RIGHT_CALL;
import core.linuxobj : linuxNoteTranslate, linuxNoteBlocked;

extern (C) @nogc nothrow:

enum int LXAPP_MAX = 32;

// §7.1 — the Linux syscall families whose authority we make explicit.  Each maps to
// the capability right the native object layer already gates on, so a Linux op is
// "translate name → namespace target, then require this right".
enum LinuxOp : uint {
    OpenRead  = 0,   // open(O_RDONLY)/stat/access — needs READ on the resolved object
    OpenWrite = 1,   // open(O_WRONLY|O_RDWR)/unlink — needs WRITE
    Mmap      = 2,   // mmap(PROT_*) — needs MMAP (and untyped budget, §1.4)
    Socket    = 3,   // socket/connect — needs CALL on an endpoint (§2.3)
}

public uint linuxOpRight(LinuxOp op) {
    final switch (op) {
        case LinuxOp.OpenRead:  return CAP_RIGHT_READ;
        case LinuxOp.OpenWrite: return CAP_RIGHT_WRITE;
        case LinuxOp.Mmap:      return CAP_RIGHT_MMAP;
        case LinuxOp.Socket:    return CAP_RIGHT_CALL;
    }
}

struct LinuxApp {
    bool inUse;
    uint nsObjId;    // the app's private Namespace (the sandbox handle)
    uint ephObjId;   // ephemeral root Directory ("/" — disposable)
    uint privObjId;  // persistent private volume ("/private")
    uint nameHash;   // cheap label for stats/lookup
}

__gshared LinuxApp[LXAPP_MAX] g_lxApps;

__gshared ulong g_lxAppCreated  = 0;
__gshared ulong g_lxAppDestroyed = 0;
__gshared ulong g_lxResolveOk   = 0;   // path ops resolved through a namespace
__gshared ulong g_lxResolveDeny = 0;   // ops denied (no binding / right)
__gshared ulong g_lxSyntheticGrant = 0;// /proc·/sys·/dev bindings handed out
__gshared bool  g_lxPersSelfTested = false;

private LinuxApp* appByNs(uint nsObjId) {
    if (nsObjId == 0) return null;
    foreach (ref a; g_lxApps)
        if (a.inUse && a.nsObjId == nsObjId) return &a;
    return null;
}

private uint nameHashOf(const(char)* s) {
    uint h = 0x811c9dc5;
    if (s !is null) for (uint i = 0; s[i] != 0 && i < 64; ++i) { h ^= s[i]; h *= 0x01000193; }
    return h;
}

// --- §7.2 per-app ephemeral root + private volume -----------------------------
// Create a sandboxed Linux app: its own namespace cloned from the system view, but
// with "/" rebound to a fresh ephemeral Directory (so writes to the root are
// disposable and never reach the real system tree) and a persistent private volume
// at "/private".  Returns the app's namespace objId (its handle), or 0 on failure.
public uint linuxAppCreate(const(char)* name) {
    uint sysNs = storeMountSystem();
    if (sysNs == 0) return 0;
    foreach (ref a; g_lxApps) {
        if (a.inUse) continue;
        uint ns = nsClone(sysNs);                 // inherits /usr(ro) /etc /var
        if (ns == 0) return 0;
        uint eph  = objAlloc(ObjType.Directory, null);
        uint priv = objAlloc(ObjType.Directory, null);
        if (eph == 0 || priv == 0) { nsRelease(ns); return 0; }
        // Replace the inherited "/" → real-root binding with an ephemeral root, so
        // the app cannot see or mutate the real system root.  Bind the private vol.
        nsBind(ns, "/\0".ptr,        eph,  CAP_RIGHT_READ | CAP_RIGHT_WRITE);
        nsBind(ns, "/private\0".ptr, priv, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
        a = LinuxApp.init;
        a.inUse = true;
        a.nsObjId = ns;
        a.ephObjId = eph;
        a.privObjId = priv;
        a.nameHash = nameHashOf(name);
        ++g_lxAppCreated;
        return ns;
    }
    return 0;
}

public uint linuxAppEphemeralRoot(uint appNs) { auto a = appByNs(appNs); return a is null ? 0 : a.ephObjId; }
public uint linuxAppPrivateVol(uint appNs)    { auto a = appByNs(appNs); return a is null ? 0 : a.privObjId; }

public void linuxAppDestroy(uint appNs) {
    auto a = appByNs(appNs);
    if (a is null) return;
    if (a.ephObjId)  objRelease(a.ephObjId);
    if (a.privObjId) objRelease(a.privObjId);
    nsRelease(a.nsObjId);
    *a = LinuxApp.init;
    ++g_lxAppDestroyed;
}

// --- §7.1 personality op → namespace/cap resolution ---------------------------
// Resolve a Linux path op for an app through its namespace, requiring the op's
// capability right on the matching mount binding.  Returns the target object id, or
// 0 if no binding covers the path or it lacks the required right (a denied op).
public uint linuxTranslatePath(uint appNs, LinuxOp op, const(char)* path) {
    const(char)* rest;
    uint rights;
    uint target = nsResolveWithRights(appNs, path, rest, rights);
    uint need = linuxOpRight(op);
    if (target == 0 || (rights & need) != need) {
        ++g_lxResolveDeny;
        linuxNoteBlocked();
        return 0;
    }
    ++g_lxResolveOk;
    linuxNoteTranslate();
    return target;
}

// True iff a Linux write op to `path` is permitted in the app's namespace (the
// op→cap translation for the immutability boundary: writes to read-only mounts
// like /usr are refused without a global uid-0 escape).
public bool linuxAppCanWrite(uint appNs, const(char)* path) {
    return linuxTranslatePath(appNs, LinuxOp.OpenWrite, path) != 0;
}

// --- §7.3 capability-gated /proc · /sys · /dev --------------------------------
// Bind a synthetic tree into the app's namespace with explicit rights — the "cap"
// that makes /dev or /proc reachable at all.  Without this an app cannot resolve
// the path (the trees are not ambient).
public bool linuxAppGrantSynthetic(uint appNs, const(char)* mountPath, uint rights) {
    auto a = appByNs(appNs);
    if (a is null) return false;
    uint node = objAlloc(ObjType.Directory, null);
    if (node == 0) return false;
    if (!nsBind(appNs, mountPath, node, rights)) { objRelease(node); return false; }
    ++g_lxSyntheticGrant;
    return true;
}

// True iff the app may access `path` with `wantRights` (e.g. read /proc, write /dev).
public bool linuxAppSyntheticAccess(uint appNs, const(char)* path, uint wantRights) {
    const(char)* rest;
    uint rights;
    uint target = nsResolveWithRights(appNs, path, rest, rights);
    return target != 0 && (rights & wantRights) == wantRights;
}

// --- proof --------------------------------------------------------------------
private bool selfTestSandbox(uint app1, uint app2) {   // §7.2
    if (app1 == 0 || app2 == 0 || app1 == app2) return false;
    uint eph1 = linuxAppEphemeralRoot(app1);
    uint eph2 = linuxAppEphemeralRoot(app2);
    uint pv1  = linuxAppPrivateVol(app1);
    // Distinct apps get distinct ephemeral roots and private volumes.
    bool distinct = (eph1 != 0 && eph2 != 0 && eph1 != eph2 && pv1 != 0 && pv1 != eph1);
    // The app's "/" resolves to its ephemeral root, NOT the shared real system root.
    const(char)* rest; uint rights;
    uint rootTarget = nsResolveWithRights(app1, "/\0".ptr, rest, rights);
    bool ephemeralRoot = (rootTarget == eph1);
    // The private volume is writable; the inherited /usr is NOT (immutable system).
    bool privWritable = linuxAppCanWrite(app1, "/private/data\0".ptr);
    bool usrReadOnly  = !linuxAppCanWrite(app1, "/usr/lib/x\0".ptr);
    return distinct && ephemeralRoot && privWritable && usrReadOnly;
}

private bool selfTestTranslate(uint app) {             // §7.1
    // open(O_RDONLY) on /usr resolves (READ granted); a write op on /usr is denied
    // — the immutable-system boundary holds even though "/" is a writable mount.
    bool readOk  = (linuxTranslatePath(app, LinuxOp.OpenRead,  "/usr/lib/x\0".ptr) != 0);
    bool writeNo = (linuxTranslatePath(app, LinuxOp.OpenWrite, "/usr/lib/x\0".ptr) == 0);
    // A write outside the system mounts lands in the disposable ephemeral root.
    uint eph = linuxAppEphemeralRoot(app);
    bool ephWrite = (linuxTranslatePath(app, LinuxOp.OpenWrite, "/tmp/scratch\0".ptr) == eph);
    // The op→right table is explicit and distinct per family.
    bool table = (linuxOpRight(LinuxOp.OpenRead)  == CAP_RIGHT_READ  &&
                  linuxOpRight(LinuxOp.OpenWrite) == CAP_RIGHT_WRITE &&
                  linuxOpRight(LinuxOp.Mmap)      == CAP_RIGHT_MMAP  &&
                  linuxOpRight(LinuxOp.Socket)    == CAP_RIGHT_CALL);
    return readOk && writeNo && ephWrite && table;
}

private bool selfTestSynthetic(uint app) {             // §7.3
    uint eph = linuxAppEphemeralRoot(app);
    const(char)* rest; uint rights;
    // By default there is no real /dev or /proc in the app's namespace: the paths
    // fall through to the disposable ephemeral root, never a real device/proc node.
    uint devBefore  = nsResolveWithRights(app, "/dev/null\0".ptr,  rest, rights);
    uint procBefore = nsResolveWithRights(app, "/proc/self\0".ptr, rest, rights);
    bool notAmbient = (devBefore == eph && procBefore == eph);
    // Granting /dev with READ (the cap) makes it resolve to a dedicated node, with
    // READ allowed but WRITE still denied.
    bool granted = linuxAppGrantSynthetic(app, "/dev\0".ptr, CAP_RIGHT_READ);
    uint devAfter = nsResolveWithRights(app, "/dev/null\0".ptr, rest, rights);
    bool devReal      = (devAfter != 0 && devAfter != eph);
    bool devReadOk    = ((rights & CAP_RIGHT_READ)  == CAP_RIGHT_READ);
    bool devWriteDeny = ((rights & CAP_RIGHT_WRITE) == 0);
    return notAmbient && granted && devReal && devReadOk && devWriteDeny;
}

public void linuxPersSelfTest() {
    if (g_lxPersSelfTested) return;
    g_lxPersSelfTested = true;

    uint app1 = linuxAppCreate("p7-app1\0".ptr);
    uint app2 = linuxAppCreate("p7-app2\0".ptr);

    bool box = selfTestSandbox(app1, app2);
    bool tr  = selfTestTranslate(app1);
    bool syn = selfTestSynthetic(app1);

    // The sandbox is disposable — tearing it down releases its namespace + volumes.
    linuxAppDestroy(app1);
    linuxAppDestroy(app2);
    bool torn = (appByNs(app1) is null && appByNs(app2) is null);

    if (box && tr && syn && torn) {
        klog("[lxpers] selftest PASS\n");
    } else {
        klog("[lxpers] selftest FAIL:");
        if (!box) klog(" sandbox");
        if (!tr)  klog(" translate");
        if (!syn) klog(" synthetic");
        if (!torn) klog(" teardown");
        klog("\n");
    }
}

private uint lxAppLive() {
    uint n = 0;
    foreach (ref a; g_lxApps) if (a.inUse) ++n;
    return n;
}

public void linuxPersStats() {
    klog("[lxpers] apps=");  klog_hex(cast(ulong)lxAppLive());
    klog(" created=");       klog_hex(g_lxAppCreated);
    klog(" destroyed=");     klog_hex(g_lxAppDestroyed);
    klog(" resolveok=");     klog_hex(g_lxResolveOk);
    klog(" resolvedeny=");   klog_hex(g_lxResolveDeny);
    klog(" synthgrant=");    klog_hex(g_lxSyntheticGrant);
    klog("\n");
}
