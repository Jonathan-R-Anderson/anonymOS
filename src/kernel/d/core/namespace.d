// Namespace objects — Phase 9 of roadmap/OBJECT_OS_ROADMAP.md.
//
// Gives every process a first-class **Namespace** object: a map of mount-point
// name → object (a Directory/Device/... reached, eventually, via a capability).
// A process sees exactly the objects bound into its namespace (the Plan 9 model).
// The global rtfs root (`g_rt` in posix.d) stops being "the filesystem" and
// becomes *a* mountable **Directory** object that each namespace binds at "/".
//
// In the additive spirit of the earlier phases this establishes per-process
// namespace *identity*, fork-time *cloning*, and routes `sys_open` resolution
// through the calling task's namespace root — while the existing rtfs/synthetic
// resolution in posix.d remains the backing implementation of the "/" mount.
// Divergent per-process mounts (unshare/mount/bind of additional objects) and
// binding the `/dev` Device tree as separate mounts are the natural next step;
// the binding table and resolver needed for them exist now.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.namespace;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;

extern (C) @nogc nothrow:

enum int NS_MAX       = 64;   // live Namespace objects
enum int NS_BIND_MAX  = 16;   // mount bindings per namespace
enum int NS_PATH_MAX  = 64;   // mount-point path length

struct NsBinding {
    bool   inUse;
    uint   targetObjId;       // object this mount point resolves to
    uint   rights;            // capability rights granted at this mount
    uint   pathLen;
    char[NS_PATH_MAX] path;   // mount point, e.g. "/" or "/dev"
}

struct NamespaceRec {
    bool                    inUse;
    uint                    objId;   // ObjType.Namespace
    NsBinding[NS_BIND_MAX]  binds;
}

__gshared NamespaceRec[NS_MAX] g_namespaces;

// The rtfs root, now a first-class Directory object that namespaces mount at "/".
// `g_rt` (posix.d) is its backing store; this is its object identity.
__gshared uint g_rootDirObjId = 0;

__gshared ulong g_nsAllocTotal   = 0;
__gshared ulong g_nsCloneTotal   = 0;
__gshared ulong g_nsReleaseTotal = 0;
__gshared uint  g_nsLive         = 0;
__gshared ulong g_nsBindTotal    = 0;
__gshared ulong g_nsResolveTotal = 0;
__gshared ulong g_nsRootResolve  = 0;   // resolutions that hit the "/" mount
__gshared bool  g_nsSelfTested   = false;

// --- string helpers (no libc) -------------------------------------------------
private uint nsStrLen(const(char)* s) {
    if (s is null) return 0;
    uint n = 0;
    while (s[n] != 0 && n < NS_PATH_MAX) ++n;
    return n;
}

// Ensure the rtfs root Directory object exists; return its id.
public uint nsRootDir() {
    if (g_rootDirObjId == 0 || objGet(g_rootDirObjId) is null)
        g_rootDirObjId = objAlloc(ObjType.Directory, null); // impl = rtfs root (g_rt[0])
    return g_rootDirObjId;
}

private NamespaceRec* nsRecByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref ns; g_namespaces)
        if (ns.inUse && ns.objId == objId) return &ns;
    return null;
}

private void bindRoot(ref NamespaceRec ns) {
    ns.binds[0] = NsBinding.init;
    ns.binds[0].inUse = true;
    ns.binds[0].targetObjId = nsRootDir();
    ns.binds[0].rights = uint.max;
    ns.binds[0].pathLen = 1;
    ns.binds[0].path[0] = '/';
    ++g_nsBindTotal;
}

// Create a fresh namespace with just the "/" → rtfs-root binding.
public uint nsAlloc() {
    foreach (ref ns; g_namespaces) {
        if (ns.inUse) continue;
        uint id = objAlloc(ObjType.Namespace, cast(void*)&ns);
        if (id == 0) return 0;
        ns = NamespaceRec.init;
        ns.inUse = true;
        ns.objId = id;
        bindRoot(ns);
        ++g_nsAllocTotal;
        ++g_nsLive;
        return id;
    }
    return 0;
}

// Clone an existing namespace's bindings into a new one (fork semantics: the
// child can later rebind without affecting the parent).  A missing/invalid
// source yields a fresh root-only namespace.
public uint nsClone(uint srcObjId) {
    auto src = nsRecByObj(srcObjId);
    if (src is null) return nsAlloc();
    foreach (ref ns; g_namespaces) {
        if (ns.inUse) continue;
        uint id = objAlloc(ObjType.Namespace, cast(void*)&ns);
        if (id == 0) return 0;
        ns = *src;            // copy all bindings by value
        ns.inUse = true;
        ns.objId = id;
        ++g_nsCloneTotal;
        ++g_nsLive;
        return id;
    }
    return 0;
}

public void nsRelease(uint objId) {
    auto ns = nsRecByObj(objId);
    if (ns is null) return;
    objRelease(ns.objId);
    *ns = NamespaceRec.init;
    ++g_nsReleaseTotal;
    if (g_nsLive > 0) --g_nsLive;
}

// Bind (mount) an object at a mount-point path; replaces an existing binding for
// the same path.  Returns false if the table is full or args are bad.
public bool nsBind(uint nsObjId, const(char)* path, uint targetObjId, uint rights) {
    auto ns = nsRecByObj(nsObjId);
    uint len = nsStrLen(path);
    if (ns is null || len == 0 || len > NS_PATH_MAX || targetObjId == 0) return false;
    NsBinding* free = null;
    foreach (ref b; ns.binds) {
        if (b.inUse && b.pathLen == len) {
            bool same = true;
            foreach (i; 0 .. len) if (b.path[i] != path[i]) { same = false; break; }
            if (same) { free = &b; break; }
        }
        if (!b.inUse && free is null) free = &b;
    }
    if (free is null) return false;
    free.inUse = true;
    free.targetObjId = targetObjId;
    free.rights = rights;
    free.pathLen = len;
    foreach (i; 0 .. len) free.path[i] = path[i];
    ++g_nsBindTotal;
    return true;
}

// Does mount-point `b` prefix `path` on a component boundary?
private bool bindMatches(ref const(NsBinding) b, const(char)* path, uint plen) {
    if (b.pathLen > plen) return false;
    foreach (i; 0 .. b.pathLen) if (b.path[i] != path[i]) return false;
    if (b.pathLen == 1 && b.path[0] == '/') return true;        // root matches all
    return plen == b.pathLen || path[b.pathLen] == '/';          // boundary
}

// Resolve `path` to the object of its longest-matching mount.  `outRest` receives
// the path suffix relative to that mount (kept absolute for the "/" mount so the
// existing rtfs/synthetic resolver in posix.d can consume it unchanged).  Returns
// 0 if the namespace is unknown or nothing matches.
public uint nsResolve(uint nsObjId, const(char)* path, out const(char)* outRest) {
    outRest = path;
    auto ns = nsRecByObj(nsObjId);
    if (ns is null || path is null || path[0] != '/') return 0;
    ++g_nsResolveTotal;
    uint plen = nsStrLen(path);
    NsBinding* best = null;
    foreach (ref b; ns.binds) {
        if (!b.inUse) continue;
        if (!bindMatches(b, path, plen)) continue;
        if (best is null || b.pathLen > best.pathLen) best = &b;
    }
    if (best is null) return 0;
    if (best.pathLen == 1) {                 // "/" mount: keep the whole path
        outRest = path;
        ++g_nsRootResolve;
    } else {
        outRest = path + best.pathLen;       // suffix begins at the mount boundary
        if (outRest[0] == 0) { /* mount root itself */ }
    }
    return best.targetObjId;
}

// The object bound at "/" in this namespace (its root Directory).
public uint nsRoot(uint nsObjId) {
    auto ns = nsRecByObj(nsObjId);
    if (ns is null) return 0;
    foreach (ref b; ns.binds)
        if (b.inUse && b.pathLen == 1 && b.path[0] == '/') return b.targetObjId;
    return 0;
}

// --- Boot self-test (Phase 9 runtime proof) -----------------------------------
// Confirms a namespace allocates with a "/" → rtfs-root binding, a clone is a
// distinct live object sharing that root, a rebind in the clone does not change
// the parent, and resolution routes a path to the root Directory.
public void nsSelfTest() {
    if (g_nsSelfTested) return;
    g_nsSelfTested = true;

    uint a = nsAlloc();
    if (a == 0) { klog("[ns] selftest FAIL: alloc\n"); return; }
    uint root = nsRoot(a);

    uint b = nsClone(a);
    const(char)* rest;
    uint r = nsResolve(a, "/run/user/0\0".ptr, rest);

    bool ok = (root != 0 && b != 0 && b != a &&
               objGet(a) !is null && objGet(b) !is null &&
               nsRoot(b) == root &&         // clone shares the same root object
               r == root && rest !is null && rest[0] == '/');

    // A rebind in the clone must not leak into the parent.
    uint fakeDir = nsRootDir();
    nsBind(b, "/dev\0".ptr, fakeDir, uint.max);
    const(char)* rest2;
    ok = ok && (nsResolve(b, "/dev/x\0".ptr, rest2) == fakeDir);
    ok = ok && (nsResolve(a, "/dev/x\0".ptr, rest2) == root); // parent still root

    if (ok) klog("[ns] selftest PASS\n");
    else    klog("[ns] selftest FAIL: behaviour\n");

    nsRelease(a);
    nsRelease(b);
}

public void nsStats() {
    klog("[ns] live=");     klog_hex(cast(ulong)g_nsLive);
    klog(" alloc=");        klog_hex(g_nsAllocTotal);
    klog(" clone=");        klog_hex(g_nsCloneTotal);
    klog(" freed=");        klog_hex(g_nsReleaseTotal);
    klog(" nsobj=");        klog_hex(cast(ulong)objCountType(ObjType.Namespace));
    klog(" bind=");         klog_hex(g_nsBindTotal);
    klog(" resolve=");      klog_hex(g_nsResolveTotal);
    klog(" rootres=");      klog_hex(g_nsRootResolve);
    klog("\n");
}
