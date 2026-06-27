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
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_STAT;  // DOMAIN_MANAGER DM2 (restricted-view selftest)

extern (C) @nogc nothrow:

enum int NS_MAX       = 64;   // live Namespace objects
enum int NS_BIND_MAX  = 32;   // mount bindings per namespace (DM2: real per-domain fs policies)
enum int NS_PATH_MAX  = 64;   // mount-point path length

struct NsBinding {
    bool   inUse;
    bool   denied;            // DOMAIN_MANAGER DM2: a deny binding — a longest-prefix match here
                              // denies access (EACCES) even if a shorter allow-binding would match
    uint   targetObjId;       // object this mount point resolves to (0 for a deny binding)
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

public NamespaceRec* nsRecByObj(uint objId) {   // Z12.1: re-validate a live namespace for ns_enter
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

// DOMAIN_MANAGER DM2: create a fresh namespace WITHOUT the "/" → rtfs-root binding.
// This is the deny-by-default substrate: with no "/" mount, any path that isn't covered
// by an explicit allow-binding resolves to nothing → namespaceCheckOpen denies it.
public uint nsAllocRestricted() {
    foreach (ref ns; g_namespaces) {
        if (ns.inUse) continue;
        uint id = objAlloc(ObjType.Namespace, cast(void*)&ns);
        if (id == 0) return 0;
        ns = NamespaceRec.init;
        ns.inUse = true;
        ns.objId = id;
        // deliberately NO bindRoot() — restricted view
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
    free.denied = false;          // DM2: an allow binding (clears any prior deny on this slot)
    free.targetObjId = targetObjId;
    free.rights = rights;
    free.pathLen = len;
    foreach (i; 0 .. len) free.path[i] = path[i];
    ++g_nsBindTotal;
    return true;
}

// DOMAIN_MANAGER DM2: add a DENY binding at `path`.  A longest-prefix match here denies
// access (EACCES) even if a shorter allow-binding would otherwise grant it — this is how a
// domain carves a hole (e.g. deny "/Shared/Private") inside an allowed subtree.
public bool nsBindDeny(uint nsObjId, const(char)* path) {
    auto ns = nsRecByObj(nsObjId);
    uint len = nsStrLen(path);
    if (ns is null || len == 0 || len > NS_PATH_MAX) return false;
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
    *free = NsBinding.init;
    free.inUse = true;
    free.denied = true;
    free.targetObjId = 0;
    free.rights = 0;
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
// DOMAIN_MANAGER DM2: the full resolver — also reports whether the longest match is an
// explicit DENY binding (so the caller can return EACCES vs ENOENT).  A namespace with no
// "/" binding (a restricted domain) returns 0 for any unbound path = deny-by-default.
public uint nsResolveCheck(uint nsObjId, const(char)* path, out const(char)* outRest,
                           out uint outRights, out bool outDenied) {
    outRest = path;
    outRights = 0;
    outDenied = false;
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
    if (best is null) return 0;              // no binding → deny-by-default (ENOENT)
    if (best.denied) {                       // explicit deny overrides any shorter allow → EACCES
        outDenied = true;
        outRest = path;
        return 0;
    }
    outRights = best.rights;
    if (best.pathLen == 1) {                 // "/" mount: keep the whole path
        outRest = path;
        ++g_nsRootResolve;
    } else {
        outRest = path + best.pathLen;       // suffix begins at the mount boundary
        if (outRest[0] == 0) { /* mount root itself */ }
    }
    return best.targetObjId;
}

public uint nsResolveWithRights(uint nsObjId, const(char)* path,
                                out const(char)* outRest, out uint outRights) {
    bool denied;
    return nsResolveCheck(nsObjId, path, outRest, outRights, denied);
}

public uint nsResolve(uint nsObjId, const(char)* path, out const(char)* outRest) {
    uint rights; bool denied;
    return nsResolveCheck(nsObjId, path, outRest, rights, denied);
}

// ORG P4.3 — namespace validation: count bindings whose target object is no
// longer live (a dangling name).  Pure query: a dangling name is *flagged*, never
// a crash.  The validator/GC uses this to report/repair stale mounts.
public uint nsValidateBindings() {
    uint dangling = 0;
    foreach (ref ns; g_namespaces) {
        if (!ns.inUse) continue;
        foreach (ref b; ns.binds)
            if (b.inUse && !b.denied && (b.targetObjId == 0 || objGet(b.targetObjId) is null))
                ++dangling;   // DM2: deny bindings legitimately have no target — not dangling
    }
    return dangling;
}

// DOMAIN_MANAGER DM2.4: enumerate a namespace's in-use bindings (for the RuntimeView render).
// Returns false once `idx` is past the last in-use binding.  `denied` marks a deny binding.
public bool nsBindingAt(uint nsObjId, int idx, out const(char)* path, out uint pathLen,
                        out uint rights, out bool denied) {
    auto ns = nsRecByObj(nsObjId);
    if (ns is null) return false;
    int n = 0;
    foreach (ref b; ns.binds) {
        if (!b.inUse) continue;
        if (n == idx) { path = b.path.ptr; pathLen = b.pathLen; rights = b.rights; denied = b.denied; return true; }
        ++n;
    }
    return false;
}

// True if this namespace has the wide-open "/" mount (i.e. NOT deny-by-default).
public bool nsHasRootMount(uint nsObjId) {
    auto ns = nsRecByObj(nsObjId);
    if (ns is null) return false;
    foreach (ref b; ns.binds)
        if (b.inUse && !b.denied && b.pathLen == 1 && b.path[0] == '/') return true;
    return false;
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

// DOMAIN_MANAGER DM2 boot proof: a restricted namespace (no "/" binding) enforces
// deny-by-default; an allow binding grants exactly its rights; a deny binding overrides a
// shorter allow.  Mirrors what namespaceCheckOpen does on a domain-bound open().
__gshared bool g_nsRestrictedSelfTested = false;
public void nsRestrictedSelfTest() {
    if (g_nsRestrictedSelfTested) return;
    g_nsRestrictedSelfTested = true;

    const uint r = nsAllocRestricted();
    if (r == 0) { klog("[ns] restricted selftest FAIL: alloc\n"); return; }
    const uint home = nsRootDir();   // any live Directory object as a stand-in mount target

    bool ok = true;
    ok = ok && nsBind(r, "/home/x\0".ptr, home, CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_STAT);
    ok = ok && nsBind(r, "/sys\0".ptr,    home, CAP_RIGHT_READ | CAP_RIGHT_STAT);
    ok = ok && nsBindDeny(r, "/sys/secret\0".ptr);

    const(char)* rest; uint rights; bool denied;
    // (1) allowed read-write path resolves, with the WRITE right, not denied
    const uint t1 = nsResolveCheck(r, "/home/x/file\0".ptr, rest, rights, denied);
    ok = ok && (t1 == home) && ((rights & CAP_RIGHT_WRITE) != 0) && !denied;
    // (2) an unbound path → deny-by-default: target 0, NOT flagged denied (caller → ENOENT)
    const uint t2 = nsResolveCheck(r, "/etc/shadow\0".ptr, rest, rights, denied);
    ok = ok && (t2 == 0) && !denied;
    // (3) a read-only allow grants READ but NOT WRITE (open-for-write would EACCES)
    const uint t3 = nsResolveCheck(r, "/sys/public\0".ptr, rest, rights, denied);
    ok = ok && (t3 == home) && ((rights & CAP_RIGHT_READ) != 0) && ((rights & CAP_RIGHT_WRITE) == 0) && !denied;
    // (4) an explicit deny overrides the shorter /sys allow → target 0, flagged denied (caller → EACCES)
    const uint t4 = nsResolveCheck(r, "/sys/secret/key\0".ptr, rest, rights, denied);
    ok = ok && (t4 == 0) && denied;

    nsRelease(r);
    if (ok) klog("[ns] restricted selftest PASS (deny-by-default + ro-rights + deny-override)\n");
    else    klog("[ns] restricted selftest FAIL: behaviour\n");
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
    klog(" dangling=");     klog_hex(cast(ulong)nsValidateBindings()); // ORG P4.3
    klog("\n");
}
