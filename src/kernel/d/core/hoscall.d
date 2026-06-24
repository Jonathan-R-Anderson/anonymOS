// ─────────────────────────────────────────────────────────────────────────────
// Native object-model syscall ABI  (SHELL_AND_COMMANDS_ROADMAP Track B0)
//
// Exposes the microkernel's OWN object / capability / namespace / identity /
// service tables to userspace — the substrate the native object shell (-sh / dash)
// uses for `obj ls`, `id ls`, `ns ls`, `svc ls`.  This is the distinctly-native
// surface busybox cannot provide.  Reached via a dedicated native syscall number
// (HOS_SYS_QUERY) outside the Linux-compat range, dispatched in kernel_main.d.
//
// This first cut is READ-ONLY enumeration (deny-by-default still applies to the
// mutating ops to come: cap/grant, ns/clone, id/freeze, svc/start — they will be
// gated on the identity-domain rights ceiling).  Each op formats a human-readable
// text listing into the caller's buffer and returns the byte count.
// ─────────────────────────────────────────────────────────────────────────────
module core.hoscall;

import core.objmgr   : ObjType, objCountType, g_objects, OBJ_MAX;
import core.identity : g_identities, identityCount, identityById, NetPolicy;
import core.cap      : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_CALL,
                       CAP_RIGHT_EXEC, CAP_RIGHT_ADMIN_ALL;
import core.namespace: g_namespaces;
import core.servicemgr : g_svcs;
import core.task     : g_tasks, MAX_TASKS;
import core.user     : userByObj, g_users;
import core.exports  : g_current_task_id;
import core.store    : g_gens, g_activeGen;
// Z4a.1: the native FS verbs reuse the kernel VFS behind native handles.  posix.d already
// imports hoscall.d; the reverse import is a function-only cycle, fine under -betterC
// (no module static-ctor init order).
import core.syscalls.posix : linux_sys_open, linux_sys_read, linux_sys_write,
                             linux_sys_close, linux_sys_lseek;

@nogc nothrow:

enum HOS_SYS_QUERY = 0x4000;   // native syscall number (rax)

enum : ulong {
    HOSQ_OBJECTS    = 1,   // object table: type -> live count
    HOSQ_IDENTITIES = 2,   // identity domains: name, trust, ceiling, state
    HOSQ_NAMESPACES = 3,   // namespaces in use
    HOSQ_SERVICES   = 4,   // services: name, state
    HOSQ_SYS        = 5,   // one-line system summary
    HOSQ_WHOAMI     = 6,   // "<user>@<namespace>" for the calling task (shell prompt)
    // Z4a.1 — native FS verbs (the first piece of the true native-ABI port).  Handle-based,
    // operate on raw bytes (not the text-formatting buffer the query ops use).
    HOSQ_OPEN       = 7,   // object_open(buf=path, arg=rights)          -> native handle
    HOSQ_READ       = 8,   // object_read(arg=handle, buf=dst, buflen=n) -> bytes
    HOSQ_WRITE      = 9,   // object_write(arg=handle, buf=src, buflen=n)-> bytes
    HOSQ_CLOSE      = 10,  // object_close(arg=handle)                   -> 0
    HOSQ_LSEEK      = 11,  // object_lseek(arg=handle, buf=off, buflen=whence) -> offset
}

// Z4a.1: per-task native object handles for the FS verbs.  A handle is an index into this
// table; the slot stores the backing Linux VFS fd + 1 (0 = free).  A native task reaches
// the filesystem ONLY through object_open/read/write/close — it never issues a Linux
// open(); the kernel reuses the VFS (namespace-gated path resolution, the F0–F5 object FS)
// behind the handle.  Distinct number space from Linux fds.
private enum NHANDLE = 64;
__gshared int[NHANDLE][MAX_TASKS] g_nativeFd;

private int hosFdOf(int tid, ulong handle) @nogc nothrow {
    if (tid < 0 || tid >= MAX_TASKS || handle >= NHANDLE) return -1;
    const int v = g_nativeFd[tid][cast(size_t)handle];
    return (v == 0) ? -1 : (v - 1);
}

// object_open: resolve `path` through the object FS and bind a native handle to it.
private long hosOpen(ulong pathPtr, ulong rights) @nogc nothrow {
    const int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return -9;   // EBADF
    if (pathPtr == 0) return -14;                  // EFAULT
    int slot = -1;
    foreach (i; 0 .. NHANDLE) if (g_nativeFd[tid][i] == 0) { slot = cast(int)i; break; }
    if (slot < 0) return -24;                      // EMFILE
    const bool wr = (rights & CAP_RIGHT_WRITE) != 0;
    const bool rd = (rights & CAP_RIGHT_READ)  != 0;
    const ulong flags = (wr && rd) ? 2UL : (wr ? 1UL : 0UL);   // O_RDWR / O_WRONLY / O_RDONLY
    const long fd = linux_sys_open(pathPtr, flags, 0);
    if (fd < 0) return fd;
    g_nativeFd[tid][slot] = cast(int)fd + 1;
    return slot;
}

private long hosRead(ulong handle, ulong buf, ulong len) @nogc nothrow {
    const int fd = hosFdOf(cast(int)g_current_task_id, handle);
    if (fd < 0) return -9;
    return linux_sys_read(cast(ulong)fd, buf, len);
}
private long hosWrite(ulong handle, ulong buf, ulong len) @nogc nothrow {
    const int fd = hosFdOf(cast(int)g_current_task_id, handle);
    if (fd < 0) return -9;
    return linux_sys_write(cast(ulong)fd, buf, len);
}
private long hosClose(ulong handle) @nogc nothrow {
    const int tid = cast(int)g_current_task_id;
    const int fd = hosFdOf(tid, handle);
    if (fd < 0) return -9;
    const long r = linux_sys_close(cast(ulong)fd);
    g_nativeFd[tid][cast(size_t)handle] = 0;
    return r;
}
private long hosLseek(ulong handle, ulong off, ulong whence) @nogc nothrow {
    const int fd = hosFdOf(cast(int)g_current_task_id, handle);
    if (fd < 0) return -9;
    return linux_sys_lseek(cast(ulong)fd, cast(long)off, whence);
}

// Z4a.1: drop a task's native handles (exec/exit).  The backing fds are closed by the
// normal fd-table teardown; this just frees the slots so a reused tid starts clean.
public void hosClearHandles(int tid) @nogc nothrow {
    if (tid < 0 || tid >= MAX_TASKS) return;
    foreach (i; 0 .. NHANDLE) g_nativeFd[tid][i] = 0;
}

private immutable string[ObjType.Count] g_objTypeNames = [
    "Invalid", "File", "Process", "Thread", "MemRegion", "Vmo", "Directory",
    "Device", "Driver", "NetIf", "Window", "User", "Service", "Namespace",
    "Capability", "Endpoint", "LinuxProcess", "LinuxVFS", "LinuxSyscall",
    "LinuxELFLoader", "LinuxDeviceAdapter", "Untyped", "Admin", "StoreObject",
    "Generation", "SecChannel", "SecSession", "SecCert", "SecDescriptor", "Identity",
];

// Minimal text builder over the user buffer (no allocation, bounds-checked).
private struct UB { char* p; size_t cap; size_t len; }
private void put(ref UB b, char c)        { if (b.len + 1 < b.cap) b.p[b.len++] = c; }
private void lit(ref UB b, string z)      { foreach (c; z) put(b, c); }
private void num(ref UB b, ulong v) {
    char[24] t = void; int i = 0;
    if (v == 0) t[i++] = '0';
    while (v) { t[i++] = cast(char)('0' + v % 10); v /= 10; }
    while (i > 0) put(b, t[--i]);
}
private void hex(ref UB b, ulong v) {
    lit(b, "0x");
    bool started = false;
    for (int sh = 60; sh >= 0; sh -= 4) {
        const uint nib = cast(uint)((v >> sh) & 0xF);
        if (nib != 0 || started || sh == 0) {
            started = true;
            put(b, cast(char)(nib < 10 ? ('0' + nib) : ('a' + nib - 10)));
        }
    }
}

// ── /objects live filesystem views (OBJECT_FILESYSTEM_ROADMAP F1) ─────────────
// Each /objects/<kind> lists its live objects (one file per object); cat'ing the
// object file renders its metadata.  The kinds map onto the kernel's own tables.
enum int OBJFS_NONE = 0, OBJFS_IDENTITIES = 1, OBJFS_SERVICES = 2,
         OBJFS_NAMESPACES = 3, OBJFS_USERS = 4;

private bool nameEq(const(char)* a, size_t alen, const(char)[] lit_) {
    if (alen != lit_.length) return false;
    foreach (i; 0 .. alen) if (a[i] != lit_[i]) return false;
    return true;
}

// "identities"/"services"/... -> kind id (0 = not an object kind).
public int objfsKindId(const(char)* name, size_t len) {
    if (nameEq(name, len, "identities")) return OBJFS_IDENTITIES;
    if (nameEq(name, len, "services"))   return OBJFS_SERVICES;
    if (nameEq(name, len, "namespaces")) return OBJFS_NAMESPACES;
    if (nameEq(name, len, "users"))      return OBJFS_USERS;
    return OBJFS_NONE;
}

// The Nth (0-based) live object name of `kind` -> nameBuf; returns its length, or -1
// when `logical` is past the end (used by getdents to enumerate /objects/<kind>).
public int objfsEnum(int kind, int logical, char* nameBuf, size_t cap) {
    int n = 0;
    switch (kind) {
        case OBJFS_IDENTITIES:
            foreach (ref e; g_identities) if (e.inUse) {
                if (n == logical) { size_t l = e.nameLen < cap ? e.nameLen : cap; foreach (i; 0 .. l) nameBuf[i] = e.name[i]; return cast(int)l; }
                ++n;
            }
            return -1;
        case OBJFS_SERVICES:
            foreach (ref e; g_svcs) if (e.inUse) {
                if (n == logical) { size_t l = e.nameLen < cap ? e.nameLen : cap; foreach (i; 0 .. l) nameBuf[i] = e.name[i]; return cast(int)l; }
                ++n;
            }
            return -1;
        case OBJFS_USERS:
            foreach (ref e; g_users) if (e.inUse) {
                if (n == logical) { size_t l = e.nameLen < cap ? e.nameLen : cap; foreach (i; 0 .. l) nameBuf[i] = e.name[i]; return cast(int)l; }
                ++n;
            }
            return -1;
        case OBJFS_NAMESPACES:
            foreach (ref ns; g_namespaces) if (ns.inUse) {
                if (n == logical) {
                    // name = its objId (no string name on a namespace)
                    UB b; b.p = nameBuf; b.cap = cap; b.len = 0; num(b, ns.objId);
                    return cast(int)b.len;
                }
                ++n;
            }
            return -1;
        default: return -1;
    }
}

// ── F5: capabilities + relationships as first-class FS fields ─────────────────
// Each object is a directory of fields: `meta` (F1 metadata), `capabilities` (the
// rights it holds, decoded), `relationships` (its graph edges — namespace/owner/…).
enum int OBJF_META = 1, OBJF_CAPS = 2, OBJF_RELS = 3;

private immutable string[19] g_capBitNames = [
    "read", "write", "close", "stat", "ioctl", "mmap", "dup", "pass", "retype", "call",
    "admin-mount", "admin-reboot", "admin-update", "admin-user", "admin-device",
    "admin-inspect", "exec", "admin-identity", "id-share",
];

// "meta"/"capabilities"/"relationships" -> field id (0 = not a field).
public int objfsFieldId(const(char)* name, size_t len) {
    if (nameEq(name, len, "meta"))          return OBJF_META;
    if (nameEq(name, len, "capabilities"))  return OBJF_CAPS;
    if (nameEq(name, len, "relationships")) return OBJF_RELS;
    return 0;
}

// Decode a rights bitmask into named rights, one per line.
private void capDecode(ref UB b, uint rights) {
    lit(b, "rights="); hex(b, rights); put(b, '\n');
    bool any = false;
    foreach (i, nm; g_capBitNames)
        if (rights & (1u << i)) { lit(b, "+ "); lit(b, nm); put(b, '\n'); any = true; }
    if (!any) lit(b, "(none)\n");
}

// Render an object's `capabilities` or `relationships` field. Returns len or -2.
public long objfsField(int kind, const(char)* objName, size_t objLen, int field,
                       char* buf, size_t buflen) {
    if (field == OBJF_META) return objfsRead(kind, objName, objLen, buf, buflen);
    UB b; b.p = buf; b.cap = buflen; b.len = 0;
    switch (kind) {
        case OBJFS_IDENTITIES:
            foreach (ref e; g_identities) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                if (field == OBJF_CAPS) {
                    lit(b, "# capability ceiling of identity "); foreach (i; 0 .. e.nameLen) put(b, e.name[i]); put(b, '\n');
                    capDecode(b, e.rightsCeiling);
                } else { // relationships
                    lit(b, "identity=");   foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                    lit(b, "\nnamespace="); num(b, e.nsTemplate);
                    lit(b, "\nobjRoot=");   num(b, e.objRootObjId);
                    lit(b, "\ntemplate=");  num(b, e.templateId);
                    lit(b, "\ntrust=");     num(b, e.trust);
                    lit(b, "\ndevices=");   hex(b, e.allowedDevices);
                    lit(b, "\npolicyEpoch="); num(b, e.policyEpoch);
                    put(b, '\n');
                }
                return cast(long)b.len;
            }
            return -2;
        case OBJFS_SERVICES:
            foreach (ref e; g_svcs) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                if (field == OBJF_CAPS) {
                    lit(b, "# authority held by service "); foreach (i; 0 .. e.nameLen) put(b, e.name[i]); put(b, '\n');
                    capDecode(b, e.rights);
                } else {
                    lit(b, "service=");  foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                    lit(b, "\nowner=");    num(b, e.ownerUserObjId);
                    lit(b, "\nendpoint="); num(b, e.endpointObjId);
                    lit(b, "\nversion=");  num(b, e.version_);
                    lit(b, "\ngeneration="); num(b, e.genObjId);
                    put(b, '\n');
                }
                return cast(long)b.len;
            }
            return -2;
        case OBJFS_USERS:
            foreach (ref e; g_users) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                if (field == OBJF_CAPS) {
                    lit(b, "# administrative authority of user "); foreach (i; 0 .. e.nameLen) put(b, e.name[i]); put(b, '\n');
                    capDecode(b, e.rights);
                } else {
                    lit(b, "user=");  foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                    lit(b, "\nuid="); num(b, e.uid);
                    lit(b, "\ngid="); num(b, e.gid);
                    put(b, '\n');
                }
                return cast(long)b.len;
            }
            return -2;
        case OBJFS_NAMESPACES:
            foreach (ref ns; g_namespaces) if (ns.inUse) {
                char[16] nb = void; UB t; t.p = nb.ptr; t.cap = 16; t.len = 0; num(t, ns.objId);
                if (nameEq(objName, objLen, nb[0 .. t.len])) {
                    if (field == OBJF_CAPS) { lit(b, "rights=0x0\n(namespaces hold no rights bitmask)\n"); }
                    else { lit(b, "namespace objId="); num(b, ns.objId); put(b, '\n'); }
                    return cast(long)b.len;
                }
            }
            return -2;
        default: return -2;
    }
}

// Render /objects/<kind>/<objName> metadata into buf; returns length or negative errno.
public long objfsRead(int kind, const(char)* objName, size_t objLen, char* buf, size_t buflen) {
    UB b; b.p = cast(char*)buf; b.cap = buflen; b.len = 0;
    switch (kind) {
        case OBJFS_IDENTITIES:
            foreach (ref e; g_identities) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                lit(b, "type=Identity\nname=");  foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                lit(b, "\nobjId=");   num(b, e.objId);
                lit(b, "\ntrust=");   num(b, e.trust);
                lit(b, "\nceiling="); hex(b, e.rightsCeiling);
                lit(b, "\nstate=");   lit(b, e.active ? "active" : "draft");
                lit(b, "\ndisposable="); lit(b, e.disposable ? "true" : "false");
                lit(b, "\nnamespace="); num(b, e.nsTemplate);
                lit(b, "\npolicyEpoch="); num(b, e.policyEpoch);
                put(b, '\n');
                return cast(long)b.len;
            }
            return -2; // ENOENT
        case OBJFS_SERVICES:
            foreach (ref e; g_svcs) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                lit(b, "type=Service\nname="); foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                lit(b, "\nobjId=");    num(b, e.objId);
                lit(b, "\nstate=");    lit(b, e.started ? "started" : "stopped");
                lit(b, "\nrights=");   hex(b, e.rights);
                lit(b, "\nendpoint="); num(b, e.endpointObjId);
                lit(b, "\nversion=");  num(b, e.version_);
                put(b, '\n');
                return cast(long)b.len;
            }
            return -2;
        case OBJFS_USERS:
            foreach (ref e; g_users) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                lit(b, "type=User\nname="); foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                lit(b, "\nobjId="); num(b, e.objId);
                lit(b, "\nuid=");   num(b, e.uid);
                lit(b, "\ngid=");   num(b, e.gid);
                lit(b, "\nrights="); hex(b, e.rights);
                put(b, '\n');
                return cast(long)b.len;
            }
            return -2;
        case OBJFS_NAMESPACES:
            foreach (ref ns; g_namespaces) if (ns.inUse) {
                char[16] nb = void; UB t; t.p = nb.ptr; t.cap = 16; t.len = 0; num(t, ns.objId);
                if (nameEq(objName, objLen, nb[0 .. t.len])) {
                    lit(b, "type=Namespace\nobjId="); num(b, ns.objId); put(b, '\n');
                    return cast(long)b.len;
                }
            }
            return -2;
        default: return -2;
    }
}

// ── /config declarative views (OBJECT_FILESYSTEM_ROADMAP F2) ──────────────────
// /config/<name>.json renders the live kernel tables as declarative JSON — the
// system's configuration as data generated from (and, later, applied back to) the
// object tables.  Read-only for now; the mutable ones become writable via the
// identity policyEpoch transaction path (F2 phase 2).  /etc becomes a view of this.
enum int CFG_NONE = 0, CFG_SYSTEM = 1, CFG_IDENTITIES = 2, CFG_USERS = 3, CFG_SERVICES = 4;

private immutable string[4] g_configFiles =
    ["system.json", "identities.json", "users.json", "services.json"];

// "<name>.json" -> config id (0 = not a config file).
public int configfsId(const(char)* name, size_t len) {
    foreach (i, f; g_configFiles) if (nameEq(name, len, f)) return cast(int)(i + 1);
    return CFG_NONE;
}

// Enumerate the config file names (for getdents over /config); -1 past the end.
public int configfsEnum(int logical, char* nameBuf, size_t cap) {
    if (logical < 0 || logical >= cast(int)g_configFiles.length) return -1;
    auto s = g_configFiles[logical];
    const size_t l = s.length < cap ? s.length : cap;
    foreach (i; 0 .. l) nameBuf[i] = s[i];
    return cast(int)l;
}

// JSON string literal (minimal escaping — kernel object names are controlled).
private void jstr(ref UB b, const(char)* s, size_t n) {
    put(b, '"');
    foreach (i; 0 .. n) { const char c = s[i]; if (c == '"' || c == '\\') put(b, '\\'); put(b, c); }
    put(b, '"');
}

// Render /config/<id>.json into buf; returns length or negative errno.
public long configfsRender(int id, char* buf, size_t buflen) {
    UB b; b.p = buf; b.cap = buflen; b.len = 0;
    switch (id) {
        case CFG_SYSTEM: {
            uint objTotal = 0;
            for (uint t = 1; t < ObjType.Count; ++t) objTotal += objCountType(cast(ObjType)t);
            uint nsCount = 0;  foreach (ref ns; g_namespaces) if (ns.inUse) ++nsCount;
            uint svcCount = 0; foreach (ref s; g_svcs)        if (s.inUse) ++svcCount;
            lit(b, "{\n  \"kernel\": \"EpinAnonymOS\",\n  \"model\": \"object-capability\",\n");
            lit(b, "  \"objects\": ");    num(b, objTotal);
            lit(b, ",\n  \"identities\": "); num(b, identityCount());
            lit(b, ",\n  \"namespaces\": "); num(b, nsCount);
            lit(b, ",\n  \"services\": ");   num(b, svcCount);
            lit(b, "\n}\n");
            return cast(long)b.len;
        }
        case CFG_IDENTITIES: {
            lit(b, "[\n"); bool first = true;
            foreach (ref e; g_identities) if (e.inUse) {
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"name\": ");        jstr(b, e.name.ptr, e.nameLen);
                lit(b, ", \"objId\": ");         num(b, e.objId);
                lit(b, ", \"trust\": ");         num(b, e.trust);
                lit(b, ", \"ceiling\": \"");     hex(b, e.rightsCeiling); put(b, '"');
                lit(b, ", \"state\": \"");       lit(b, e.active ? "active" : "draft"); put(b, '"');
                lit(b, ", \"disposable\": ");    lit(b, e.disposable ? "true" : "false");
                lit(b, ", \"namespace\": ");     num(b, e.nsTemplate);
                lit(b, ", \"policyEpoch\": ");   num(b, e.policyEpoch);
                lit(b, " }");
            }
            lit(b, "\n]\n");
            return cast(long)b.len;
        }
        case CFG_USERS: {
            lit(b, "[\n"); bool first = true;
            foreach (ref e; g_users) if (e.inUse) {
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"name\": ");    jstr(b, e.name.ptr, e.nameLen);
                lit(b, ", \"objId\": ");     num(b, e.objId);
                lit(b, ", \"uid\": ");       num(b, e.uid);
                lit(b, ", \"gid\": ");       num(b, e.gid);
                lit(b, ", \"rights\": \"");  hex(b, e.rights); put(b, '"');
                lit(b, " }");
            }
            lit(b, "\n]\n");
            return cast(long)b.len;
        }
        case CFG_SERVICES: {
            lit(b, "[\n"); bool first = true;
            foreach (ref e; g_svcs) if (e.inUse) {
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"name\": ");      jstr(b, e.name.ptr, e.nameLen);
                lit(b, ", \"objId\": ");       num(b, e.objId);
                lit(b, ", \"state\": \"");     lit(b, e.started ? "started" : "stopped"); put(b, '"');
                lit(b, ", \"rights\": \"");    hex(b, e.rights); put(b, '"');
                lit(b, ", \"endpoint\": ");    num(b, e.endpointObjId);
                lit(b, ", \"version\": ");     num(b, e.version_);
                lit(b, " }");
            }
            lit(b, "\n]\n");
            return cast(long)b.len;
        }
        default: return -2; // ENOENT
    }
}

// ── /system immutable base views (OBJECT_FILESYSTEM_ROADMAP F3) ───────────────
// Read-only view over the content-addressed Generation snapshots: /system/current
// is the active deployment, /system/generations lists every captured generation.
// Writes are denied (EROFS); an update lands as a new Generation (anti-rollback
// already enforced by the store layer).  Component bodies = the boot modules.

// Render the active generation's metadata (for /system/current/generation).
public long sysGenMeta(char* buf, size_t buflen) {
    UB b; b.p = buf; b.cap = buflen; b.len = 0;
    const uint active = g_activeGen;
    foreach (ref g; g_gens) if (g.inUse && g.objId == active) {
        lit(b, "type=Generation\nnumber="); num(b, g.number);
        lit(b, "\nobjId=");      num(b, g.objId);
        lit(b, "\nparent=");     num(b, g.parentObjId);
        lit(b, "\ncomponents="); num(b, g.count);
        lit(b, "\nstatus=active\nimmutable=true\n");
        return cast(long)b.len;
    }
    // Boot generation captured with no store entries yet (count 0) — still active.
    lit(b, "type=Generation\nnumber=0\nobjId="); num(b, active);
    lit(b, "\nstatus=active\nimmutable=true\n");
    return cast(long)b.len;
}

// List every live generation, the active one marked (for /system/generations).
public long sysGenList(char* buf, size_t buflen) {
    UB b; b.p = buf; b.cap = buflen; b.len = 0;
    foreach (ref g; g_gens) if (g.inUse) {
        lit(b, "gen");           num(b, g.number);
        lit(b, " objId=");       num(b, g.objId);
        lit(b, " parent=");      num(b, g.parentObjId);
        lit(b, " components=");  num(b, g.count);
        if (g.objId == g_activeGen) lit(b, " [active]");
        put(b, '\n');
    }
    if (b.len == 0) lit(b, "(no generations)\n");
    return cast(long)b.len;
}

// op = HOSQ_*, arg reserved, buf/buflen = caller's text buffer. Returns bytes
// written (>= 0) or a negative errno.
public long hosQuery(ulong op, ulong arg, ulong buf, ulong buflen) {
    // Z4a.1: native FS verbs — handle-based, raw bytes; dispatched before the read-only
    // text queries (which require a non-empty text buffer).
    switch (op) {
        case HOSQ_OPEN:  return hosOpen(buf, arg);            // buf=path, arg=rights
        case HOSQ_READ:  return hosRead(arg, buf, buflen);    // arg=handle, buf=dst, buflen=n
        case HOSQ_WRITE: return hosWrite(arg, buf, buflen);
        case HOSQ_CLOSE: return hosClose(arg);
        case HOSQ_LSEEK: return hosLseek(arg, buf, buflen);   // arg=handle, buf=off, buflen=whence
        default: break;
    }

    if (buf == 0 || buflen == 0) return -14; // EFAULT
    UB b; b.p = cast(char*)buf; b.cap = buflen; b.len = 0;

    switch (op) {
        case HOSQ_OBJECTS:
            for (uint t = 1; t < ObjType.Count; ++t) {
                const uint c = objCountType(cast(ObjType)t);
                if (c == 0) continue;
                lit(b, g_objTypeNames[t]);
                for (size_t k = g_objTypeNames[t].length; k < 20; ++k) put(b, ' ');
                num(b, c); put(b, '\n');
            }
            break;

        case HOSQ_IDENTITIES:
            foreach (ref e; g_identities) if (e.inUse) {
                foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                for (size_t k = e.nameLen; k < 12; ++k) put(b, ' ');
                lit(b, "trust=");   num(b, e.trust);
                lit(b, " ceiling="); hex(b, e.rightsCeiling);
                lit(b, e.active ? " [active]" : " [draft]");
                if (e.disposable) lit(b, " [disposable]");
                put(b, '\n');
            }
            break;

        case HOSQ_NAMESPACES:
            foreach (ref ns; g_namespaces) if (ns.inUse) {
                lit(b, "namespace objId="); num(b, ns.objId); put(b, '\n');
            }
            break;

        case HOSQ_SERVICES:
            foreach (ref e; g_svcs) if (e.inUse) {
                foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                for (size_t k = e.nameLen; k < 20; ++k) put(b, ' ');
                lit(b, e.started ? "[started]" : "[stopped]");
                put(b, '\n');
            }
            break;

        case HOSQ_SYS: {
            uint objTotal = 0;
            for (uint t = 1; t < ObjType.Count; ++t) objTotal += objCountType(cast(ObjType)t);
            uint nsCount = 0; foreach (ref ns; g_namespaces) if (ns.inUse) ++nsCount;
            uint svcCount = 0; foreach (ref s; g_svcs) if (s.inUse) ++svcCount;
            lit(b, "EpinAnonymOS object kernel\n");
            lit(b, "objects     "); num(b, objTotal);    put(b, '\n');
            lit(b, "identities  "); num(b, identityCount()); put(b, '\n');
            lit(b, "namespaces  "); num(b, nsCount);      put(b, '\n');
            lit(b, "services    "); num(b, svcCount);     put(b, '\n');
            break;
        }

        case HOSQ_WHOAMI: {
            // "<user>@<namespace>" — the calling task's User name and identity-domain
            // (namespace) name, for the native shell's prompt.
            const int tid = cast(int)g_current_task_id;
            auto u = (tid >= 0 && tid < MAX_TASKS) ? userByObj(g_tasks[tid].userObjId) : null;
            if (u !is null && u.nameLen > 0) foreach (i; 0 .. u.nameLen) put(b, u.name[i]);
            else lit(b, "user");
            put(b, '@');
            auto e = (tid >= 0 && tid < MAX_TASKS) ? identityById(g_tasks[tid].identityObjId) : null;
            if (e !is null && e.nameLen > 0) foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
            else lit(b, "system");
            // Prompt permissions: a compact capability-flag summary derived from the
            // calling task's identity (rights ceiling + net policy + brokered devices),
            // so the native prompt shows user@namespace [perms]:/path.
            if (e !is null) {
                lit(b, " [");
                bool first = true;
                void flag(string s) { if (!first) put(b, ' '); first = false; lit(b, s); }
                if (e.rightsCeiling & CAP_RIGHT_WRITE)     flag("fs:rw");
                else if (e.rightsCeiling & CAP_RIGHT_READ) flag("fs:ro");
                final switch (e.net) {
                    case NetPolicy.None:       break;
                    case NetPolicy.NAT:        flag("net:nat");   break;
                    case NetPolicy.VPN:        flag("net:vpn");   break;
                    case NetPolicy.Tor:        flag("net:tor");   break;
                    case NetPolicy.LocalOnly:  flag("net:local"); break;
                    case NetPolicy.Disposable: flag("net:disp");  break;
                }
                if (e.rightsCeiling & CAP_RIGHT_CALL)      flag("ipc");
                if (e.allowedDevices != 0)                 flag("dev");
                if (e.rightsCeiling & CAP_RIGHT_EXEC)      flag("exec");
                if (e.rightsCeiling & CAP_RIGHT_ADMIN_ALL) flag("admin");
                put(b, ']');
            }
            break;
        }

        default:
            return -22; // EINVAL
    }
    return cast(long)b.len;
}
