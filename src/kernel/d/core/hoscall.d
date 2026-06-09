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
import core.identity : g_identities, identityCount, identityById;
import core.namespace: g_namespaces;
import core.servicemgr : g_svcs;
import core.task     : g_tasks, MAX_TASKS;
import core.user     : userByObj;
import core.exports  : g_current_task_id;

@nogc nothrow:

enum HOS_SYS_QUERY = 0x4000;   // native syscall number (rax)

enum : ulong {
    HOSQ_OBJECTS    = 1,   // object table: type -> live count
    HOSQ_IDENTITIES = 2,   // identity domains: name, trust, ceiling, state
    HOSQ_NAMESPACES = 3,   // namespaces in use
    HOSQ_SERVICES   = 4,   // services: name, state
    HOSQ_SYS        = 5,   // one-line system summary
    HOSQ_WHOAMI     = 6,   // "<user>@<namespace>" for the calling task (shell prompt)
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

// op = HOSQ_*, arg reserved, buf/buflen = caller's text buffer. Returns bytes
// written (>= 0) or a negative errno.
public long hosQuery(ulong op, ulong arg, ulong buf, ulong buflen) {
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
            break;
        }

        default:
            return -22; // EINVAL
    }
    return cast(long)b.len;
}
