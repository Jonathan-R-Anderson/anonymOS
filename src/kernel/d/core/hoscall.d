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
import core.identity : g_identities, identityCount, identityById, identityByName, IdentityId, NetPolicy;  // +L4.2
import core.domain   : g_domains, DomainState, domainStateName, domainCount,
                       PERSIST_EPHEMERAL, PERSIST_HOME_ONLY, PERSIST_FULL;  // DOMAIN_MANAGER DM0
import core.pkgrepo  : pkgRepoCount, pkgRepoAt, pkgInstalledMask;          // DOMAIN_MANAGER DM7
import core.domain   : domainDeviceMask;                                  // DOMAIN_MANAGER DM10.7
import core.domain   : domainDistro, domainPkgMgr, distroName, pkgMgrName; // DOMAIN_MANAGER DM11
import core.template_bundle : templateCount, templateAt;                  // DOMAIN_MANAGER DM12
import core.cap      : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_CALL,
                       CAP_RIGHT_EXEC, CAP_RIGHT_ADMIN_ALL,
                       Capability, capGet, capUsable, capInstall, CAP_INVALID, CAP_MAX; // Z4c.3
import core.namespace: g_namespaces, nsClone, nsRecByObj,
                       nsBindingAt, nsHasRootMount;          // Z4c.3 / Z12.1 + DOMAIN_MANAGER DM2.4
import core.io       : klog, klog_hex, klog_dec;  // Z4b.3/Z4c.3 verb tracing
import core.servicemgr : g_svcs;
import core.task     : g_tasks, MAX_TASKS;
import core.user     : userByObj, g_users;
import core.exports  : g_current_task_id;
import core.store    : g_gens, g_activeGen;
import core.audit    : auditLog, AuditKind, auditCount;   // SHELL_AND_COMMANDS B5
// Z4a.1: the native FS verbs reuse the kernel VFS behind native handles.  posix.d already
// imports hoscall.d; the reverse import is a function-only cycle, fine under -betterC
// (no module static-ctor init order).
import core.syscalls.posix : linux_sys_open, linux_sys_read, linux_sys_write,
                             linux_sys_close, linux_sys_lseek, linux_sys_fstat;

@nogc nothrow:

extern(C) bool installConfigPresent();

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
    HOSQ_FSTAT      = 12,  // object_fstat(arg=handle, buf=struct stat*)      -> 0
    // Z4a.6 — Device (the controlling terminal as a §12 Device object).  Same VFS reuse as
    // the file verbs, but a distinct surface: native zsh's terminal I/O goes through these.
    HOSQ_DEV_READ   = 13,  // device_read(arg=fd, buf, buflen)  -> bytes
    HOSQ_DEV_WRITE  = 14,  // device_write(arg=fd, buf, buflen) -> bytes
    // Z4a.7 — Process (§4).  spawn_process loads an image into the (forked) caller — the
    // native-ABI counterpart of execve; handled in kernel_main.d (it re-enters userspace).
    HOSQ_SPAWN      = 15,  // spawn_process(rsi=path, rdx=argv, r10=envp) -> (re-enter) / -errno
    // Z4b.1 — Process-exit event wait (§6 object_wait specialised to child-exit = SIGCHLD).
    // Over wait4Task + the cooperative wait-block; handled in kernel_main.d (it can yield).
    HOSQ_WAIT       = 16,  // object_wait(rsi=pid, rdx=statusbuf, r10=options) -> pid / 0 / -errno
    // Z4b.3 — §6 event subscription (formalizes the already-working SIGCHLD/SIGINT delivery).
    HOSQ_SUBSCRIBE  = 17,  // object_subscribe(arg=events) -> 0
    // Z4b.4 — §8 channel message-passing (the explicit send/recv over a channel fd).
    HOSQ_SEND       = 18,  // object_send(arg=chan_fd, buf=src, buflen=n) -> bytes
    HOSQ_RECV       = 19,  // object_recv(arg=chan_fd, buf=dst, buflen=n) -> bytes
    // Z4c.3 — §7/§11 mutations: capability grant (attenuation-only) + namespace clone/enter.
    HOSQ_CAP_GRANT  = 20,  // cap_grant(arg=srcHandle, buf=wantRights) -> newHandle / -errno
    HOSQ_NS_CLONE   = 21,  // namespace_clone() -> nsObjId / -errno
    HOSQ_NS_ENTER   = 22,  // namespace_enter(arg=nsObjId) -> 0 / -errno (owned namespaces only)
    // L4.2 — identity_switch(buf=name): de-escalation-only (target trust <= current) + cap attenuation.
    HOSQ_ID_SWITCH  = 23,  // identity_switch(buf=name) -> 0 / -errno

    // BARE_METAL L3 (roadmap 5.1) — PCI config space for a userspace LKL.
    //
    // LKL's PCI backend contract (struct lkl_dev_pci_ops) needs four things from the host, and
    // .read/.write on CONFIG space are the first two.  The kernel has pciConfigRead32 already;
    // what was missing was any way for userspace to reach it, so a userspace LKL could not
    // enumerate or program a device at all.
    //
    // ADMIN-GATED.  Raw PCI config access is device-level authority: it can reprogram BARs, turn
    // bus mastering on, or move a device's interrupt line.  It requires CAP_RIGHT_ADMIN_DEVICE,
    // which PID1 deliberately does NOT hold (adminInstallInitCaps gives it mount/reboot/inspect/
    // identity only), so this is reachable solely by a task explicitly granted it.
    HOSQ_PCI_CFG_RD = 24,  // pci_config_read(arg=BDF|off<<32) -> value / -errno
    HOSQ_PCI_CFG_WR = 25,  // pci_config_write(arg=BDF|off<<32, buf=value) -> 0 / -errno

    // BARE_METAL L3, capabilities 2 and 3.  LKL's PCI backend needs BAR access and a DMA address.
    //
    // .resource_alloc calls LKL's register_iomem(), and the LKL kernel then routes every BAR MMIO
    // read/write back through the backend -- so the backend only has to FORWARD each access.  That
    // is what these two verbs are: no mmap of the BAR is required, which is the key simplifier the
    // roadmap identified when it scoped L3.
    //
    // .map_page needs a physical address for a buffer LKL allocated.  With no IOMMU the IOVA is
    // the physical address, so a virt->phys of the caller's own page is the whole operation.
    HOSQ_MMIO_RD    = 26,  // mmio_read(arg=phys, buf=width 1/2/4/8) -> value / -errno
    HOSQ_MMIO_WR    = 27,  // mmio_write(arg=phys, buf=value, buflen=width) -> 0 / -errno
    HOSQ_VIRT2PHYS  = 28,  // virt_to_phys(arg=vaddr) -> phys / -errno  (caller's own space)
}


// BARE_METAL L3: pack/unpack the (bus,slot,func,offset) selector carried in `arg`.
//   bits 0..7 bus | 8..12 slot | 13..15 func | 32..39 offset
private void pciUnpack(ulong a, out ubyte bus, out ubyte slot, out ubyte func, out ubyte off) {
    bus  = cast(ubyte)(a & 0xFF);
    slot = cast(ubyte)((a >> 8) & 0x1F);
    func = cast(ubyte)((a >> 13) & 0x07);
    off  = cast(ubyte)((a >> 32) & 0xFF);
}


// SHELL_AND_COMMANDS B5 — one audit record per privileged native verb.
//
// `detail` carries the verb in the high 32 bits and the result in the low 32, so a single ring
// entry says WHICH operation and WHAT happened without needing a second kind per verb.  The
// return value is passed straight through, so wrapping a call can never change its behaviour --
// only whether it was recorded.
private long hosAuditPriv(uint verb, uint subj, long r) {
    const ulong detail = (cast(ulong)verb << 32) | (cast(uint)cast(int)r);
    auditLog(r >= 0 ? AuditKind.NativeVerbOk : AuditKind.NativeVerbDeny, subj, detail);
    return r;
}

// Z4b.3 / Z4c.3 per-task state for the native mutation verbs.

__gshared uint[MAX_TASKS] g_taskSubscriptions;   // §6 subscribed-event bitmask
__gshared uint[MAX_TASKS] g_taskOwnedNs;         // last namespace this task cloned (ns_enter gate)

// Z4a.5: native FS verbs.  object_open resolves the path through the object FS (the F0–F5
// tree, namespace-gated) and returns a handle that, for a VFS-backed file, IS the backing
// fd.  Making the handle a real fd is what lets a native shell actually run: every other fd
// operation it does (dup/fcntl/mmap/fstat/…) keeps working through the normal path, and zsh
// doesn't blow up its fd-indexed tables on a huge handle number.  (A future *pure* object
// filesystem — files that are not VFS-backed — would instead hand back an opaque handle and
// route every byte through object_read/write.)  The data verbs take that handle = fd.
private long hosOpen(ulong pathPtr, ulong rights) @nogc nothrow {
    if (pathPtr == 0) return -14;                  // EFAULT
    const bool wr = (rights & CAP_RIGHT_WRITE) != 0;
    const bool rd = (rights & CAP_RIGHT_READ)  != 0;
    const ulong flags = (wr && rd) ? 2UL : (wr ? 1UL : 0UL);   // O_RDWR / O_WRONLY / O_RDONLY
    return linux_sys_open(pathPtr, flags, 0);      // the real backing fd is the native handle
}
private long hosRead (ulong h, ulong buf, ulong len)    @nogc nothrow { return linux_sys_read (h, buf, len); }
private long hosWrite(ulong h, ulong buf, ulong len)    @nogc nothrow { return linux_sys_write(h, buf, len); }
private long hosClose(ulong h)                          @nogc nothrow { return linux_sys_close(h); }
private long hosLseek(ulong h, ulong off, ulong whence) @nogc nothrow { return linux_sys_lseek(h, cast(long)off, whence); }
private long hosFstat(ulong h, ulong statbuf)           @nogc nothrow { return linux_sys_fstat(h, statbuf); }

// Z4b.3 — §6 native event subscription.  SIGCHLD (child-exit) + SIGINT (^C) already deliver to
// native tasks (rt_sigframe / EINTR at a blocking device_read); this records the explicit native
// subscription so the surface is the native ABI's, not just an implicit Linux signal.  Per-task
// bitmask — a formalization of already-functional delivery, not a gate on it.
private long hosSubscribe(ulong events) @nogc nothrow {
    const int tid = cast(int)g_current_task_id;
    if (tid >= 0 && tid < MAX_TASKS) g_taskSubscriptions[tid] |= cast(uint)events;
    static uint sn;
    if ((sn++ & 0x3F) == 0) {
        klog("[obj-subscribe tid="); klog_hex(cast(ulong)tid);
        klog(" events="); klog_hex(events); klog("]\n");
    }
    return 0;
}

// Z4c.3 — §7 capability grant, ATTENUATION-ONLY.  Derive a NEW handle in the caller's cap table
// from one it already holds, with rights that can only SHRINK: newRights = want ∩ source.rights ∩
// identity-ceiling.  Cannot escalate by construction; deny-by-default (nothing left ⇒ EPERM).
private long hosCapGrant(ulong srcHandle, ulong wantRights) @nogc nothrow {
    auto src = capGet(cast(uint)srcHandle);
    if (!capUsable(src)) return -1;                       // -EPERM: no such usable source cap
    const int tid = cast(int)g_current_task_id;
    auto e = (tid >= 0 && tid < MAX_TASKS) ? identityById(g_tasks[tid].identityObjId) : null;
    // Z12.1 hardening: a missing/invalid identity record fails CLOSED (ceiling 0 ⇒ deny), never
    // open — never fall back to src.rights, which would silently drop the rights-ceiling clamp.
    const uint ceiling   = (e !is null) ? e.rightsCeiling : 0;
    const uint newRights = cast(uint)wantRights & src.rights & ceiling;
    if (newRights == 0) return -1;                        // attenuation left nothing → deny
    uint h = CAP_INVALID;                                 // a free slot in the caller's active table
    for (uint i = 1; i < CAP_MAX; ++i) {
        auto c = capGet(i);
        if (c !is null && c.objId == 0) { h = i; break; }
    }
    if (h == CAP_INVALID) return -24;                     // -EMFILE: table full
    if (capInstall(h, src.objId, newRights, cast(uint)srcHandle) == CAP_INVALID) return -1;
    klog("[cap-grant tid="); klog_hex(cast(ulong)tid);
    klog(" src="); klog_hex(srcHandle); klog(" -> h="); klog_hex(cast(ulong)h);
    klog(" rights="); klog_hex(cast(ulong)newRights); klog("]\n");
    return cast(long)h;
}

// Z4c.3 — §11/§4 namespace_clone: a private copy of the caller's namespace (fork semantics).  The
// caller owns the clone and may later enter it; recorded per-task so namespace_enter can only
// re-enter a namespace the caller itself created (never another domain's).
private long hosNsClone() @nogc nothrow {
    const int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return -1;
    const uint cur = g_tasks[tid].namespaceObjId;
    const uint nid = nsClone(cur);
    if (nid == 0) return -1;
    g_taskOwnedNs[tid] = nid;                             // gate for hosNsEnter
    klog("[ns-clone tid="); klog_hex(cast(ulong)tid);
    klog(" src="); klog_hex(cast(ulong)cur); klog(" -> "); klog_hex(cast(ulong)nid); klog("]\n");
    return cast(long)nid;
}

// Z4c.3 — namespace_enter: switch the caller to a namespace it OWNS (created via namespace_clone).
// Deny-by-default — entering an arbitrary/other-domain namespace would breach isolation.
private long hosNsEnter(ulong nsObjId) @nogc nothrow {
    const int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return -1;
    // -EPERM unless this is the namespace the caller itself cloned (g_taskOwnedNs) AND it is
    // still a LIVE namespace object — Z12.1 hardening: object ids are recycled without a
    // generation tag, so re-validate the id still resolves to a namespace (fail closed if the
    // slot was released + reused for a non-namespace object) before committing the switch.
    if (nsObjId == 0 || cast(uint)nsObjId != g_taskOwnedNs[tid] ||
        nsRecByObj(cast(uint)nsObjId) is null) return -1;
    g_tasks[tid].namespaceObjId = cast(uint)nsObjId;
    klog("[ns-enter tid="); klog_hex(cast(ulong)tid); klog(" ns="); klog_hex(nsObjId); klog("]\n");
    return 0;
}

// L4.2 — identity_switch(name): relabel the calling task's identity domain.  DE-ESCALATION ONLY —
// the target identity's trust must be <= the caller's current trust (you may drop privilege, never
// gain it; an unknown name is denied).  On success the task's rights-ceiling drops to the target's,
// and its capabilities are attenuated to that ceiling so no existing cap retains a right the new
// identity forbids.  Like every native verb this is already behind the native-personality gate.
private long hosIdSwitch(ulong namePtr) @nogc nothrow {
    if (namePtr == 0) return -14;                              // -EFAULT
    const int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return -1;
    auto cur = identityById(g_tasks[tid].identityObjId);
    if (cur is null) return -1;                                // -EPERM: no current identity
    const IdentityId target = identityByName(cast(const(char)*)namePtr);
    if (target == 0) return -2;                                // -ENOENT: no such identity
    auto te = identityById(target);
    if (te is null) return -2;
    if (te.trust > cur.trust) return -1;                       // -EPERM: never escalate trust
    g_tasks[tid].identityObjId = target;                       // relabel
    const uint newCeiling = te.rightsCeiling;
    for (uint h = 1; h < CAP_MAX; ++h) { auto c = capGet(h); if (c !is null && c.objId != 0) c.rights &= newCeiling; }
    klog("[id-switch tid="); klog_hex(cast(ulong)tid); klog(" -> objId="); klog_hex(cast(ulong)target);
    klog(" trust="); klog_hex(cast(ulong)te.trust); klog(" ceiling="); klog_hex(cast(ulong)newCeiling); klog("]\n");
    return 0;
}

private immutable string[ObjType.Count] g_objTypeNames = [
    "Invalid", "File", "Process", "Thread", "MemRegion", "Vmo", "Directory",
    "Device", "Driver", "NetIf", "Window", "User", "Service", "Namespace",
    "Capability", "Endpoint", "LinuxProcess", "LinuxVFS", "LinuxSyscall",
    "LinuxELFLoader", "LinuxDeviceAdapter", "Untyped", "Admin", "StoreObject",
    "Generation", "SecChannel", "SecSession", "SecCert", "SecDescriptor", "Identity",
    "Domain", "Template", "Overlay", "Snapshot",
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
         OBJFS_NAMESPACES = 3, OBJFS_USERS = 4, OBJFS_DOMAINS = 5;  // DOMAIN_MANAGER DM0

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
    if (nameEq(name, len, "domains"))    return OBJFS_DOMAINS;   // DOMAIN_MANAGER DM0
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
        case OBJFS_DOMAINS:   // DOMAIN_MANAGER DM0
            foreach (ref e; g_domains) if (e.inUse) {
                if (n == logical) { size_t l = e.nameLen < cap ? e.nameLen : cap; foreach (i; 0 .. l) nameBuf[i] = e.name[i]; return cast(int)l; }
                ++n;
            }
            return -1;
        default: return -1;
    }
}

// ── F5: capabilities + relationships as first-class FS fields ─────────────────
// Each object is a directory of fields: `meta` (F1 metadata), `capabilities` (the
// rights it holds, decoded), `relationships` (its graph edges — namespace/owner/…).
enum int OBJF_META = 1, OBJF_CAPS = 2, OBJF_RELS = 3, OBJF_FS = 4;  // OBJF_FS: DOMAIN_MANAGER DM2.4 RuntimeView

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
    if (nameEq(name, len, "filesystem"))    return OBJF_FS;   // DOMAIN_MANAGER DM2.4
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
        case OBJFS_DOMAINS:   // DOMAIN_MANAGER DM0
            foreach (ref e; g_domains) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                if (field == OBJF_CAPS) {
                    // a domain's authority ceiling is inherited from its identity
                    lit(b, "# capability ceiling of domain "); foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                    auto idr = identityById(e.identityObjId);
                    if (idr !is null) {
                        lit(b, " (inherited from identity "); foreach (i; 0 .. idr.nameLen) put(b, idr.name[i]); lit(b, ")\n");
                        capDecode(b, idr.rightsCeiling);
                    } else { lit(b, " (no identity)\n"); capDecode(b, 0); }
                } else if (field == OBJF_FS) {   // DM2.4: the resolved RESTRICTED filesystem view (RuntimeView)
                    lit(b, "# restricted filesystem view of domain "); foreach (i; 0 .. e.nameLen) put(b, e.name[i]); put(b, '\n');
                    if (e.nsObjId == 0) {
                        lit(b, "namespace=none (no restricted view built yet)\n");
                    } else {
                        lit(b, "namespace=");     num(b, e.nsObjId);
                        lit(b, "\ndefaultPolicy="); lit(b, nsHasRootMount(e.nsObjId) ? "allow (\"/\" mounted)" : "deny");
                        lit(b, "\n# mode  path  (resolved bindings; longest-prefix wins, deny overrides)\n");
                        int idx = 0;
                        const(char)* p; uint pl; uint rr; bool dn;
                        while (nsBindingAt(e.nsObjId, idx, p, pl, rr, dn)) {
                            if (dn)                          lit(b, "deny  ");
                            else if (rr & CAP_RIGHT_WRITE)   lit(b, "rw    ");
                            else                             lit(b, "ro    ");
                            foreach (i; 0 .. pl) put(b, p[i]);
                            put(b, '\n');
                            ++idx;
                        }
                    }
                } else { // relationships — the domain's object-graph edges
                    lit(b, "domain=");      foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                    lit(b, "\nidentity=");  num(b, e.identityObjId);
                    lit(b, "\ntemplate=");  num(b, e.templateObjId);
                    lit(b, "\nnamespace="); num(b, e.nsObjId);
                    lit(b, "\noverlay=");   num(b, e.overlayObjId);
                    lit(b, "\nstate=");     litz(b, domainStateName(e.state));
                    put(b, '\n');
                }
                return cast(long)b.len;
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
        case OBJFS_DOMAINS:   // DOMAIN_MANAGER DM0
            foreach (ref e; g_domains) if (e.inUse && nameEq(objName, objLen, e.name[0 .. e.nameLen])) {
                lit(b, "type=Domain\nname=");  foreach (i; 0 .. e.nameLen) put(b, e.name[i]);
                lit(b, "\nobjId=");        num(b, e.objId);
                lit(b, "\nidentity=");
                auto idr = identityById(e.identityObjId);
                if (idr !is null) foreach (i; 0 .. idr.nameLen) put(b, idr.name[i]); else lit(b, "(none)");
                lit(b, "\nidentityObjId="); num(b, e.identityObjId);
                lit(b, "\ntemplate=");     num(b, e.templateObjId);
                lit(b, "\nstate=");        litz(b, domainStateName(e.state));
                lit(b, "\ntype=");         lit(b, e.isTemplate ? "template" : "domain");
                lit(b, "\npersist=");      persistName(b, e.persistMode);
                lit(b, "\npolicyEpoch=");  num(b, e.policyEpoch);
                put(b, '\n');
                return cast(long)b.len;
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
enum int CFG_NONE = 0, CFG_SYSTEM = 1, CFG_IDENTITIES = 2, CFG_USERS = 3, CFG_SERVICES = 4,
         CFG_DOMAINS = 5, CFG_PACKAGES = 6, CFG_TEMPLATES = 7, CFG_DISKS = 8;

private immutable string[8] g_configFiles =
    ["system.json", "identities.json", "users.json", "services.json", "domains.json", "packages.json", "templates.json", "disks.json"];

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

private size_t tCstrLen(const(char)* s) { size_t n = 0; while (s[n] != 0) ++n; return n; }  // DM12

// JSON string literal (minimal escaping — kernel object names are controlled).
private void jstr(ref UB b, const(char)* s, size_t n) {
    put(b, '"');
    foreach (i; 0 .. n) { const char c = s[i]; if (c == '"' || c == '\\') put(b, '\\'); put(b, c); }
    put(b, '"');
}

// Write a NUL-terminated C string into the buffer (e.g. a domainStateName()).
private void litz(ref UB b, const(char)* s) {
    if (s is null) return;
    for (size_t i = 0; s[i] != 0; ++i) put(b, s[i]);
}

// "ephemeral" | "home-only" | "full" for a domain's persistMode.
private void persistName(ref UB b, ubyte m) {
    if (m == PERSIST_FULL)           lit(b, "full");
    else if (m == PERSIST_HOME_ONLY) lit(b, "home-only");
    else                             lit(b, "ephemeral");
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
            import core.sysversion : SYSTEM_VERSION, SYSTEM_VERSION_STRING, SYSTEM_CHANNEL, g_bootSlot;
            lit(b, "{\n  \"kernel\": \"EpinAnonymOS\",\n  \"model\": \"object-capability\",\n");
            lit(b, "  \"version\": ");        num(b, SYSTEM_VERSION);
            lit(b, ",\n  \"versionString\": \""); lit(b, SYSTEM_VERSION_STRING); lit(b, "\"");
            lit(b, ",\n  \"channel\": \"");   lit(b, SYSTEM_CHANNEL); lit(b, "\"");
            lit(b, ",\n  \"slot\": \"");      put(b, g_bootSlot); lit(b, "\"");
            lit(b, ",\n");
            lit(b, "  \"installed\": "); lit(b, installConfigPresent() ? "true" : "false");
            lit(b, ",\n");
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
        case CFG_DOMAINS: {
            // DOMAIN_MANAGER DM0: the live domain registry as declarative JSON.
            lit(b, "[\n"); bool first = true;
            foreach (ref e; g_domains) if (e.inUse) {
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"name\": ");      jstr(b, e.name.ptr, e.nameLen);
                lit(b, ", \"objId\": ");       num(b, e.objId);
                lit(b, ", \"identity\": ");
                auto idr = identityById(e.identityObjId);
                if (idr !is null) jstr(b, idr.name.ptr, idr.nameLen); else lit(b, "null");
                lit(b, ", \"color\": \"");     hex(b, idr !is null ? idr.color : 0xFF808080u); put(b, '"');  // DM10: GUI accent
                lit(b, ", \"template\": ");    num(b, e.templateObjId);
                lit(b, ", \"state\": \"");     litz(b, domainStateName(e.state)); put(b, '"');
                lit(b, ", \"type\": \"");      lit(b, e.isTemplate ? "template" : "domain"); put(b, '"');
                lit(b, ", \"persist\": \"");   persistName(b, e.persistMode); put(b, '"');
                lit(b, ", \"devices\": \"");   hex(b, domainDeviceMask(e.objId)); put(b, '"');  // DM10.7 peripheral mask
                lit(b, ", \"distro\": \"");          litz(b, distroName(domainDistro(e.objId))); put(b, '"');   // DM11
                lit(b, ", \"packageManager\": \""); litz(b, pkgMgrName(domainPkgMgr(e.objId))); put(b, '"');    // DM11
                lit(b, ", \"policyEpoch\": "); num(b, e.policyEpoch);
                lit(b, " }");
            }
            lit(b, "\n]\n");
            return cast(long)b.len;
        }
        case CFG_PACKAGES: {
            // DOMAIN_MANAGER DM7: the software repository catalog + per-domain installs as JSON.
            lit(b, "{ \"repository\": [\n"); bool first = true;
            foreach (uint i; 0 .. pkgRepoCount()) {
                auto p = pkgRepoAt(i);
                if (p is null) continue;
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"name\": ");          jstr(b, p.name.ptr, p.nameLen);
                lit(b, ", \"version\": \"");       litz(b, p.ver.ptr); put(b, '"');
                lit(b, ", \"sizeKb\": ");          num(b, p.sizeKb);
                lit(b, ", \"requiredCaps\": \"");  hex(b, p.requiredCaps); put(b, '"');
                lit(b, ", \"signed\": ");          lit(b, p.signed ? "true" : "false");
                lit(b, " }");
            }
            lit(b, "\n], \"installed\": [\n"); first = true;
            foreach (ref e; g_domains) if (e.inUse) {
                const uint mask = pkgInstalledMask(e.objId);
                if (mask == 0) continue;
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"domain\": ");  jstr(b, e.name.ptr, e.nameLen);
                lit(b, ", \"packages\": [");
                bool pf = true;
                foreach (uint i; 0 .. pkgRepoCount()) if (mask & (1u << i)) {
                    auto p = pkgRepoAt(i); if (p is null) continue;
                    if (!pf) lit(b, ", "); pf = false;
                    jstr(b, p.name.ptr, p.nameLen);
                }
                lit(b, "] }");
            }
            lit(b, "\n] }\n");
            return cast(long)b.len;
        }
        case CFG_TEMPLATES: {
            // DOMAIN_MANAGER DM12: the local signed-template registry as declarative JSON.
            lit(b, "[\n"); bool first = true;
            foreach (uint i; 0 .. templateCount()) {
                auto t = templateAt(i);
                if (t is null) continue;
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"name\": ");        jstr(b, t.name.ptr, tCstrLen(t.name.ptr));
                lit(b, ", \"publisher\": ");     jstr(b, t.publisher.ptr, tCstrLen(t.publisher.ptr));
                lit(b, ", \"version\": \"");     num(b, (t.ver>>16)&0xff); put(b,'.'); num(b,(t.ver>>8)&0xff); put(b,'.'); num(b,t.ver&0xff); put(b,'"');
                lit(b, ", \"policyEpoch\": ");   num(b, t.policyEpoch);
                lit(b, ", \"generation\": ");    num(b, t.genObjId);
                lit(b, ", \"bundleHash\": \"");  hex(b, t.bundleHash); put(b,'"');
                lit(b, " }");
            }
            lit(b, "\n]\n");
            return cast(long)b.len;
        }
        case CFG_DISKS: {
            // INSTALLER §D2(b): the live block devices as declarative JSON so the
            // installer GUI's Disk-Selection page can enumerate REAL install targets
            // (index + size + a role hint).  Read-only; the kernel owns block I/O, so
            // the GUI never touches raw devices — it just chooses an index to install to.
            import drivers.block.ahci : g_ahciDevices;
            import drivers.block.disk : diskStoreIndex, diskIsNvme, diskSectors;
            ulong storeSec = 0;
            const int storeIdx = diskStoreIndex(storeSec);
            lit(b, "{ \"disks\": [\n"); bool first = true;
            if (diskIsNvme()) {
                // NVMe machines expose ONE disk at index 0 (disk.d backend convention).
                lit(b, "  { \"index\": 0, \"sizeMiB\": "); num(b, diskSectors() / 2048);
                lit(b, ", \"role\": \""); lit(b, (storeIdx == 0) ? "store" : "target"); put(b, '"');
                lit(b, " }");
                first = false;
            }
            else foreach (uint i; 0 .. cast(uint)g_ahciDevices.length) {
                auto d = g_ahciDevices[i];
                if (!d.present || d.type != 1 || d.capacity == 0) continue; // SATA data disks only
                if (!first) lit(b, ",\n"); first = false;
                lit(b, "  { \"index\": ");  num(b, i);
                lit(b, ", \"sizeMiB\": ");  num(b, d.capacity / (1024UL * 1024UL));
                lit(b, ", \"role\": \"");   lit(b, (cast(int)i == storeIdx) ? "store" : "target"); put(b, '"');
                lit(b, " }");
            }
            lit(b, "\n] }\n");
            return cast(long)b.len;
        }
        default: return -2; // ENOENT
    }
}

// DOMAIN_MANAGER DM0: one-shot boot proof that /config/domains.json renders the
// seeded registry (headless verification — no shell needed).  Mirrors the
// selftest philosophy; runs once.
__gshared char[2048] g_domDumpBuf;
__gshared bool       g_domDumped = false;
public void configDomainsDump() {
    if (g_domDumped) return;
    g_domDumped = true;
    const long n = configfsRender(CFG_DOMAINS, g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    if (n < 0) { klog("[domain] /config/domains.json render FAIL\n"); return; }
    klog("[domain] /config/domains.json render OK: ");
    klog_hex(cast(ulong)domainCount()); klog(" domains, ");
    klog_hex(cast(ulong)n); klog(" bytes\n");
}

// DOMAIN_MANAGER DM7: one-shot boot proof that /config/packages.json renders the repository
// catalog + per-domain installs (headless verification of the software-repo view).
__gshared bool g_pkgDumped = false;
public void configPackagesDump() {
    if (g_pkgDumped) return;
    g_pkgDumped = true;
    const long n = configfsRender(CFG_PACKAGES, g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    if (n < 0) { klog("[pkg] /config/packages.json render FAIL\n"); return; }
    klog("[pkg] /config/packages.json render OK: "); klog_hex(cast(ulong)pkgRepoCount());
    klog(" packages, "); klog_hex(cast(ulong)n); klog(" bytes\n");
}

// INSTALLER: one-shot boot proof of the /config/disks.json install-target view — the
// full JSON, so "installer sees no disks" is diagnosable from klog alone (no GUI).
__gshared bool g_disksDumped = false;
public void configDisksDump() {
    if (g_disksDumped) return;
    g_disksDumped = true;
    const long n = configfsRender(CFG_DISKS, g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    if (n < 0) { klog("[install] /config/disks.json render FAIL\n"); return; }
    g_domDumpBuf[cast(size_t)n] = '\0';
    klog("[install] /config/disks.json: ");
    klog(g_domDumpBuf.ptr);
}

// DOMAIN_MANAGER DM0.d: one-shot boot proof that /objects/domains/<name>/{meta,
// relationships,capabilities} render (headless — exercises the same renderers the
// sys_open/getdents path calls).  Runs once at boot init.
__gshared bool g_domViewDumped = false;
public void domObjViewDump() {
    if (g_domViewDumped) return;
    g_domViewDumped = true;
    char[32] nm = void; int cnt = 0;
    for (int i = 0; ; ++i) { const int l = objfsEnum(OBJFS_DOMAINS, i, nm.ptr, nm.length); if (l < 0) break; ++cnt; }
    const long m = objfsRead(OBJFS_DOMAINS, "Development\0".ptr, 11, g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    const long r = objfsField(OBJFS_DOMAINS, "Development\0".ptr, 11, OBJF_RELS, g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    const long c = objfsField(OBJFS_DOMAINS, "Banking\0".ptr, 7, OBJF_CAPS, g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    klog("[domain] /objects/domains view OK: ");
    klog_hex(cast(ulong)cnt); klog(" entries; meta=");
    klog_hex(cast(ulong)(m > 0 ? m : 0)); klog("B rels=");
    klog_hex(cast(ulong)(r > 0 ? r : 0)); klog("B caps=");
    klog_hex(cast(ulong)(c > 0 ? c : 0)); klog("B\n");
}

// DOMAIN_MANAGER DM2.4: one-shot dump of a manifest domain's RuntimeView (the resolved
// restricted-filesystem view) — proves `cat /objects/domains/DevSandbox/filesystem` works.
__gshared bool g_domFsViewDumped = false;
public void domFsViewDump() {
    if (g_domFsViewDumped) return;
    g_domFsViewDumped = true;
    const long n = objfsField(OBJFS_DOMAINS, "DevSandbox\0".ptr, 10, OBJF_FS,
                              g_domDumpBuf.ptr, g_domDumpBuf.length - 1);
    if (n > 0) {
        g_domDumpBuf[cast(size_t)n] = 0;
        klog("[domain] /objects/domains/DevSandbox/filesystem (DM2.4 RuntimeView):\n");
        klog(g_domDumpBuf.ptr);
    } else klog("[domain] RuntimeView render: no DevSandbox fs view\n");
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
        case HOSQ_FSTAT: return hosFstat(arg, buf);           // arg=handle, buf=struct stat*
        case HOSQ_DEV_READ:  return hosRead(arg, buf, buflen);   // Z4a.6: terminal Device read
        case HOSQ_DEV_WRITE: return hosWrite(arg, buf, buflen);  // Z4a.6: terminal Device write
        case HOSQ_SEND:      return hosWrite(arg, buf, buflen);  // Z4b.4: §8 channel send (over the fd)
        case HOSQ_RECV:      return hosRead(arg, buf, buflen);   // Z4b.4: §8 channel recv
        case HOSQ_SUBSCRIBE: return hosSubscribe(arg);           // Z4b.3: §6 event subscription
        // SHELL_AND_COMMANDS B5: "audit-log every privileged action".  These four are the whole
        // mutating surface of the native object ABI -- a task can attenuate and grant itself a
        // capability, clone a namespace, enter one, and change the identity it runs as -- and
        // until now not one of them left a record.  hoscall.d did not even import core.audit,
        // so in a system whose entire security model is capabilities plus identity, the
        // operations that move both were the only ones invisible to the audit log.
        //
        // Wrapped at the DISPATCH site rather than inside each helper: it is one place, it
        // cannot be forgotten when a fifth verb is added next to these four, and it records the
        // OUTCOME, so a refused grant is as visible as a successful one.  A denial is the more
        // interesting record of the two.
        case HOSQ_CAP_GRANT: return hosAuditPriv(HOSQ_CAP_GRANT, cast(uint)arg, hosCapGrant(arg, buf));
        case HOSQ_NS_CLONE:  return hosAuditPriv(HOSQ_NS_CLONE,  0,             hosNsClone());
        case HOSQ_NS_ENTER:  return hosAuditPriv(HOSQ_NS_ENTER,  cast(uint)arg, hosNsEnter(arg));
        case HOSQ_ID_SWITCH: return hosAuditPriv(HOSQ_ID_SWITCH, 0,             hosIdSwitch(buf));
        case HOSQ_PCI_CFG_RD: return hosAuditPriv(HOSQ_PCI_CFG_RD, cast(uint)arg, hosPciCfgRead(arg));
        case HOSQ_PCI_CFG_WR: return hosAuditPriv(HOSQ_PCI_CFG_WR, cast(uint)arg, hosPciCfgWrite(arg, buf));
        case HOSQ_MMIO_RD:   return hosAuditPriv(HOSQ_MMIO_RD,   cast(uint)arg, hosMmioRead(arg, buf));
        case HOSQ_MMIO_WR:   return hosAuditPriv(HOSQ_MMIO_WR,   cast(uint)arg, hosMmioWrite(arg, buf, buflen));
        case HOSQ_VIRT2PHYS: return hosAuditPriv(HOSQ_VIRT2PHYS, cast(uint)arg, hosVirtToPhys(arg));
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

// BARE_METAL L3 capability 2 — is `phys` inside some PCI device's BAR?
//
// Arbitrary physical MMIO from userspace would be a hole big enough to write kernel memory through
// the HHDM, so the address must belong to a real device aperture.  Walking the BARs is both the
// safety check and exactly the scope LKL needs: its iomem forward only ever touches BARs.
private bool physInSomeBar(ulong phys, uint width) {
    import drivers.pci : scanPCIDevices, pciConfigRead32, pciConfigWrite32;
    if (width == 0) return false;
    auto devs = scanPCIDevices();
    foreach (ref dev; devs) {
        auto d = &dev;
        for (uint b = 0; b < 6; ++b) {
            const ubyte off = cast(ubyte)(0x10 + b * 4);
            const uint lo = pciConfigRead32(d.bus, d.slot, d.func, off);
            if (lo == 0 || (lo & 1) != 0) continue;          // unused, or I/O-space BAR
            ulong base = lo & 0xFFFFFFF0u;
            bool is64 = ((lo & 0x6) == 0x4);
            if (is64) {
                const uint hi = pciConfigRead32(d.bus, d.slot, d.func, cast(ubyte)(off + 4));
                base |= (cast(ulong)hi << 32);
            }
            if (base == 0) { if (is64) ++b; continue; }
            // Size a BAR the standard way: write all-ones, read back the mask, restore.  Done
            // with interrupts as they are because this runs only from an admin-gated verb.
            pciConfigWrite32(d.bus, d.slot, d.func, off, 0xFFFFFFFFu);
            const uint mask = pciConfigRead32(d.bus, d.slot, d.func, off);
            pciConfigWrite32(d.bus, d.slot, d.func, off, lo);
            const uint sizeMask = mask & 0xFFFFFFF0u;
            if (sizeMask == 0) { if (is64) ++b; continue; }
            const ulong size = (~cast(ulong)sizeMask + 1) & 0xFFFFFFFFUL;
            if (phys >= base && (phys + width) <= (base + size)) return true;
            if (is64) ++b;
        }
    }
    return false;
}

private long hosMmioRead(ulong phys, ulong width) {
    import core.admin : adminRequire;
    import core.cap : CAP_RIGHT_ADMIN_DEVICE;
    import core.globals : hhdm_offset;
    if (!adminRequire(CAP_RIGHT_ADMIN_DEVICE)) return -1;
    if (width != 1 && width != 2 && width != 4 && width != 8) return -22;
    if ((phys % width) != 0) return -22;                       // an unaligned MMIO can fault
    if (!physInSomeBar(phys, cast(uint)width)) return -1;      // not a device aperture: refuse
    auto p = cast(void*)(phys + hhdm_offset);
    final switch (width) {
        case 1: return cast(long)(*cast(shared const ubyte*)p);
        case 2: return cast(long)(*cast(shared const ushort*)p);
        case 4: return cast(long)(*cast(shared const uint*)p);
        case 8: return cast(long)(*cast(shared const ulong*)p);
    }
}

private long hosMmioWrite(ulong phys, ulong val, ulong width) {
    import core.admin : adminRequire;
    import core.cap : CAP_RIGHT_ADMIN_DEVICE;
    import core.globals : hhdm_offset;
    if (!adminRequire(CAP_RIGHT_ADMIN_DEVICE)) return -1;
    if (width != 1 && width != 2 && width != 4 && width != 8) return -22;
    if ((phys % width) != 0) return -22;
    if (!physInSomeBar(phys, cast(uint)width)) return -1;
    auto p = cast(void*)(phys + hhdm_offset);
    switch (width) {
        case 1: *cast(shared ubyte*)p  = cast(ubyte)val;  break;
        case 2: *cast(shared ushort*)p = cast(ushort)val; break;
        case 4: *cast(shared uint*)p   = cast(uint)val;   break;
        default: *cast(shared ulong*)p = val;             break;
    }
    return 0;
}

// BARE_METAL L3 capability 3 — the caller's OWN virtual address to a physical one.
//
// Deliberately the active address space only.  Translating an arbitrary task's address would let a
// caller discover another domain's physical layout, which is exactly the isolation L4 is meant to
// establish rather than undermine.
private long hosVirtToPhys(ulong va) {
    import core.admin : adminRequire;
    import core.cap : CAP_RIGHT_ADMIN_DEVICE;
    import core.addrspace : activeVirtToPhys;
    if (!adminRequire(CAP_RIGHT_ADMIN_DEVICE)) return -1;
    const ulong phys = activeVirtToPhys(va);
    if (phys == 0) return -14;                                 // -EFAULT: not a present page
    return cast(long)phys;
}

// BARE_METAL L3 (roadmap 5.1) — PCI config read/write for a userspace LKL.

//
// Both refuse without CAP_RIGHT_ADMIN_DEVICE.  That cap is not held by PID1, so this is not
// ambient authority: a task must be granted it explicitly, and every call is audited by the
// hosAuditPriv wrapper at the dispatch site whether it succeeds or is refused.
private long hosPciCfgRead(ulong arg) {
    import core.admin : adminRequire;
    import core.cap : CAP_RIGHT_ADMIN_DEVICE;
    import drivers.pci : pciConfigRead32;
    if (!adminRequire(CAP_RIGHT_ADMIN_DEVICE)) return -1;   // -EPERM
    ubyte bus, slot, func, off;
    pciUnpack(arg, bus, slot, func, off);
    // Config space is dword-addressed; a misaligned offset would silently read the wrong register.
    if ((off & 3) != 0) return -22;                         // -EINVAL
    return cast(long)cast(uint)pciConfigRead32(bus, slot, func, off);
}

private long hosPciCfgWrite(ulong arg, ulong val) {
    import core.admin : adminRequire;
    import core.cap : CAP_RIGHT_ADMIN_DEVICE;
    import drivers.pci : pciConfigWrite32;
    if (!adminRequire(CAP_RIGHT_ADMIN_DEVICE)) return -1;
    ubyte bus, slot, func, off;
    pciUnpack(arg, bus, slot, func, off);
    if ((off & 3) != 0) return -22;
    pciConfigWrite32(bus, slot, func, off, cast(uint)val);
    return 0;
}

// ── SHELL_AND_COMMANDS B5 proof ─
//
// B5 says "audit-log every privileged action".  Wiring auditLog into the dispatch is worth
// nothing on its own -- this tier has repeatedly found machinery that was written, self-tested
// and never reached -- so this drives the REAL entry point, hosQuery(), and reads the audit ring
// back to prove records actually landed.
//
// Both outcomes are exercised deliberately.  ns_enter is called with an object id the caller does
// not own, which must be refused: an audit trail that only records successes is precisely the one
// an attacker does not mind, so the denial is the record that matters.
__gshared bool g_hosAuditProofDone = false;
public void hosAuditPrivProof() {
    if (g_hosAuditProofDone) return;
    g_hosAuditProofDone = true;

    const ulong okBefore   = auditCount(AuditKind.NativeVerbOk);
    const ulong denyBefore = auditCount(AuditKind.NativeVerbDeny);

    // A privileged verb that should SUCCEED: clone the caller's namespace.
    const long cloned = hosQuery(HOSQ_NS_CLONE, 0, 0, 0);

    // A privileged verb that should FAIL: enter a namespace object that is not ours.  0xFFFFFF is
    // not a live namespace the caller owns, so hosNsEnter must refuse it.
    const long entered = hosQuery(HOSQ_NS_ENTER, 0xFFFFFF, 0, 0);

    const ulong okAfter   = auditCount(AuditKind.NativeVerbOk);
    const ulong denyAfter = auditCount(AuditKind.NativeVerbDeny);

    klog("[4.5] B5 privileged-verb audit: ns_clone=");
    klog_hex(cast(ulong)cloned);
    klog(" ns_enter(bogus)=");
    klog_hex(cast(ulong)entered);
    klog(" auditOk +");   klog_dec(okAfter - okBefore);
    klog(" auditDeny +"); klog_dec(denyAfter - denyBefore);

    // The denial is the load-bearing half: a refused privileged verb MUST leave a record.
    const bool pass = (entered < 0) && (denyAfter > denyBefore)
                   && ((cloned < 0) ? (denyAfter - denyBefore) >= 2 : (okAfter > okBefore));
    klog(pass ? " -- B5 PASS\n" : " -- B5 FAIL\n");
}

// ── BARE_METAL L3 proof (roadmap 5.1) ────────────────────────────────────────────────────────
//
// Reads a device's vendor/device ID through the NEW userspace verb and compares it to what the
// kernel's own PCI scan found.  Comparing against an independent source is the point: a verb that
// returned a plausible-looking constant would pass a self-consistency check.
//
// It also drives the REFUSAL path, because the interesting property is not that an authorised
// caller can read config space -- it is that an unauthorised one cannot.  PID1 does not hold
// CAP_RIGHT_ADMIN_DEVICE (adminInstallInitCaps grants mount/reboot/inspect/identity only), so the
// boot task is already the unauthorised case and needs no setup to test.
__gshared bool g_l3ProofDone = false;
public void hosPciVerbProof() {
    import drivers.pci : scanPCIDevices;
    import core.admin : adminInstallCapIn, adminRequire;
    import core.cap : CAP_RIGHT_ADMIN_DEVICE;
    import core.exports : g_current_task_id;
    import core.task : g_tasks;

    if (g_l3ProofDone) return;
    g_l3ProofDone = true;

    auto devs = scanPCIDevices();
    if (devs.length == 0) { klog("[5.1] L3 PCI verb: SKIP (no PCI devices)\n"); return; }
    auto d = &devs[0];
    const ulong sel = cast(ulong)d.bus | (cast(ulong)d.slot << 8) | (cast(ulong)d.func << 13);

    // 1. UNAUTHORISED: the running task has no ADMIN_DEVICE cap, so the verb must refuse.
    const long denied = hosQuery(HOSQ_PCI_CFG_RD, sel, 0, 0);

    // 2. AUTHORISED: grant the cap to this task's own table, then the same call must succeed and
    //    agree with the kernel's scan.
    const int tab = g_tasks[cast(int)g_current_task_id].capTabId;
    adminInstallCapIn(tab, CAP_RIGHT_ADMIN_DEVICE);
    const long got = hosQuery(HOSQ_PCI_CFG_RD, sel, 0, 0);
    const uint expect = (cast(uint)d.deviceId << 16) | cast(uint)d.vendorId;

    // 3. A misaligned offset must be rejected: config space is dword-addressed, and silently
    //    reading the wrong register is worse than an error.
    const long misaligned = hosQuery(HOSQ_PCI_CFG_RD, sel | (1UL << 32), 0, 0);

    // ── capability 2: MMIO forward ────────────────────────────────────────────────────────
    // Read the SAME vendor/device dword through the MMIO path is not possible (config space is
    // not a BAR), so instead prove the SAFETY properties, which are the ones that matter for a
    // verb that can otherwise touch any device register:
    //   * an address that is not inside any BAR is refused, so this cannot be used to reach
    //     kernel memory through the HHDM;
    //   * an unaligned or bad-width access is refused rather than faulting.
    const long mmioBadAddr  = hosQuery(HOSQ_MMIO_RD, 0x1000, 4, 0);   // low RAM, not a BAR
    const long mmioBadWidth = hosQuery(HOSQ_MMIO_RD, 0x1000, 3, 0);   // width 3 is not legal

    // ── capability 3: virt->phys ──────────────────────────────────────────────────────────
    // Use a page whose physical address we KNOW because we just allocated it, and address it
    // through the HHDM.  The first version of this check used a kernel global and subtracted
    // hhdm_offset -- but kernel globals live in the kernel IMAGE mapping, not the HHDM, so the
    // expected value was nonsense and the check failed against a verb that was working.  The
    // expectation has to be derived independently AND correctly.
    import core.globals : hhdm_offset;
    import memory.mm : alloc_phys_page;
    const ulong probePhys = alloc_phys_page();
    const ulong probeVa   = (probePhys == 0) ? 0 : (probePhys + hhdm_offset);
    const long  v2p     = hosQuery(HOSQ_VIRT2PHYS, probeVa, 0, 0);
    const bool  v2pOk   = (probePhys != 0) && (v2p > 0) && (cast(ulong)v2p == probePhys);
    const long  v2pBad  = hosQuery(HOSQ_VIRT2PHYS, 0x00007f0000000000UL, 0, 0);  // unmapped

    const bool pass = (denied < 0) && (got == cast(long)expect) && (misaligned == -22)
                   && (mmioBadAddr < 0) && (mmioBadWidth == -22)
                   && v2pOk && (v2pBad == -14);
    klog("[5.1] L3 PCI verb: unauth="); klog_hex(cast(ulong)denied);
    klog(" read=");    klog_hex(cast(ulong)got);
    klog(" expect=");  klog_hex(expect);
    klog(" misaligned="); klog_hex(cast(ulong)misaligned);
    klog(" mmioNotBar="); klog_hex(cast(ulong)mmioBadAddr);
    klog(" mmioBadWidth="); klog_hex(cast(ulong)mmioBadWidth);
    klog(" v2p="); klog_hex(v2pOk ? 1 : 0);
    klog(" v2pUnmapped="); klog_hex(cast(ulong)v2pBad);
    klog(pass ? " -- L3 PASS\n" : " -- L3 FAIL\n");
}
