module core.task;

import core.io;
import core.globals;
import memory.mm;
import core.objmgr : ObjType, objAlloc, objRetain, objRelease, objGet,
                     objBeginSweep, objMark, objSweepType; // Phase 3/4
import core.namespace : nsAlloc, nsClone, nsRelease, nsResolveCheck; // Phase 9 + DOMAIN_MANAGER DM3
import core.domain : domainById, domainByName,
                     domainClone, domainStart, domainDelete;         // DOMAIN_MANAGER DM3/DM6.2
import core.overlay : overlayWrite, overlayChangeCount;             // DOMAIN_MANAGER DM6.2 data plane
import core.identity : identityCanTransition, identityByName;        // DOMAIN_MANAGER DM3
import core.untyped : untypedDestroy; // IMMUTABLE_ROOTLESS §1.4: task memory budget
import core.cap : CAP_RIGHT_RETYPE; // rights on Process -> Untyped authority edges
import core.linuxobj : linuxProcEnsure, linuxProcSweep; // Phase 12: Linux pid-view wrapper
import core.org : edgeEnsure, orgPruneDeadOut, EdgeKind,
                  orgClearRoots, orgAddRoot; // ORG P3/P4: edges + reachability roots

extern (C) @nogc nothrow:

// Register indices — match context.S constant definitions
enum : uint {
    REG_RAX    = 0,
    REG_RBX    = 1,
    REG_RCX    = 2,
    REG_RDX    = 3,
    REG_RSI    = 4,
    REG_RDI    = 5,
    REG_R8     = 6,
    REG_R9     = 7,
    REG_R10    = 8,
    REG_R11    = 9,
    REG_R12    = 10,
    REG_R13    = 11,
    REG_R14    = 12,
    REG_R15    = 13,
    REG_RIP    = 14,
    REG_RSP    = 15,
    REG_RBP    = 16,
    REG_RFLAGS = 17,
    NUM_REGS   = 18,
}

// Matches context.S reason codes for curUserSpaceState[0]
enum : ulong {
    REASON_SYSCALL = 1,
    REASON_TRAP    = 2,
    REASON_IRQ     = 3,
}

enum MAX_TASKS   = 256;   // bumped from 64: LKL+desktop+dbus+NM exhaust 64 (exited threads also leak slots -- see reaper TODO)
// A real Mesa/softpipe + Hyprland startup maps several hundred persistent regions
// (gallium buffers, the 1080p framebuffer, musl's mmap-backed large allocations),
// which overflowed the old 512 cap ("addRegion: full") before the first frame.
// munmap now reclaims entries (removeRegion), but the steady-state working set is
// still large, so keep a generous ceiling. Cost: MAX_TASKS(64) * 4096 * ~32B ≈ 8MB.
enum MAX_REGIONS = 4096;

enum RegionType : ubyte {
    None             = 0,
    Mapped           = 1,   // direct physical mapping, already mapped
    CopyOnWrite      = 2,   // read-only from physBase; write faults copy
    AllocateOnDemand = 3,   // demand-zero pages
}

enum RegionPerms : ubyte {
    ReadOnly  = 0,
    ReadWrite = 1,
}

struct AddrRegion {
    ulong       start;
    ulong       end;      // exclusive
    RegionType  type;
    RegionPerms perms;
    ulong       physBase; // for Mapped / CopyOnWrite
    // True when this region's physical pages were freshly allocated from the
    // bump pool and are exclusively owned by this address space (anonymous and
    // private file-backed maps).  Such pages are safe to free_phys_page() on
    // munmap / task exit.  False for device (g_fb / DRM) and shared (memfd) maps
    // whose pages must never be reclaimed.
    bool        owned;
    // Phase 3 (roadmap/OBJECT_OS_ROADMAP.md): id of the core.objmgr MemRegion
    // object mirroring this region (0 = none/not yet registered).
    uint        objId;
    // Phase 3: optional VMO object id for shared physical backing (memfd / DRM
    // GEM).  Private anonymous/file regions leave this as 0.
    uint        vmoObjId;
    bool        vmoRetained;
}

struct Task {
    bool active;
    bool exited;
    bool waiting;   // blocked in wait4, vfork, or a scheduler-backed futex wait
    int  exitCode;
    int  parentId;
    // Phase 4 (roadmap/OBJECT_OS_ROADMAP.md): scheduled identity for this task.
    // Every runnable task is a Thread object, including process leaders.
    uint objId;
    // Owning Process object.  Process leaders point at their own process object;
    // CLONE_VM threads inherit their leader's process object.
    uint processObjId;
    // Parent object in the process/thread tree: fork children point at the
    // parent's Process object; clone threads point at their owning Process.
    uint parentObjId;
    // Task slot of the process leader for Linux pid view and process ownership.
    int  processLeaderTid;

    // Saved user registers (layout matches curUserSpaceState+8 / context.S)
    ulong[NUM_REGS] regs;
    // fxsave area (512 bytes); must be 16-byte aligned in curUserSpaceState
    align(16) ubyte[512] sseState;

    // Physical address of this task's PML4 page table
    ulong pml4Phys;

    // Virtual address space regions
    AddrRegion[MAX_REGIONS] regions;
    int regionCount;

    // Linux heap (brk)
    ulong brkStart;   // lowest valid brk address
    ulong brkCurrent; // current program break

    // Child-exit notification: childStatus[i] is set when child i exits
    bool[MAX_TASKS] childExited;
    int[MAX_TASKS]  childExitCode;
    int waitingForPid; // -1 = any child

    // Per-task mmap bump pointer (avoids collisions after fork)
    ulong mmapNext;

    // Which per-process fd table this task uses (posix.d g_fdTabs).  Threads
    // share their process leader's id; a fork()ed child gets its own (its task
    // id) with a copied table.  0 = the initial process (task 0).
    int fdTabId;
    // Phase 6: per-process capability table.  Kept separate from fdTabId so the
    // native object/capability model can eventually outgrow the Linux fd view;
    // for now fork/clone assign it in lockstep with fdTabId.
    int capTabId;
    // IMMUTABLE_ROOTLESS §1.4: Untyped-memory object selected for this task's
    // physical allocations. Fork gets a child budget; clone shares the process one.
    uint untypedObjId;
    // Phase 9: this process's Namespace object (name→object bindings/mounts).
    // Threads of a process share the leader's namespace; fork clones it.
    uint namespaceObjId;
    // IMMUTABLE_ROOTLESS §3.1/3.3: User object this task runs as. Threads and
    // forked processes inherit it; setuid-style calls can replace it only with
    // ADMIN_USER authority.
    uint userObjId;
    // IDENTITY_DOMAIN §1: the security-domain / Identity object this task is
    // labelled with (ObjType.Identity).  Immutable once set at launch; fork/clone
    // copy it (inheritance by default).  0 until the Identity Manager (§2) assigns
    // the System identity to task 0.  Authority is still the capability — this is
    // only a label, never an ambient "current identity" privilege check.
    uint identityObjId;
    // DOMAIN_MANAGER DM6.2: the Domain (ObjType.Domain) this task is bound INTO (0 = none).
    // Set by domainBindTaskNs; the rtCreate copy-up hook records this task's file writes into
    // the domain's writable overlay.
    uint domainObjId;
    // DM13: execution MODE, a one-way ratchet.  0 = native, 1 = linux.
    //
    // A session starts native and may DROP DOWN into linux exactly once; linux -> native is
    // refused, and the mode is inherited by every child, so a process tree can only ever get
    // more Linux-y, never less.  The point is that dropping into the Linux personality is a
    // trapdoor: nothing running under it can climb back out to the native object ABI, so a
    // compromised Linux shell cannot reach native-only authority by re-exec'ing itself.
    ubyte execMode;
}

enum ubyte EXECMODE_NATIVE = 0;
enum ubyte EXECMODE_LINUX  = 1;

// DM13: the ratchet.  Returns true if the task is now in `want`, false if the transition was
// refused.  Going to the mode you are already in is a no-op success; native<-linux is the only
// refused direction, and it is refused for EVERY caller regardless of capability -- this is a
// structural property of the process tree, not a permission.
public bool taskSetExecMode(int tid, ubyte want) {
    if (tid < 0 || tid >= MAX_TASKS) return false;
    if (want != EXECMODE_NATIVE && want != EXECMODE_LINUX) return false;
    auto t = &g_tasks[tid];
    if (t.execMode == want) return true;
    if (t.execMode == EXECMODE_LINUX && want == EXECMODE_NATIVE) {
        klog("[domain] mode: refused linux -> native (one-way ratchet)\n");
        return false;
    }
    t.execMode = want;
    klog("[domain] mode: task dropped to linux\n");
    return true;
}

public ubyte taskExecMode(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return EXECMODE_NATIVE;
    return g_tasks[tid].execMode;
}

__gshared Task[MAX_TASKS] g_tasks;

// Track A A4 — terminal signals (^C/^\). Kept as side arrays (not Task fields) so the
// shared Task layout is untouched. g_taskPgid: the task's process group (linux pid of
// the group leader; 0 = use the task's own pid). g_taskSigCustom: bitmask of signals
// with a non-default disposition (SIG_IGN or a handler) — those are NOT auto-terminated.
// g_taskPendingSig: a pending terminate-signal the run loop delivers from the victim's
// own context (signalling another task's exitTask from the writer's context is unsafe).
__gshared int[MAX_TASKS]   g_taskPgid;
__gshared ulong[MAX_TASKS] g_taskSigCustom;
__gshared int[MAX_TASKS]   g_taskPendingSig;

// Z1: the child's Linux pid captured at exit, BEFORE cleanup resets processLeaderTid
// (which would make linuxPidForTask return a stale 1).  wait4 returns this so the pid a
// reaping parent sees matches the pid fork() gave it — zsh matches reaped pids to its job
// table, so a mismatch left the job forever "not done".  Indexed by the child's tid.
__gshared int[MAX_TASKS]   g_childExitLinuxPid;

// Z1 (ZSH_INTEGRATION_ROADMAP): real userspace signal-handler delivery.  g_taskSigCustom
// above only records *that* a signal has a non-default disposition (to suppress the
// default terminate); these hold the actual sa_handler + sa_restorer addresses so the
// run loop can build an x86-64 rt_sigframe and invoke the handler.  Used for SIGCHLD so
// zsh's wait_for_processes() runs, reaps the child, and returns from sigsuspend — without
// it zsh wedges after its first external command.  [signo] indexed (standard 1..31; 0
// unused).  0 = no handler (default / SIG_IGN).
__gshared ulong[64][MAX_TASKS] g_sigHandler;
__gshared ulong[64][MAX_TASKS] g_sigRestorer;

// A4: per-task program name (basename of the exec'd binary), for /proc/<pid> comm.
// Set by execveTask / forkTask in kernel_main.d; read by posix.d's procfs.
__gshared const(char)*[MAX_TASKS] g_taskExecName;

// NATIVE_OBJECT_ABI §3: per-task personality. true = the AnonymOS native shell context
// (may call the native object ABI HOS_SYS_QUERY); false = Linux personality (the native
// ABI returns ENOSYS).  Set on execve of /hos-sh, inherited by fork/clone, cleared on
// execve of any non-native image.  Native tasks ALSO speak the Linux ABI (downward
// introspection: see the Linux process table, manage its permissions/settings).
__gshared bool[MAX_TASKS] g_taskNativeAbi;

// L5.2 — native-launch authorization.  Entering the native personality on exec requires this OR
// an already-native caller.  Held by the trusted desktop/terminal chain (default true, inherited
// on fork) and DROPPED when the Linux interactive shell (/bin/zsh) is exec'd — so a Linux shell,
// and everything it spawns, can never enter the native object ABI (even by exec'ing /hos-sh).
__gshared bool[MAX_TASKS] g_taskNativeLaunch = true;

// A task's effective process group: its own pid until setpgid() changes it.
public int taskEffectivePgid(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    return g_taskPgid[tid] != 0 ? g_taskPgid[tid] : linuxPidForTask(tid);
}

// Terminal line discipline (^C/^\) → deliver `sig` to every task in process group
// `pgid` whose disposition for it is default. SIG_IGN/handler tasks (the shell, vi,
// less, …) are skipped so they aren't killed. Blocked victims are woken so the run
// loop schedules them and applies the pending signal.  Returns # of tasks signalled.
public int deliverSignalToGroup(int pgid, int sig) {
    if (pgid == 0 || sig <= 0 || sig >= 64) return 0;
    int n = 0;
    for (int t = 1; t < MAX_TASKS; ++t) {
        if (!g_tasks[t].active || g_tasks[t].exited) continue;
        if (taskEffectivePgid(t) != pgid) continue;
        // SIG_IGN (a custom disposition with no real handler) → ignore, don't deliver.
        // Z3: a task WITH a handler (e.g. zsh's SIGINT) now gets the signal pending too —
        // the run loop invokes its handler (Z1 delivery) instead of terminating it.  A
        // default-disposition task still gets the default terminate.
        if ((g_taskSigCustom[t] & (1UL << sig)) && g_sigHandler[t][sig] == 0) continue;
        g_taskPendingSig[t] = sig;
        g_tasks[t].waiting  = false;                        // wake a blocked victim
        ++n;
    }
    return n;
}

private bool taskAddressSpaceIsShared(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return false;
    ulong pml4 = g_tasks[tid].pml4Phys;
    if (pml4 == 0) return false;
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (i == tid) continue;
        auto other = &g_tasks[i];
        if (other.active && !other.exited && other.pml4Phys == pml4)
            return true;
    }
    return false;
}

public void objEnsureTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;

    auto task = &g_tasks[tid];
    if (!task.active || task.exited) return;
    auto h = objGet(task.objId);
    if (h is null || h.impl !is cast(void*)task || h.type != ObjType.Thread) {
        if (h !is null && h.impl is cast(void*)task &&
            h.type == ObjType.Thread)
            objRelease(task.objId);
        task.objId = objAlloc(ObjType.Thread, cast(void*)task);
    }
}

public void objEnsureProcess(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    if (!task.active || task.exited) return;

    int leader = task.processLeaderTid;
    if (leader < 0 || leader >= MAX_TASKS || !g_tasks[leader].active)
        leader = tid;
    auto impl = cast(void*)&g_tasks[leader];
    auto h = objGet(task.processObjId);
    if (h is null || h.impl !is impl || h.type != ObjType.Process)
        task.processObjId = objAlloc(ObjType.Process, impl);
}

public void objSetProcess(int tid, int leaderTid, uint parentObjId) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    task.processLeaderTid = leaderTid;
    task.parentObjId = parentObjId;
    if (leaderTid >= 0 && leaderTid < MAX_TASKS && leaderTid != tid) {
        task.processObjId = g_tasks[leaderTid].processObjId;
    } else {
        task.processObjId = 0;
        task.processLeaderTid = tid;
    }
    objEnsureProcess(tid);
}

public void objReleaseTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    auto h = objGet(task.objId);
    if (h !is null && h.impl is cast(void*)task &&
        h.type == ObjType.Thread)
        objRelease(task.objId);
    objReleaseNamespace(tid);
    task.objId = 0;
    task.processObjId = 0;
    task.parentObjId = 0;
    task.processLeaderTid = 0;
}

// Phase 9: ensure this task references a Namespace object.  A thread shares its
// process leader's namespace; a process leader without one gets a fresh
// root-bound namespace.  Idempotent — used both at create time and by the
// amortized reconcile to self-heal (e.g. the init task, exec).
public void objEnsureNamespace(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    if (!task.active || task.exited) return;

    int leader = task.processLeaderTid;
    if (leader < 0 || leader >= MAX_TASKS || !g_tasks[leader].active) leader = tid;

    if (leader != tid) {
        if (objGet(g_tasks[leader].namespaceObjId) is null)
            g_tasks[leader].namespaceObjId = nsAlloc();
        task.namespaceObjId = g_tasks[leader].namespaceObjId; // thread shares
        return;
    }
    if (objGet(task.namespaceObjId) is null)
        task.namespaceObjId = nsAlloc();
}

// fork: give the child process a private clone of the parent's namespace, so a
// later rebind in either does not affect the other.
public void objCloneNamespace(int childTid, int parentTid) {
    if (childTid < 0 || childTid >= MAX_TASKS ||
        parentTid < 0 || parentTid >= MAX_TASKS) return;
    g_tasks[childTid].namespaceObjId = nsClone(g_tasks[parentTid].namespaceObjId);
}

// DOMAIN_MANAGER DM3: the raw bind — give a task a PRIVATE clone of the domain's restricted
// namespace + the domain's identity, so its absolute opens are enforced against that domain's
// filesystem policy (namespaceCheckOpen reads g_tasks[tid].namespaceObjId).  No authorization
// here (the gated entry point is domainEnterTask).  Returns the new ns objId, or 0.
public uint domainBindTaskNs(int tid, uint domObjId) {
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    auto d = domainById(domObjId);
    if (d is null || d.nsObjId == 0) return 0;
    const uint ns = nsClone(d.nsObjId);          // private clone (a later rebind won't touch the template)
    if (ns == 0) return 0;
    g_tasks[tid].namespaceObjId = ns;
    if (d.identityObjId != 0) g_tasks[tid].identityObjId = d.identityObjId;
    g_tasks[tid].domainObjId = domObjId;   // DM6.2: the rtCreate copy-up hook uses this
    return ns;
}

// DOMAIN_MANAGER DM6.2 data plane: a copy-up hook called from rtCreate.  If task `tid` is bound
// into a domain, the file it just created is recorded in that domain's writable overlay (so the
// domain's real writes are captured, and snapshot/commit fold them in).  No-op for normal tasks.
public void domainRecordWrite(int tid, const(char)* path, size_t len) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    const uint dom = g_tasks[tid].domainObjId;
    if (dom == 0 || len == 0) return;
    overlayWrite(dom, cast(const(ubyte)*)path, cast(uint)len);
}

// DOMAIN_MANAGER DM6.2 boot proof: a domain-bound task's file create lands in the domain overlay.
__gshared bool g_domOvlWriteProofDone = false;
public void domainOverlayWriteProof() {
    if (g_domOvlWriteProofDone) return;
    g_domOvlWriteProofDone = true;
    const uint dev = domainByName("DevSandbox\0".ptr);
    if (dev == 0) { klog("[domain] overlay-write proof SKIP (no DevSandbox)\n"); return; }
    const uint probe = domainClone(dev, "WriteProbe\0".ptr);   // a throwaway domain
    if (probe == 0 || !domainStart(probe)) { klog("[domain] overlay-write proof SKIP (clone/start)\n"); return; }
    // bind a spare task slot into the probe domain
    int tid = -1;
    for (int i = MAX_TASKS - 1; i > 0; --i) if (!g_tasks[i].active) { tid = i; break; }
    if (tid < 0) { domainDelete(probe); klog("[domain] overlay-write proof SKIP (no spare task)\n"); return; }
    const uint savedDom = g_tasks[tid].domainObjId;
    g_tasks[tid].domainObjId = probe;                          // simulate a domain-bound task
    const uint before = overlayChangeCount(probe);
    domainRecordWrite(tid, "/tmp/edit\0".ptr, 9);             // simulate the rtCreate copy-up
    domainRecordWrite(tid, "/home/x\0".ptr, 7);
    const uint after = overlayChangeCount(probe);
    g_tasks[tid].domainObjId = savedDom;                       // restore the spare slot
    const bool ok = (after == before + 2);
    domainDelete(probe);
    if (ok) klog("[domain] overlay-write proof PASS: domain-bound writes captured in the overlay (copy-up)\n");
    else    klog("[domain] overlay-write proof FAIL\n");
}

// DOMAIN_MANAGER DM3: launch a task INTO a domain.  Authorizes the launcher→domain-identity
// transition through identityCanTransition (needs CAP_RIGHT_ADMIN_IDENTITY in the launcher's cap
// table + a compiled launch rule), then binds the task's namespace + identity.  This is what the
// trusted launcher (HOSQ_DOMAIN_SPAWN) calls instead of a bare fork+execve; deny-by-default.
public bool domainEnterTask(int childTid, uint domObjId, uint launcherIdentity, int launcherCapTab) {
    auto d = domainById(domObjId);
    if (d is null || d.identityObjId == 0) return false;
    if (!identityCanTransition(launcherIdentity, d.identityObjId, launcherCapTab)) return false;
    return domainBindTaskNs(childTid, domObjId) != 0;
}

// DOMAIN_MANAGER DM3 boot proof: bind a spare task slot into DevSandbox and verify the task now
// resolves against the domain's restricted ns (its opens are denied/allowed per the domain policy)
// + carries the domain's identity.  The transition gate itself is proven by idprocSelfTest.
__gshared bool g_domEnterProofDone = false;
public void domainEnterProof() {
    if (g_domEnterProofDone) return;
    g_domEnterProofDone = true;
    const uint dev = domainByName("DevSandbox\0".ptr);
    if (dev == 0) { klog("[domain] enter proof SKIP (no DevSandbox)\n"); return; }
    int tid = -1;
    for (int i = MAX_TASKS - 1; i > 0; --i) if (!g_tasks[i].active) { tid = i; break; }
    if (tid < 0) { klog("[domain] enter proof SKIP (no spare task slot)\n"); return; }
    const uint savedNs = g_tasks[tid].namespaceObjId;
    const uint savedId = g_tasks[tid].identityObjId;

    const uint ns = domainBindTaskNs(tid, dev);
    bool ok = (ns != 0) && (g_tasks[tid].namespaceObjId == ns);
    ok = ok && (g_tasks[tid].identityObjId == identityByName("Personal\0".ptr)); // DevSandbox → Personal
    const(char)* rest; uint rights; bool denied;
    // an unbound path through the bound task's ns → deny-by-default (a real open() would ENOENT)
    ok = ok && (nsResolveCheck(g_tasks[tid].namespaceObjId, "/etc/passwd\0".ptr, rest, rights, denied) == 0);
    // the domain's own home → allowed
    ok = ok && (nsResolveCheck(g_tasks[tid].namespaceObjId, "/Domains/DevSandbox/Home/x\0".ptr, rest, rights, denied) != 0);

    if (ns != 0) nsRelease(ns);
    g_tasks[tid].namespaceObjId = savedNs;   // restore the spare slot
    g_tasks[tid].identityObjId  = savedId;

    if (ok) klog("[domain] enter proof PASS: task bound to DevSandbox restricted ns + identity Personal (opens enforced)\n");
    else    klog("[domain] enter proof FAIL\n");
}

// Release this task's namespace unless another active task still shares it
// (threads of the same process).
public void objReleaseNamespace(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    uint ns = g_tasks[tid].namespaceObjId;
    g_tasks[tid].namespaceObjId = 0;
    if (ns == 0) return;
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (i == tid) continue;
        if (g_tasks[i].active && !g_tasks[i].exited &&
            g_tasks[i].namespaceObjId == ns) return; // still shared
    }
    nsRelease(ns);
}

public void objReleaseUntyped(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    uint ut = g_tasks[tid].untypedObjId;
    g_tasks[tid].untypedObjId = 0;
    if (ut == 0) return;
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (i == tid) continue;
        if (g_tasks[i].active && !g_tasks[i].exited &&
            g_tasks[i].untypedObjId == ut) return; // still shared by a thread
    }
    physClearUntypedOwner(ut);
    untypedDestroy(ut);
}

// Allocate a task slot (id > 0 reserved for non-init tasks)
private int initTaskSlot(int i) {
    g_tasks[i] = Task.init;
    g_tasks[i].active = true;
    g_tasks[i].processLeaderTid = i;
    g_tasks[i].mmapNext = 0x700000000000UL;
    g_tasks[i].fdTabId = i;
    g_tasks[i].capTabId = i;
    objEnsureTask(i);
    return i;
}

int allocTask() {
    for (int i = 1; i < MAX_TASKS; i++)
        if (!g_tasks[i].active)
            return initTaskSlot(i);
    // NOTE: a dead-thread-slot reclaim was tried here but faulted on real hardware (triggers only when
    // the table is full, which QEMU never reached) — reverted.  The task-slot thread leak is a known
    // latent issue; 256 slots + the light diagnostics are enough that it isn't hit in practice.
    return -1;
}

public int linuxTidForTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    return tid + 1;
}

public int linuxPidForTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return 0;
    int leader = g_tasks[tid].processLeaderTid;
    if (leader < 0 || leader >= MAX_TASKS) leader = tid;
    return leader + 1;
}

public int taskIdFromLinuxPid(int pid) {
    int tid = pid - 1;
    if (tid >= 0 && tid < MAX_TASKS) return tid;
    return -1;
}

void releaseTask(int tid) {
    if (tid > 0 && tid < MAX_TASKS) {
        objReleaseTask(tid);
        objReleaseUntyped(tid);
        clearRegions(g_tasks[tid]);
        g_tasks[tid] = Task.init;
    }
}

public void objEnsureRegion(AddrRegion* r) {
    if (r is null) return;
    auto h = objGet(r.objId);
    if (h is null || h.type != ObjType.MemRegion || h.impl !is cast(void*)r) {
        if (h !is null && h.impl is cast(void*)r && h.type == ObjType.MemRegion)
            objRelease(r.objId);
        r.objId = objAlloc(ObjType.MemRegion, cast(void*)r);
    }
    if (r.vmoObjId != 0 && !r.vmoRetained && objGet(r.vmoObjId) !is null) {
        objRetain(r.vmoObjId);
        r.vmoRetained = true;
    }
}

private void objReleaseRegion(AddrRegion* r) {
    if (r is null) return;
    auto h = objGet(r.objId);
    if (h !is null && h.impl is cast(void*)r && h.type == ObjType.MemRegion)
        objRelease(r.objId);
    if (r.vmoRetained && objGet(r.vmoObjId) !is null)
        objRelease(r.vmoObjId);
    r.objId = 0;
    r.vmoObjId = 0;
    r.vmoRetained = false;
}

// Add a virtual address region to a task.
AddrRegion* addRegion(ref Task task, ulong start, ulong end,
                      RegionType type, RegionPerms perms, ulong physBase = 0,
                      bool owned = false, uint vmoObjId = 0) {
    if (task.regionCount >= MAX_REGIONS) {
        klog("[task] addRegion: full\n");
        return null;
    }
    auto r          = &task.regions[task.regionCount++];
    r.start         = start;
    r.end           = end;
    r.type          = type;
    r.perms         = perms;
    r.physBase      = physBase;
    r.owned         = owned;
    r.vmoObjId      = vmoObjId;
    r.vmoRetained   = false;
    r.objId         = 0; // a reused slot must not inherit a stale object id
    objEnsureRegion(r);
    return r;
}

// Does the region containing `vaddr` own its physical pages (safe to free)?
bool regionOwnedAt(ref Task task, ulong vaddr) {
    auto r = findRegion(task, vaddr);
    return r !is null && r.owned;
}

// Remove regions fully contained in [start, end) from a task's table (compacting
// via swap-remove).  Called by munmap so the per-task region table doesn't leak
// one entry per mmap — Mesa/softpipe churn many short-lived maps and otherwise
// exhaust MAX_REGIONS ("addRegion: full").  Partial/straddling unmaps (rare) are
// left intact; their pages are still unmapped by sys_munmap.
void removeRegion(ref Task task, ulong start, ulong end) {
    if (end <= start) return;
    int n = task.regionCount;
    int i = 0;
    while (i < n) {
        auto r = &task.regions[i];
        if (r.start >= start && r.end <= end) {
            objReleaseRegion(r);
            task.regions[i] = task.regions[n - 1];   // swap-remove
            --n;
            continue;                                 // re-check swapped-in entry
        }
        ++i;
    }
    task.regionCount = n;
}

void clearRegions(ref Task task) {
    for (int i = 0; i < task.regionCount; ++i)
        objReleaseRegion(&task.regions[i]);
    task.regionCount = 0;
}

// Find the region that contains vaddr (or null)
AddrRegion* findRegion(ref Task task, ulong vaddr) {
    for (int i = 0; i < task.regionCount; i++) {
        auto r = &task.regions[i];
        if (vaddr >= r.start && vaddr < r.end)
            return r;
    }
    return null;
}

// Phase 3 (roadmap/OBJECT_OS_ROADMAP.md): mirror every live AddrRegion of every
// active task as a core.objmgr MemRegion object, so "every region is an object"
// holds for audit/accounting — additive, no behaviour change (mmap/munmap/fault
// paths are untouched).
//
// Unlike the fd table, AddrRegion slots are NOT address-stable: removeRegion()
// swap-removes (moving a surviving region — and its objId — to a different slot)
// and forkTask deep-copies the whole Task (duplicating objIds into the child).
// The impl-pointer check (object.impl == &slot) re-registers any slot whose
// object no longer points back at it (moved, fork-copied, or never registered);
// the mark-sweep then frees exactly the MemRegion objects that no live slot
// claims this pass (orphans from swap-remove, munmap, and task exit).
public void objReconcileRegions() {
    objBeginSweep();
    for (int t = 0; t < MAX_TASKS; ++t) {
        if (!g_tasks[t].active || g_tasks[t].exited) continue;
        auto task = &g_tasks[t];
        int n = task.regionCount;
        for (int i = 0; i < n; ++i) {
            auto r = &task.regions[i];
            objEnsureRegion(r);
            objMark(r.objId);
        }
    }
    objSweepType(ObjType.MemRegion);
}

// Phase 4: mirror every live Task as either a Process or Thread object.  Task
// slots are stable, but their desired object type can change: allocTask starts
// as a generic runnable slot, fork assigns a private address space, clone shares
// one, and vfork+exec moves a temporary Thread into its own Process identity.
public void objReconcileTasks() {
    objBeginSweep();
    for (int t = 0; t < MAX_TASKS; ++t) {
        if (!g_tasks[t].active || g_tasks[t].exited) continue;
        objEnsureTask(t);
        objEnsureProcess(t);
        objEnsureNamespace(t); // Phase 9: per-process namespace (self-heal)
        // Phase 12: ensure a LinuxProcessObject wraps each process leader's native
        // Process object (the Linux pid view).
        if (g_tasks[t].processLeaderTid == t)
            linuxProcEnsure(g_tasks[t].processObjId, linuxPidForTask(t));
        objMark(g_tasks[t].objId);
        objMark(g_tasks[t].processObjId);
    }
    objSweepType(ObjType.Process);
    objSweepType(ObjType.Thread);
    linuxProcSweep(); // Phase 12: drop Linux wrappers whose Process object is gone
}

// ORG P3 (OBJECT_REFERENCE_GRAPH_ROADMAP.md, ORG_ARCHITECTURE.md E1–E8): mirror
// the process ownership tree and memory edges into the object reference graph as
// typed edges, so there is a real graph to validate/GC.  Driven from the amortized
// reconcile (idempotent `edgeEnsure` + dead-edge prune) rather than per-syscall
// hooks — the same low-risk strategy used to adopt object identity.
//   Process →(StrongOwn) Thread / Namespace / MemRegion / Untyped (E1, E3, E2)
//   Process →(Weak)      parent Process                      (E5: back-edge, no pin)
//   MemRegion →(StrongRef) Vmo                               (E8)
public void orgReconcileOwnership() {
    for (int t = 0; t < MAX_TASKS; ++t) {
        auto task = &g_tasks[t];
        if (!task.active || task.exited) continue;
        uint proc = task.processObjId;
        if (proc != 0 && task.objId != 0)
            edgeEnsure(proc, task.objId, EdgeKind.StrongOwn, 0); // owns its Thread
        if (proc != 0 && task.untypedObjId != 0)
            edgeEnsure(proc, task.untypedObjId, EdgeKind.StrongOwn, CAP_RIGHT_RETYPE);
        if (proc != 0 && task.userObjId != 0)
            edgeEnsure(proc, task.userObjId, EdgeKind.Weak, 0); // subject identity
        if (task.processLeaderTid == t) {
            if (task.namespaceObjId != 0)
                edgeEnsure(proc, task.namespaceObjId, EdgeKind.StrongOwn, 0);
            if (task.parentObjId != 0 && task.parentObjId != proc)
                edgeEnsure(proc, task.parentObjId, EdgeKind.Weak, 0); // parent back-edge
        }
        for (int i = 0; i < task.regionCount; ++i) {
            auto r = &task.regions[i];
            if (proc != 0 && r.objId != 0)
                edgeEnsure(proc, r.objId, EdgeKind.StrongOwn, 0);
            if (r.objId != 0 && r.vmoObjId != 0)
                edgeEnsure(r.objId, r.vmoObjId, EdgeKind.StrongRef, 0);
        }
    }
    // Drop owner→child edges left dangling by threads/regions/namespaces that have
    // since been freed (so killing a task tears its subtree out of the graph).
    for (int t = 0; t < MAX_TASKS; ++t) {
        auto task = &g_tasks[t];
        if (task.active && !task.exited &&
            task.processLeaderTid == t && task.processObjId != 0)
            orgPruneDeadOut(task.processObjId);
    }
}

// ORG P4.2: register the scheduler-anchored roots for reachability.  Every process
// leader's Process object is an external anchor (the scheduler holds it via
// g_tasks); anything not reachable from these over strong edges is a GC candidate.
public void orgReconcileRoots() {
    orgClearRoots();
    for (int t = 0; t < MAX_TASKS; ++t) {
        auto task = &g_tasks[t];
        if (task.active && !task.exited &&
            task.processLeaderTid == t && task.processObjId != 0)
            orgAddRoot(task.processObjId);
    }
}
