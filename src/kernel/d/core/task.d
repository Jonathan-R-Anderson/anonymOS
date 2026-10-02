module core.task;

import core.io;
import core.globals;
import memory.mm;
import core.objmgr : ObjType, objAlloc, objRetain, objRelease, objGet,
                     objBeginSweep, objMark, objSweepType; // Phase 3/4
import core.namespace : nsAlloc, nsClone, nsCloneStrict, nsRelease, nsResolveCheck; // Phase 9 + DOMAIN_MANAGER DM3 + appgate
import core.domain : domainById, domainByName,
                     domainClone, domainStart, domainDelete,         // DOMAIN_MANAGER DM3/DM6.2
                     domainBuildNamespace, g_domains;               // appgate: exec-time namespace
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
// An address space's regions live in ONE table shared by all its threads, grown a page-sized chunk
// at a time.  It used to be a fixed 4096-entry array inside every task, each thread holding its own
// copy: Firefox's parent (~3,700 live mappings, like on Linux) filled every new thread's copy
// ("addRegion: full", then a NULL malloc), a mapping made by one thread was unknown to the others'
// tables, munmap had to walk every thread's copy, and the arrays alone took ~50 MB of kernel memory.
// Chunks never move, so an AddrRegion* stays valid for as long as its entry does.
enum int RT_PER_CHUNK  = cast(int)(4096 / AddrRegion.sizeof);
enum int RT_MAX_CHUNKS = 508;                        // the header fits one page
enum MAX_REGIONS = RT_PER_CHUNK * RT_MAX_CHUNKS;     // ~43k regions per address space
struct RegionTable {
    int count;
    int nchunks;
    int refs;                                        // tasks (threads) sharing it
    AddrRegion*[RT_MAX_CHUNKS] chunks;
}
static assert(RegionTable.sizeof <= 4096);

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

    // Virtual address space regions: ONE table per address space, shared by its threads (see
    // RegionTable below).  null until the task maps something.
    RegionTable* rtab;

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
__gshared ulong[64][MAX_TASKS] g_sigFlags;      // sa_flags (SA_ONSTACK, SA_SIGINFO, ...)

// Signal dispositions belong to the PROCESS, not the thread (CLONE_SIGHAND): every table above is
// indexed by the process leader, so a handler installed on one thread runs on any of them.  They
// used to be per thread, and clone() did not copy them, so a signal meeting any thread but the one
// that installed the handlers took the default action -- for a Go program, every M but the first.
public int sigProc(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return tid;
    const int l = g_tasks[tid].processLeaderTid;
    return (l > 0 && l < MAX_TASKS && g_tasks[l].active) ? l : tid;
}

// Signals whose default action is to IGNORE them.  With no handler they are dropped when they are
// raised (POSIX), never queued -- a queued SIGCHLD used to be "delivered" by terminating the task.
public bool sigDefaultIgnores(int sig) {
    return sig == 17 /*SIGCHLD*/ || sig == 18 /*SIGCONT*/ || sig == 23 /*SIGURG*/ || sig == 28 /*SIGWINCH*/;
}

// Does `tid`'s process have a handler installed for `sig` (not SIG_DFL, not SIG_IGN)?
public bool sigHasHandler(int tid, int sig) {
    if (sig <= 0 || sig >= 64) return false;
    const int p = sigProc(tid);
    return (g_taskSigCustom[p] & (1UL << sig)) != 0 && g_sigHandler[p][sig] != 0;
}

// Does `tid`'s process ignore `sig` (SIG_IGN, or SIG_DFL for a default-ignore signal)?
public bool sigIgnored(int tid, int sig) {
    if (sig <= 0 || sig >= 64) return true;
    const int p = sigProc(tid);
    const bool custom = (g_taskSigCustom[p] & (1UL << sig)) != 0;
    if (custom) return g_sigHandler[p][sig] == 0;        // SIG_IGN
    return sigDefaultIgnores(sig);
}

// sigaltstack, per THREAD (each thread has its own signal stack).  flags: SS_DISABLE = 2.
__gshared ulong[MAX_TASKS] g_sigAltSp;
__gshared ulong[MAX_TASKS] g_sigAltSize;
__gshared bool[MAX_TASKS]  g_sigAltOn;

// A4: per-task program name (basename of the exec'd binary), for /proc/<pid> comm.
// Set by execveTask / forkTask in kernel_main.d; read by posix.d's procfs.
__gshared const(char)*[MAX_TASKS] g_taskExecName;
// appgate: the objstore app a task is running (index + 1; 0 = not an objstore app).  The app's grant
// key is "store:<name>", and a /proc/self/exe re-exec must keep it (execName is just "store-app").
__gshared ushort[MAX_TASKS] g_taskStoreApp1;
// Installed-package provenance of the task's image: 1-based package record (0 = not a package
// program), so a /proc/self/exe re-exec keeps its appgate key ("pkg:<name>").
__gshared ushort[MAX_TASKS] g_taskPkg1;

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
        if (sigIgnored(t, sig)) continue;
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

    // appgate: self-healing a missing namespace with nsAlloc() gives a ROOT namespace ("/" with every
    // right).  That is right for the kernel's own tasks and wrong for a domain-bound one, which would be
    // unconfined by the repair -- so a domain task with no live namespace stays at 0, and every
    // absolute open then fails closed (namespaceCheckOpen resolves nothing against namespace 0).
    if (leader != tid) {
        if (objGet(g_tasks[leader].namespaceObjId) is null)
            g_tasks[leader].namespaceObjId = (g_tasks[leader].domainObjId != 0) ? 0 : nsAlloc();
        task.namespaceObjId = g_tasks[leader].namespaceObjId; // thread shares
        return;
    }
    if (objGet(task.namespaceObjId) is null)
        task.namespaceObjId = (task.domainObjId != 0) ? 0 : nsAlloc();
}

// ── appgate: the namespace a task gets when it execs (kernel_main.d execveTask) ─────────────────
//
// Split in two so the one step that can fail runs BEFORE the exec is committed: a failed clone must
// return an error to the still-intact caller, never let the new image run with the namespace it
// inherited (for a kernel spawn or a Hyprland child that is a clone of the ROOT namespace).

// Prepare: a private clone of domain `target`'s namespace (building it on first use -- a domain created
// from the GUI has none until then).  target 0 = unconfined, nothing to prepare.
public bool taskPrepareExecNs(uint target, out uint newNs) {
    newNs = 0;
    if (target == 0) return true;
    auto d = domainById(target);
    if (d is null || d.isTemplate) return false;
    if (d.nsObjId == 0) domainBuildNamespace(target);
    if (d.nsObjId == 0) return false;
    newNs = nsCloneStrict(d.nsObjId);
    return newNs != 0;
}

// Commit (cannot fail): install the prepared namespace + the domain label + the domain's identity, and
// release the namespace the task had -- unless someone else still holds it (a vfork parent sharing
// it, threads), or it is PID1's or a domain's template namespace.  Without the release every exec
// leaked one of the NS_MAX namespace slots, and exhausting them made later binds fail.
public void taskCommitExecNs(int tid, uint target, uint newNs) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    const uint old = g_tasks[tid].namespaceObjId;
    if (target == 0) {
        g_tasks[tid].namespaceObjId = g_tasks[0].namespaceObjId;   // unconfined: PID1's root view
        g_tasks[tid].domainObjId    = 0;                           // identity unchanged, as before
    } else {
        auto d = domainById(target);
        g_tasks[tid].namespaceObjId = newNs;
        g_tasks[tid].domainObjId    = target;
        if (d !is null && d.identityObjId != 0) g_tasks[tid].identityObjId = d.identityObjId;
    }
    releasePrivateNs(tid, old);
}

private void releasePrivateNs(int tid, uint ns) {
    if (ns == 0 || ns == g_tasks[tid].namespaceObjId) return;
    if (ns == g_tasks[0].namespaceObjId) return;
    foreach (ref d; g_domains) if (d.inUse && d.nsObjId == ns) return;   // a domain's template ns
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (i == tid) continue;
        if (g_tasks[i].active && !g_tasks[i].exited && g_tasks[i].namespaceObjId == ns) return;
    }
    nsRelease(ns);
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
    // A new task has no signal stack (a new thread starts with it disabled; fork copies the
    // parent's afterwards).  A reused slot kept its last occupant's, and a thread whose stack
    // happened to lie in that stale range got EPERM from sigaltstack -- which Go answers by
    // crashing on purpose.
    g_sigAltOn[i] = false; g_sigAltSp[i] = 0; g_sigAltSize[i] = 0;
    // appgate: a fresh slot runs no image yet.  execveTask reads the PREVIOUS image as the launcher
    // (the app grid's children are restricted), so a kernel spawn must not inherit the name of
    // whatever last occupied this slot.
    g_taskExecName[i]  = null;
    g_taskStoreApp1[i] = 0;
    g_taskPkg1[i] = 0;
    g_tasks[i].active = true;
    g_tasks[i].processLeaderTid = i;
    g_tasks[i].mmapNext = 0x700000000000UL;
    g_tasks[i].fdTabId = i;
    g_tasks[i].capTabId = i;
    objEnsureTask(i);
    return i;
}

// Slots are handed out round-robin from just past the last one, not lowest-free-first.  The slot is
// the Linux PID (linuxPidForTask), and lowest-free-first gave an exiting process's PID to the very
// next one: busybox `timeout`'s watchdog polls kill(pid, 0) to see whether its command is still
// running, kept seeing the NEW occupant of the slot, and SIGTERMed it (it killed a Go test binary that
// started after the node it was guarding had long exited).  Linux allocates PIDs incrementally for
// the same reason; with 256 slots a PID now comes back only after the others have been used.
private __gshared int g_taskNextSlot = 1;

int allocTask() {
    foreach (k; 0 .. MAX_TASKS - 1) {
        const int i = 1 + (g_taskNextSlot - 1 + k) % (MAX_TASKS - 1);
        if (!g_tasks[i].active) {
            g_taskNextSlot = i + 1 >= MAX_TASKS ? 1 : i + 1;
            return initTaskSlot(i);
        }
    }
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
        rtabDetach(g_tasks[tid]);
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

// --- region table plumbing --------------------------------------------------------------------
// Table pages are kernel bookkeeping: charged to the kernel, not to whichever task asked.
private ulong rtabPage() {
    const uint saved = physActiveUntyped();
    physSetActiveUntyped(g_tasks[0].untypedObjId);
    const ulong ph = alloc_phys_page();              // zeroed
    physSetActiveUntyped(saved);
    return ph;
}
private RegionTable* rtabAlloc() {
    const ulong ph = rtabPage();
    if (ph == 0) return null;
    auto t = cast(RegionTable*)(ph + hhdm_offset);
    t.refs = 1;
    return t;
}
private bool rtabGrow(RegionTable* t) {
    if (t.nchunks >= RT_MAX_CHUNKS) return false;
    const ulong ph = rtabPage();
    if (ph == 0) return false;
    t.chunks[t.nchunks++] = cast(AddrRegion*)(ph + hhdm_offset);
    return true;
}
// Room for one more entry.
private bool rtabRoom(RegionTable* t) {
    return t.count < t.nchunks * RT_PER_CHUNK || rtabGrow(t);
}
int regionCountOf(ref Task task) { return task.rtab is null ? 0 : task.rtab.count; }
ref AddrRegion regionAt(ref Task task, int i) {
    return task.rtab.chunks[i / RT_PER_CHUNK][i % RT_PER_CHUNK];
}
bool rtabEnsure(ref Task task) {
    if (task.rtab is null) task.rtab = rtabAlloc();
    return task.rtab !is null;
}
// A thread (CLONE_VM) shares its creator's table.
void rtabShare(ref Task child, ref Task parent) {
    rtabDetach(child);
    if (!rtabEnsure(parent)) return;
    child.rtab = parent.rtab;
    ++child.rtab.refs;
}
// fork: the child gets its own copy (its own region objects, made lazily).
bool rtabCopy(ref Task child, ref Task parent) {
    rtabDetach(child);
    const int n = regionCountOf(parent);
    if (n == 0) return true;
    if (!rtabEnsure(child)) return false;
    foreach (i; 0 .. n) {
        if (!rtabRoom(child.rtab)) return false;
        auto d = &regionAt(child, child.rtab.count++);
        *d = regionAt(parent, i);
        d.objId = 0;
        d.vmoRetained = false;
    }
    return true;
}
// Drop this task's reference; the last one frees the table and its region objects.  (The frames the
// regions map are the caller's business -- exit/exec release them before detaching.)
void rtabDetach(ref Task task) {
    auto t = task.rtab;
    task.rtab = null;
    if (t is null || --t.refs > 0) return;
    foreach (i; 0 .. t.count)
        objReleaseRegion(&t.chunks[i / RT_PER_CHUNK][i % RT_PER_CHUNK]);
    foreach (c; 0 .. t.nchunks) free_phys_page(cast(ulong)t.chunks[c] - hhdm_offset);
    free_phys_page(cast(ulong)t - hhdm_offset);
}

// Add a virtual address region to a task.
AddrRegion* addRegion(ref Task task, ulong start, ulong end,
                      RegionType type, RegionPerms perms, ulong physBase = 0,
                      bool owned = false, uint vmoObjId = 0) {
    if (!rtabEnsure(task) || !rtabRoom(task.rtab)) {
        klog("[task] addRegion: full\n");
        return null;
    }
    auto r          = &regionAt(task, task.rtab.count++);
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

// Take [start, end) out of a task's region table: an entry wholly inside is dropped (swap-remove),
// one the range cuts is trimmed to what is left, and one it punches a hole in is split in two.
// Called by munmap so the per-task table doesn't leak an entry per mapping -- Mesa/softpipe churn
// many short-lived maps, and aligned allocators (Rust's, wgpu's) map size+alignment and unmap
// the head and tail, so their mappings are only ever unmapped in PIECES.  Dropping just the
// wholly-contained entries leaked one per such allocation until "addRegion: full" failed the
// next mmap (ratty died "memory allocation of 118272 bytes failed" a minute after start).
void removeRegion(ref Task task, ulong start, ulong end) {
    if (end <= start || task.rtab is null) return;
    auto tab = task.rtab;
    int n = tab.count;
    int i = 0;
    while (i < n) {
        auto r = &regionAt(task, i);
        if (r.end <= start || r.start >= end) { ++i; continue; }      // untouched
        if (r.start >= start && r.end <= end) {
            objReleaseRegion(r);
            *r = regionAt(task, n - 1);              // swap-remove
            // The swap moves a LIVE region to a new ADDRESS.  Its MemRegion object still records
            // the old slot in `impl`, so the next objEnsureRegion() sees impl != &regions[i],
            // treats the object as stale, and -- because its release is guarded on impl MATCHING
            // -- silently orphans it and allocates another.  That leaks one MemRegion per unmap.
            //
            // Mesa/softpipe churns many short-lived maps (see the note above), so this drains the
            // 8192-object table during ordinary desktop work: the installer reached ~5%% and then
            // every open/read/write failed EBADF, because publishActiveFd could no longer get an
            // object and cleared the fd's capability.  The symptom is nowhere near the cause.
            if (i != n - 1) {
                auto mh = objGet(r.objId);
                if (mh !is null && mh.type == ObjType.MemRegion)
                    mh.impl = cast(void*)r;
            }
            --n;
            tab.count = n;
            continue;                                 // re-check swapped-in entry
        }
        if (r.start < start && r.end > end) {
            // A hole in the middle: this entry keeps the head, a new one takes the tail.  With the
            // table full it stays whole (still correct: its pages are unmapped all the same, and a
            // live tail must stay listed -- fork copies and exit frees only what is listed).
            tab.count = n;
            if (!rtabRoom(tab)) { ++i; continue; }
            auto t = &regionAt(task, n++);
            r = &regionAt(task, i);
            *t = *r;
            t.start = end;
            if (t.physBase != 0) t.physBase += end - r.start;
            t.objId = 0; t.vmoRetained = false;       // its own object and VMO reference
            objEnsureRegion(t);
            r.end = start;
        } else if (r.start < start) {
            r.end = start;                            // the range took its tail
        } else {
            if (r.physBase != 0) r.physBase += end - r.start;
            r.start = end;                            // the range took its head
        }
        ++i;
    }
    tab.count = n;
}

// Threads share one table now, so these are the plain operations; the names stay for callers.
void removeRegionShared(int tid, ulong start, ulong end) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    removeRegion(g_tasks[tid], start, end);
}
AddrRegion* findRegionShared(int tid, ulong vaddr) {
    if (tid < 0 || tid >= MAX_TASKS) return null;
    return findRegion(g_tasks[tid], vaddr);
}
bool regionOwnedAtShared(int tid, ulong vaddr) {
    if (tid < 0 || tid >= MAX_TASKS) return false;
    return regionOwnedAt(g_tasks[tid], vaddr);
}

void clearRegions(ref Task task) {
    rtabDetach(task);
}

// The main thread's user stack: exec (kernel_main.d) maps it eagerly at this fixed address in every
// process.  RLIMIT_STACK reports 8 MiB (posix.d prlimit64); for an Android binary exec adds a
// demand-zero region directly below the eager pages so that claim is backed -- bionic hands ART
// [top - RLIMIT_STACK, top) as the main thread's stack and ART recurses within it.
enum ulong USER_STACK_BASE     = 0x700000000000UL;
enum ulong USER_STACK_PAGES    = 256;                            // 1 MiB, eagerly mapped
enum ulong USER_STACK_TOP      = USER_STACK_BASE + USER_STACK_PAGES * 4096;
enum ulong USER_STACK_RLIMIT   = 8UL * 1024 * 1024;

// The main-thread stack of `tid`'s address space as /proc/<pid>/maps reports it: the eager pages plus
// the demand-zero extension below them, when there is one.
void mainStackRange(int tid, out ulong lo, out ulong hi) {
    lo = USER_STACK_BASE;
    hi = USER_STACK_TOP;
    auto below = findRegionShared(tid, USER_STACK_BASE - 1);
    if (below !is null && below.type == RegionType.AllocateOnDemand && below.end == USER_STACK_BASE)
        lo = below.start;
}

// True when NO region of task `tid`'s address space overlaps [start, end).  Lets a non-MAP_FIXED
// mmap honor its caller's address hint: Linux places a hinted mapping there when the range is free
// and elsewhere otherwise.  ART relies on this to load its boot image at the fixed base the image
// was compiled for (its contents hold absolute pointers relative to that base), so a hint we ignore
// becomes "Failed to mmap at expected address" and ART drops to a boot-image-less, non-working mode.
bool rangeFreeShared(int tid, ulong start, ulong end) {
    if (tid < 0 || tid >= MAX_TASKS) return false;
    if (end <= start) return false;
    auto tab = g_tasks[tid].rtab;
    if (tab is null) return true;
    foreach (c; 0 .. tab.nchunks) {
        auto ch = tab.chunks[c];
        const int lim = (c + 1) * RT_PER_CHUNK <= tab.count ? RT_PER_CHUNK : tab.count - c * RT_PER_CHUNK;
        foreach (k; 0 .. lim) {
            auto r = &ch[k];
            if (r.start < end && start < r.end) return false;   // [start,end) overlaps a live region
        }
        if ((c + 1) * RT_PER_CHUNK >= tab.count) break;
    }
    return true;
}

// Find the region that contains vaddr (or null)
AddrRegion* findRegion(ref Task task, ulong vaddr) {
    auto tab = task.rtab;
    if (tab is null) return null;
    foreach (c; 0 .. tab.nchunks) {
        auto ch = tab.chunks[c];
        const int lim = (c + 1) * RT_PER_CHUNK <= tab.count ? RT_PER_CHUNK : tab.count - c * RT_PER_CHUNK;
        foreach (k; 0 .. lim) {
            auto r = &ch[k];
            if (vaddr >= r.start && vaddr < r.end) return r;
        }
        if ((c + 1) * RT_PER_CHUNK >= tab.count) break;
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
        int n = regionCountOf(*task);
        for (int i = 0; i < n; ++i) {
            auto r = &regionAt(*task, i);
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
        for (int i = 0; i < regionCountOf(*task); ++i) {
            auto r = &regionAt(*task, i);
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
