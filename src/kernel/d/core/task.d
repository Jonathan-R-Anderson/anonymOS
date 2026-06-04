module core.task;

import core.io;
import core.globals;
import memory.mm;
import core.objmgr : ObjType, objAlloc, objRetain, objRelease, objGet,
                     objBeginSweep, objMark, objSweepType; // Phase 3/4

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

enum MAX_TASKS   = 64;
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
}

__gshared Task[MAX_TASKS] g_tasks;

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
    task.objId = 0;
    task.processObjId = 0;
    task.parentObjId = 0;
    task.processLeaderTid = 0;
}

// Allocate a task slot (id > 0 reserved for non-init tasks)
int allocTask() {
    for (int i = 1; i < MAX_TASKS; i++) {
        if (!g_tasks[i].active) {
            g_tasks[i] = Task.init;
            g_tasks[i].active = true;
            g_tasks[i].processLeaderTid = i;
            g_tasks[i].mmapNext = 0x700000000000UL;
            g_tasks[i].fdTabId = i;
            g_tasks[i].capTabId = i;
            objEnsureTask(i);
            return i;
        }
    }
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
        objMark(g_tasks[t].objId);
        objMark(g_tasks[t].processObjId);
    }
    objSweepType(ObjType.Process);
    objSweepType(ObjType.Thread);
}
