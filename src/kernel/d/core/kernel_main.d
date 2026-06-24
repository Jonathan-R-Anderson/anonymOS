// D replacement for the Haskell kernel (hosMain + kernelize + dispatch).
// Called from bootstrap_kernel() after hardware init; never returns.
module core.kernel_main;

import core.task;
import core.hoscall : hosQuery, HOS_SYS_QUERY, hosClearHandles;   // Track B0 / Z4a native ABI
import core.addrspace;
import core.elf_loader;
import core.io;
import core.globals;
import core.exports :
    phys_to_virt, copy_phys_page,
    alloc_from_regions,
    curUserSpaceState, kernelState,
    x64TrapErrorCode,
    x64LastSyscallRax, x64LastSyscallRdi, x64LastSyscallRsi,
    x64LastSyscallRdx, x64LastSyscallR10, x64LastSyscallR8, x64LastSyscallR9,
    x64LastSyscallRip,
    x64_set_user_state_word, x64_get_user_state_word,
    g_current_task_id,
    d_store_task_fsbase, d_apply_task_fsbase,
    d_do_cleartid,
    linux_seed_initial_stack,
    linux_seed_initial_stack_with_args,
    x64_ready_for_userspace,
    x64_setup_full_idt,
    setupSysCalls,
    g_module_count, g_mboot_modules, multiboot_module_t;
import memory.mm;
import arch.x86_64.arch;
import arch.x86_64.bootstrap : g_fb, g_terminal;

// Linux syscall implementations already in D
import core.syscalls.posix;
import core.objmgr : objStats; // Phase 2: object-table runtime stats (objReconcileFds comes via core.syscalls.posix)
import core.cap : capTableSetActive, capTableClear, capStats,
                  capInstallIn, CAP_INVALID, CAP_RIGHT_RETYPE;
import core.untyped : untypedRootInit, untypedCreateProcess, untypedSelfTest,
                      untypedStats, UNTYPED_CAP_HANDLE;
import core.ipc : ipcSelfTest, ipcStats; // Phase 7: IPC router proof
import core.device : deviceRegistryInit, deviceSelfTest, deviceStats; // Phase 8
import core.namespace : nsSelfTest, nsStats, nsClone; // Phase 9: per-process namespaces
import core.user : userRegistryInit, userSelfTest, userStats, userDefaultObjId,
                  userSetActiveSubject, USER_RIGHT_LOGIN, USER_RIGHT_SPAWN; // Phase 10 / IR-P3
import core.admin : adminInstallInitCaps, adminSelfTest, adminStats; // IR-P3 typed admin caps
import core.store : storeSelfTest, storeStats, storeMountSystem; // IR-P4 immutable store
import core.update : updateInit, updateSelfTest, updateStats; // IR-P6 A/B update + rollback
import drivers.block.disk : diskInit, diskSelfTest; // A5/F4 persistence: SATA disk layer
import core.objstore : objstoreMount, objstoreResolveExecPath, objstoreAppRights,
                       objstoreLoadExec; // F4/F4.2 persisted object store (/objects/apps) + launch
import core.crypto : cryptoSelfTest, cryptoStats; // IR-P8.1/8.2 SHA-256/HMAC + measured boot
import core.hardening : hardeningSelfTest, hardeningStats; // IR-P8.3/8.4 W^X + cap audit
import core.distos : distosSelfTest, distosStats; // IR-P9 distributed refs + macaroons + dist store
import core.secipc : secipcSelfTest, secipcStats; // SECURE_IPC P1 identity + descriptors + routing gate
import core.libsecipc : libsecipcSelfTest; // SECURE_IPC P0 crypto+transport foundation (X25519/AEAD/HKDF)
import core.secsession : secsessionSelfTest, secsessionStats,
                        seclifeSelfTest; // SECURE_IPC P2 sessions / P3 lifecycle
import core.secobj : secobjSelfTest, secobjStats; // SECURE_IPC P4 object-tree + Linux shim
import core.sechard : sechardSelfTest, sechardStats; // SECURE_IPC P5 hardening + parser fuzz
import core.servicemgr : serviceManagerInit, serviceSelfTest, serviceStats,
                        servicePhase5SelfTest; // Phase 10 / IR-P5 service management
import core.window : windowRegistryInit, windowSelfTest, windowStats; // Phase 11
import core.identity : identityInitDefaults, identityInitLaunchRules, identityByName,
                       identitySelfTest, idprocSelfTest, identityStats, identityNamePrint,
                       identityById; // IDENTITY_DOMAIN P2/P3 (+ F4.2 launch cap-gate)
import core.idns : idnsInitRoots, idnsSelfTest, idnsStats; // IDENTITY_DOMAIN P4 per-identity namespaces
import core.idipc : idipcInit, idipcSelfTest, idipcStats; // IDENTITY_DOMAIN P5 cross-identity IPC policy
import core.idwin : idwinInit, idwinSelfTest, idwinStats; // IDENTITY_DOMAIN P6 unspoofable window identity borders
import display.compositor.compositor : compositorIdentitySelfTest; // GUI: trusted identity borders
import core.linuxobj : linuxObjectInit, linuxEnabled, linuxNoteTranslate,
                       linuxNoteBlocked, linuxNoteElfLoad, linuxSelfTest,
                       linuxStats; // Phase 12: Linux-compat object subtree
import core.linuxpers : linuxPersSelfTest, linuxPersStats; // IR-P7: Linux personality → cap/ns ops
import core.census : kernelCensusReport, kernelCensusStats; // Phase 13: six-pillar census
import core.org : orgInit, orgSelfTest, orgStats, orgAudit, orgIntegReport,
                  orgApiSelfTest, orgCycleSelfTest, orgGcSelfTest,
                  orgSecuritySelfTest, orgVizSelfTest,
                  orgLinuxSelfTest; // ORG P2–P10 (validator → daemon)
import core.cap : capRevokeClosureSelfTest; // ORG P7.2
import core.org_validator : orgValidatorInit, orgValidatorTick,
                            orgValidatorSelfTest, orgValidatorStats; // ORG P8
import core.audit : auditStats; // ORG P8.2
import core.org_dist : orgDistSelfTest, orgDistTick, orgDistStats; // ORG P11
import core.org_test : orgTestSuite; // ORG P12: invariant/fuzz/scale test suite
import core.syscalls.mmap : sys_munmap, sys_mprotect;
import core.ticks : increment_ticks, get_ticks, pitMs;
import core.random;

extern (C) @nogc nothrow:

extern (C) ulong x64ReadCR2() @nogc nothrow;
extern (C) ulong x64ReadCR3() @nogc nothrow;
extern (C) void  x64WriteCR3(ulong) @nogc nothrow;

// Assembly context switcher — defined in context.S
extern (C) ulong x64SwitchToUserspace(void* userState, void* kernelState) @nogc nothrow;

// ------------------------------------------------------------------
// Helpers: load / save task register state from/to curUserSpaceState
// ------------------------------------------------------------------

private void loadTaskState(ref Task task) {
    // reason word at curUserSpaceState[0]
    *cast(ulong*)&curUserSpaceState[0] = REASON_TRAP;

    // registers at curUserSpaceState[8..144]
    auto dst = cast(ulong*)(&curUserSpaceState[0] + 8);
    for (uint i = 0; i < NUM_REGS; i++)
        dst[i] = task.regs[i];

    // A freshly created task starts with a zero-filled FXSAVE image, whose MXCSR
    // (offset 24) is 0 — meaning every SSE floating-point exception is UNMASKED.
    // On a real FPU (KVM) the first invalid/overflow op (e.g. Hyprgraphics' OkLab
    // colour math) then raises #XM and kills the task; QEMU's TCG software FPU
    // happened to tolerate it.  Seed an uninitialised image with the standard
    // masked default (MXCSR 0x1F80, FCW 0x037F) so no FP op ever traps.
    {
        auto mxcsr = cast(uint*)(task.sseState.ptr + 24);
        if (*mxcsr == 0) {
            *mxcsr = 0x1F80;
            *cast(ushort*)(task.sseState.ptr + 0) = 0x037F; // x87 control word
        }
    }

    // SSE state at curUserSpaceState[8 + 0x90]
    auto sseDst = cast(ubyte*)(&curUserSpaceState[0] + 8 + 0x90);
    auto sseSrc = task.sseState.ptr;
    for (int i = 0; i < 512; i++)
        sseDst[i] = sseSrc[i];
}

private void saveTaskState(ref Task task) {
    // registers
    auto src = cast(ulong*)(&curUserSpaceState[0] + 8);
    for (uint i = 0; i < NUM_REGS; i++)
        task.regs[i] = src[i];

    // SSE state
    auto sseSrc = cast(ubyte*)(&curUserSpaceState[0] + 8 + 0x90);
    auto sseDst = task.sseState.ptr;
    for (int i = 0; i < 512; i++)
        sseDst[i] = sseSrc[i];
}

// Set RAX in the saved user state (syscall return value)
private void setReturnValue(ref Task task, ulong val) {
    task.regs[REG_RAX] = val;
}

// ------------------------------------------------------------------
// Scheduler: simple round-robin
// ------------------------------------------------------------------

private enum FUTEX_WAIT           = 0;
private enum FUTEX_WAKE           = 1;
private enum FUTEX_REQUEUE        = 3;
private enum FUTEX_CMP_REQUEUE    = 4;
private enum FUTEX_WAKE_OP        = 5;
private enum FUTEX_WAIT_BITSET    = 9;
private enum FUTEX_WAKE_BITSET    = 10;
private enum FUTEX_PRIVATE_FLAG   = 0x80;
private enum FUTEX_CLOCK_REALTIME = 0x100;
private enum uint FUTEX_BITSET_MATCH_ANY = 0xffffffffU;

__gshared bool[MAX_TASKS]  g_futexWaitActive;
__gshared ulong[MAX_TASKS] g_futexWaitUaddr;

// PERF profiling: per-task userspace CPU cycles (one quantum = one trip through
// x64SwitchToUserspace) — reveals a CPU hog starving the compositor.  Interval
// counters reset each stats dump.
__gshared ulong[MAX_TASKS] g_schedCyc;
__gshared ulong[MAX_TASKS] g_schedN;

// PERF: cooperative poll/epoll sleep.  A task that polls with nothing ready and a
// non-zero timeout is parked (waiting=true) instead of being re-run every
// round-robin cycle (which busy-spins the single core, starving the compositor).
// It is re-checked when woken: every PIT tick (≤1 ms latency) and on input IRQs.
__gshared bool[MAX_TASKS]  g_pollBlocked;
__gshared ulong[MAX_TASKS] g_pollDeadline;   // pitMs deadline; 0 = infinite (fd-only)

// The idle task: a userspace PAUSE-spinner the scheduler runs ONLY when every real
// task is parked, so the kernel isn't re-running parked pollers' epoll scans at full
// rate (which saturated the kernel and starved the compositor).  -1 until spawned.
__gshared int g_idleTid = -1;

// Wake parked pollers so they re-check their fds.  Called from the PIT tick and
// input IRQs.  Clearing `waiting` lets the scheduler pick them; they re-run their
// poll/epoll and either return (fd ready / timed out) or re-park.
private void wakePollers() @nogc nothrow {
    foreach (i; 0 .. MAX_TASKS) {
        if (g_pollBlocked[i] && g_tasks[i].active && !g_tasks[i].exited)
            g_tasks[i].waiting = false;
    }
}
__gshared int[MAX_TASKS]   g_futexWaitVal;
__gshared uint[MAX_TASKS]  g_futexWaitBitset;
__gshared ulong g_futexLogCount = 0;
__gshared ulong g_futexWakeLogCount = 0;
__gshared bool g_guiClientAutostartEnabled = false;
__gshared bool g_guiClientStarted = false;
__gshared bool g_guiClientListenerSeen = false;
__gshared ulong g_guiClientLaunchTick = 0;
private enum ulong GUI_CLIENT_SETTLE_TICKS = 6000;
private enum ulong USER_MAIN_PIE_BASE = 0x550000000000UL;
private enum ulong USER_INTERP_BASE   = 0x5A0000000000UL;

private bool futexWaitMatches(int tid, ulong uaddr, uint wakeBits) {
    if (tid < 0 || tid >= MAX_TASKS) return false;
    if (!g_futexWaitActive[tid]) return false;
    if (g_futexWaitUaddr[tid] != uaddr) return false;
    return (g_futexWaitBitset[tid] & wakeBits) != 0;
}

private void clearFutexWait(int tid, long ret) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    g_futexWaitActive[tid] = false;
    g_futexWaitUaddr[tid] = 0;
    g_futexWaitVal[tid] = 0;
    g_futexWaitBitset[tid] = 0;

    auto t = &g_tasks[tid];
    if (t.active && !t.exited) {
        t.waiting = false;
        t.regs[REG_RAX] = cast(ulong)ret;
    }
}

private void installTaskUntypedCap(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    if (task.untypedObjId == 0) return;
    capInstallIn(task.capTabId, UNTYPED_CAP_HANDLE, task.untypedObjId,
                 CAP_RIGHT_RETYPE, CAP_INVALID);
}

private bool refreshFutexWaiter(int tid) {
    if (tid < 0 || tid >= MAX_TASKS || !g_futexWaitActive[tid]) return false;

    auto t = &g_tasks[tid];
    if (!t.active || t.exited) {
        clearFutexWait(tid, -4); // EINTR-like cleanup for dead slots
        return false;
    }

    ulong uaddr = g_futexWaitUaddr[tid];
    if (t.pml4Phys == 0 || findRegion(*t, uaddr) is null) {
        clearFutexWait(tid, -4);
        return false;
    }

    ulong savedCr3 = x64ReadCR3();
    bool switchedCr3 = savedCr3 != t.pml4Phys;
    if (switchedCr3) x64WriteCR3(t.pml4Phys);
    int cur = *cast(int*)uaddr;
    if (switchedCr3) x64WriteCR3(savedCr3);
    if (cur != g_futexWaitVal[tid]) {
        klog("[futex-unblock] t="); klog_hex(cast(ulong)tid);
        klog(" u="); klog_hex(uaddr);
        klog(" want="); klog_hex(cast(ulong)cast(uint)g_futexWaitVal[tid]);
        klog(" now="); klog_hex(cast(ulong)cast(uint)cur);
        klog("\n");
        clearFutexWait(tid, 0);
        return true;
    }
    return false;
}

private uint futexWakeAddress(ulong uaddr, uint maxWake, uint wakeBits, int wakerTid) {
    if (uaddr == 0 || maxWake == 0 || wakeBits == 0) return 0;

    uint woke = 0;
    for (int i = 0; i < MAX_TASKS && woke < maxWake; i++) {
        if (!futexWaitMatches(i, uaddr, wakeBits)) continue;
        clearFutexWait(i, 0);
        woke++;
        klog("[futex-wake-one] waker="); klog_hex(cast(ulong)wakerTid);
        klog(" waiter="); klog_hex(cast(ulong)i);
        klog(" u="); klog_hex(uaddr);
        klog("\n");
    }
    return woke;
}

private uint futexRequeueAddress(ulong from, ulong to, uint maxRequeue, uint wakeBits) {
    if (from == 0 || to == 0 || maxRequeue == 0 || wakeBits == 0) return 0;

    uint moved = 0;
    for (int i = 0; i < MAX_TASKS && moved < maxRequeue; i++) {
        if (!futexWaitMatches(i, from, wakeBits)) continue;
        g_futexWaitUaddr[i] = to;
        moved++;
        klog("[futex-requeue-one] waiter="); klog_hex(cast(ulong)i);
        klog(" from="); klog_hex(from);
        klog(" to="); klog_hex(to);
        klog("\n");
    }
    return moved;
}

private void scheduleNext() {
    for (int i = 0; i < MAX_TASKS; i++)
        refreshFutexWaiter(i);

    ulong cur = g_current_task_id;
    // Round-robin over ALL task slots including 0: task 0 is the main userspace
    // process, so once it blocks (poll/futex/vfork) it must be reschedulable like
    // any other.  (Previously slot 0 was skipped, which permanently starved the
    // main thread whenever it yielded.)
    for (uint i = 1; i <= MAX_TASKS; i++) {
        uint next = cast(uint)((cur + i) % MAX_TASKS);
        if (cast(int)next == g_idleTid) continue;   // idle is a last resort only
        auto t = &g_tasks[next];
        if (t.active && !t.exited && !t.waiting) {
            g_current_task_id = next;
            return;
        }
    }
    // Nothing runnable: check for waiting tasks that might now be unblocked
    for (uint i = 0; i < MAX_TASKS; i++) {
        auto t = &g_tasks[i];
        if (t.active && !t.exited && t.waiting) {
            // poll whether the waited-for child has exited
            bool found = false;
            if (t.waitingForPid == -1) {
                for (uint j = 0; j < MAX_TASKS; j++)
                    if (t.childExited[j]) { found = true; break; }
            } else {
                uint c = cast(uint)t.waitingForPid;
                if (c < MAX_TASKS && t.childExited[c]) found = true;
            }
            if (found) {
                t.waiting = false;
                g_current_task_id = i;
                return;
            }
        }
    }
    // Nothing else runnable: rather than spin the run loop with interrupts masked
    // (which would freeze the PIT/input IRQs and deadlock the parked poll/epoll
    // sleepers), wake them so at least one becomes runnable and the system stays
    // live to service interrupts.  During active work the compositor is runnable
    // and chosen above, so the parked pollers keep yielding it the core — they are
    // only force-woken here when truly *everyone* is idle.
    // Every real task is parked.  Run the dedicated idle task (a cheap userspace
    // PAUSE-spinner) so the PIT/input IRQs keep firing WITHOUT re-running the parked
    // pollers' expensive epoll scans — that re-run was saturating the kernel (~190k
    // scans/s) and starving the compositor.  The pollers stay parked until a real
    // event (input IRQ / sendmsg) or the ~8 ms timer wake.
    if (g_idleTid > 0 && g_tasks[g_idleTid].active && !g_tasks[g_idleTid].exited
        && !g_tasks[g_idleTid].waiting) {
        g_current_task_id = cast(ulong)g_idleTid;
        return;
    }
    // No idle task yet — fall back to waking one parked poller to keep IRQs alive.
    for (uint i = 1; i <= MAX_TASKS; i++) {
        uint next = cast(uint)((cur + i) % MAX_TASKS);
        if (g_pollBlocked[next] && g_tasks[next].active && !g_tasks[next].exited
            && g_tasks[next].waiting) {
            g_tasks[next].waiting = false;
            g_current_task_id = next;
            return;
        }
    }
    // All tasks gone or stuck — just keep running the current one
}

// ------------------------------------------------------------------
// Task exit
// ------------------------------------------------------------------

private void exitTask(int tid, int code) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    if (g_futexWaitActive[tid])
        clearFutexWait(tid, -4); // EINTR-like cleanup for the exiting waiter

    auto t = &g_tasks[tid];
    // Z1: snapshot the Linux pid NOW, before any cleanup below resets processLeaderTid;
    // the parent-notify further down stores it for wait4 to return (zsh matches on it).
    const int exitLinuxPid = linuxPidForTask(tid);
    t.exited   = true;
    t.exitCode = code;
    g_pollBlocked[tid] = false;   // PERF: drop any parked poll/epoll state
    if (tid >= 0 && tid < MAX_TASKS) {
        g_taskExecModPhys[tid] = 0;                 // A4: clear exe info
        g_taskPgid[tid] = 0; g_taskSigCustom[tid] = 0; g_taskPendingSig[tid] = 0;
        g_sigHandler[tid][] = 0; g_sigRestorer[tid][] = 0;   // Z1: clear signal handlers
    }
    if (tid == g_idleTid) g_idleTid = -1;   // idle task died — re-spawn next loop
    objReleaseTask(tid);

    // Close the dying task's fds so socket PEERS see the hangup — without this a
    // Wayland client's exit never reaches Weston, so a closed window's surface is
    // never destroyed and its pixels linger on screen.  Skipped while a live thread
    // still shares the fd table (CLONE_VM); fork copies the table (own fdTabId), so
    // the refcount-aware close only hangs up a peer when the last holder goes.
    {
        bool fdTabShared = false;
        for (int i = 0; i < MAX_TASKS; i++) {
            if (i == tid) continue;
            if (g_tasks[i].active && !g_tasks[i].exited && g_tasks[i].fdTabId == t.fdTabId) {
                fdTabShared = true; break;
            }
        }
        if (!fdTabShared) taskCloseAllFds(t.fdTabId);
    }
    bool capTableStillShared = false;
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (i != tid && g_tasks[i].active && !g_tasks[i].exited &&
            g_tasks[i].capTabId == t.capTabId) {
            capTableStillShared = true;
            break;
        }
    }
    if (!capTableStillShared)
        capTableClear(t.capTabId);
    d_do_cleartid(cast(ulong)tid);

    // If a vfork parent is suspended on this child, resume it (the child is gone).
    resumeVforkParent(tid);

    // CLONE_CHILD_CLEARTID: zero the thread's tid word so a joining thread's
    // futex wait observes termination.  Runs in the exiting thread's context, so
    // the (shared) address space is active and the user pointer is valid.
    if (tid >= 0 && tid < MAX_TASKS && g_threadCleartidVirt[tid] != 0) {
        ulong clearTid = g_threadCleartidVirt[tid];
        *cast(int*)clearTid = 0;
        futexWakeAddress(clearTid, 1, FUTEX_BITSET_MATCH_ANY, tid);
        g_threadCleartidVirt[tid] = 0;
    }

    // Notify parent
    int parent = t.parentId;
    // parent >= 0: task 0 (the main process) can also be a parent — children of
    // it (fork/vfork) must set its childExited[] so its wait4() returns.
    if (parent >= 0 && parent < MAX_TASKS && parent != tid) {
        auto p = &g_tasks[parent];
        if (p.active) {
            p.childExited[tid]   = true;
            p.childExitCode[tid] = code;
            // The child's Linux pid snapshotted at entry (processLeaderTid is reset by the
            // cleanup above), so wait4 returns the same pid fork() gave the parent.
            g_childExitLinuxPid[tid] = exitLinuxPid;
            if (p.waiting) {
                bool unblock = false;
                if (p.waitingForPid == -1) unblock = true;
                else if (p.waitingForPid == tid) unblock = true;
                if (unblock) p.waiting = false;
            }
            // Z1: if the parent installed a SIGCHLD handler (zsh does, and waits for jobs
            // via sigsuspend+SIGCHLD rather than a blocking waitpid), raise a pending
            // SIGCHLD so the run loop invokes that handler — which reaps the child and
            // lets sigsuspend return.  Tasks without a handler use the blocking-wait path
            // (childExited above) and never see this.
            // SIGCHLD delivery is driven from rt_sigsuspend (case 130), where zsh
            // temporarily unblocks SIGCHLD — not from here, since outside sigsuspend zsh
            // keeps SIGCHLD blocked (child_block) and would queue, not reap.  The
            // childExited[] flag set above is what sigsuspendTask polls; the waiting-clear
            // below wakes the parent so it re-runs sigsuspend and delivers.
        }
    }
    // Reclaim this task's private physical pages if it is the LAST user of its
    // address space.  Threads (CLONE_VM) share pml4Phys, so freeing while a
    // sibling is still alive would corrupt the shared space — in that case we
    // leak (safe).  Only `owned` regions (anonymous / private file maps) are
    // freed; device (g_fb) / shared (memfd) maps are left intact.
    if (t.pml4Phys != 0) {
        bool sharedAS = false;
        for (int i = 0; i < MAX_TASKS; i++) {
            if (i == tid) continue;
            if (g_tasks[i].active && !g_tasks[i].exited &&
                g_tasks[i].pml4Phys == t.pml4Phys) { sharedAS = true; break; }
        }
        if (!sharedAS) {
            x64WriteCR3(t.pml4Phys);
            for (int ri = 0; ri < t.regionCount; ri++) {
                auto r = &t.regions[ri];
                if (!r.owned) continue;
                for (ulong va = r.start; va < r.end; va += 4096) {
                    ulong phys = unmap_page_hhdm(va);
                    if (phys != 0) free_phys_page(phys);
                }
            }
        }
    }
    clearRegions(*t);
    objReleaseUntyped(tid);

    klog("[kernel] task "); klog_hex(tid); klog(" exited code="); klog_hex(code); klog("\n");
    scheduleNext();
}

// ------------------------------------------------------------------
// Fork
// ------------------------------------------------------------------

private int forkTask(int parentTid) {
    int childTid = allocTask();
    if (childTid < 0) {
        klog("[fork] no free task slot\n");
        return -12; // ENOMEM
    }

    auto parent = &g_tasks[parentTid];
    auto child  = &g_tasks[childTid];
    objEnsureProcess(parentTid);

    // Copy register state; child returns 0 from fork
    for (uint i = 0; i < NUM_REGS; i++)
        child.regs[i] = parent.regs[i];
    child.regs[REG_RAX] = 0;

    for (int i = 0; i < 512; i++)
        child.sseState[i] = parent.sseState[i];

    // Copy address space regions metadata
    child.regionCount = parent.regionCount;
    for (int i = 0; i < parent.regionCount; i++) {
        child.regions[i] = parent.regions[i];
        child.regions[i].objId = 0;
        child.regions[i].vmoRetained = false;
    }

    child.brkStart   = parent.brkStart;
    child.brkCurrent = parent.brkCurrent;
    child.mmapNext   = parent.mmapNext;
    child.parentId   = parentTid;
    child.userObjId  = parent.userObjId;
    child.identityObjId = parent.identityObjId; // IDENTITY_DOMAIN §3: inherit by default
    child.untypedObjId = untypedCreateProcess(parent.untypedObjId);
    if (child.untypedObjId == 0) {
        releaseTask(childTid);
        return -12;
    }

    // Allocate new PML4 and copy kernel mappings
    uint savedUntyped = physActiveUntyped();
    physSetActiveUntyped(child.untypedObjId);
    ulong childPml4 = alloc_phys_page();
    if (childPml4 == 0) {
        physSetActiveUntyped(savedUntyped);
        releaseTask(childTid);
        return -12;
    }
    child.pml4Phys = childPml4;
    archMapKernel(childPml4);

    // Copy-on-write the parent's user pages into the child (shares frames
    // read-only instead of duplicating them — see walkAndCopyUserPages). Must
    // run while parent's CR3 is active so HHDM accesses resolve.
    walkAndCopyUserPages(parent.pml4Phys, childPml4, child);
    physSetActiveUntyped(savedUntyped);
    // The walk demoted the parent's now-shared pages to read-only; flush its TLB
    // so stale writable entries can't bypass the CoW fault on the next write.
    x64WriteCR3(parent.pml4Phys);

    // Copy FS base
    d_store_task_fsbase(cast(ulong)childTid,
                        g_task_fsbase[parentTid]);
    child.active = true;

    // The child is a new process: give it its own fd table (id = childTid) with an
    // independent copy of the parent's descriptors, so each can close() its own
    // copies (POSIX fork semantics — required by libseat's embedded seatd).
    child.fdTabId = childTid;
    child.capTabId = childTid;
    fdtabForkCopy(parent.fdTabId, childTid);
    installTaskUntypedCap(childTid);
    objEnsureTask(childTid);
    objSetProcess(childTid, childTid, parent.processObjId);
    objCloneNamespace(childTid, parentTid); // Phase 9: child gets a private namespace clone

    // Track A A4: the child runs the same binary as the parent (CoW fork), so it
    // inherits /proc/self/exe resolution (busybox standalone re-execs it for applets).
    if (parentTid >= 0 && parentTid < MAX_TASKS && childTid >= 0 && childTid < MAX_TASKS) {
        g_taskExecModPhys[childTid] = g_taskExecModPhys[parentTid];
        g_taskExecModSize[childTid] = g_taskExecModSize[parentTid];
        g_taskExecName[childTid]    = g_taskExecName[parentTid];
        // NATIVE_OBJECT_ABI §3: the native personality is inherited across fork (native
        // helpers the shell spawns stay native; a Linux fork stays Linux).
        g_taskNativeAbi[childTid]   = g_taskNativeAbi[parentTid];
        // A4: a child inherits its parent's process group + signal dispositions.
        g_taskPgid[childTid]      = g_taskPgid[parentTid];
        g_taskSigCustom[childTid] = g_taskSigCustom[parentTid];
        g_taskPendingSig[childTid] = 0;
        g_sigHandler[childTid]  = g_sigHandler[parentTid];    // Z1: inherit signal handlers
        g_sigRestorer[childTid] = g_sigRestorer[parentTid];
    }

    klog("[fork] parent="); klog_hex(parentTid);
    klog(" child="); klog_hex(childTid); klog("\n");
    return childTid;
}

// ------------------------------------------------------------------
// clone (thread creation): CLONE_VM path — a new task sharing the caller's
// address space (page tables), used by pthread_create / std::thread.
// ------------------------------------------------------------------

// Linux clone() flag bits we care about.
enum : ulong {
    CLONE_VM             = 0x00000100,
    CLONE_FS             = 0x00000200,
    CLONE_FILES          = 0x00000400,
    CLONE_SIGHAND        = 0x00000800,
    CLONE_VFORK          = 0x00004000,
    CLONE_THREAD         = 0x00010000,
    CLONE_SETTLS         = 0x00080000,
    CLONE_PARENT_SETTID  = 0x00100000,
    CLONE_CHILD_CLEARTID = 0x00200000,
    CLONE_CHILD_SETTID   = 0x01000000,
}

// Per-thread CLONE_CHILD_CLEARTID address (user virtual). On thread exit the
// kernel writes 0 here so a joiner's futex wait observes termination.
__gshared ulong[MAX_TASKS] g_threadCleartidVirt;

// vfork: when a child is created with CLONE_VFORK, its parent is suspended until
// the child execve()s or exits.  g_vforkParentPlus1[child] = parentTid+1 records
// who to resume (0 = none).
__gshared int[MAX_TASKS] g_vforkParentPlus1;

// Resume a vfork parent suspended on `childTid` (called when the child execs or
// exits).  Clears the parent's `waiting` flag so the scheduler runs it again.
void resumeVforkParent(int childTid) {
    if (childTid < 0 || childTid >= MAX_TASKS) return;
    int p1 = g_vforkParentPlus1[childTid];
    if (p1 == 0) return;
    g_vforkParentPlus1[childTid] = 0;
    int p = p1 - 1;
    if (p >= 0 && p < MAX_TASKS)
        g_tasks[p].waiting = false;
}

// clone(flags, childStack, ptid, ctid, tls).  Returns the new tid, or a negative
// errno.  The child shares the parent's page tables (CLONE_VM); the caller-
// supplied stack and TLS are already mapped in that shared address space, so no
// page setup is needed here.
private int cloneThread(int parentTid, ulong flags, ulong childStack,
                        ulong ptidPtr, ulong ctidPtr, ulong tls) {
    int childTid = allocTask();
    if (childTid < 0) {
        klog("[clone] no free task slot\n");
        return -11; // EAGAIN (matches pthread_create's resource error)
    }

    auto parent = &g_tasks[parentTid];
    auto child  = &g_tasks[childTid];
    objEnsureProcess(parentTid);

    // Child resumes right after the `syscall` instruction with rax=0, on the
    // caller-provided stack.  The userspace __clone trampoline pops the thread
    // entry/arg from that stack and calls it.
    for (uint i = 0; i < NUM_REGS; i++)
        child.regs[i] = parent.regs[i];
    child.regs[REG_RAX] = 0;
    child.regs[REG_RSP] = childStack;
    child.regs[REG_RBP] = 0;

    for (int i = 0; i < 512; i++)
        child.sseState[i] = parent.sseState[i];

    // Share the address space: same PML4, same region view, same brk.
    child.pml4Phys   = parent.pml4Phys;
    child.regionCount = parent.regionCount;
    for (int i = 0; i < parent.regionCount; i++) {
        child.regions[i] = parent.regions[i];
        child.regions[i].objId = 0;
        child.regions[i].vmoRetained = false;
    }
    child.brkStart   = parent.brkStart;
    child.brkCurrent = parent.brkCurrent;
    child.parentId   = parentTid;

    // A thread shares its process's fd table (CLONE_FILES semantics): same
    // descriptors, opens/closes are visible to all threads of the process.
    child.fdTabId    = parent.fdTabId;
    child.capTabId   = parent.capTabId;
    child.untypedObjId = parent.untypedObjId;
    child.userObjId  = parent.userObjId;
    child.identityObjId = parent.identityObjId; // IDENTITY_DOMAIN §3: threads share the label
    g_taskNativeAbi[childTid] = g_taskNativeAbi[parentTid]; // NATIVE_OBJECT_ABI §3: same personality
    g_taskExecName[childTid]  = g_taskExecName[parentTid];

    // Threads share one address space but keep separate mmap bump pointers; give
    // each thread a disjoint 64 GiB window so concurrent mmap()s never collide.
    child.mmapNext   = parent.mmapNext + cast(ulong)childTid * 0x1000000000UL;

    // TLS (FS base): use the supplied tls for CLONE_SETTLS, else inherit.
    if (flags & CLONE_SETTLS)
        d_store_task_fsbase(cast(ulong)childTid, tls);
    else
        d_store_task_fsbase(cast(ulong)childTid, g_task_fsbase[parentTid]);

    // tid notifications — written through the shared (currently active) address
    // space, so direct user-pointer writes are valid here.
    int childLinuxTid = linuxTidForTask(childTid);
    if ((flags & CLONE_PARENT_SETTID) && ptidPtr != 0)
        *cast(int*)ptidPtr = childLinuxTid;
    if ((flags & CLONE_CHILD_SETTID) && ctidPtr != 0)
        *cast(int*)ctidPtr = childLinuxTid;
    if ((flags & CLONE_CHILD_CLEARTID) && ctidPtr != 0)
        g_threadCleartidVirt[childTid] = ctidPtr;
    else
        g_threadCleartidVirt[childTid] = 0;

    child.active = true;
    objEnsureTask(childTid);
    objSetProcess(childTid, parent.processLeaderTid, parent.processObjId);
    objEnsureNamespace(childTid); // Phase 9: thread shares the process namespace

    klog("[clone] parent="); klog_hex(parentTid);
    klog(" thread="); klog_hex(childTid);
    klog(" stack="); klog_hex(childStack); klog("\n");
    return childTid;
}

// ------------------------------------------------------------------
// execve: replace current task's address space with a new ELF
// ------------------------------------------------------------------

// execve environment snapshot — see the capture in execveTask. Kernel-resident
// (always mapped, survives the CR3 switch) so the new image's stack seeder can
// read the real env after the outgoing address space is gone.
private enum size_t EXEC_ENV_MAX     = 256;
private enum size_t EXEC_ENV_STR_CAP = 16384;
__gshared char[EXEC_ENV_STR_CAP]  g_execEnvStrings;
__gshared ulong[EXEC_ENV_MAX + 1] g_execEnvPtrs;
__gshared size_t g_execEnvCount;

// Track A A4: argv snapshot (mirror of the envp snapshot) so an exec'd program gets
// its REAL arguments, not just [execName].  busybox standalone's applet dispatch
// re-execs /proc/self/exe with argv[0]=<applet> — passing the real argv is what makes
// `cat`, `grep`, … run the right applet.
private enum size_t EXEC_ARG_MAX     = 128;
private enum size_t EXEC_ARG_STR_CAP = 8192;
__gshared char[EXEC_ARG_STR_CAP]  g_execArgStrings;
__gshared ulong[EXEC_ARG_MAX + 1] g_execArgPtrs;
__gshared size_t g_execArgCount;

// Track A A4: per-task loaded binary, so /proc/self/exe re-exec resolves to the
// task's own image (busybox), not the global /init.elf.  g_taskExecModPhys/Size live
// here; g_taskExecName moved to core.task so posix.d's /proc/<pid> can read the comm.
__gshared ulong[MAX_TASKS] g_taskExecModPhys;
__gshared ulong[MAX_TASKS] g_taskExecModSize;

private long execveTask(int tid, ulong pathPtr, ulong argvPtr, ulong envpPtr) {
    auto task = &g_tasks[tid];

    // Find the ELF binary in the boot modules by filename
    const(char)* path = cast(const(char)*)pathPtr;
    const(char)* execName = null;
    ulong modPhys = 0;
    ulong modSize = 0;

    // Track A A4: /proc/self/exe re-exec (busybox standalone applet dispatch) resolves
    // to THIS task's own loaded binary, recorded on its last successful exec.
    if (cstrEqK(path, "/proc/self/exe") && tid >= 0 && tid < MAX_TASKS &&
        g_taskExecModPhys[tid] != 0) {
        modPhys  = g_taskExecModPhys[tid];
        modSize  = g_taskExecModSize[tid];
        execName = g_taskExecName[tid];
    }

    // Track A A4: follow a leading RT-overlay symlink chain (e.g. /bin/cat -> /busybox)
    // so the boot-module scan below matches by the real binary's basename.
    char[512] _canonPath = void;
    if (modPhys == 0 && posixCanonExecPath(path, _canonPath.ptr, 512))
        path = _canonPath.ptr;
    const(char)* pathBase = cstrBasenameK(path);

    // Try boot module scan
    if (modPhys == 0 && g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;
        for (int i = 0; i < g_module_count; i++) {
            auto rec = cast(multiboot_module_t*)(recs + i * 128);
            // compare path to the tail of the module name
            const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 8); // name field at byte 8
            // basename of module name (part after last '/')
            const(char)* modBase = modName;
            for (const(char)* p = modName; *p != 0; p++)
                if (*p == '/') modBase = p + 1;
            if (cstrEqK(path, modBase) || cstrEqK(path, modName) || cstrEqK(pathBase, modBase)) {
                modPhys = cast(ulong)rec.mod_start;
                modSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                execName = modBase;
                break;
            }
        }
    }

    // F4.2: a persisted app object — /objects/apps/<app>/executable — launched from
    // the on-disk store, CAP-GATED on the app's declared rights ⊆ the launching
    // task's identity ceiling.  Grant → load the executable blob like a boot module;
    // exceed the ceiling → deny (EPERM) + audit.  (The original path is used here,
    // before posixCanonExecPath, since /objects/apps/... is not an RT symlink.)
    if (modPhys == 0) {
        const(char)* origPath = cast(const(char)*)pathPtr;
        int appIdx = objstoreResolveExecPath(origPath);
        if (appIdx >= 0) {
            uint declared = objstoreAppRights(appIdx);
            uint ceiling = 0;
            if (tid >= 0 && tid < MAX_TASKS) {
                auto idr = identityById(g_tasks[tid].identityObjId);
                if (idr !is null) ceiling = idr.rightsCeiling;
            }
            if ((declared & ~ceiling) != 0) {
                klog("[objstore] launch DENIED: "); klog(origPath);
                klog(" declared=0x"); klog_hex(declared);
                klog(" ceiling=0x"); klog_hex(ceiling); klog("\n");
                return -1; // EPERM — declared capabilities exceed the identity ceiling
            }
            ulong ep, es;
            if (objstoreLoadExec(appIdx, &ep, &es) && es > 0) {
                modPhys  = ep;
                modSize  = es;
                execName = "store-app".ptr;
                klog("[objstore] launch GRANTED: "); klog(origPath);
                klog(" rights=0x"); klog_hex(declared); klog("\n");
            }
        }
    }

    if (modPhys == 0) {
        klog("[exec] not found: ");
        klog(path);
        klog("\n");
        return -2; // ENOENT
    }

    // Track A A4: remember this task's binary so a later /proc/self/exe re-exec
    // (busybox standalone) resolves back to it.
    if (tid >= 0 && tid < MAX_TASKS) {
        g_taskExecModPhys[tid] = modPhys;
        g_taskExecModSize[tid] = modSize;
        g_taskExecName[tid]    = execName;
        // NATIVE_OBJECT_ABI §3: enter the native personality iff this is the trusted
        // /hos-sh image; any other exec leaves it (so the native shell can't launch a
        // Linux tool INTO the native object ABI).  fork/clone inherit the flag below.
        g_taskNativeAbi[tid]   = (execName !is null && cstrEqK(execName, "hos-sh"));
        // A4: execve resets caught/ignored signals to the default disposition (POSIX),
        // so a freshly exec'd foreground command (cat/grep) is interruptible by ^C.
        g_taskSigCustom[tid]   = 0;
        g_taskPendingSig[tid]  = 0;
        g_sigHandler[tid][] = 0; g_sigRestorer[tid][] = 0;   // Z1: exec resets handlers to default
        hosClearHandles(tid);                                // Z4a.1: drop native FS handles on exec
    }

    // Track A A4: snapshot the caller's argv (mirror of the envp snapshot below) so the
    // new image gets its real arguments + argv[0].  For busybox, argv[0] is the applet
    // name (e.g. "cat"), which is how it dispatches the right applet after re-exec.
    g_execArgCount = 0;
    {
        size_t strOff = 0;
        if (argvPtr != 0) {
            auto argArr = cast(const(ulong)*)argvPtr;
            for (size_t i = 0; i < EXEC_ARG_MAX && argArr[i] != 0; ++i) {
                auto s = cast(const(char)*)argArr[i];
                if (s is null) continue;
                size_t len = 0;
                while (s[len] != 0 && len < 4095) ++len;
                if (strOff + len + 1 >= EXEC_ARG_STR_CAP) break;
                foreach (j; 0 .. len) g_execArgStrings[strOff + j] = s[j];
                g_execArgStrings[strOff + len] = 0;
                g_execArgPtrs[g_execArgCount++] = cast(ulong)&g_execArgStrings[strOff];
                strOff += len + 1;
            }
        }
        g_execArgPtrs[g_execArgCount] = 0;   // NULL terminator
    }

    // Snapshot the caller's envp into kernel buffers WHILE the outgoing address
    // space is still active (its user pages are unmapped just below, and the CR3
    // switch a few lines later makes the user pointers unreadable). The stack
    // seeder then propagates the REAL environment to the new image instead of the
    // kernel's fixed default — this is what carries Weston's WAYLAND_SOCKET=<fd>
    // to its spawned clients, so the privileged desktop-shell rebinds the trusted
    // wl_client connection instead of being denied. (envp==0 → keep fixed env.)
    g_execEnvCount = 0;
    {
        size_t strOff = 0;
        if (envpPtr != 0) {
            auto envArr = cast(const(ulong)*)envpPtr;
            for (size_t i = 0; i < EXEC_ENV_MAX && envArr[i] != 0; ++i) {
                auto s = cast(const(char)*)envArr[i];
                if (s is null) continue;
                size_t len = 0;
                while (s[len] != 0 && len < 4095) ++len;
                if (strOff + len + 1 >= EXEC_ENV_STR_CAP) break;
                foreach (j; 0 .. len) g_execEnvStrings[strOff + j] = s[j];
                g_execEnvStrings[strOff + len] = 0;
                g_execEnvPtrs[g_execEnvCount++] = cast(ulong)&g_execEnvStrings[strOff];
                strOff += len + 1;
            }
        }
        g_execEnvPtrs[g_execEnvCount] = 0;   // NULL terminator
    }

    // Release the outgoing address space's private pages before installing a
    // fresh one (old CR3 is still active, so unmap_page_hhdm operates on it).
    // A freshly forked child reaches execve sharing all of its parent's pages
    // copy-on-write; dropping those references here returns the parent's frames
    // to exclusive ownership (no needless CoW copies later) and reclaims any
    // truly private pages instead of leaking them.  Shared (device/memfd) maps
    // are left intact.  Page-table pages and the old PML4 are left mapped (a
    // small, pre-existing leak) since CR3 still points at them until the switch.
    for (int ri = 0; ri < task.regionCount; ri++) {
        auto r = &task.regions[ri];
        if (!r.owned) continue;
        for (ulong va = r.start; va < r.end; va += 4096) {
            ulong phys = unmap_page_hhdm(va);
            if (phys != 0) free_phys_page(phys);
        }
    }

    // Switch to a fresh page table
    ulong newPml4 = alloc_phys_page();
    if (newPml4 == 0) return -12;
    archMapKernel(newPml4);
    x64WriteCR3(newPml4);

    task.pml4Phys    = newPml4;
    clearRegions(*task);
    task.brkStart    = 0;
    task.brkCurrent  = 0;
    task.mmapNext    = 0x740000000000UL;

    ulong elfVirt = phys_to_virt(modPhys);
    ushort elfType = *cast(ushort*)(elfVirt + 16);
    ulong mainBias = (elfType == ET_DYN) ? USER_MAIN_PIE_BASE : 0;
    char[256] interpPath;
    linuxNoteElfLoad(); // Phase 12: LinuxELFLoaderObject sees the execve load
    auto res = loadElf(*task, elfVirt, modPhys, mainBias,
                       interpPath.ptr, interpPath.length);
    if (!res.ok) {
        klog("[exec] loadElf failed\n");
        return -8; // ENOEXEC
    }

    // Set brk base to top of ELF image
    task.brkStart   = res.topVirt;
    task.brkCurrent = res.topVirt;

    ulong entryRip = res.entry;
    ulong atBase = 0;
    if (res.hasInterp) {
        klog("[exec] PT_INTERP="); klog(interpPath.ptr); klog("\n");
        ulong ipPhys = 0, ipSize = 0;
        if (!findInterpModule(interpPath.ptr, ipPhys, ipSize)) {
            klog("[exec] interp module NOT FOUND\n");
            return -2;
        }
        ulong ipVirt = phys_to_virt(ipPhys);
        auto ires = loadElf(*task, ipVirt, ipPhys, USER_INTERP_BASE, null, 0);
        if (!ires.ok) {
            klog("[exec] interp load FAILED\n");
            return -8;
        }
        entryRip = ires.entry;
        atBase = USER_INTERP_BASE;
        klog("[exec] interp loaded base="); klog_hex(USER_INTERP_BASE);
        klog(" entry="); klog_hex(entryRip); klog("\n");
    }

    // Allocate user stack (32 pages = 128 KB)
    enum stackPages = 32;
    ulong stackPhys = alloc_phys_pages(stackPages);
    if (stackPhys == 0) return -12;
    ulong stackSize = stackPages * 4096;
    ulong stackBase = 0x700000000000UL;
    ulong stackTop  = stackBase + stackSize;

    for (ulong pg = 0; pg < stackPages; pg++)
        map_page_hhdm(stackPhys + pg * 4096, stackBase + pg * 4096,
                      PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);

    auto stackRegion = addRegion(*task, stackBase, stackTop, RegionType.Mapped,
                                 RegionPerms.ReadWrite, stackPhys, true);
    if (stackRegion !is null)
        physPagesSetOwner(stackPhys, stackPages, stackRegion.objId, stackRegion.vmoObjId);

    // Seed a Linux-style process stack using auxv from the loaded ELF. argv[0] is
    // the matched boot-module basename (execfn). The environment is the caller's
    // real env, snapshotted above into g_execEnvPtrs/Strings (kernel memory, valid
    // after the CR3 switch); fall back to the kernel's fixed GUI env only when the
    // caller passed no envp (e.g. kernel-internal exec).
    ulong[7] infoWords = [
        res.entry,
        res.phdrVaddr,
        cast(ulong)res.phEnt,
        cast(ulong)res.phNum,
        atBase,
        mainBias,
        cast(ulong)execName
    ];
    // Track A A4: pass the caller's real argv (snapshotted above) so the new image
    // gets its arguments + the right argv[0]; fall back to execfn-as-argv[0] only for
    // kernel-internal execs that supply no argv (e.g. /idle).
    ulong rsp;
    if (g_execArgCount > 0 || g_execEnvCount > 0) {
        rsp = linux_seed_initial_stack_with_args(
            stackPhys, stackSize, stackBase, infoWords.ptr, 4096,
            (g_execArgCount > 0) ? cast(ulong)&g_execArgPtrs[0] : 0,
            (g_execEnvCount > 0) ? cast(ulong)&g_execEnvPtrs[0] : 0);
    } else {
        rsp = linux_seed_initial_stack(
            stackPhys, stackSize, stackBase, infoWords.ptr, 4096);
    }

    // The legacy freestanding C probes were compiled with GCC treating _start
    // like a regular function.  Keep their old call-like stack alignment while
    // giving libc-linked programs the normal process-entry stack.
    if (isFreestandingExecName(execName) && (rsp & 0xF) == 0) rsp -= 8;

    klog("[exec] entry="); klog_hex(entryRip);
    klog(" rsp="); klog_hex(rsp); klog("\n");

    // Reset registers
    for (uint r = 0; r < NUM_REGS; r++) task.regs[r] = 0;
    task.regs[REG_RIP]    = entryRip;
    task.regs[REG_RSP]    = rsp;
    task.regs[REG_RFLAGS] = 0x202;

    // Clear FS base
    d_store_task_fsbase(cast(ulong)tid, 0);
    objEnsureTask(tid);
    if (task.processLeaderTid != tid)
        objSetProcess(tid, tid, task.parentObjId);
    else
        objEnsureProcess(tid);

    // vfork semantics: a successful execve releases the suspended parent (the
    // child now has its own fresh address space, no longer sharing the parent's).
    resumeVforkParent(tid);

    return 0;
}

// GUI roadmap clients: launch Wayland clients once Hyprland has a listener. Each
// client is a boot module, reusing the existing task/exec machinery. Best-effort
// and isolated: failure logs and leaves desktop boot untouched.
private bool spawnWaylandProgram(const(char)* prog, const(char)* tag) {
    int t = allocTask();
    if (t <= 0) {
        klog(tag); klog(" no free task slot for "); klog(prog); klog("\n");
        return false;
    }
    g_tasks[t].parentId         = 0;
    g_tasks[t].processLeaderTid = t;
    g_tasks[t].userObjId        = g_tasks[0].userObjId;
    g_tasks[t].untypedObjId     = untypedCreateProcess(0);
    if (g_tasks[t].untypedObjId == 0) {
        klog(tag); klog(" no untyped budget for "); klog(prog); klog("\n");
        releaseTask(t);
        return false;
    }
    g_tasks[t].namespaceObjId   = nsClone(g_tasks[0].namespaceObjId);
    capTableClear(g_tasks[t].capTabId);
    installTaskUntypedCap(t);
    fdtabSetupConsoleStdio(g_tasks[t].fdTabId);

    ulong savedCr3 = x64ReadCR3();
    uint savedUntyped = physActiveUntyped();
    physSetActiveUntyped(g_tasks[t].untypedObjId);
    long r = execveTask(t, cast(ulong)prog, 0, 0);
    physSetActiveUntyped(savedUntyped);
    x64WriteCR3(savedCr3);
    if (r != 0) {
        klog(tag); klog(" "); klog(prog); klog(" spawn failed\n");
        releaseTask(t);
        return false;
    }
    klog(tag); klog(" "); klog(prog); klog(" launched as task ");
    klog_hex(cast(ulong)t); klog("\n");
    g_current_task_id = cast(ulong)t;
    return true;
}

// Spawn the idle task (/idle boot module) once.  Like spawnWaylandProgram but does
// NOT make it current (the scheduler only runs it as a last resort) and records its
// tid in g_idleTid.
private void maybeSpawnIdle() {
    if (g_idleTid >= 0) return;                  // already spawned
    int t = allocTask();
    if (t <= 0) return;
    g_tasks[t].parentId         = 0;
    g_tasks[t].processLeaderTid = t;
    g_tasks[t].userObjId        = g_tasks[0].userObjId;
    g_tasks[t].untypedObjId     = untypedCreateProcess(0);
    if (g_tasks[t].untypedObjId == 0) { releaseTask(t); return; }
    g_tasks[t].namespaceObjId   = nsClone(g_tasks[0].namespaceObjId);
    capTableClear(g_tasks[t].capTabId);
    installTaskUntypedCap(t);
    fdtabSetupConsoleStdio(g_tasks[t].fdTabId);

    ulong savedCr3 = x64ReadCR3();
    uint savedUntyped = physActiveUntyped();
    ulong savedCur = g_current_task_id;          // execveTask/our setup must not steal `current`
    physSetActiveUntyped(g_tasks[t].untypedObjId);
    long r = execveTask(t, cast(ulong)"/idle\0".ptr, 0, 0);
    physSetActiveUntyped(savedUntyped);
    x64WriteCR3(savedCr3);
    g_current_task_id = savedCur;
    if (r != 0) { releaseTask(t); return; }
    g_idleTid = t;
    klog("[idle] idle task spawned as tid "); klog_hex(cast(ulong)t); klog("\n");
}

private void spawnWaylandClients() {
    const int mode = guiAutostartMode();
    if (mode == 0) {
        klog("[gui] autostart disabled by display.conf\n");
        return;
    }
    if (mode == 1 || mode == 3)
        spawnWaylandProgram("wl-term\0".ptr, "[g4]\0".ptr);
    if (mode == 2 || mode == 3)
        spawnWaylandProgram("wl-cairo-demo\0".ptr, "[g11]\0".ptr);
    if (mode == 4)
        spawnWaylandProgram("wl-files\0".ptr, "[g17]\0".ptr);
}

private void maybeSpawnWaylandClient() {
    if (!g_guiClientAutostartEnabled || g_guiClientStarted) return;
    if (!unixSocketListenerReady("/run/user/1000/wayland-0\0".ptr)) return;

    ulong now = get_ticks();
    if (!g_guiClientListenerSeen) {
        g_guiClientListenerSeen = true;
        g_guiClientLaunchTick = now + GUI_CLIENT_SETTLE_TICKS;
        klog("[g2] wayland listener ready; waiting for compositor settle\n");
        return;
    }
    if (now < g_guiClientLaunchTick) return;

    g_guiClientStarted = true;
    klog("[g11] wayland listener ready; launching GUI clients\n");
    spawnWaylandClients();
}

// ------------------------------------------------------------------
// wait4
// ------------------------------------------------------------------

private long wait4Task(int tid, int waitPid, ulong statusPtr, ulong options) {
    auto task = &g_tasks[tid];

    // waitPid semantics (Track A A4): -1 = any child; 0 = any child in the caller's
    // process group; < -1 = any child in process group |waitPid|; > 0 = that pid.
    // We don't track process groups precisely, so 0 and < -1 are treated as "any
    // child" — the case busybox ash's job control uses (waitpid(0)/waitpid(-pgid)).
    // Without this, those calls checked childExited[0], never matched, and the shell
    // blocked forever after its first forking command.
    const bool anyChild = (waitPid <= 0);
    int targetTid = -1;
    if (waitPid > 0) {
        targetTid = taskIdFromLinuxPid(waitPid);
        if (targetTid < 0 || targetTid >= MAX_TASKS) return -10; // ECHILD
    }

    // Reap an already-exited matching child.
    if (anyChild) {
        for (int c = 1; c < MAX_TASKS; c++) {
            if (task.childExited[c]) {
                int code = task.childExitCode[c];
                task.childExited[c] = false;
                if (statusPtr != 0) *cast(int*)statusPtr = (code & 0xff) << 8;
                int childPid = g_childExitLinuxPid[c] != 0 ? g_childExitLinuxPid[c] : linuxPidForTask(c);
                releaseTask(c);
                return cast(long)childPid;
            }
        }
    } else {
        uint c = cast(uint)targetTid;
        if (c < MAX_TASKS && task.childExited[c]) {
            int code = task.childExitCode[c];
            task.childExited[c] = false;
            if (statusPtr != 0) *cast(int*)statusPtr = (code & 0xff) << 8;
            int childPid = g_childExitLinuxPid[c] != 0 ? g_childExitLinuxPid[c] : linuxPidForTask(cast(int)c);
            releaseTask(c);
            return cast(long)childPid;
        }
    }

    // No matching child has exited.  If the task has no living matching child either,
    // return ECHILD instead of blocking — otherwise ash's reap loop (which waits until
    // ECHILD) would hang.
    bool hasLivingChild = false;
    if (anyChild) {
        for (int i = 1; i < MAX_TASKS; i++)
            if (g_tasks[i].active && !g_tasks[i].exited && g_tasks[i].parentId == tid) {
                hasLivingChild = true; break;
            }
    } else {
        if (targetTid > 0 && targetTid < MAX_TASKS &&
            g_tasks[targetTid].active && !g_tasks[targetTid].exited &&
            g_tasks[targetTid].parentId == tid)
            hasLivingChild = true;
    }
    if (!hasLivingChild) return -10; // ECHILD — no matching child at all

    // WNOHANG?
    enum WNOHANG = 1;
    if (options & WNOHANG) return 0;

    // Block.  Return the -4 sentinel so the dispatcher rewinds RIP and reschedules —
    // the task transparently re-runs wait4 when a child exits (no spurious EINTR).
    task.waiting       = true;
    task.waitingForPid = anyChild ? -1 : targetTid;
    return -4;
}

// ------------------------------------------------------------------
// Z1: userspace signal-handler delivery (rt_sigframe).  See task.d g_sigHandler.
// ------------------------------------------------------------------

// Build an x86-64 rt_sigframe on `tid`'s user stack and redirect the task into its
// installed handler for `sig`.  Mirrors what Linux pushes (struct rt_sigframe): the
// restorer trampoline at the top (pretcode), then a ucontext whose uc_mcontext.gregs[]
// hold the interrupted register state.  The handler runs `void h(int signo)`, returns
// into the restorer, which calls rt_sigreturn → sigreturnTask restores the context.
// Returns false (caller does the default action) if no usable handler/restorer exists.
private bool deliverUserSignal(int tid, int sig) {
    if (tid < 0 || tid >= MAX_TASKS || sig <= 0 || sig >= 64) return false;
    auto task = &g_tasks[tid];
    const ulong handler  = g_sigHandler[tid][sig];
    const ulong restorer = g_sigRestorer[tid][sig];
    if (handler == 0 || restorer == 0) return false;

    // Carve the frame from the user stack below the 128-byte red zone; 16-align then -8 so
    // the handler sees the ABI's post-`call` alignment (RSP % 16 == 8 at entry).
    enum ulong FRAME = 512;
    enum ulong GREGS = 48;          // pretcode(8) + offsetof(ucontext,uc_mcontext)=40
    ulong sp = task.regs[REG_RSP];
    sp -= 128;
    sp -= FRAME;
    sp &= ~15UL;
    sp -= 8;
    const ulong frame = sp;

    const ulong savedCr3 = x64ReadCR3();
    x64WriteCR3(task.pml4Phys);     // user stack is in the low half; kernel stays mapped (high half)
    {
        auto b = cast(ubyte*)frame;
        for (ulong i = 0; i < FRAME; ++i) b[i] = 0;
        *cast(ulong*)(frame + 0) = restorer;            // pretcode = restorer trampoline
        ulong* g = cast(ulong*)(frame + GREGS);         // uc_mcontext.gregs[] (R8..CR2 order)
        g[0]=task.regs[REG_R8];  g[1]=task.regs[REG_R9];  g[2]=task.regs[REG_R10];
        g[3]=task.regs[REG_R11]; g[4]=task.regs[REG_R12]; g[5]=task.regs[REG_R13];
        g[6]=task.regs[REG_R14]; g[7]=task.regs[REG_R15]; g[8]=task.regs[REG_RDI];
        g[9]=task.regs[REG_RSI]; g[10]=task.regs[REG_RBP];g[11]=task.regs[REG_RBX];
        g[12]=task.regs[REG_RDX];g[13]=task.regs[REG_RAX];g[14]=task.regs[REG_RCX];
        g[15]=task.regs[REG_RSP];g[16]=task.regs[REG_RIP];g[17]=task.regs[REG_RFLAGS];
    }
    x64WriteCR3(savedCr3);

    task.regs[REG_RIP] = handler;
    task.regs[REG_RSP] = frame;
    task.regs[REG_RDI] = cast(ulong)sig;     // void handler(int signo)
    task.regs[REG_RSI] = frame + 312;        // &siginfo  (zeroed; SA_SIGINFO handlers)
    task.regs[REG_RDX] = frame + 8;          // &ucontext
    task.regs[REG_RAX] = 0;
    task.regs[REG_RFLAGS] &= ~(0x100UL | 0x400UL);   // clear TF, DF for the handler
    return true;
}

// rt_sigreturn: restore the context deliverUserSignal saved.  The restorer was reached by
// the handler's `ret` (which popped pretcode), so the user RSP now points at the ucontext
// (frame+8); uc_mcontext.gregs[] is at RSP+40.  We run in syscall context with the task's
// CR3 active, so the user stack is directly readable.
private void sigreturnTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    const ulong uc = task.regs[REG_RSP];
    ulong* g = cast(ulong*)(uc + 40);
    task.regs[REG_R8]=g[0];   task.regs[REG_R9]=g[1];   task.regs[REG_R10]=g[2];
    task.regs[REG_R11]=g[3];  task.regs[REG_R12]=g[4];  task.regs[REG_R13]=g[5];
    task.regs[REG_R14]=g[6];  task.regs[REG_R15]=g[7];  task.regs[REG_RDI]=g[8];
    task.regs[REG_RSI]=g[9];  task.regs[REG_RBP]=g[10]; task.regs[REG_RBX]=g[11];
    task.regs[REG_RDX]=g[12]; task.regs[REG_RAX]=g[13]; task.regs[REG_RCX]=g[14];
    task.regs[REG_RSP]=g[15]; task.regs[REG_RIP]=g[16]; task.regs[REG_RFLAGS]=g[17];
}

// rt_sigsuspend (Z1): zsh waits for a foreground job here, temporarily unblocking SIGCHLD.
// This is the correct point to deliver the SIGCHLD handler (it runs wait_for_processes(),
// reaps the child, marks the job done).  Returns:
//   SIGSUSP_DELIVERED — a handler was armed (task.regs set up; dispatcher must `return`)
//   SIGSUSP_BLOCK     — no child has exited yet (dispatcher rewinds RIP + reschedules)
//   -4 (-EINTR)       — nothing to wait for / no handler (classic immediate return)
private enum long SIGSUSP_DELIVERED = 0x7fffffff;
private enum long SIGSUSP_BLOCK     = 0x7ffffffe;
private long sigsuspendTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return cast(long)(-4); // -EINTR
    auto task = &g_tasks[tid];
    enum int SIGCHLD = 17;
    const bool hasHandler = (g_taskSigCustom[tid] & (1UL << SIGCHLD)) != 0 &&
                            g_sigHandler[tid][SIGCHLD] != 0;
    if (hasHandler) {
        // A child has already exited → deliver the handler now.  Arrange that, after the
        // handler returns (rt_sigreturn), sigsuspend itself returns -EINTR so zsh's
        // zwaitjob loop re-checks the (now STAT_DONE) job.
        for (int c = 1; c < MAX_TASKS; c++) {
            if (task.childExited[c]) {
                task.regs[REG_RAX] = cast(ulong)(-4);   // saved as the post-handler sigsuspend result
                if (deliverUserSignal(tid, SIGCHLD)) return SIGSUSP_DELIVERED;
                break;
            }
        }
        // No child has exited yet, but one is still running → block until it does (the
        // child's exitTask clears `waiting`), then re-run sigsuspend and deliver.
        for (int c = 1; c < MAX_TASKS; c++) {
            if (g_tasks[c].active && !g_tasks[c].exited && g_tasks[c].parentId == tid) {
                task.waiting = true; task.waitingForPid = -1;
                return SIGSUSP_BLOCK;
            }
        }
    }
    return cast(long)(-4); // -EINTR: no handler / no children
}

// ------------------------------------------------------------------
// brk — allocate/release heap pages
// ------------------------------------------------------------------

private long brkTask(int tid, ulong newBrk) {
    auto task = &g_tasks[tid];

    if (newBrk == 0)
        return cast(long)task.brkCurrent;

    if (newBrk < task.brkStart || newBrk > 0x8000000UL)
        return cast(long)task.brkCurrent;

    ulong oldAligned = (task.brkCurrent + 0xFFF) & ~0xFFFUL;
    ulong newAligned = (newBrk + 0xFFF) & ~0xFFFUL;

    if (newAligned > oldAligned) {
        auto heapRegion = addRegion(*task, oldAligned, newAligned,
                                    RegionType.Mapped, RegionPerms.ReadWrite,
                                    0, true);
        if (heapRegion is null) return cast(long)task.brkCurrent;
        // Allocate pages from oldAligned to newAligned
        ulong mappedBytes = 0;
        for (ulong pg = oldAligned; pg < newAligned; pg += 4096) {
            ulong phys = alloc_phys_page();
            if (phys == 0) {
                if (mappedBytes != 0) sys_munmap(oldAligned, mappedBytes, true);
                removeRegion(*task, oldAligned, newAligned);
                return cast(long)task.brkCurrent;
            }
            map_page_hhdm(phys, pg, PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
            physPageSetOwner(phys, heapRegion.objId, heapRegion.vmoObjId);
            mappedBytes += 4096;
        }
    }

    task.brkCurrent = newBrk;
    return cast(long)newBrk;
}

// ------------------------------------------------------------------
// Helper: case-insensitive/exact C-string comparison
// ------------------------------------------------------------------

private bool cstrEqK(const(char)* a, const(char)* b) {
    if (a is null || b is null) return false;
    while (*a != 0 && *b != 0) {
        if (*a != *b) return false;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

private bool isFreestandingExecName(const(char)* name) {
    return cstrEqK(name, "test-drm\0".ptr) ||
           cstrEqK(name, "compositor\0".ptr) ||
           cstrEqK(name, "hello-gui\0".ptr) ||
           cstrEqK(name, "wl-probe\0".ptr);
}

// ------------------------------------------------------------------
// PIC (8259A) helpers
// ------------------------------------------------------------------

// Use outb/inb from core.io (already imported)
private void picIOwait() @nogc nothrow { outb(0x80, 0); }

// Remap PIC1→vectors 32-39, PIC2→vectors 40-47, then unmask kbd (IRQ1) and mouse (IRQ12).
private void initPIC() @nogc nothrow {
    // ICW1: start initialisation, edge-triggered, ICW4 needed
    outb(0x20, 0x11); picIOwait();
    outb(0xA0, 0x11); picIOwait();
    // ICW2: vector offsets
    outb(0x21, 0x20); picIOwait(); // PIC1 base = 32 (IRQ0→int 32)
    outb(0xA1, 0x28); picIOwait(); // PIC2 base = 40 (IRQ8→int 40)
    // ICW3
    outb(0x21, 0x04); picIOwait(); // PIC1: cascade on IRQ2
    outb(0xA1, 0x02); picIOwait(); // PIC2: cascade ID = 2
    // ICW4: 8086 mode
    outb(0x21, 0x01); picIOwait();
    outb(0xA1, 0x01); picIOwait();
    // OCW1: bit set = masked.  Unmask IRQ0 (timer), IRQ1 (kbd), IRQ2 (cascade).
    outb(0x21, cast(ubyte)~(0x01 | 0x02 | 0x04));
    // PIC2 mask: unmask bit 4 (IRQ12 = mouse)
    outb(0xA1, cast(ubyte)~0x10);           // unmask IRQ12
}

// Program PIT channel 0 to ~1000 Hz square wave so IRQ0 ticks every ~1 ms.
private void initPIT() @nogc nothrow {
    enum ushort divisor = 1193; // 1193182 Hz / 1193 ≈ 1000.15 Hz
    outb(0x43, 0x36);                              // ch0, lo/hi byte, mode 3
    outb(0x40, cast(ubyte)(divisor & 0xFF));
    outb(0x40, cast(ubyte)((divisor >> 8) & 0xFF));
}

// Send End-Of-Interrupt.  slave=true also sends EOI to PIC2 (for IRQ8-15).
private void picEOI(bool slave) @nogc nothrow {
    if (slave) outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

// ------------------------------------------------------------------
// PS/2 mouse initialisation
// ------------------------------------------------------------------

private void ps2WaitWrite() @nogc nothrow {
    // Wait until input buffer empty (bit 1 of status = 0)
    uint timeout = 100000;
    while (timeout-- && (inb(0x64) & 0x02)) {}
}
private void ps2WaitRead() @nogc nothrow {
    uint timeout = 100000;
    while (timeout-- && !(inb(0x64) & 0x01)) {}
}

private void initPS2Mouse() @nogc nothrow {
    // Enable auxiliary device (mouse)
    ps2WaitWrite(); outb(0x64, 0xA8);
    // Enable mouse interrupts: read command byte, set bit 1, write back
    ps2WaitWrite(); outb(0x64, 0x20);       // read command byte
    ps2WaitRead();
    ubyte cb = inb(0x60);
    cb |= 0x02;  // enable IRQ12
    cb &= ~0x20; // clear "mouse disabled" bit
    ps2WaitWrite(); outb(0x64, 0x60);       // write command byte
    ps2WaitWrite(); outb(0x60, cb);
    // Send "enable data reporting" to mouse
    ps2WaitWrite(); outb(0x64, 0xD4);       // route next byte to mouse
    ps2WaitWrite(); outb(0x60, 0xF4);       // enable reporting
    ps2WaitRead();  inb(0x60);              // discard ACK
}

// ------------------------------------------------------------------
// PS/2 IRQ handlers
// ------------------------------------------------------------------

// State machine for extended (0xE0) scancodes
private __gshared bool g_kbd_extended = false;

private void handleKbdIRQ() @nogc nothrow {
    // Read all available bytes from the keyboard data port
    while (inb(0x64) & 0x01) {
        ubyte sc = inb(0x60);
        if (sc == 0xE0) { g_kbd_extended = true; continue; }
        bool extended = g_kbd_extended;
        g_kbd_extended = false;

        bool release = (sc & 0x80) != 0;
        ubyte key    = sc & 0x7F;

        ushort code;
        if (extended) {
            // Map common E0 keys to Linux keycodes
            switch (key) {
                case 0x48: code = 103; break; // KEY_UP
                case 0x50: code = 108; break; // KEY_DOWN
                case 0x4B: code = 105; break; // KEY_LEFT
                case 0x4D: code = 106; break; // KEY_RIGHT
                case 0x1C: code = 96;  break; // KEY_KPENTER
                case 0x35: code = 98;  break; // KEY_KPSLASH
                case 0x47: code = 102; break; // KEY_HOME
                case 0x4F: code = 107; break; // KEY_END
                case 0x49: code = 104; break; // KEY_PAGEUP
                case 0x51: code = 109; break; // KEY_PAGEDOWN
                case 0x52: code = 110; break; // KEY_INSERT
                case 0x53: code = 111; break; // KEY_DELETE
                case 0x38: code = 100; break; // KEY_RIGHTALT
                case 0x1D: code = 97;  break; // KEY_RIGHTCTRL
                case 0x5B: code = 125; break; // KEY_LEFTMETA  (Super) — GUI G15 launcher
                case 0x5C: code = 126; break; // KEY_RIGHTMETA (Super)
                case 0x5D: code = 127; break; // KEY_COMPOSE   (Menu)
                default:   code = 0;   break;
            }
        } else {
            code = g_sc1_keycode(key);
        }
        if (code == 0) continue;

        input_enqueue(true, EV_KEY, code, release ? 0 : 1);
        // SYN_REPORT after each key event
        input_enqueue(true, EV_SYN, SYN_REPORT, 0);
    }
}

// 3-byte PS/2 mouse packet accumulator
private __gshared ubyte[3] g_mouse_buf;
private __gshared int      g_mouse_idx = 0;
// Last reported button bitmask (bit0 left, bit1 right, bit2 middle).  evdev only
// reports EV_KEY transitions, not level — libinput/Hyprland treat a repeated
// press without an intervening release as a protocol error, so we diff state and
// emit a button event only when it actually changes (GUI roadmap G3).
private __gshared ubyte g_mouse_prevButtons = 0;

private void handleMouseIRQ() @nogc nothrow {
    while (inb(0x64) & 0x21) {      // output-buffer-full AND aux-data bit
        if (!(inb(0x64) & 0x20)) break; // not aux data — skip
        ubyte b = inb(0x60);
        // Resync: first byte must have bit 3 set
        if (g_mouse_idx == 0 && !(b & 0x08)) continue;
        g_mouse_buf[g_mouse_idx++] = b;
        if (g_mouse_idx < 3) continue;
        g_mouse_idx = 0;

        ubyte status = g_mouse_buf[0];
        int dx = cast(int)g_mouse_buf[1];
        int dy = cast(int)g_mouse_buf[2];
        // Sign-extend using bit 4/5 of status byte
        if (status & 0x10) dx |= 0xFFFFFF00;
        if (status & 0x20) dy |= 0xFFFFFF00;
        // PS/2 Y axis is inverted relative to screen
        dy = -dy;

        bool any = false;
        if (dx != 0 || dy != 0) {
            // Accumulate raw deltas into an absolute on-screen position, stamp the
            // kernel cursor there immediately (snappy, IRQ-rate), and report the
            // SAME absolute position to Weston so its pointer stays exactly aligned.
            cursorSetPos(cursorGetX() + dx, cursorGetY() + dy);
            input_enqueue(false, EV_ABS, ABS_X, cursorGetX());
            input_enqueue(false, EV_ABS, ABS_Y, cursorGetY());
            any = true;
        }

        // Button state — emit only the bits that changed since the last packet.
        ubyte cur     = cast(ubyte)(status & 0x07);
        ubyte changed = cast(ubyte)(cur ^ g_mouse_prevButtons);
        if (changed & 0x01) { input_enqueue(false, EV_KEY, BTN_LEFT,   (cur & 0x01) ? 1 : 0); any = true; }
        if (changed & 0x02) { input_enqueue(false, EV_KEY, BTN_RIGHT,  (cur & 0x02) ? 1 : 0); any = true; }
        if (changed & 0x04) { input_enqueue(false, EV_KEY, BTN_MIDDLE, (cur & 0x04) ? 1 : 0); any = true; }
        g_mouse_prevButtons = cur;

        // One SYN_REPORT terminates each evdev frame, but only when the frame
        // carried at least one motion/button event.
        if (any) input_enqueue(false, EV_SYN, SYN_REPORT, 0);
    }
}

// IDENTITY_DOMAIN §3/§10: the `idps` process-identity table — pid, parent, and
// the security-domain each live task is labelled with.  One-shot for now (the
// interactive debug command is wired in §10); proves fork/clone inheritance —
// every process descends from PID1 (System) and carries that label.
__gshared bool g_idpsDumped = false;
private void identityDumpProcesses() @nogc nothrow {
    if (g_idpsDumped) return;
    g_idpsDumped = true;
    klog("[idps] pid parent identity\n");
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (!g_tasks[i].active || g_tasks[i].exited) continue;
        klog("[idps]  "); klog_hex(cast(ulong)i);
        klog(" <- "); klog_hex(cast(ulong)g_tasks[i].parentId);
        klog(" id="); klog_hex(cast(ulong)g_tasks[i].identityObjId);
        klog(" ["); identityNamePrint(g_tasks[i].identityObjId); klog("]\n");
    }
}

// ------------------------------------------------------------------
// Syscall dispatch
// ------------------------------------------------------------------

// g_task_fsbase / g_task_fsbase_set are in exports.d
extern __gshared ulong[1024] g_task_fsbase;
extern __gshared bool[1024]  g_task_fsbase_set;

// Toggle for the very verbose per-syscall trace ([sc] t=/n=).  Off by default.
__gshared bool g_traceSyscalls = false;

// Phase 2: amortization counter for objReconcileFds()/objStats() (see dispatchSyscall).
__gshared uint g_objReconcileCtr = 0;

// PERF: dump per-task CPU share (permil = tenths of a percent) over the interval,
// so a busy-looping task that starves the compositor stands out.  Resets counters.
private void schedProfStats() {
    ulong total = 0;
    foreach (i; 0 .. MAX_TASKS) total += g_schedCyc[i];
    if (total == 0) return;
    klog("[sched] cpu_permil:");
    foreach (i; 0 .. MAX_TASKS) {
        if (g_schedCyc[i] == 0) continue;
        const ulong permil = g_schedCyc[i] * 1000 / total;
        if (permil < 5) continue;                 // hide <0.5%
        klog(" t"); klog_dec(cast(ulong)i);
        klog("="); klog_dec(permil);
        klog("/proc"); klog_hex(g_tasks[i].processObjId);
    }
    klog("\n");
    foreach (i; 0 .. MAX_TASKS) { g_schedCyc[i] = 0; g_schedN[i] = 0; }
}

private void dispatchSyscall(int tid) {
    ulong rax = x64LastSyscallRax;
    ulong rdi = x64LastSyscallRdi;
    ulong rsi = x64LastSyscallRsi;
    ulong rdx = x64LastSyscallRdx;
    ulong r10 = x64LastSyscallR10;
    ulong r8  = x64LastSyscallR8;
    ulong r9  = x64LastSyscallR9;

    // Per-syscall trace — extremely verbose (hundreds of thousands of lines) and a
    // heavy perf drain since every syscall writes to the serial port.  Gated off by
    // default now that bring-up is past the syscall-by-syscall debugging stage.
    if (g_traceSyscalls) {
        kchar('S');
        klog("[sc] t="); klog_hex(cast(ulong)tid); klog(" n="); klog_hex(rax); klog("\n");
    }

    auto task = &g_tasks[tid];
    // Select this task's process fd table before servicing the syscall, so each
    // process sees its own descriptors (fork gives the child an independent copy).
    fdtabSetActive(task.fdTabId);
    capTableSetActive(task.capTabId);
    physSetActiveUntyped(task.untypedObjId);
    userSetActiveSubject(task.userObjId);

    // Phase 2 (roadmap/OBJECT_OS_ROADMAP.md): keep the core.objmgr object table
    // mirrored onto the now-active fd table, and periodically run the object-graph
    // reconciliation + research self-test proofs.  This block costs ~hundreds of
    // millions of cycles per run (graph walks + crypto self-tests), so running it
    // every 256 syscalls dominated runtime — Hyprland issues ~hundreds of syscalls
    // per frame, so it fired roughly once per frame and pinned the desktop at ~5
    // fps.  These are non-functional proofs/audits; amortize them over 64k syscalls
    // so they remain runtime evidence without throttling interactive work.
    if (((++g_objReconcileCtr) & 0xFFFFF) == 0) {
        objReconcileTasks();
        objReconcileFds();
        objReconcileRegions();
        orgReconcileOwnership(); // ORG P3: process/memory ownership edges
        orgReconcileFdEdges();   // ORG P3: fd capability + epoll observer edges
        ipcSelfTest(); // Phase 7: one-shot proof the IPC router round-trips
        deviceSelfTest(); // Phase 8: one-shot proof /dev resolves to Device objects
        nsSelfTest(); // Phase 9: one-shot proof per-process namespaces clone & route
        userSelfTest(); // Phase 10: one-shot proof identity/passwd derive from User objects
        adminSelfTest(); // IR-P3: one-shot proof typed admin caps gate actions
        serviceSelfTest(); // Phase 10: one-shot proof services are rights-narrowed
        servicePhase5SelfTest(); // IR-P5: dependency-ordered start, FS-first migration, versioning
        windowSelfTest(); // Phase 11: one-shot proof Output/Window/Surface objects
        identitySelfTest(); // IDENTITY_DOMAIN P2: one-shot proof identity create/lookup/validate/freeze
        idprocSelfTest();   // IDENTITY_DOMAIN P3: one-shot proof inherit / transition-gate / cap⊆ceiling
        idnsSelfTest();     // IDENTITY_DOMAIN P4: one-shot proof per-identity disjoint roots + shares
        idipcSelfTest();    // IDENTITY_DOMAIN P5: one-shot proof same-domain OK / cross denied / brokered allowed
        idwinSelfTest();    // IDENTITY_DOMAIN P6: one-shot proof window identity stamped from owner / unspoofable / border
        identityDumpProcesses(); // IDENTITY_DOMAIN P3: one-shot idps process-identity table
        compositorIdentitySelfTest(); // GUI: one-shot proof of trusted, unspoofable identity borders
        linuxSelfTest(); // Phase 12: one-shot proof the Linux-compat subtree & gate
        linuxPersSelfTest(); // IR-P7: ephemeral-root sandbox + ns/cap op translation + gated /dev
        kernelCensusReport(); // Phase 13: Milestone 3 proof once the graph is populated
        orgSelfTest(); // ORG P2: one-shot proof of typed edges + weak coherence
        orgIntegReport(); // ORG P3: one-shot proof the real graph passes I1/I4 audit
        orgApiSelfTest(); // ORG P4: one-shot proof of query/reachability/ns-validation
        orgCycleSelfTest(); // ORG P5: one-shot proof of cycle prevention + SCC GC
        orgGcSelfTest(); // ORG P6: one-shot proof of invariant/quarantine/GC/rebuild
        orgSecuritySelfTest(); // ORG P7: one-shot proof of label/rights escalation rejection
        capRevokeClosureSelfTest(); // ORG P7.2: one-shot proof of transitive revocation
        orgValidatorSelfTest(); // ORG P8: one-shot proof of the validator daemon + control
        orgVizSelfTest(); // ORG P9: one-shot proof of DOT/stats graph export
        orgLinuxSelfTest(); // ORG P10: one-shot proof SCM cycle GC + sandboxed edges
        orgDistSelfTest(); // ORG P11: one-shot proof of federated refs + leased edges
        orgDistTick(1);    // ORG P11: advance the distributed clock / expire stale leases
        orgTestSuite();    // ORG P12: one-shot invariant + GC-fuzz + scale test suite
        untypedSelfTest(); // IMMUTABLE_ROOTLESS §1.4: one-shot proof no ambient allocation
        storeSelfTest(); // IMMUTABLE_ROOTLESS §4: content-addr store + verity + split + generations
        updateSelfTest(); // IMMUTABLE_ROOTLESS §6: A/B slots + signed apply + anti-downgrade + auto-rollback
        cryptoSelfTest(); // IMMUTABLE_ROOTLESS §8.1/8.2: real SHA-256/HMAC + measured/verified boot
        hardeningSelfTest(); // IMMUTABLE_ROOTLESS §8.3/8.4: W^X / NX policy + capability audit log
        distosSelfTest(); // IMMUTABLE_ROOTLESS §9: network-transparent refs + macaroon caps + dist store
        libsecipcSelfTest(); // SECURE_IPC P0: X25519/HKDF/ChaCha20-Poly1305/framing (RFC vectors)
        secipcSelfTest(); // SECURE_IPC P1: identity certs + broker-signed descriptors + cap-gated routing
        secsessionSelfTest(); // SECURE_IPC P2: signed-DH handshake + HKDF keys + AEAD record layer
        seclifeSelfTest(); // SECURE_IPC P3: rekey + revocation + failure handling (fail-closed)
        secobjSelfTest(); // SECURE_IPC P4: channel/session/cert/descriptor objects + Linux AEAD shim
        sechardSelfTest(); // SECURE_IPC P5: const-time + nonce-reuse + zeroize + parser fuzz + state machine
        // ORG P8: drive the runtime validator daemon one bounded step per reconcile
        // tick — it cycles reachability → SCC → invariant → GC → audit across ticks,
        // epoch-driven, never stalling the scheduler (replaces the old inline pass).
        orgValidatorTick();
        if ((g_objReconcileCtr & 0x3FFF) == 0) {
            objStats();
            capStats();
            ipcStats();
            deviceStats();
            nsStats();
            userStats();
            adminStats();
            serviceStats();
            windowStats();
            identityStats(); // IDENTITY_DOMAIN P2: identity count / created / frozen
            idnsStats();     // IDENTITY_DOMAIN P4: ns clones / shares / roots
            idipcStats();    // IDENTITY_DOMAIN P5: gate checks / allow / deny
            idwinStats();    // IDENTITY_DOMAIN P6: windows stamped / hook installed
            presentProfStats(); // PERF: frame rate + kernel-present share of each frame
            schedProfStats();   // PERF: per-task CPU share (find a hog starving the compositor)
            fdReadableStats();  // PERF: which fd type keeps reporting ready (busy-spin source)
            inputStats();       // R1: input events enqueued / dropped / read
            linuxStats();
            linuxPersStats();
            kernelCensusStats();
            orgAudit(); // refresh I1/I4 violation counters for the stats line
            orgStats();
            orgValidatorStats();
            auditStats();
            orgDistStats();
            untypedStats();
            storeStats();
            updateStats();
            cryptoStats();
            hardeningStats();
            distosStats();
            secipcStats();
            secsessionStats();
            secobjStats();
            sechardStats();
        }
    }

    long ret  = 0;

    switch (rax) {
        // mmap — use per-task bump pointer so we never collide with the stack.
        // When fd is a DRM device and offset is non-zero (= physical framebuffer
        // address from MAP_DUMB), map those existing physical pages directly
        // instead of allocating fresh anonymous pages.
        case 9: {
            enum MAP_FIXED = 0x10;
            enum MAP_ANONYMOUS = 0x20;
            ulong mlen    = rsi;
            ulong mflags  = r10;
            ulong mfd     = r8;
            ulong moffset = r9;
            if (mlen == 0) {
                klog("[mmap-einval] len=0 flags="); klog_hex(mflags);
                klog(" fd="); klog_hex(mfd); klog(" off="); klog_hex(moffset); klog("\n");
                ret = -22; break;
            }
            ulong alignedLen = (mlen + 0xFFF) & ~0xFFFUL;
            ulong vaddr;
            if (mflags & MAP_FIXED) {
                if (rdi == 0 || (rdi & 0xFFF) != 0) { ret = -22; break; }
                vaddr = rdi;
            } else {
                vaddr = task.mmapNext;
                task.mmapNext += alignedLen;
            }
            x64WriteCR3(task.pml4Phys);
            ulong numPgs = alignedLen >> 12;
            bool mmapOk = true;

            // Shared fd backings (DRM dumb-buffer mmap and memfd mmap) now route
            // through the fd object's mmap op instead of peeking at File.type here.
            ulong backingPhys = 0;
            uint vmoObjId = 0;
            bool useObjectBacking = false;
            if (mfd < 1024) {
                long backing = fdMmapBacking(mfd, moffset, &backingPhys,
                                             null, &vmoObjId,
                                             &useObjectBacking);
                if (backing <= 0) useObjectBacking = false;
            }

            // File-backed mmap (MAP_PRIVATE of a regular file): the dynamic linker
            // maps each shared object's segments this way.  Allocate fresh pages
            // and copy the file's bytes at `moffset`, zero-filling past EOF.  Pages
            // stay writable + executable (the kernel never sets NX, so PROT_EXEC is
            // satisfied and ld.so can write relocations); ld.so tightens perms via
            // mprotect afterwards.
            bool useFile = !useObjectBacking &&
                           (mflags & MAP_ANONYMOUS) == 0 &&
                           cast(long)mfd >= 0 && mfd < 1024;

            ulong regionPhysBase = useObjectBacking ? backingPhys : 0;

            auto mappedRegion = addRegion(*task, vaddr, vaddr + alignedLen,
                                           RegionType.Mapped,
                                           RegionPerms.ReadWrite,
                                           regionPhysBase,
                                           !useObjectBacking,
                                           vmoObjId);
            if (mappedRegion is null) {
                if ((mflags & MAP_FIXED) == 0) task.mmapNext -= alignedLen;
                ret = -12;
                break;
            }

            ulong mappedPgs = 0;
            for (ulong pg = 0; pg < numPgs; pg++) {
                ulong phys = useObjectBacking ? (backingPhys + pg * 4096)
                           : alloc_phys_page();
                if (phys == 0) { mmapOk = false; break; }
                map_page_hhdm(phys, vaddr + pg * 4096,
                              PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
                if (useFile)
                    mmapCopyFileRange(cast(int)mfd, moffset + pg * 4096,
                                      cast(ubyte*)phys_to_virt(phys), 4096);
                physPageSetOwner(phys, mappedRegion.objId, mappedRegion.vmoObjId);
                ++mappedPgs;
            }
            if (mmapOk) {
                ret = cast(long)vaddr;
                // Diagnostic: log large file-backed maps (e.g. the DRI driver) so
                // a crash RIP inside a dlopen'd .so can be mapped back to a base.
                if (useFile && alignedLen >= 0x100000) {
                    klog("[mmap-so] base="); klog_hex(vaddr);
                    klog(" len="); klog_hex(alignedLen);
                    klog(" fd="); klog_hex(mfd); klog("\n");
                }
            } else {
                if (mappedPgs != 0)
                    sys_munmap(vaddr, mappedPgs * 4096, mappedRegion.owned);
                removeRegion(*task, vaddr, vaddr + alignedLen);
                if ((mflags & MAP_FIXED) == 0) task.mmapNext -= alignedLen;
                ret = -12;
            }
            break;
        }

        // mremap(old_addr, old_size, new_size, flags, new_addr)
        // Only the wl_shm pool-growth pattern is supported: a shared, memfd/VMO-
        // backed mapping is re-pointed at the memfd's current (ftruncate-grown)
        // physical backing.  The compositor's wayland-shm uses this to enlarge a
        // pool; everything else gets ENOSYS so glibc/GIO fall back to malloc/copy.
        case 25: {
            enum MREMAP_MAYMOVE = 1;
            ulong mrOld   = rdi;
            ulong mrOldSz = rsi;
            ulong mrNewSz = rdx;
            ulong mrFlags = r10;
            if (mrNewSz == 0) { ret = -22; break; }              // EINVAL
            ulong mrOldAligned = (mrOldSz + 0xFFF) & ~0xFFFUL;
            ulong mrNewAligned = (mrNewSz + 0xFFF) & ~0xFFFUL;
            auto mrR = findRegion(*task, mrOld);
            if (mrR is null || mrR.vmoObjId == 0 ||
                mrR.type != RegionType.Mapped) { ret = -38; break; }  // ENOSYS
            // Capture region fields before any addRegion/removeRegion churns the
            // table (swap-remove would invalidate the pointer).
            ulong mrStart = mrR.start;
            ulong mrEnd   = mrR.end;
            uint  mrVmo   = mrR.vmoObjId;
            ulong mfSize  = 0;
            ulong mfPhys  = memfdPhysByVmo(mrVmo, &mfSize);
            if (mfPhys == 0) { ret = -38; break; }                // not a live memfd
            // Same-or-smaller: keep the existing mapping (it already covers it).
            if (mrNewAligned <= (mrEnd - mrStart)) { ret = cast(long)mrOld; break; }
            if ((mrFlags & MREMAP_MAYMOVE) == 0) { ret = -12; break; }  // ENOMEM
            if (mrNewAligned > mfSize) { ret = -22; break; }      // backing too small
            x64WriteCR3(task.pml4Phys);
            ulong mrVa = task.mmapNext;
            task.mmapNext += mrNewAligned;
            auto mrNew = addRegion(*task, mrVa, mrVa + mrNewAligned,
                                   RegionType.Mapped, RegionPerms.ReadWrite,
                                   mfPhys, false, mrVmo);
            if (mrNew is null) { task.mmapNext -= mrNewAligned; ret = -12; break; }
            ulong mrPgs = mrNewAligned >> 12;
            for (ulong pg = 0; pg < mrPgs; pg++) {
                map_page_hhdm(mfPhys + pg * 4096, mrVa + pg * 4096,
                              PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
                physPageSetOwner(mfPhys + pg * 4096, mrNew.objId, mrNew.vmoObjId);
            }
            // Drop the old mapping (shared memfd pages must NOT be freed).
            sys_munmap(mrStart, mrEnd - mrStart, false);
            removeRegion(*task, mrStart, mrEnd);
            ret = cast(long)mrVa;
            break;
        }

        // brk
        case 12:
            ret = brkTask(tid, rdi);
            break;

        // clone / fork (clone with SIGCHLD flags acts like fork)
        case 56:
            // clone(flags=rdi, stack=rsi, ptid=rdx, ctid=r10, tls=r8).
            // CLONE_VM ⇒ thread creation (pthread_create / std::thread): a new
            // task sharing this address space, running on the supplied stack.
            if (rdi & CLONE_VM) {
                ret = cast(long)cloneThread(tid, rdi, rsi, rdx, r10, r8);
                if (ret > 0)
                    task.regs[REG_RAX] = cast(ulong)linuxTidForTask(cast(int)ret);
                else {
                    task.regs[REG_RAX] = cast(ulong)ret; // negative errno
                    return;
                }
                // vfork (posix_spawn): the child shares this address space and
                // runs to execve()/_exit() on its own stack; suspend the parent
                // until then.  This avoids fork's deep copy of the address space
                // (which would inherit locked mutexes from other threads and
                // deadlock the child before it can exec).
                if (rdi & CLONE_VFORK) {
                    int childTid = cast(int)ret;
                    g_vforkParentPlus1[childTid] = tid + 1;
                    task.waiting = true;   // resumed by resumeVforkParent() on exec/exit
                    scheduleNext();         // run the child now
                }
                return;
            }
            // No shared VM: treat as fork (clone with a fresh address space).
            goto case 57;

        // fork
        case 57:
        // vfork (treat as fork)
        case 58:
            ret = cast(long)forkTask(tid);
            if (ret > 0) {
                // Parent gets child pid; child already has RAX=0 in its Task.regs
                task.regs[REG_RAX] = cast(ulong)linuxPidForTask(cast(int)ret);
            }
            return; // already set return value

        // execve
        case 59:
            ret = execveTask(tid, rdi, rsi, rdx);
            if (ret == 0) {
                // execve succeeded — re-enter userspace from scratch
                // The task registers were reset by execveTask
                return;
            }
            break;

        // exit
        case 60:
        // exit_group
        case 231:
            exitTask(tid, cast(int)rdi);
            return; // exitTask switches tasks; we never reach the set-RAX below

        // rt_sigreturn (Z1: return from a signal handler — restore the saved context)
        case 15:
            sigreturnTask(tid);
            return;   // task.regs fully restored (incl. RAX/RIP/RSP); don't touch them

        // pause (34) / rt_sigsuspend (130): zsh's foreground-job wait point.  zsh's
        // configure picked BROKEN_POSIX_SIGSUSPEND (our sigsuspend returned EINTR), so it
        // actually waits with sigprocmask+pause — handle both.  This is where SIGCHLD is
        // unblocked, so deliver its handler here (it reaps the child, returns from the
        // wait), instead of from the generic run-loop point where zsh keeps it blocked.
        case 34:
        case 130:
            ret = sigsuspendTask(tid);
            if (ret == SIGSUSP_DELIVERED) return;   // handler armed; task.regs set up
            if (ret == SIGSUSP_BLOCK) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
            break;                                  // -EINTR → set RAX below

        // wait4
        case 61:
            ret = wait4Task(tid, cast(int)rdi, rsi, rdx);
            // Blocking: rewind RIP so the task transparently re-runs wait4 on wake
            // (the child's exit clears `waiting`), instead of returning EINTR.
            if (ret == -4) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
            break;

        // kill
        case 62:
            ret = linux_sys_kill(rdi, rsi);
            break;

        // waitpid (via wait4 with NULL rusage)
        case 114:
            ret = wait4Task(tid, cast(int)rdi, rsi, rdx);
            if (ret == -4) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
            break;

        // mprotect
        case 10:
            ret = sys_mprotect(rdi, rsi, rdx);
            break;

        // munmap
        case 11: {
            // Free the underlying physical pages only when they belong to an
            // owned (private anonymous / file) region; device (g_fb) and shared
            // (memfd) maps must stay intact.  Walk on the task's own page tables.
            bool freePages = (rsi != 0) && regionOwnedAt(*task, rdi);
            if (rsi != 0) x64WriteCR3(task.pml4Phys);
            ret = sys_munmap(rdi, rsi, freePages);
            if (ret == 0 && rsi != 0) {
                ulong ulen = (rsi + 0xFFF) & ~0xFFFUL;
                removeRegion(*task, rdi, rdi + ulen);
            }
            break;
        }

        // arch_prctl (handles ARCH_SET_FS, updates g_task_fsbase)
        case 158:
            ret = linux_sys_arch_prctl(rdi, rsi);
            break;

        // sched_yield — cooperatively hand the CPU to the next runnable task.
        case 24:
            task.regs[REG_RAX] = 0;
            scheduleNext();
            return;

        // futex — cooperative blocking implementation.  Under this single-core
        // round-robin scheduler we block FUTEX_WAIT in the task table and wake
        // it from FUTEX_WAKE.  We also poll the word from scheduleNext() so a
        // userspace store without an explicit wake cannot strand the process.
        case 202: {
            ulong op = rsi & ~cast(ulong)(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

            // Diagnostic: log early futex traffic + a periodic sample of the
            // steady state, to identify a stuck FUTEX_WAIT and its waker.
            if (g_futexLogCount < 80 || (g_futexLogCount % 50000) == 0) {
                klog("[futex] t="); klog_hex(cast(ulong)tid);
                klog(" op="); klog_hex(op);
                klog(" u="); klog_hex(rdi);
                klog(" val="); klog_hex(rdx);
                if (rdi != 0) { klog(" *u="); klog_hex(cast(ulong)cast(uint)*cast(int*)rdi); }
                klog("\n");
            }
            g_futexLogCount++;

            if (rdi == 0) { task.regs[REG_RAX] = cast(ulong)(-14); return; } // EFAULT
            if (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) {
                uint waitBits = (op == FUTEX_WAIT_BITSET)
                              ? cast(uint)r9
                              : FUTEX_BITSET_MATCH_ANY;
                if (waitBits == 0) { task.regs[REG_RAX] = cast(ulong)(-22); return; } // EINVAL
                int cur = *cast(int*)rdi;
                if (cur != cast(int)rdx) {
                    task.regs[REG_RAX] = cast(ulong)(-11); // EAGAIN: value changed
                } else {
                    g_futexWaitActive[tid] = true;
                    g_futexWaitUaddr[tid] = rdi;
                    g_futexWaitVal[tid] = cast(int)rdx;
                    g_futexWaitBitset[tid] = waitBits;
                    task.waiting = true;
                    scheduleNext();
                }
                return;
            } else if (op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET) {
                uint wakeBits = (op == FUTEX_WAKE_BITSET)
                              ? cast(uint)r9
                              : FUTEX_BITSET_MATCH_ANY;
                if (wakeBits == 0) { task.regs[REG_RAX] = cast(ulong)(-22); return; } // EINVAL

                uint maxWake = rdx > uint.max ? uint.max : cast(uint)rdx;
                uint woke = futexWakeAddress(rdi, maxWake, wakeBits, tid);
                if (g_futexWakeLogCount < 80 || woke != 0 || (g_futexWakeLogCount % 50000) == 0) {
                    klog("[futex-wake] t="); klog_hex(cast(ulong)tid);
                    klog(" u="); klog_hex(rdi);
                    klog(" max="); klog_hex(cast(ulong)maxWake);
                    klog(" bits="); klog_hex(cast(ulong)wakeBits);
                    klog(" woke="); klog_hex(cast(ulong)woke);
                    klog("\n");
                }
                g_futexWakeLogCount++;
                task.regs[REG_RAX] = cast(ulong)woke;
                return;
            } else if (op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE) {
                if (r8 == 0) { task.regs[REG_RAX] = cast(ulong)(-14); return; } // EFAULT
                if (op == FUTEX_CMP_REQUEUE && *cast(int*)rdi != cast(int)r9) {
                    task.regs[REG_RAX] = cast(ulong)(-11); // EAGAIN
                    return;
                }

                uint maxWake = rdx > uint.max ? uint.max : cast(uint)rdx;
                uint maxRequeue = r10 > uint.max ? uint.max : cast(uint)r10;
                uint woke = futexWakeAddress(rdi, maxWake, FUTEX_BITSET_MATCH_ANY, tid);
                uint moved = futexRequeueAddress(rdi, r8, maxRequeue, FUTEX_BITSET_MATCH_ANY);
                klog("[futex-requeue] t="); klog_hex(cast(ulong)tid);
                klog(" from="); klog_hex(rdi);
                klog(" to="); klog_hex(r8);
                klog(" woke="); klog_hex(cast(ulong)woke);
                klog(" moved="); klog_hex(cast(ulong)moved);
                klog("\n");
                task.regs[REG_RAX] = cast(ulong)(woke + moved);
                return;
            } else if (op == FUTEX_WAKE_OP) {
                uint maxWake1 = rdx > uint.max ? uint.max : cast(uint)rdx;
                uint maxWake2 = r10 > uint.max ? uint.max : cast(uint)r10;
                uint woke = futexWakeAddress(rdi, maxWake1, FUTEX_BITSET_MATCH_ANY, tid);
                woke += futexWakeAddress(r8, maxWake2, FUTEX_BITSET_MATCH_ANY, tid);
                klog("[futex-wake-op] t="); klog_hex(cast(ulong)tid);
                klog(" u1="); klog_hex(rdi);
                klog(" u2="); klog_hex(r8);
                klog(" woke="); klog_hex(cast(ulong)woke);
                klog("\n");
                task.regs[REG_RAX] = cast(ulong)woke;
                return;
            }
            task.regs[REG_RAX] = cast(ulong)(-38); // ENOSYS for unsupported ops
            return;
        }

        // All other Linux syscalls are translated by the LinuxSyscallObject
        // (Phase 12): the personality is reached only through its gate, so the
        // whole Linux subtree can be disabled without touching the native kernel.
        // The translation bodies still live in posix.d, which now calls native
        // object ops from Phases 3–11.
        default:
            if (!linuxEnabled()) {
                linuxNoteBlocked();
                ret = -38; // ENOSYS — Linux personality not present
                break;
            }
            linuxNoteTranslate();
            ret = dispatchLinuxSyscall(rax, rdi, rsi, rdx, r10, r8, r9);
            break;
    }

    // Cooperative blocking for console reads: when a task read()s the console
    // but no keyboard input is pending, posix.d returns EAGAIN.  Rather than
    // spin in-kernel (which starves every other task under this cooperative
    // scheduler), rewind RIP to the `syscall` instruction (2 bytes: 0F 05) and
    // yield.  The task transparently re-runs read() next time it is scheduled,
    // so userspace still sees a normal blocking read once data arrives.
    if (rax == 0 && ret == -11 /*EAGAIN*/ &&
        (isConsoleFd(rdi) || ptyBlockingReadFd(rdi) || pipeBlockingReadFd(rdi))) {
        // Z3: a pending handler-signal (e.g. ^C -> SIGINT for zsh) interrupts the blocking
        // read with EINTR — POSIX semantics.  RIP is still just past the `syscall`, so we
        // make the read "return" -EINTR (saved by deliverUserSignal) and run the handler;
        // after rt_sigreturn the read has returned EINTR and zsh's ZLE re-checks its abort
        // flag instead of swallowing the keystroke.  Else: rewind + yield (normal block).
        int psig = g_taskPendingSig[tid];
        if (psig > 0 && psig < 64 && (g_taskSigCustom[tid] & (1UL << psig)) &&
            g_sigHandler[tid][psig] != 0) {
            g_taskPendingSig[tid] = 0;
            task.regs[REG_RAX] = cast(ulong)(-4);   // the read returns -EINTR after the handler
            if (deliverUserSignal(tid, psig)) return;
        }
        task.regs[REG_RIP] -= 2;
        scheduleNext();
        return;
    }

    // Cooperative blocking for poll/ppoll/select: when nothing is ready yet but
    // the caller is willing to wait, yield instead of returning 0 immediately.
    // Otherwise an event-loop thread busy-spins on poll(), monopolising this
    // cooperative scheduler so the *other* task (e.g. the worker thread that
    // would signal the awaited fd) never runs — a livelock.  Rewinding RIP re-runs
    // the poll when this task is next scheduled, after others have had a turn.
    //   poll(7):   fds=rdi nfds=rsi timeout_ms=rdx (0 = non-blocking, else wait)
    //   ppoll(271):fds=rdi nfds=rsi timeout_ts=rdx (NULL = infinite)
    // Both scan fd readiness (ppoll fixed below); select/pselect are excluded
    // since they don't scan and would yield forever.
    //   epoll_pwait(281): handled below without RIP rewind. Hyprland's
    //     wl_event_loop must see timeout returns to fire timers, but other tasks
    //     still need a turn before Hyprland immediately re-enters epoll.
    // ppoll(271) / epoll_pwait2(441): timeout is a userspace timespec we don't parse
    // here, so keep the original rewind/return-0 yield (re-runs each round-robin turn).
    if (ret == 0 && rax == 271) {
        task.regs[REG_RIP] -= 2;
        scheduleNext();
        return;
    }
    if (ret == 0 && rax == 441) {
        task.regs[REG_RAX] = 0;
        scheduleNext();
        return;
    }

    // poll(7) + epoll_wait/pwait(232/281): PARK the task until an fd is ready or the
    // timeout expires, instead of returning 0 immediately (which busy-spins the
    // single core).  Woken by wakePollers() on the PIT tick + input IRQs.
    //   poll(7) timeout_ms = rdx ; epoll timeout_ms = r10 ; 0 = nonblock, <0 = infinite.
    {
        const bool isPoll  = (rax == 7);
        const bool isEpoll = (rax == 232 || rax == 281);
        if (ret == 0 && (isPoll || isEpoll)) {
            const long tmo = isPoll ? cast(long)rdx : cast(long)r10;
            if (tmo != 0) {
                if (g_pollBlocked[tid]) {
                    const ulong dl = g_pollDeadline[tid];
                    if (dl != 0 && pitMs() >= dl) {
                        g_pollBlocked[tid] = false;
                        task.regs[REG_RAX] = 0;        // timed out → return 0
                        return;
                    }
                } else {
                    g_pollBlocked[tid]  = true;
                    g_pollDeadline[tid] = (tmo < 0) ? 0 : (pitMs() + cast(ulong)tmo);
                }
                task.waiting = true;                  // park: scheduler skips us
                task.regs[REG_RIP] -= 2;              // re-run the syscall on wake
                scheduleNext();
                return;
            }
        }
        // got events (or an error): the wait is satisfied.
        if ((isPoll || isEpoll) && ret != 0) g_pollBlocked[tid] = false;
    }

    // Wayland and other local-socket protocols use sendmsg() as an IPC handoff.
    // After a successful write, yield once so the peer can accept/read/reply
    // without relying on debug logging or timer timing for fairness.
    if (ret > 0 && rax == 46) {
        task.regs[REG_RAX] = cast(ulong)ret;
        wakePollers();   // the peer (parked on its socket via poll/epoll) can now read
        scheduleNext();
        return;
    }

    task.regs[REG_RAX] = cast(ulong)ret;
}

// Dispatch to the large posix.d table
private long dispatchLinuxSyscall(ulong n, ulong a, ulong b, ulong c,
                                   ulong d, ulong e, ulong f) {
    long capPrecheck = linuxSyscallCapPrecheck(n, a, b, c, d, e, f);
    if (capPrecheck < 0) return capPrecheck;

    switch (n) {
        case 0:   return linux_sys_read(a, b, c);
        case 1:   return linux_sys_write(a, b, c);
        case 2:   return linux_sys_open(a, b, c);
        case 3:   return linux_sys_close(a);
        case 4:   return linux_sys_stat(a, b);
        case 5:   return linux_sys_fstat(a, b);
        case 6:   return linux_sys_lstat(a, b);
        case 7:   return linux_sys_poll(a, b, c);
        case 8:   return linux_sys_lseek_wrap(a, b, c);
        case 13:  return linux_sys_rt_sigaction(a, b, c, d);
        case 14:  return linux_sys_rt_sigprocmask(a, b, c, d);
        case 16:  return linux_sys_ioctl(a, b, c);
        case 17:  return linux_sys_pread64(a, b, c, d);
        case 18:  return linux_sys_pwrite64(a, b, c, d);
        case 19:  return linux_sys_readv(a, b, c);
        case 20:  return linux_sys_writev(a, b, c);
        case 21:  return linux_sys_access(a, b);
        case 22:  return linux_sys_pipe(a);
        case 23:  return linux_sys_select(a, b, c, d, e);
        case 24:  return linux_sys_sched_yield();
        case 28:  return linux_sys_madvise(a, b, c);
        case 32:  return linux_sys_dup(a);
        case 33:  return linux_sys_dup2(a, b);
        case 34:  return linux_sys_pause();
        case 35:  return linux_sys_nanosleep(a, b);
        case 36:  return linux_sys_getitimer(a, b);
        case 37:  return linux_sys_alarm(a);
        case 39:  return linux_sys_getpid();
        case 40:  return linux_sys_sendfile(a, b, c, d);
        case 41:  return linux_sys_socket(a, b, c);
        case 42:  return linux_sys_connect(a, b, c);
        case 43:  return linux_sys_accept(a, b, c);
        case 44:  return linux_sys_sendto(a, b, c, d, e, f);
        case 45:  return linux_sys_recvfrom(a, b, c, d, e, f);
        case 46:  return linux_sys_sendmsg(a, b, c);
        case 47:  return linux_sys_recvmsg(a, b, c);
        case 49:  return linux_sys_bind(a, b, c);
        case 50:  return linux_sys_listen(a, b);
        case 51:  return linux_sys_getsockname(a, b, c);
        case 52:  return linux_sys_getpeername(a, b, c);
        case 53:  return linux_sys_socketpair(a, b, c, d);
        case 54:  return linux_sys_setsockopt(a, b, c, d, e);
        case 55:  return linux_sys_getsockopt(a, b, c, d, e);
        case 63:  return linux_sys_uname(a);
        case 72:  return linux_sys_fcntl(a, b, c);
        case 73:  return linux_sys_flock(a, b);
        case 77:  return linux_sys_ftruncate(a, b);
        case 285: return linux_sys_fallocate(a, b, c, d);  // posix_fallocate (wl_shm buffers)
        case 79:  return linux_sys_getcwd(a, b);
        case 80:  return linux_sys_chdir(a);
        case 81:  return linux_sys_fchdir(a);
        case 83:  return linux_sys_mkdir(a, b);
        case 84:  return linux_sys_rmdir(a);
        case 87:  return linux_sys_unlink(a);
        case 89:  return linux_sys_readlink(a, b, c);
        case 96:  return linux_sys_gettimeofday(a, b);
        case 97:  return linux_sys_getrlimit(a, b);
        case 98:  return linux_sys_getrusage(a, b);   // Z1: zsh's `time`/resource reporting
        case 99:  return linux_sys_sysinfo(a);
        case 100: return linux_sys_times(a);
        case 102: return linux_sys_getuid();
        case 104: return linux_sys_getgid();
        case 105: return linux_sys_setuid(a);
        case 106: return linux_sys_setgid(a);
        case 107: return linux_sys_geteuid();
        case 108: return linux_sys_getegid();
        case 109: return linux_sys_setpgid(a, b);
        case 110: return linux_sys_getppid();
        case 111: return linux_sys_getpgrp();
        case 112: return linux_sys_setsid();
        case 113: return linux_sys_setreuid(a, b);
        case 116: return linux_sys_setgroups(a, b);
        case 117: return linux_sys_setresuid(a, b, c);
        case 118: return linux_sys_getresuid(a, b, c);
        case 119: return linux_sys_setresgid(a, b, c);
        case 120: return linux_sys_getresgid(a, b, c);
        case 121: return linux_sys_getpgid(a);
        case 124: return linux_sys_getsid(a);
        case 131: return linux_sys_sigaltstack(a, b);
        case 137: return linux_sys_statfs(a, b);
        case 138: return linux_sys_fstatfs(a, b);     // Z1: zsh probes the cwd filesystem
        case 154: return linux_sys_sched_setparam(a, b);
        case 155: return linux_sys_sched_getparam(a, b);
        case 157: return linux_sys_prctl(a, b, c, d, e);
        case 160: return linux_sys_setrlimit(a, b);
        case 162: return linux_sys_sync();
        case 165: return linux_sys_mount(a, b, c, d, e);
        case 186: return linux_sys_gettid();
        case 200: return linux_sys_tkill(a, b);
        case 202: return linux_sys_futex(a, b, c, d, e, f);
        case 78:  return linux_sys_getdents(a, b, c);
        case 217: return linux_sys_getdents64(a, b, c);
        case 218: return linux_sys_set_tid_address(a);
        case 228: return linux_sys_clock_gettime(a, b);
        case 229: return linux_sys_clock_getres(a, b);
        case 230: return linux_sys_clock_nanosleep(a, b, c, d);
        case 213: return linux_sys_epoll_create(a);
        case 232: return linux_sys_epoll_pwait(a, b, c, d, 0, 0);  // epoll_wait
        case 233: return linux_sys_epoll_ctl(a, b, c, d);          // was mis-routed to epoll_create!
        case 234: return linux_sys_tgkill(a, b, c);
        case 254: return linux_sys_inotify_init();
        case 257: return linux_sys_openat(a, b, c, d);
        case 258: return linux_sys_mkdirat(a, b, c);
        case 260: return linux_sys_fchownat(a, b, c, d, e);
        case 262: return linux_sys_newfstatat(a, b, c, d);
        case 263: return linux_sys_unlinkat(a, b, c);
        case 264: return linux_sys_renameat(a, b, c, d);
        case 265: return linux_sys_linkat(a, b, c, d, e);
        case 266: return linux_sys_symlinkat(a, b, c);
        case 267: return linux_sys_readlinkat(a, b, c, d);
        case 268: return linux_sys_fchmodat(a, b, c, d);
        case 269: return linux_sys_faccessat(a, b, c, d);
        case 270: return linux_sys_pselect6(a, b, c, d, e, f);
        case 271: return linux_sys_ppoll(a, b, c, d, e);
        case 275: return linux_sys_splice(a, b, c, d, e, f);
        case 276: return linux_sys_tee(a, b, c, d);
        case 277: return linux_sys_sync_file_range(a, b, c, d);
        case 280: return linux_sys_utimensat(a, b, c, d);
        case 281: return linux_sys_epoll_pwait(a, b, c, d, e, f);
        case 282: return linux_sys_signalfd4(a, b, c, 0);
        case 283: return linux_sys_timerfd_create(a, b);
        case 284: return linux_sys_eventfd2(a, 0);
        case 286: return linux_sys_timerfd_settime(a, b, c, d);
        case 287: return linux_sys_timerfd_gettime(a, b);
        case 288: return linux_sys_accept4(a, b, c, d);
        case 289: return linux_sys_signalfd4(a, b, c, d);
        case 290: return linux_sys_eventfd2(a, b);
        case 291: return linux_sys_epoll_create1(a);
        case 292: return linux_sys_dup3(a, b, c);
        case 293: return linux_sys_pipe2(a, b);
        case 294: return linux_sys_inotify_init1(a);
        case 295: return linux_sys_pread64(a, b, c, d);
        case 296: return linux_sys_pwrite64(a, b, c, d);
        case 299: return linux_sys_recvmmsg(a, b, c, d, e);
        case 302: return linux_sys_prlimit64(a, b, c, d);
        case 307: return linux_sys_sendmmsg(a, b, c, d);
        case 316: return linux_sys_renameat2(a, b, c, d, e);
        case 318: return linux_sys_getrandom(a, b, c);
        case 319: return linux_sys_memfd_create(a, b);
        case 323: return linux_sys_userfaultfd(a);
        case 324: return linux_sys_membarrier(a, b, c);
        case 332: return linux_sys_statx(a, b, c, d, e);
        case 334: return linux_sys_rseq(a, b, c, d);
        case 435: return linux_sys_clone3(a, b);
        case 439: return linux_sys_faccessat2(a, b, c, d);  // Z1: zsh/musl access() checks
        case 441: return linux_sys_epoll_pwait2(a, b, c, d, e);

        // Track B0 / NATIVE_OBJECT_ABI §3: the native object ABI (outside the Linux
        // range).  GATED to the AnonymOS native shell personality — a Linux-personality
        // task gets ENOSYS, identical to a kernel without the ABI compiled in, so the
        // object/capability surface is unreachable from the Linux shell.  (Native tasks
        // still speak the Linux ABI, which is how they introspect/override Linux state.)
        case HOS_SYS_QUERY: {
            const int ctid = cast(int)g_current_task_id;
            if (ctid < 0 || ctid >= MAX_TASKS || !g_taskNativeAbi[ctid])
                return cast(long)(-38);   // ENOSYS — native ABI absent for this personality
            return hosQuery(a, b, c, d);
        }

        default:
            klog("[syscall] ENOSYS "); klog_hex(n); klog("\n");
            return -38; // ENOSYS
    }
}

// ------------------------------------------------------------------
// Kernel main loop
// ------------------------------------------------------------------

private void kernelLoop() {
    while (true) {
        maybeSpawnWaylandClient();
        maybeSpawnIdle();   // ensure the scheduler's idle task exists

        int tid = cast(int)g_current_task_id;
        auto task = &g_tasks[tid];

        if (!task.active || task.exited) {
            scheduleNext();
            // If scheduleNext found nothing new, check whether any task can
            // still run; if not, halt cleanly instead of spinning forever.
            if (cast(int)g_current_task_id == tid) {
                bool anyRunnable = false;
                for (uint i = 0; i < MAX_TASKS; i++) {
                    if (g_tasks[i].active && !g_tasks[i].exited) {
                        anyRunnable = true;
                        break;
                    }
                }
                if (!anyRunnable) {
                    klog("[kernel] all tasks exited — halting\n");
                    while (true) { asm @nogc nothrow { cli; hlt; } }
                }
            }
            continue;
        }
        if (task.waiting) {
            scheduleNext();
            continue;
        }

        // Track A A4: a terminal signal (^C/^\) marked this task for the default
        // terminate action.  Apply it now from the victim's own context (about to run
        // tid) — exitTask switches to tid's CR3 to free its pages, which is unsafe to
        // do from the keystroke-writer's context where the signal was raised.
        if (g_taskPendingSig[tid] != 0) {
            int psig = g_taskPendingSig[tid];
            if (psig > 0 && psig < 64 && (g_taskSigCustom[tid] & (1UL << psig)) &&
                g_sigHandler[tid][psig] != 0) {
                // Z3: the task has a real handler (e.g. zsh's SIGINT for ^C).  Leave the
                // signal pending and run the task — it will be delivered at its next
                // blocking syscall (the read/pause yield below), where it interrupts that
                // syscall with EINTR so userspace (zsh's ZLE) re-checks its interrupt flag.
                // Delivering it async here would resume the rewound read and never EINTR.
            } else {
                g_taskPendingSig[tid] = 0;
                exitTask(tid, 128 + psig);   // default action: 128+signo (killed job)
                continue;
            }
        }

        physSetActiveUntyped(task.untypedObjId);

        // Apply this task's FS base (for TLS)
        d_apply_task_fsbase(cast(ulong)tid);

        // Load task registers into curUserSpaceState
        loadTaskState(*task);

        // Switch to this task's page table
        x64WriteCR3(task.pml4Phys);

        // Hand off to userspace; returns when an interrupt/syscall fires
        const ulong _sw0 = rdtsc();
        ulong reason = x64SwitchToUserspace(
            cast(void*)&curUserSpaceState[0],
            cast(void*)&kernelState[0]);
        if (tid >= 0 && tid < MAX_TASKS) {
            g_schedCyc[tid] += rdtsc() - _sw0;   // userspace cycles this quantum
            ++g_schedN[tid];
        }

        // Kernel is back; switch page table back to the kernel's own CR3
        // (not strictly needed since kernel is in high half, but safer)
        // x64WriteCR3(kernelCr3);  — skip; kernel mappings are always valid

        // Save user register state
        saveTaskState(*task);

        if (reason == 0x100) {
            // SYSCALL instruction
            dispatchSyscall(tid);
        } else if ((reason & 0x80) != 0) {
            // Hardware IRQ — irq0 pushes 0x80, irq1 → 0x81, …, irq12 → 0x8C
            uint irqIdx = cast(uint)(reason - 0x80);

            if (irqIdx == 0) {
                // PIT timer tick (~1000 Hz) — drives clock_gettime and timerfd
                increment_ticks();
                // Re-check parked poll/epoll sleepers every tick (catch-all for passive
                // fds like the compositor's repaint timerfd).  Cheap now that the idle
                // task — not the parked pollers' epoll re-runs — absorbs the idle core.
                wakePollers();
                picEOI(false);
                scheduleNext();
            } else if (irqIdx == 1) {
                // PS/2 keyboard — read all available scancodes
                handleKbdIRQ();
                wakePollers();   // wake input-waiting clients immediately (low latency)
                picEOI(false);
            } else if (irqIdx == 12) {
                // PS/2 mouse — accumulate 3-byte packet
                handleMouseIRQ();
                wakePollers();
                picEOI(true);   // mouse is on PIC2 (slave), needs both EOIs
            } else {
                // All other IRQs: just send EOI so PIC doesn't stay masked
                if (irqIdx >= 8) picEOI(true);
                else             picEOI(false);
            }
        } else if (reason == 14) {
            // Page fault (#PF)
            ulong cr2     = x64ReadCR2();
            bool  isWrite = (x64TrapErrorCode & 2) != 0;

            // Special TLS arch_prctl compatibility path:
            // Some runtimes trigger a read fault at 0x10 with RDI=0x1002 (ARCH_SET_FS)
            if (cr2 == 0x10 && !isWrite) {
                ulong rdi = task.regs[REG_RDI];
                ulong rsi = task.regs[REG_RSI];
                if (rdi == 0x1002 && rsi != 0) {
                    linux_sys_arch_prctl(rdi, rsi);
                    // No page was mapped; advance RIP past the faulting instruction
                    // (the fault is at a "mov (%rdi), ..." — 3 bytes for movq (%r), r)
                    // Just resume; the instruction will fault again on next access
                    // if it is truly accessing 0x10. For arch_prctl emulation we
                    // can just return 0 to RAX and skip ahead.
                    task.regs[REG_RAX] = 0;
                    continue;
                }
            }

            if (!handlePageFault(tid, cr2, isWrite)) {
                klog("[kernel] fatal PF tid="); klog_hex(tid);
                klog(" cr2="); klog_hex(cr2);
                klog(" rip="); klog_hex(task.regs[REG_RIP]);
                klog(" rsp="); klog_hex(task.regs[REG_RSP]);
                // For a fault on the first instruction of a leaf like strlen(),
                // [rsp] holds the return address into the caller — log it (and a
                // few stack slots) to locate the offending call site.
                {
                    ulong rsp = task.regs[REG_RSP];
                    if (rsp >= 0x1000) {
                        klog(" ret0="); klog_hex(*cast(ulong*)(rsp));
                        klog(" ret1="); klog_hex(*cast(ulong*)(rsp + 8));
                    }
                }
                klog(" err="); klog_hex(x64TrapErrorCode); klog("\n");
                exitTask(tid, 11); // SIGSEGV
            }
        } else if (reason <= 31) {
            // CPU exception — kill task
            klog("[kernel] exception "); klog_hex(reason);
            klog(" tid="); klog_hex(tid);
            klog(" rip="); klog_hex(task.regs[REG_RIP]);
            klog(" rsp="); klog_hex(task.regs[REG_RSP]);
            klog("\n");
            exitTask(tid, 11);
        }
        // else: unknown — ignore and continue
    }
}

// ------------------------------------------------------------------
// Entry point called from bootstrap_kernel()
// ------------------------------------------------------------------

// Locate the dynamic-linker boot module (ld-musl) for a PT_INTERP request.
// Matched by a stable substring of the module name rather than the exact
// PT_INTERP path, which is the host build path until binaries are linked with
// -Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1.
private bool findInterpModule(const(char)* interpPath, out ulong physOut, out ulong sizeOut) {
    physOut = 0;
    sizeOut = 0;
    if (g_mboot_modules is null || g_module_count <= 0) return false;
    auto recs = cast(ubyte*)g_mboot_modules;
    for (int i = 0; i < g_module_count; i++) {
        auto rec  = cast(multiboot_module_t*)(recs + i * 128);
        auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
        if (cstrContainsK(name, "ld-musl") || cstrContainsK(name, "ld.so")) {
            physOut = cast(ulong)rec.mod_start;
            sizeOut = cast(ulong)rec.mod_end - physOut;
            return true;
        }
    }
    return false;
}

void d_kernel_main() {
    klog("[dkernel] EpinAnonymOS D kernel starting\n");

    // Initialise task 0 (init process) slot
    g_tasks[0] = Task.init;
    g_tasks[0].active   = true;
    g_tasks[0].parentId = -1;
    g_tasks[0].processLeaderTid = 0;
    g_tasks[0].fdTabId = 0;
    g_tasks[0].capTabId = 0;
    g_tasks[0].mmapNext = 0x740000000000UL;
    g_current_task_id   = 0;
    untypedRootInit();
    g_tasks[0].untypedObjId = untypedCreateProcess(0);
    if (g_tasks[0].untypedObjId == 0) {
        klog("[dkernel] ERROR: no init untyped budget\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }
    installTaskUntypedCap(0);
    physSetActiveUntyped(g_tasks[0].untypedObjId);
    physEnableUntypedGate(true);

    // Find an ELF module to use as the init process.
    // Preference order: Hyprland desktop, busybox shell, then init.elf.
    ulong initPhys = 0;
    ulong initSize = 0;
    const(char)* initExecName = "sh\0".ptr;
    bool initIsHyprland = false;
    random_init();
    // Phase 8: stand up Driver/Device objects for the synthetic /dev tree (and
    // wrap the block/NIC driver globals) before the init process opens /dev nodes.
    deviceRegistryInit();
    // Phase 10 / IMMUTABLE_ROOTLESS §3: register User objects, flip task 0 to
    // the non-root subject, then grant PID1 only explicit typed admin caps needed
    // by the current compatibility stubs.
    userRegistryInit();
    g_tasks[0].userObjId = userDefaultObjId();
    userSetActiveSubject(g_tasks[0].userObjId);
    adminInstallInitCaps(g_tasks[0].capTabId);
    // IMMUTABLE_ROOTLESS §4.3: assemble the read-only /usr · overlay /etc · user-state
    // /var system namespace so its mount-rights write gate exists from first boot.
    storeMountSystem();
    // IMMUTABLE_ROOTLESS §6.1: stand up the A/B slots with the booted generation in
    // the active slot, marked known-good (the boot we are in succeeded this far).
    updateInit();
    // A5/F4: bring up the SATA disk so the object store can persist (no-op if no
    // disk is attached — the store then stays in-memory).
    diskInit();
    diskSelfTest();
    // F4: mount the persisted object store (formats on first boot, seeds the sample
    // app, bumps the on-disk boot counter — the cross-reboot persistence proof).
    // F4.2: locate the store-app image boot module so seeded apps get a real,
    // launchable executable blob (phys -> HHDM virt for the CPU read).
    const(void)* appImg = null; uint appImgLen = 0;
    if (g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;
        for (int i = 0; i < g_module_count; i++) {
            auto rec = cast(multiboot_module_t*)(recs + i * 128);
            const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 8);
            const(char)* modBase = modName;
            for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
            if (cstrEqK(modBase, "store-app")) {
                appImgLen = cast(uint)(cast(ulong)rec.mod_end - cast(ulong)rec.mod_start);
                appImg = cast(const(void)*)(cast(ulong)rec.mod_start + hhdm_offset);
                break;
            }
        }
    }
    objstoreMount(appImg, appImgLen);
    serviceManagerInit(USER_RIGHT_LOGIN | USER_RIGHT_SPAWN);
    // Phase 11: register the primary Output object for the firmware framebuffer
    // (the in-kernel compositor's Window/Surface objects register as it runs).
    windowRegistryInit(g_fb !is null ? cast(uint)g_fb.width : 0,
                       g_fb !is null ? cast(uint)g_fb.height : 0);
    // IDENTITY_DOMAIN §2/§3: build the compiled-in security-domain identities and
    // label PID1 (task 0) with the System identity before its first syscall.
    // fork/clone inherit this label; transitions into other identities (§3) require
    // CAP_RIGHT_ADMIN_IDENTITY + a launch rule.
    identityInitDefaults();
    identityInitLaunchRules();   // §3 compiled-in transition rules (after the identities exist)
    idnsInitRoots();             // §4 private object-root Directory per identity
    idipcInit();                 // §5 install cross-identity IPC gate + default brokered pairs
    idwinInit();                 // §6 install winRegister identity-stamp hook (unspoofable borders)
    g_tasks[0].identityObjId = identityByName("System\0".ptr);
    // Phase 12: build the Linux-compat object subtree and enable the personality
    // before the init process issues its first syscall (the dispatcher routes all
    // Linux syscalls through the LinuxSyscallObject gate from here on).
    linuxObjectInit();
    // ORG P2: initialise the object reference graph (installs the free-notify hook
    // for weak-edge coherence) before any object churn.
    orgInit();
    orgValidatorInit(); // ORG P8: stand up the validator daemon + its capability token
    if (g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;

        // Highest priority: the dynamic-linking verification harness (Phase E).
        // Only present when the "dyntest" module is staged for testing; in normal
        // builds this finds nothing and falls through to the desktop target.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            if (cstrContainsK(name, "dyntest")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = dyntest (dynamic-linker test)\n");
            }
        }

        // GW3: Weston (Wayland reference compositor + Pixman software renderer)
        // takes priority over Hyprland as the desktop target when its module is
        // staged. Match the binary by EXACT basename "weston" so the weston-*
        // helper-client modules (weston-desktop-shell, weston-terminal, …) aren't
        // mistaken for the compositor. Staging weston is what toggles this on;
        // remove it from the ISO to fall back to Hyprland for comparison.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            if (cstrEqK(cstrBasenameK(name), "weston\0".ptr)) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = Weston module (GW3)\n");
            }
        }

        // First pass: Hyprland is the desktop autostart target when present.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            if (cstrContainsK(name, "Hyprland") || cstrContainsK(name, "hyprland")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                initIsHyprland = true;
                klog("[dkernel] init = Hyprland module\n");
            }
        }

        // Second pass: look for busybox and dispatch it as ash.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            if (cstrContainsK(name, "busybox")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = "sh\0".ptr;
                klog("[dkernel] init = busybox module\n");
            }
        }

        // Third pass: init.elf
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            if (cstrContainsK(name, "init.elf") || cstrContainsK(name, "init")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = init.elf module\n");
            }
        }

        // Fallback: last module that looks like an ELF
        for (int i = g_module_count - 1; i >= 0 && initPhys == 0; i--) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            ulong phys = cast(ulong)rec.mod_start;
            ulong size = cast(ulong)rec.mod_end - phys;
            if (size < 16) continue;
            auto magic = cast(ubyte*)(phys + hhdm_offset);
            if (magic[0] == 0x7f && magic[1] == 'E' &&
                magic[2] == 'L'  && magic[3] == 'F') {
                initPhys = phys;
                initSize = size;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = fallback ELF module\n");
            }
        }
    }

    if (initPhys == 0) {
        klog("[dkernel] ERROR: no init module found, halting\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }

    klog("[dkernel] init phys="); klog_hex(initPhys);
    klog(" size="); klog_hex(initSize); klog("\n");

    // Allocate a new PML4 for the init process
    ulong pml4Phys = alloc_phys_page();
    if (pml4Phys == 0) {
        klog("[dkernel] OOM allocating PML4\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }
    g_tasks[0].pml4Phys = pml4Phys;
    objEnsureTask(0);
    objSetProcess(0, 0, 0);

    // Copy kernel high-half mappings into the new page table
    archMapKernel(pml4Phys);

    // Switch to the init process page table
    x64WriteCR3(pml4Phys);

    // Load the ELF binary.  A fixed-address ET_EXEC loads at its own vaddrs
    // (bias 0); an ET_DYN (PIE) main exe is relocated to a high base.
    ulong elfVirt = phys_to_virt(initPhys);
    ushort initType = *cast(ushort*)(elfVirt + 16);
    ulong mainBias = (initType == 3 /*ET_DYN*/) ? USER_MAIN_PIE_BASE : 0;

    char[256] interpPath;
    linuxNoteElfLoad(); // Phase 12: LinuxELFLoaderObject sees the init load
    auto res = loadElf(g_tasks[0], elfVirt, initPhys, mainBias,
                       interpPath.ptr, interpPath.length);
    if (!res.ok) {
        klog("[dkernel] ELF load failed\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }

    klog("[dkernel] ELF entry="); klog_hex(res.entry);
    klog(" topVirt="); klog_hex(res.topVirt); klog("\n");

    g_tasks[0].brkStart   = res.topVirt;
    g_tasks[0].brkCurrent = res.topVirt;

    // If the binary is dynamically linked, load its interpreter (ld-musl) at a
    // high base and begin execution there.  ld.so then maps the exe's shared
    // libraries, relocates everything, and jumps to the real entry itself — the
    // kernel does not implement relocations.
    ulong entryRip = res.entry;
    ulong atBase   = 0;
    if (res.hasInterp) {
        klog("[dkernel] PT_INTERP="); klog(interpPath.ptr); klog("\n");
        ulong ipPhys = 0, ipSize = 0;
        if (findInterpModule(interpPath.ptr, ipPhys, ipSize)) {
            ulong ipVirt = phys_to_virt(ipPhys);
            auto ires = loadElf(g_tasks[0], ipVirt, ipPhys, USER_INTERP_BASE, null, 0);
            if (ires.ok) {
                entryRip = ires.entry;
                atBase   = USER_INTERP_BASE;
                klog("[dkernel] interp loaded base="); klog_hex(USER_INTERP_BASE);
                klog(" entry="); klog_hex(entryRip); klog("\n");
            } else {
                klog("[dkernel] interp load FAILED\n");
            }
        } else {
            klog("[dkernel] interp module NOT FOUND\n");
        }
    }

    // Allocate user stack (32 pages = 128 KB at 0x700000000000)
    enum stackPages = 32;
    ulong stackPhys = alloc_phys_pages(stackPages);
    if (stackPhys == 0) {
        klog("[dkernel] OOM allocating stack\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }
    ulong stackSize = stackPages * 4096;
    ulong stackBase = 0x700000000000UL;
    ulong stackTop  = stackBase + stackSize;

    for (ulong pg = 0; pg < stackPages; pg++)
        map_page_hhdm(stackPhys + pg * 4096, stackBase + pg * 4096,
                      PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);

    auto initStackRegion = addRegion(g_tasks[0], stackBase, stackTop,
                                     RegionType.Mapped, RegionPerms.ReadWrite,
                                     stackPhys, true);
    if (initStackRegion !is null)
        physPagesSetOwner(stackPhys, stackPages, initStackRegion.objId,
                          initStackRegion.vmoObjId);

    // Auxv from the loaded image (handles PIE bias + dynamic interpreter).
    ulong[7] infoWords = [
        res.entry,                      // AT_ENTRY  (real exe entry, with bias)
        res.phdrVaddr,                  // AT_PHDR   (phdr table in memory)
        cast(ulong)res.phEnt,           // AT_PHENT
        cast(ulong)res.phNum,           // AT_PHNUM
        atBase,                         // AT_BASE   (interp base, 0 if static)
        0,                              // execBase
        cast(ulong)initExecName         // execfn kernel ptr -> argv[0]
    ];
    ulong rsp = linux_seed_initial_stack(
        stackPhys, stackSize, stackBase, infoWords.ptr, 4096);

    klog("[dkernel] rsp="); klog_hex(rsp);
    klog(" rip="); klog_hex(entryRip); klog("\n");

    // Set initial register state for init task.  For a dynamic binary RIP is the
    // interpreter's entry; for a static one it's the exe's own entry.
    for (uint i = 0; i < NUM_REGS; i++) g_tasks[0].regs[i] = 0;
    g_tasks[0].regs[REG_RIP]    = entryRip;
    g_tasks[0].regs[REG_RSP]    = rsp;
    g_tasks[0].regs[REG_RFLAGS] = 0x202; // IF=1

    g_guiClientAutostartEnabled = initIsHyprland;
    if (g_guiClientAutostartEnabled)
        klog("[g11] GUI client autostart armed\n");

    // Set up IDT and SYSCALL MSRs
    x64_ready_for_userspace();

    // Remap PIC to vectors 32-47 and unmask timer (IRQ0) + keyboard (IRQ1) + mouse (IRQ12)
    initPIC();
    // Start the ~1000 Hz PIT tick so clock_gettime / timerfd advance
    initPIT();
    // Enable PS/2 mouse and its IRQ
    initPS2Mouse();

    klog("[dkernel] entering kernel loop\n");
    kernelLoop();

    // Should never reach here
    while (true) { asm @nogc nothrow { cli; hlt; } }
}

// ------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------

private bool cstrContainsK(const(char)* haystack, string needle) {
    if (haystack is null) return false;
    size_t hl = 0;
    while (haystack[hl] != 0) hl++;
    if (needle.length > hl) return false;
    for (size_t i = 0; i <= hl - needle.length; i++) {
        bool match = true;
        for (size_t j = 0; j < needle.length; j++) {
            if (haystack[i + j] != needle[j]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

private const(char)* cstrBasenameK(const(char)* path) {
    if (path is null) return null;

    const(char)* base = path;
    for (const(char)* p = path; *p != 0; p++) {
        if (*p == '/') base = p + 1;
    }
    return base;
}
