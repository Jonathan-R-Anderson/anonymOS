// D replacement for the Haskell kernel (hosMain + kernelize + dispatch).
// Called from bootstrap_kernel() after hardware init; never returns.
module core.kernel_main;

import core.task;
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
    x64_ready_for_userspace,
    x64_setup_full_idt,
    setupSysCalls,
    g_module_count, g_mboot_modules, multiboot_module_t;
import memory.mm;
import arch.x86_64.arch;
import arch.x86_64.bootstrap : g_fb, g_terminal;

// Linux syscall implementations already in D
import core.syscalls.posix;
import core.syscalls.mmap : sys_munmap, sys_mprotect;
import core.ticks : increment_ticks;
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
__gshared int[MAX_TASKS]   g_futexWaitVal;
__gshared uint[MAX_TASKS]  g_futexWaitBitset;
__gshared ulong g_futexLogCount = 0;
__gshared ulong g_futexWakeLogCount = 0;

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

private bool refreshFutexWaiter(int tid) {
    if (tid < 0 || tid >= MAX_TASKS || !g_futexWaitActive[tid]) return false;

    auto t = &g_tasks[tid];
    if (!t.active || t.exited) {
        clearFutexWait(tid, -4); // EINTR-like cleanup for dead slots
        return false;
    }

    int cur = *cast(int*)g_futexWaitUaddr[tid];
    if (cur != g_futexWaitVal[tid]) {
        klog("[futex-unblock] t="); klog_hex(cast(ulong)tid);
        klog(" u="); klog_hex(g_futexWaitUaddr[tid]);
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
    t.exited   = true;
    t.exitCode = code;
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
            if (p.waiting) {
                bool unblock = false;
                if (p.waitingForPid == -1) unblock = true;
                else if (p.waitingForPid == tid) unblock = true;
                if (unblock) p.waiting = false;
            }
        }
    }
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

    // Copy register state; child returns 0 from fork
    for (uint i = 0; i < NUM_REGS; i++)
        child.regs[i] = parent.regs[i];
    child.regs[REG_RAX] = 0;

    for (int i = 0; i < 512; i++)
        child.sseState[i] = parent.sseState[i];

    // Copy address space regions metadata
    child.regionCount = parent.regionCount;
    for (int i = 0; i < parent.regionCount; i++)
        child.regions[i] = parent.regions[i];

    child.brkStart   = parent.brkStart;
    child.brkCurrent = parent.brkCurrent;
    child.mmapNext   = parent.mmapNext;
    child.parentId   = parentTid;

    // Allocate new PML4 and copy kernel mappings
    ulong childPml4 = alloc_phys_page();
    if (childPml4 == 0) {
        releaseTask(childTid);
        return -12;
    }
    child.pml4Phys = childPml4;
    archMapKernel(childPml4);

    // Deep-copy all user-space pages from parent's page table
    // (must be done while parent's CR3 is active so HHDM accesses work)
    walkAndCopyUserPages(parent.pml4Phys, childPml4);

    // Copy FS base
    d_store_task_fsbase(cast(ulong)childTid,
                        g_task_fsbase[parentTid]);
    child.active = true;

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
    for (int i = 0; i < parent.regionCount; i++)
        child.regions[i] = parent.regions[i];
    child.brkStart   = parent.brkStart;
    child.brkCurrent = parent.brkCurrent;
    child.parentId   = parentTid;

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
    if ((flags & CLONE_PARENT_SETTID) && ptidPtr != 0)
        *cast(int*)ptidPtr = childTid;
    if ((flags & CLONE_CHILD_SETTID) && ctidPtr != 0)
        *cast(int*)ctidPtr = childTid;
    if ((flags & CLONE_CHILD_CLEARTID) && ctidPtr != 0)
        g_threadCleartidVirt[childTid] = ctidPtr;
    else
        g_threadCleartidVirt[childTid] = 0;

    child.active = true;

    klog("[clone] parent="); klog_hex(parentTid);
    klog(" thread="); klog_hex(childTid);
    klog(" stack="); klog_hex(childStack); klog("\n");
    return childTid;
}

// ------------------------------------------------------------------
// execve: replace current task's address space with a new ELF
// ------------------------------------------------------------------

private long execveTask(int tid, ulong pathPtr, ulong argvPtr, ulong envpPtr) {
    auto task = &g_tasks[tid];

    // Find the ELF binary in the boot modules by filename
    const(char)* path = cast(const(char)*)pathPtr;
    ulong modPhys = 0;
    ulong modSize = 0;

    // Try boot module scan
    if (g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;
        for (int i = 0; i < g_module_count; i++) {
            auto rec = cast(multiboot_module_t*)(recs + i * 128);
            // compare path to the tail of the module name
            const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 8); // name field at byte 8
            // basename of module name (part after last '/')
            const(char)* modBase = modName;
            for (const(char)* p = modName; *p != 0; p++)
                if (*p == '/') modBase = p + 1;
            // basename of requested path (e.g. "test-drm" from "/bin/test-drm")
            const(char)* pathBase = path;
            for (const(char)* p = path; *p != 0; p++)
                if (*p == '/') pathBase = p + 1;
            if (cstrEqK(path, modBase) || cstrEqK(path, modName) || cstrEqK(pathBase, modBase)) {
                modPhys = cast(ulong)rec.mod_start;
                modSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                break;
            }
        }
    }

    if (modPhys == 0) {
        klog("[exec] not found: ");
        klog(path);
        klog("\n");
        return -2; // ENOENT
    }

    // Switch to a fresh page table
    ulong newPml4 = alloc_phys_page();
    if (newPml4 == 0) return -12;
    archMapKernel(newPml4);
    x64WriteCR3(newPml4);

    task.pml4Phys    = newPml4;
    task.regionCount = 0;
    task.brkStart    = 0;
    task.brkCurrent  = 0;
    task.mmapNext    = 0x740000000000UL;

    ulong elfVirt = phys_to_virt(modPhys);
    auto res = loadElf(*task, elfVirt, modPhys);
    if (!res.ok) {
        klog("[exec] loadElf failed\n");
        return -8; // ENOEXEC
    }

    // Set brk base to top of ELF image
    task.brkStart   = res.topVirt;
    task.brkCurrent = res.topVirt;

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

    addRegion(*task, stackBase, stackTop, RegionType.Mapped,
              RegionPerms.ReadWrite, stackPhys);

    // Seed the initial stack.  pathPtr, argvPtr, and envpPtr are user-space
    // virtual addresses from the OLD address space (no longer reachable after
    // x64WriteCR3 above), so we zero them out to prevent _copyStrToStack from
    // faulting when it walks the old argv/envp strings.  Programs that need
    // argv will have it provided via a proper copyin path in a later phase.
    ulong[7] infoWords = [res.entry, stackBase, 56 /*phent*/, 1 /*phnum*/,
                           0, 0, 0 /*execfn: was pathPtr, now zeroed*/];
    ulong rsp = linux_seed_initial_stack_with_args(
        stackPhys, stackSize, stackBase,
        infoWords.ptr, 4096, 0 /*argvPtr*/, 0 /*envpPtr*/);

    // GCC compiles _start (with -nostartfiles) as a regular function, assuming
    // RSP ≡ 8 (mod 16) at entry — i.e., as if _start was entered via `call`.
    // The Linux ABI provides RSP ≡ 0 (mod 16) at process entry, which causes
    // misaligned `movaps` in GCC's prologue.  If the seeder returned 0-mod-16,
    // subtract 8 so the exec'd program sees 8-mod-16 (matching `call` semantics).
    if ((rsp & 0xF) == 0) rsp -= 8;

    klog("[exec] entry="); klog_hex(res.entry);
    klog(" rsp="); klog_hex(rsp); klog("\n");

    // Reset registers
    for (uint r = 0; r < NUM_REGS; r++) task.regs[r] = 0;
    task.regs[REG_RIP]    = res.entry;
    task.regs[REG_RSP]    = rsp;
    task.regs[REG_RFLAGS] = 0x202;

    // Clear FS base
    d_store_task_fsbase(cast(ulong)tid, 0);

    // vfork semantics: a successful execve releases the suspended parent (the
    // child now has its own fresh address space, no longer sharing the parent's).
    resumeVforkParent(tid);

    return 0;
}

// ------------------------------------------------------------------
// wait4
// ------------------------------------------------------------------

private long wait4Task(int tid, int waitPid, ulong statusPtr, ulong options) {
    auto task = &g_tasks[tid];

    // Look for an already-exited child
    if (waitPid == -1) {
        for (int c = 1; c < MAX_TASKS; c++) {
            if (task.childExited[c]) {
                int code = task.childExitCode[c];
                task.childExited[c] = false;
                if (statusPtr != 0)
                    *cast(int*)statusPtr = (code & 0xff) << 8;
                releaseTask(c);
                return cast(long)c;
            }
        }
    } else {
        uint c = cast(uint)waitPid;
        if (c < MAX_TASKS && task.childExited[c]) {
            int code = task.childExitCode[c];
            task.childExited[c] = false;
            if (statusPtr != 0)
                *cast(int*)statusPtr = (code & 0xff) << 8;
            releaseTask(c);
            return cast(long)c;
        }
    }

    // WNOHANG?
    enum WNOHANG = 1;
    if (options & WNOHANG) return 0;

    // Block waiting for child
    task.waiting       = true;
    task.waitingForPid = waitPid;
    scheduleNext();
    return -4; // EINTR (will be retried by kernel loop when unblocked)
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
        // Allocate pages from oldAligned to newAligned
        for (ulong pg = oldAligned; pg < newAligned; pg += 4096) {
            ulong phys = alloc_phys_page();
            if (phys == 0) return cast(long)task.brkCurrent; // OOM
            map_page_hhdm(phys, pg, PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
        }
        addRegion(*task, oldAligned, newAligned,
                  RegionType.Mapped, RegionPerms.ReadWrite, 0);
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

        if (dx != 0) input_enqueue(false, EV_REL, REL_X, dx);
        if (dy != 0) input_enqueue(false, EV_REL, REL_Y, dy);

        // Button state
        input_enqueue(false, EV_KEY, BTN_LEFT,   (status & 0x01) ? 1 : 0);
        input_enqueue(false, EV_KEY, BTN_RIGHT,  (status & 0x02) ? 1 : 0);
        input_enqueue(false, EV_KEY, BTN_MIDDLE, (status & 0x04) ? 1 : 0);
        input_enqueue(false, EV_SYN, SYN_REPORT, 0);
    }
}

// ------------------------------------------------------------------
// Syscall dispatch
// ------------------------------------------------------------------

// g_task_fsbase / g_task_fsbase_set are in exports.d
extern __gshared ulong[1024] g_task_fsbase;
extern __gshared bool[1024]  g_task_fsbase_set;

// linux_seed_initial_stack_with_args is in exports.d
extern (C) ulong linux_seed_initial_stack_with_args(
    ulong stackPhys, ulong stackSize, ulong stackVirtBase,
    const(ulong)* infoWords, ulong pg,
    ulong argvUserVirt, ulong envpUserVirt) @nogc nothrow;

private void dispatchSyscall(int tid) {
    ulong rax = x64LastSyscallRax;
    ulong rdi = x64LastSyscallRdi;
    ulong rsi = x64LastSyscallRsi;
    ulong rdx = x64LastSyscallRdx;
    ulong r10 = x64LastSyscallR10;
    ulong r8  = x64LastSyscallR8;
    ulong r9  = x64LastSyscallR9;

    kchar('S');
    klog("[sc] t="); klog_hex(cast(ulong)tid); klog(" n="); klog_hex(rax); klog("\n");

    auto task = &g_tasks[tid];
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
            if (mlen == 0) { ret = -22; break; }
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

            // DRM device mmap: fd refers to an FD_DRM and offset is the physical
            // framebuffer address (returned by MAP_DUMB). Map those pages directly.
            bool useDrmPhys = (moffset != 0) &&
                              (mfd < 1024) &&
                              (g_fdTable[cast(int)mfd].type == FileType.FD_DRM);

            // memfd mmap: fd refers to an FD_MEMFD with backing pages allocated by
            // ftruncate.  Map those physical pages so two processes that share the
            // memfd (via SCM_RIGHTS) see the same memory.
            ulong memfdPhys = 0;
            if (!useDrmPhys && mfd < 1024)
                memfdPhys = memfdResolve(mfd, null);
            bool useMemfd = (memfdPhys != 0);

            // File-backed mmap (MAP_PRIVATE of a regular file): the dynamic linker
            // maps each shared object's segments this way.  Allocate fresh pages
            // and copy the file's bytes at `moffset`, zero-filling past EOF.  Pages
            // stay writable + executable (the kernel never sets NX, so PROT_EXEC is
            // satisfied and ld.so can write relocations); ld.so tightens perms via
            // mprotect afterwards.
            bool useFile = !useDrmPhys && !useMemfd &&
                           (mflags & MAP_ANONYMOUS) == 0 &&
                           cast(long)mfd >= 0 && mfd < 1024;

            for (ulong pg = 0; pg < numPgs; pg++) {
                ulong phys = useDrmPhys ? (moffset + pg * 4096)
                           : useMemfd  ? (memfdPhys + moffset + pg * 4096)
                           : alloc_phys_page();
                if (phys == 0) { mmapOk = false; break; }
                map_page_hhdm(phys, vaddr + pg * 4096,
                              PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
                if (useFile)
                    mmapCopyFileRange(cast(int)mfd, moffset + pg * 4096,
                                      cast(ubyte*)phys_to_virt(phys), 4096);
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
                addRegion(*task, vaddr, vaddr + alignedLen,
                          RegionType.Mapped, RegionPerms.ReadWrite, 0);
            } else {
                if ((mflags & MAP_FIXED) == 0) task.mmapNext -= alignedLen;
                ret = -12;
            }
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
                    task.regs[REG_RAX] = cast(ulong)ret; // parent gets child tid
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
                    g_vforkParentPlus1[cast(int)ret] = tid + 1;
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
                task.regs[REG_RAX] = cast(ulong)ret;
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

        // wait4
        case 61:
            ret = wait4Task(tid, cast(int)rdi, rsi, rdx);
            // If blocking (ret == -EINTR): we'll retry next time this task runs
            break;

        // kill
        case 62:
            ret = linux_sys_kill(rdi, rsi);
            break;

        // waitpid (via wait4 with NULL rusage)
        case 114:
            ret = wait4Task(tid, cast(int)rdi, rsi, rdx);
            break;

        // mprotect
        case 10:
            ret = sys_mprotect(rdi, rsi, rdx);
            break;

        // munmap
        case 11:
            ret = sys_munmap(rdi, rsi);
            break;

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

        // All other Linux syscalls are handled by posix.d
        default:
            ret = dispatchLinuxSyscall(rax, rdi, rsi, rdx, r10, r8, r9);
            break;
    }

    // Cooperative blocking for console reads: when a task read()s the console
    // but no keyboard input is pending, posix.d returns EAGAIN.  Rather than
    // spin in-kernel (which starves every other task under this cooperative
    // scheduler), rewind RIP to the `syscall` instruction (2 bytes: 0F 05) and
    // yield.  The task transparently re-runs read() next time it is scheduled,
    // so userspace still sees a normal blocking read once data arrives.
    if (rax == 0 && ret == -11 /*EAGAIN*/ && isConsoleFd(rdi)) {
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
    if (ret == 0 && (rax == 7 || rax == 271)) {
        const bool wouldBlock = (rax == 7) ? (cast(long)rdx != 0) // poll timeout!=0
                                           : true;                // ppoll: block
        if (wouldBlock) {
            task.regs[REG_RIP] -= 2;
            scheduleNext();
            return;
        }
    }

    task.regs[REG_RAX] = cast(ulong)ret;
}

// Dispatch to the large posix.d table
private long dispatchLinuxSyscall(ulong n, ulong a, ulong b, ulong c,
                                   ulong d, ulong e, ulong f) {
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
        case 79:  return linux_sys_getcwd(a, b);
        case 80:  return linux_sys_chdir(a);
        case 81:  return linux_sys_fchdir(a);
        case 83:  return linux_sys_mkdir(a, b);
        case 84:  return linux_sys_rmdir(a);
        case 87:  return linux_sys_unlink(a);
        case 89:  return linux_sys_readlink(a, b, c);
        case 96:  return linux_sys_gettimeofday(a, b);
        case 97:  return linux_sys_getrlimit(a, b);
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
        case 233: return linux_sys_epoll_create(a);
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
        case 441: return linux_sys_epoll_pwait2(a, b, c, d, e);
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

        // Apply this task's FS base (for TLS)
        d_apply_task_fsbase(cast(ulong)tid);

        // Load task registers into curUserSpaceState
        loadTaskState(*task);

        // Switch to this task's page table
        x64WriteCR3(task.pml4Phys);

        // Hand off to userspace; returns when an interrupt/syscall fires
        ulong reason = x64SwitchToUserspace(
            cast(void*)&curUserSpaceState[0],
            cast(void*)&kernelState[0]);

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
                picEOI(false);
            } else if (irqIdx == 1) {
                // PS/2 keyboard — read all available scancodes
                handleKbdIRQ();
                picEOI(false);
            } else if (irqIdx == 12) {
                // PS/2 mouse — accumulate 3-byte packet
                handleMouseIRQ();
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
    g_tasks[0].mmapNext = 0x740000000000UL;
    g_current_task_id   = 0;

    // Find an ELF module to use as the init process.
    // Preference order: Hyprland desktop, busybox shell, then init.elf.
    ulong initPhys = 0;
    ulong initSize = 0;
    const(char)* initExecName = "sh\0".ptr;
    random_init();
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

        // First pass: Hyprland is the desktop autostart target when present.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 8);
            if (cstrContainsK(name, "Hyprland") || cstrContainsK(name, "hyprland")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
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

    // Copy kernel high-half mappings into the new page table
    archMapKernel(pml4Phys);

    // Switch to the init process page table
    x64WriteCR3(pml4Phys);

    // Load the ELF binary.  A fixed-address ET_EXEC loads at its own vaddrs
    // (bias 0); an ET_DYN (PIE) main exe is relocated to a high base.
    ulong elfVirt = phys_to_virt(initPhys);
    enum ulong MAIN_PIE_BASE = 0x550000000000UL;
    enum ulong INTERP_BASE   = 0x5A0000000000UL;
    ushort initType = *cast(ushort*)(elfVirt + 16);
    ulong mainBias = (initType == 3 /*ET_DYN*/) ? MAIN_PIE_BASE : 0;

    char[256] interpPath;
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
            auto ires = loadElf(g_tasks[0], ipVirt, ipPhys, INTERP_BASE, null, 0);
            if (ires.ok) {
                entryRip = ires.entry;
                atBase   = INTERP_BASE;
                klog("[dkernel] interp loaded base="); klog_hex(INTERP_BASE);
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

    addRegion(g_tasks[0], stackBase, stackTop,
              RegionType.Mapped, RegionPerms.ReadWrite, stackPhys);

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
