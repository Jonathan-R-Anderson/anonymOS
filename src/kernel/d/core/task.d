module core.task;

import core.io;
import core.globals;
import memory.mm;

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
enum MAX_REGIONS = 512;

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
}

struct Task {
    bool active;
    bool exited;
    bool waiting;   // blocked in wait4, vfork, or a scheduler-backed futex wait
    int  exitCode;
    int  parentId;

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
}

__gshared Task[MAX_TASKS] g_tasks;

// Allocate a task slot (id > 0 reserved for non-init tasks)
int allocTask() {
    for (int i = 1; i < MAX_TASKS; i++) {
        if (!g_tasks[i].active) {
            g_tasks[i] = Task.init;
            g_tasks[i].active = true;
            g_tasks[i].mmapNext = 0x700000000000UL;
            return i;
        }
    }
    return -1;
}

void releaseTask(int tid) {
    if (tid > 0 && tid < MAX_TASKS)
        g_tasks[tid] = Task.init;
}

// Add a virtual address region to a task
bool addRegion(ref Task task, ulong start, ulong end,
               RegionType type, RegionPerms perms, ulong physBase = 0) {
    if (task.regionCount >= MAX_REGIONS) {
        klog("[task] addRegion: full\n");
        return false;
    }
    auto r          = &task.regions[task.regionCount++];
    r.start         = start;
    r.end           = end;
    r.type          = type;
    r.perms         = perms;
    r.physBase      = physBase;
    return true;
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
