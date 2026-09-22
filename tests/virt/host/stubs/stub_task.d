// HOST STUB for core.task — used only by tests/virt/host.
//
// core.virt.vm reads g_tasks[tid].untypedObjId (0 here: no budget charged,
// the untyped stubs trivially succeed).  findRegion exists only to satisfy
// the core.virt.kvm import; the virt path never calls it.
module core.task;

extern (C) @nogc nothrow:

enum int MAX_TASKS = 64;

struct StubTask {
    uint untypedObjId; // 0: no untyped budget object in the harness
    uint domainObjId;  // 0: no domain — vmm_policy stub allows all creates
}

struct StubAddrRegion {
    ulong base;
    ulong len;
}

__gshared StubTask[MAX_TASKS] g_tasks;

public StubAddrRegion* findRegion(ref StubTask task, ulong vaddr) {
    cast(void)task; cast(void)vaddr;
    return null;
}
