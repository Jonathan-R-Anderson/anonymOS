// HOST STUB for core.exports — used only by tests/virt/host.
//
// g_current_task_id: the harness is single-tasked; task 0 is the caller.
// phys_to_virt: IDENTITY mapping.  The stub page allocator hands out real
// host pointers as "physical" addresses, so phys == virt here.
module core.exports;

extern (C) @nogc nothrow:

__gshared ulong g_current_task_id = 0;

public void* phys_to_virt(ulong phys) {
    return cast(void*)phys;
}
