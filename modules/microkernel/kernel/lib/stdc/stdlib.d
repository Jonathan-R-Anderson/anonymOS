module kernel.lib.stdc.stdlib;

// Use our own minimal memcpy implementation to avoid
// pulling in external C runtime dependencies.
import kernel.types : memcpy, strlen, memcmp;
import kernel.process_manager : process_create, scheduler_run;
import kernel.shell : sh_shell;

// Minimal C standard library function implementations for -betterC builds.
// The previous revision used a bump allocator that could only grow the heap.
// This version implements a tiny free list based allocator so that memory
// can be returned back to the heap.

struct BlockHeader {
    size_t size;          // Size of the user portion
    BlockHeader* next;    // Next block in free list when free
}

enum HEAP_SIZE = 1024 * 1024; // 1 MiB heap for kernel allocations
__gshared align(8) ubyte[HEAP_SIZE] heap;
__gshared BlockHeader* freeList;
__gshared bool heapInit = false;

private enum ALIGN = 8;

private size_t alignUp(size_t n)
{
    return (n + (ALIGN - 1)) & ~(ALIGN - 1);
}

private void heap_init()
{
    if(!heapInit)
    {
        auto first = cast(BlockHeader*)heap.ptr;
        first.size = HEAP_SIZE - BlockHeader.sizeof;
        first.next = null;
        freeList = first;
        heapInit = true;
    }
}

extern(C) void* malloc(size_t size)
{
    heap_init();
    size = alignUp(size);
    BlockHeader* prev = null;
    for(auto cur = freeList; cur !is null; prev = cur, cur = cur.next)
    {
        if(cur.size >= size)
        {
            size_t remain = cur.size - size;
            if(remain >= BlockHeader.sizeof + ALIGN)
            {
                auto next = cast(BlockHeader*)((cast(ubyte*)(cur + 1)) + size);
                next.size = remain - BlockHeader.sizeof;
                next.next = cur.next;
                if(prev is null)
                    freeList = next;
                else
                    prev.next = next;
                cur.size = size;
            }
            else
            {
                if(prev is null)
                    freeList = cur.next;
                else
                    prev.next = cur.next;
            }
            return cur + 1;
        }
    }
    return null;
}

extern(C) void* realloc(void* ptr, size_t size)
{
    if(ptr is null) return malloc(size);
    if(size == 0)
    {
        free(ptr);
        return null;
    }
    size = alignUp(size);
    auto oldHdr = cast(BlockHeader*)ptr - 1;
    auto oldSize = oldHdr.size;
    if(size <= oldSize)
    {
        size_t remain = oldSize - size;
        if(remain >= BlockHeader.sizeof + ALIGN)
        {
            auto newBlock = cast(BlockHeader*)((cast(ubyte*)(oldHdr + 1)) + size);
            newBlock.size = remain - BlockHeader.sizeof;
            oldHdr.size = size;
            free(newBlock + 1);
        }
        return ptr;
    }
    auto newPtr = malloc(size);
    if(newPtr !is null)
    {
        memcpy(newPtr, ptr, oldSize);
        free(ptr);
    }
    return newPtr;
}

extern(C) void free(void* ptr)
{
    if(ptr is null) return;
    heap_init();
    auto hdr = cast(BlockHeader*)ptr - 1;
    BlockHeader* prev = null;
    auto cur = freeList;
    while(cur !is null && cur < hdr)
    {
        prev = cur;
        cur = cur.next;
    }
    hdr.next = cur;
    if(prev is null)
        freeList = hdr;
    else
        prev.next = hdr;

    // merge with next
    if(hdr.next !is null)
    {
        auto expected = cast(BlockHeader*)((cast(ubyte*)(hdr + 1)) + hdr.size);
        if(expected is hdr.next)
        {
            hdr.size += BlockHeader.sizeof + hdr.next.size;
            hdr.next = hdr.next.next;
        }
    }
    // merge with prev
    if(prev !is null)
    {
        auto expected = cast(BlockHeader*)((cast(ubyte*)(prev + 1)) + prev.size);
        if(expected is hdr)
        {
            prev.size += BlockHeader.sizeof + hdr.size;
            prev.next = hdr.next;
        }
    }
}

/// Minimal stub for the C `system` function.
/// In a real kernel this would launch a user space
/// program via the process management subsystem.
/// Currently it simply returns -1 to indicate the
/// command was not executed.
private bool str_eq(const(char)* a, string b)
{
    auto len = strlen(a);
    if(len != b.length) return false;
    return memcmp(a, b.ptr, len) == 0;
}

extern(C) int system(const(char)* cmd)
{
    if(cmd is null) return -1;

    // Very small command mapping to demonstrate integration with
    // the kernel's process manager. The built-in shell can be
    // launched via either "shell" or "sh".
    if(str_eq(cmd, "shell") || str_eq(cmd, "sh"))
    {
        process_create(&sh_shell);
        scheduler_run();
        return 0;
    }

    // Command not recognized
    return -1;
}

