module kernel.lib.stdc.stdlib;

// Use our own minimal memcpy implementation to avoid
// pulling in external C runtime dependencies.
import kernel.types : memcpy;

// Minimal C standard library function implementations for -betterC builds.
// We provide a very simple bump allocator for kernel use. This is not
// thread safe and does not support freeing memory.

struct BlockHeader {
    size_t size;
}

enum HEAP_SIZE = 1024 * 1024; // 1 MiB heap for kernel allocations
__gshared align(8) ubyte[HEAP_SIZE] heap;
__gshared size_t heapIndex = 0;

extern(C) void* malloc(size_t size)
{
    size_t total = size + BlockHeader.sizeof;
    if(heapIndex + total > HEAP_SIZE) return null;
    auto hdr = cast(BlockHeader*) &heap[heapIndex];
    hdr.size = size;
    heapIndex += total;
    return hdr + 1;
}

extern(C) void* realloc(void* ptr, size_t size)
{
    if(ptr is null) return malloc(size);
    auto oldHdr = cast(BlockHeader*)ptr - 1;
    size_t oldSize = oldHdr.size;
    if(size <= oldSize)
    {
        oldHdr.size = size;
        return ptr;
    }
    auto newPtr = malloc(size);
    if(newPtr !is null)
    {
        memcpy(newPtr, ptr, oldSize);
    }
    return newPtr;
}

extern(C) void free(void* ptr)
{
    // Bump allocator does not support free; ignore.
}

/// Minimal stub for the C `system` function.
/// In a real kernel this would launch a user space
/// program via the process management subsystem.
/// Currently it simply returns -1 to indicate the
/// command was not executed.
extern(C) int system(const(char)* cmd)
{
    // TODO: hook into a user space process launcher.
    return -1;
}

