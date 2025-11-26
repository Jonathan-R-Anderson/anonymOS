module anonymos.kernel.heap;

import anonymos.kernel.memory; // for memset

// Simple Bump Pointer Allocator for Kernel Heap
// In a real OS, this would be a slab allocator or similar.

__gshared ubyte[1024 * 1024 * 4] g_kernelHeap; // 4MB Kernel Heap
__gshared size_t g_heapOffset = 0;

extern(C) @nogc nothrow void* kmalloc(size_t size)
{
    // Align to 8 bytes
    size = (size + 7) & ~7;
    
    if (g_heapOffset + size > g_kernelHeap.length)
    {
        return null; // Out of memory
    }
    
    void* ptr = &g_kernelHeap[g_heapOffset];
    g_heapOffset += size;
    
    return ptr;
}

extern(C) @nogc nothrow void kfree(void* ptr)
{
    // No-op for bump allocator
}

extern(C) @nogc nothrow void* kcalloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void* ptr = kmalloc(total);
    if (ptr)
    {
        memset(ptr, 0, total);
    }
    return ptr;
}
