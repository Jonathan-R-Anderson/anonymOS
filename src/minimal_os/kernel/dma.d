module minimal_os.kernel.dma;

import minimal_os.kernel.heap : kmalloc;
import minimal_os.kernel.memory : memset;

@nogc nothrow:

/// Allocate physically contiguous DMA memory with the requested alignment.
/// On the current kernel build the physical and virtual addresses are
/// identity-mapped and kmalloc() returns contiguous memory from the kernel
/// heap, so the returned virtual pointer can be treated as DMA-capable.
extern(C) void* dma_alloc(size_t size, size_t alignment, ulong* out_phys)
{
    if (alignment < 64)
    {
        alignment = 64;
    }

    // Align allocation to the requested boundary.
    const size_t mask = alignment - 1;
    size = (size + mask) & ~mask;

    // Over-allocate so we can return an aligned region within.
    auto raw = cast(ubyte*)kmalloc(size + alignment);
    if (raw is null)
    {
        return null;
    }

    // Align the returned pointer.
    auto aligned = cast(ubyte*)(((cast(size_t)raw) + mask) & ~mask);
    memset(aligned, 0, size);

    if (out_phys !is null)
    {
        // Identity-mapped: physical == virtual for DMA regions in this build.
        *out_phys = cast(ulong)aligned;
    }

    return aligned;
}
