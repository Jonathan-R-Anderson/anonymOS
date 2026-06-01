module memory.dma;

import core.globals : hhdm_offset;
import memory.physmem : allocFrame;

@nogc nothrow:

void* dma_alloc(size_t size, size_t alignment, size_t* physOut)
{
    if (size == 0) return null;

    const size_t effectiveAlignment = alignment == 0 ? 1 : alignment;
    const size_t pageSize = 4096;
    size_t first = 0;

    const size_t pages = (size + pageSize - 1) / pageSize;
    foreach (i; 0 .. pages)
    {
        size_t p = allocFrame();
        if (p == 0) return null;
        if (i == 0) first = p;
    }

    size_t aligned = (first + effectiveAlignment - 1) & ~(effectiveAlignment - 1);
    if (physOut !is null) *physOut = aligned;
    return cast(void*)(aligned + cast(size_t)hhdm_offset);
}
