module memory.dma;

import core.globals : hhdm_offset;
import memory.physmem : allocFrame, freeFrame;

@nogc nothrow:

void* dma_alloc(size_t size, size_t alignment, size_t* physOut)
{
    if (size == 0) return null;

    const size_t effectiveAlignment = alignment == 0 ? 1 : alignment;
    const size_t pageSize = 4096;
    size_t first = 0;

    // The frames must be PHYSICALLY CONTIGUOUS: callers hand `*physOut` to a device that will DMA
    // across the whole range, so a gap would make the controller write into unrelated memory.  The
    // page allocator hands out ascending frames, and this verifies that rather than assuming it --
    // a 64 KiB buffer got away with the assumption; a 1 MiB one is 256 frames and would not.
    //
    // A failed attempt gives its frames back.  This is now a real path, not a theoretical one:
    // the block layer asks for 1 MiB and walks down to 64 KiB, so a machine whose free memory is
    // fragmented can fail four times before succeeding, and keeping 480 leaked frames from that
    // walk would be a permanent loss for the life of the boot.
    const size_t pages = (size + pageSize - 1) / pageSize;
    size_t prev = 0;
    size_t got = 0;
    void unwind() @nogc nothrow {
        foreach (j; 0 .. got) freeFrame(first + j * pageSize);
    }
    foreach (i; 0 .. pages)
    {
        size_t p = allocFrame();
        if (p == 0) { unwind(); return null; }
        if (i == 0) first = p;
        else if (p != prev + pageSize) { freeFrame(p); unwind(); return null; }  // gap: refuse rather than corrupt
        prev = p;
        ++got;
    }

    size_t aligned = (first + effectiveAlignment - 1) & ~(effectiveAlignment - 1);
    if (physOut !is null) *physOut = aligned;
    return cast(void*)(aligned + cast(size_t)hhdm_offset);
}
