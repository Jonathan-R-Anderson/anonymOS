module anonymos.kernel.physmem;

import anonymos.multiboot;



private enum pageSize = 4096uL;

private __gshared ubyte[] g_bitmap; // 1 = used, 0 = free
private __gshared size_t g_totalFrames;
private __gshared size_t g_freeFrames;

private void setUsed(size_t frame) @nogc nothrow
{
    const idx = frame >> 3;
    const bit = frame & 7;
    g_bitmap[idx] |= cast(ubyte)(1u << bit);
}

private void setFree(size_t frame) @nogc nothrow
{
    const idx = frame >> 3;
    const bit = frame & 7;
    if ((g_bitmap[idx] & (1u << bit)) != 0)
    {
        g_freeFrames += 1;
    }
    g_bitmap[idx] &= cast(ubyte)~(1u << bit);
}

private bool isFree(size_t frame) @nogc nothrow
{
    const idx = frame >> 3;
    const bit = frame & 7;
    return (g_bitmap[idx] & (1u << bit)) == 0;
}

private void reserveRange(size_t start, size_t length) @nogc nothrow
{
    const first = start / pageSize;
    const last  = (start + length + pageSize - 1) / pageSize;
    foreach (f; first .. last)
    {
        if (f < g_totalFrames) setUsed(f);
    }
}

/// Initialise the physical memory bitmap from the firmware memory map.
/// Marks all frames used, then frees frames in available regions, excluding
/// low memory (first 2 MiB), multiboot modules, and framebuffer.
extern(C) pragma(inline, false) void physMemInit(void* ctxPtr)
{
    auto ctx = cast(MultibootContext*)ctxPtr;
    const info = ctx.info;

    // Determine max address
    size_t maxAddr = 0;
    
    // Check memory map flag (bit 6)
    if (info.flags & (1 << 6))
    {
        size_t current = info.mmapAddr;
        size_t remaining = info.mmapLength;
        
        while (remaining > 0)
        {
            auto entry = cast(MultibootMmapEntry*)current;
            const end = cast(size_t)(entry.address + entry.length);
            if (end > maxAddr) maxAddr = end;
            
            const advance = entry.entrySize + uint.sizeof;
            current += advance;
            if (advance >= remaining) remaining = 0;
            else remaining -= advance;
        }
    }
    
    // Fallback to upper memory if no map (bit 0)
    if (maxAddr == 0 && (info.flags & (1 << 0)))
    {
        maxAddr = (info.memLower + info.memUpper) * 1024;
    }
    assert(maxAddr > 0, "No memory map available");

    g_totalFrames = (maxAddr + pageSize - 1) / pageSize;
    g_bitmap.length = (g_totalFrames + 7) / 8;
    // Mark all used
    foreach (ref b; g_bitmap) b = 0xFF;
    g_freeFrames = 0;

    // Free available regions
    if (info.flags & (1 << 6))
    {
        size_t current = info.mmapAddr;
        size_t remaining = info.mmapLength;
        
        while (remaining > 0)
        {
            auto entry = cast(MultibootMmapEntry*)current;
            if (entry.entryType == MmapRegionType.available)
            {
                size_t addr = cast(size_t)entry.address;
                size_t len  = cast(size_t)entry.length;
                const first = addr / pageSize;
                const last  = (addr + len) / pageSize;
                foreach (f; first .. last)
                {
                    if (f < g_totalFrames) setFree(f);
                }
            }
            
            const advance = entry.entrySize + uint.sizeof;
            current += advance;
            if (advance >= remaining) remaining = 0;
            else remaining -= advance;
        }
    }

    // Reserve low memory (first 2 MiB) to cover kernel/boot structures.
    reserveRange(0, 2 * 1024 * 1024);

    // Reserve multiboot modules (bit 3)
    if (info.flags & (1 << 3))
    {
        auto mod = cast(MultibootModule*)cast(size_t)info.modsAddr;
        foreach (i; 0 .. info.modsCount)
        {
            const start = cast(size_t)mod[i].modStart;
            const len   = cast(size_t)(mod[i].modEnd - mod[i].modStart);
            reserveRange(start, len);
        }
    }

    // Reserve framebuffer (bit 12)
    if (info.flags & (1 << 12))
    {
        // We still use selectFramebufferMode because it's complex logic.
        // If this fails, we'll have to inline it too.
        const fb = selectFramebufferMode(info, FramebufferModeRequest.init);
        if (fb.valid())
        {
            const size_t fbSize = cast(size_t)fb.pitch * fb.height;
            reserveRange(cast(size_t)fb.base, fbSize);
        }
    }
}

/// Allocate one 4KiB frame; returns physical address or 0 on failure.
size_t allocFrame() @nogc nothrow
{
    foreach (idx, ref b; g_bitmap)
    {
        if (b == 0xFF) continue; // all used
        foreach (bit; 0 .. 8)
        {
            const frame = (idx << 3) + bit;
            if (frame >= g_totalFrames) break;
            if ((b & (1u << bit)) == 0)
            {
                b |= cast(ubyte)(1u << bit);
                if (g_freeFrames > 0) g_freeFrames -= 1;
                return frame * pageSize;
            }
        }
    }
    return 0;
}

/// Free a previously allocated frame by physical address.
void freeFrame(size_t phys) @nogc nothrow
{
    const frame = phys / pageSize;
    assert(frame < g_totalFrames, "frame out of range");
    if (!isFree(frame))
    {
        const idx = frame >> 3;
        const bit = frame & 7;
        g_bitmap[idx] &= cast(ubyte)~(1u << bit);
        g_freeFrames += 1;
    }
}

size_t totalFrames() @nogc nothrow { return g_totalFrames; }
size_t freeFrames()  @nogc nothrow { return g_freeFrames; }
