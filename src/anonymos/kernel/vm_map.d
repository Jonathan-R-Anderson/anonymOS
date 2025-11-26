module anonymos.kernel.vm_map;

import anonymos.kernel.physmem : allocFrame, freeFrame;
import anonymos.kernel.pagetable : mapPage, unmapPage, mapPageInCr3, unmapPageInCr3;
import anonymos.kernel.memory : memcpy, memset;

@nogc nothrow:

enum Prot : uint
{
    read  = 1u << 0,
    write = 1u << 1,
    exec  = 1u << 2,
    user  = 1u << 3,
}

private enum size_t pageSize = 4096;

struct VMRegion
{
    ulong  base;
    size_t length;
    uint   prot;
    size_t pageIndex;   // index into pool for first mapped page
    size_t pageCount;   // number of mapped pages (excludes guards)
    size_t guardBefore;
    size_t guardAfter;
}

/// Simple per-process VM map that tracks regions and programs page tables.
struct VMMap
{
    enum MAX_REGIONS = 32;
    enum MAX_PAGES_PER_REGION = 4096;
    
    VMRegion[MAX_REGIONS] _regions;
    size_t _regionCount;
    ulong _cr3;
    
    // Physical page storage for all regions
    ulong[MAX_PAGES_PER_REGION * MAX_REGIONS] _physPagePool;
    size_t _physPagePoolUsed;

    private size_t regionPageCount(ref const VMRegion region) const @nogc nothrow
    {
        return region.pageCount;
    }

    private bool rangeOverlaps(ulong base, size_t len) const @nogc nothrow
    {
        const ulong end = base + len;
        foreach (idx; 0 .. _regionCount)
        {
            const auto r = _regions[idx];
            const ulong rStart = r.base;
            const ulong rEnd = r.base + r.length;
            if (!(end <= rStart || base >= rEnd))
            {
                return true;
            }
        }
        return false;
    }

    /// Tear down all tracked regions and free their physical pages.
    void reset() @nogc nothrow
    {
        const ulong savedCr3 = _cr3;
        foreach (idx; 0 .. _regionCount)
        {
            auto region = &_regions[idx];
            const size_t totalPages = regionPageCount(*region);

            foreach (page; 0 .. totalPages)
            {
                const virt = region.base + (region.guardBefore + page) * pageSize;
                if (_cr3 != 0)
                {
                    unmapPageInCr3(_cr3, virt);
                }
                else
                {
                    unmapPage(virt);
                }
                freeFrame(_physPagePool[region.pageIndex + page]);
            }

            _regions[idx] = VMRegion.init;
        }

        _regionCount = 0;
        _physPagePoolUsed = 0;
        _cr3 = savedCr3;
    }

    /// Map an anonymous region at `base` with length `len` (bytes), permissions `prot`.
    /// Guards (in pages) can be added before/after (unmapped NOACCESS).
    bool mapRegion(ulong base, size_t len, uint prot, size_t guardBeforePages = 0, size_t guardAfterPages = 0) @nogc nothrow
    {
        assert((prot & (Prot.write | Prot.exec)) != (Prot.write | Prot.exec),
                "W^X enforced: write+exec not allowed");
        assert((base & (pageSize - 1)) == 0, "base must be page aligned");
        if (len == 0 || _regionCount >= MAX_REGIONS) return false;

        const size_t totalPages = (len + pageSize - 1) / pageSize;
        if (totalPages == 0 || totalPages > MAX_PAGES_PER_REGION) return false;
        if (_physPagePoolUsed + totalPages > _physPagePool.length) return false;

        const size_t startIndex = _physPagePoolUsed;
        VMRegion* region = &_regions[_regionCount];
        region.base = base;
        region.length = totalPages * pageSize + (guardBeforePages + guardAfterPages) * pageSize;
        region.prot = prot;
        region.guardBefore = guardBeforePages;
        region.guardAfter = guardAfterPages;
        region.pageIndex = startIndex;
        region.pageCount = totalPages;
        if (rangeOverlaps(region.base, region.length))
        {
            *region = VMRegion.init;
            return false;
        }
        
        // Allocate slice from pool
        ulong[] physPages = _physPagePool[startIndex .. startIndex + totalPages];

        // Map main pages; guards remain unmapped.
        size_t mappedIdx = 0;
        foreach (page; 0 .. totalPages)
        {
            const virt = base + (guardBeforePages + page) * pageSize;
            auto phys = allocFrame();
            if (phys == 0) return false;
            const bool writable = (prot & Prot.write) != 0;
            const bool executable = (prot & Prot.exec) != 0;
            const bool user = (prot & Prot.user) != 0;
            
            bool success;
            if (_cr3 != 0)
            {
                // Map into specific page table (user process)
                import anonymos.kernel.pagetable : mapPageInCr3;
                success = mapPageInCr3(_cr3, virt, phys, writable, executable, user);
            }
            else
            {
                // Map into current page table (kernel)
                success = mapPage(virt, phys, writable, executable, user);
            }
            
            if (!success)
            {
                // Roll back partial mappings
                foreach (rollback; 0 .. mappedIdx)
                {
                    const ulong rollVirt = base + (guardBeforePages + rollback) * pageSize;
                    if (_cr3 != 0)
                    {
                        unmapPageInCr3(_cr3, rollVirt);
                    }
                    else
                    {
                        unmapPage(rollVirt);
                    }
                    freeFrame(physPages[rollback]);
                }
                *region = VMRegion.init;
                return false;
            }
            physPages[mappedIdx++] = phys;
        }

        _physPagePoolUsed += totalPages;
        _regionCount++;
        return true;
    }

    /// Clone all user-space mappings from `src` into this map's CR3.
    /// Allocates new physical pages and copies contents page-for-page.
    bool cloneFrom(const VMMap* src) @nogc nothrow
    {
        if (src is null || src._cr3 == 0 || _cr3 == 0)
        {
            return false;
        }

        reset();

        foreach (idx; 0 .. src._regionCount)
        {
            const auto srcRegion = &src._regions[idx];
            const size_t totalPages = regionPageCount(*srcRegion);

            if (_regionCount >= MAX_REGIONS) { reset(); return false; }
            if (_physPagePoolUsed + totalPages > _physPagePool.length) { reset(); return false; }
            if (rangeOverlaps(srcRegion.base, srcRegion.length)) { reset(); return false; }

            auto destRegion = &_regions[_regionCount];
            *destRegion = *srcRegion;
            destRegion.pageIndex = _physPagePoolUsed;

            auto destPages = _physPagePool[_physPagePoolUsed .. _physPagePoolUsed + totalPages];
            size_t mappedPages = 0;

            foreach (pageIdx; 0 .. totalPages)
            {
                const ulong srcPhys = src._physPagePool[srcRegion.pageIndex + pageIdx];
                const ulong dstPhys = allocFrame();
                if (dstPhys == 0)
                {
                    goto clone_fail;
                }
                destPages[pageIdx] = dstPhys;

                const ulong virt = srcRegion.base + (srcRegion.guardBefore + pageIdx) * pageSize;
                const bool writable   = (srcRegion.prot & Prot.write) != 0;
                const bool executable = (srcRegion.prot & Prot.exec) != 0;
                const bool user       = (srcRegion.prot & Prot.user) != 0;

                if (!mapPageInCr3(_cr3, virt, dstPhys, writable, executable, user))
                {
                    goto clone_fail;
                }

                // Copy full page; caller ensures guards are unmapped.
                memcpy(cast(void*)dstPhys, cast(const void*)srcPhys, pageSize);
                ++mappedPages;
            }

            _physPagePoolUsed += totalPages;
            ++_regionCount;
            continue;

        clone_fail:
            // Roll back this region's allocations.
            foreach (rollback; 0 .. mappedPages)
            {
                const ulong virt = srcRegion.base + (srcRegion.guardBefore + rollback) * pageSize;
                unmapPageInCr3(_cr3, virt);
                freeFrame(destPages[rollback]);
            }
            reset();
            return false;
        }

        return true;
    }

    /// Map a PT_LOAD segment, copy file contents, and track it for cleanup.
    bool mapLoadSegment(ulong vaddr,
                        const(ubyte)[] fileData,
                        ulong fileOffset,
                        size_t fileSize,
                        size_t memSize,
                        bool writable,
                        bool executable) @nogc nothrow
    {
        assert(_cr3 != 0, "mapLoadSegment requires a valid CR3");
        assert(memSize >= fileSize, "memSize must be >= fileSize");
        assert(!(writable && executable), "W^X enforced");

        // Clamp file size if header is bogus.
        if (fileOffset >= fileData.length)
        {
            fileSize = 0;
        }
        else if (fileOffset + fileSize > fileData.length)
        {
            fileSize = fileData.length - fileOffset;
        }

        const ulong pageStart = vaddr & ~(pageSize - 1);
        const ulong pageEnd   = (vaddr + memSize + pageSize - 1) & ~(pageSize - 1);
        const size_t totalPages = cast(size_t)((pageEnd - pageStart) / pageSize);

        assert(totalPages <= MAX_PAGES_PER_REGION, "segment too large");
        assert(_regionCount < MAX_REGIONS, "too many regions");
        assert(_physPagePoolUsed + totalPages <= _physPagePool.length, "out of page slots");
        if (rangeOverlaps(pageStart, totalPages * pageSize))
        {
            return false;
        }

        auto physPages = _physPagePool[_physPagePoolUsed .. _physPagePoolUsed + totalPages];
        size_t mappedPages = 0;
        foreach (pageIdx; 0 .. totalPages)
        {
            auto phys = allocFrame();
            if (phys == 0)
            {
                foreach (rollback; 0 .. mappedPages)
                {
                    unmapPageInCr3(_cr3, pageStart + rollback * pageSize);
                    freeFrame(physPages[rollback]);
                }
                return false;
            }
            physPages[pageIdx] = phys;

            const ulong virt = pageStart + pageIdx * pageSize;
            const bool mapOk = mapPageInCr3(_cr3, virt, phys, writable, executable, true);
            if (!mapOk)
            {
                freeFrame(phys);
                foreach (rollback; 0 .. mappedPages)
                {
                    unmapPageInCr3(_cr3, pageStart + rollback * pageSize);
                    freeFrame(physPages[rollback]);
                }
                return false;
            }

            // Zero entire page before copying.
            memset(cast(void*)phys, 0, pageSize);

            // Copy file portion that overlaps this page.
            const ulong pageDataStart = virt;
            const ulong pageDataEnd   = virt + pageSize;
            const ulong segDataStart  = vaddr;
            const ulong segDataEnd    = vaddr + fileSize;

            const ulong copyStart = (pageDataStart > segDataStart) ? pageDataStart : segDataStart;
            const ulong copyEnd   = (pageDataEnd   < segDataEnd)   ? pageDataEnd   : segDataEnd;

            if (copyEnd > copyStart)
            {
                const size_t copySize = cast(size_t)(copyEnd - copyStart);
                const size_t fileRangeOffset = cast(size_t)(copyStart - segDataStart);
                memcpy(cast(void*)(phys + (copyStart - pageDataStart)),
                       fileData.ptr + fileOffset + fileRangeOffset,
                       copySize);
            }

            ++mappedPages;
        }

        VMRegion* region = &_regions[_regionCount++];
        region.base = pageStart;
        region.length = totalPages * pageSize;
        region.guardBefore = 0;
        region.guardAfter = 0;
        region.prot = Prot.read | (writable ? Prot.write : 0) | (executable ? Prot.exec : 0) | Prot.user;
        region.pageIndex = _physPagePoolUsed;
        region.pageCount = totalPages;

        _physPagePoolUsed += totalPages;
        return true;
    }

    /// Unmap a region starting at base; frees physical pages and removes tracking.
    bool unmapRegion(ulong base) @nogc nothrow
    {
        foreach (idx; 0 .. _regionCount)
        {
            VMRegion* region = &_regions[idx];
            if (region.base == base)
            {
                // Find physical pages for this region
                const size_t pageStart = region.pageIndex;
                const size_t totalPages = region.pageCount;
                
                foreach (page; 0 .. totalPages)
                {
                    const virt = base + (region.guardBefore + page) * pageSize;
                    if (_cr3 != 0)
                    {
                        unmapPageInCr3(_cr3, virt);
                    }
                    else
                    {
                        unmapPage(virt);
                    }
                    freeFrame(_physPagePool[pageStart + page]);
                }
                
                // Remove region by shifting
                foreach (i; idx .. _regionCount - 1)
                {
                    _regions[i] = _regions[i + 1];
                }
                _regionCount--;
                return true;
            }
        }
        return false;
    }

    /// Change protection on an existing region (reprogram PTEs with same phys).
    bool protectRegion(ulong base, uint newProt) @nogc nothrow
    {
        foreach (idx; 0 .. _regionCount)
        {
            VMRegion* region = &_regions[idx];
            if (region.base == base)
            {
                assert((newProt & (Prot.write | Prot.exec)) != (Prot.write | Prot.exec),
                        "W^X enforced: write+exec not allowed");
                region.prot = newProt;
                const bool writable = (newProt & Prot.write) != 0;
                const bool executable = (newProt & Prot.exec) != 0;
                const bool user = (newProt & Prot.user) != 0;
                
                // Find physical pages
                const size_t pageStart = region.pageIndex;
                const size_t totalPages = region.pageCount;
                
                foreach (page; 0 .. totalPages)
                {
                    const virt = base + (region.guardBefore + page) * pageSize;
                    const ulong phys = _physPagePool[pageStart + page];
                    if (_cr3 != 0)
                    {
                        unmapPageInCr3(_cr3, virt);
                        assert(mapPageInCr3(_cr3, virt, phys, writable, executable, user), "remap failed");
                    }
                    else
                    {
                        unmapPage(virt);
                        assert(mapPage(virt, phys, writable, executable, user), "remap failed");
                    }
                }
                return true;
            }
        }
        return false;
    }

    VMRegion* findRegion(ulong base) @nogc nothrow
    {
        foreach (idx; 0 .. _regionCount)
        {
            if (_regions[idx].base == base)
            {
                return &_regions[idx];
            }
        }
        return null;
    }

    /// Create a stack region with guard pages on both sides; returns base of usable stack.
    ulong mapStack(ulong base, size_t stackSize, uint prot) @nogc nothrow
    {
        size_t pages = (stackSize + pageSize - 1) / pageSize;
        // Enforce guard pages flanking the stack.
        assert(mapRegion(base, pages * pageSize, prot, 1, 1));
        return base + pageSize; // skip guard before
    }

    /// Map a code segment (RX, user optional).
    void mapCode(ulong base, size_t len, bool user) @nogc nothrow
    {
        assert(mapRegion(base, len, Prot.read | Prot.exec | (user ? Prot.user : 0), 0, 0));
    }

    /// Map a data/heap segment (RW, user optional).
    void mapData(ulong base, size_t len, bool user) @nogc nothrow
    {
        assert(mapRegion(base, len, Prot.read | Prot.write | (user ? Prot.user : 0), 0, 0));
    }

    /// Map a user stack with guards.
    ulong mapUserStack(ulong base, size_t stackSize) @nogc nothrow
    {
        return mapStack(base, stackSize, Prot.read | Prot.write | Prot.user);
    }

    /// Flip an existing RW (non-exec) region to RX (JIT-style seal).
    bool flipRegionToRX(ulong base) @nogc nothrow
    {
        foreach (idx; 0 .. _regionCount)
        {
            VMRegion* region = &_regions[idx];
            if (region.base == base)
            {
                // Require it was RW and not executable.
                if ((region.prot & Prot.exec) != 0) return false;
                if ((region.prot & Prot.write) == 0) return false;
                uint newProt = (region.prot & ~Prot.write) | Prot.exec;
                return protectRegion(base, newProt);
            }
        }
        return false;
    }

    const(VMRegion)[] regions() const { return _regions[0 .. _regionCount]; }
}
