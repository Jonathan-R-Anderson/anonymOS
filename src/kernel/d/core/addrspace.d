module core.addrspace;

import core.task;
import core.io;
import core.globals;
import memory.mm;
import arch.x86_64.arch;

extern (C) @nogc nothrow:

extern (C) ulong x64ReadCR2() @nogc nothrow;
extern (C) ulong x64ReadCR3() @nogc nothrow;
extern __gshared ulong x64TrapErrorCode;

extern (C) void copy_phys_page(ulong srcPhys, ulong dstPhys) @nogc nothrow;

// Physical-frame bits of a 64-bit page-table entry (bits 51:12).  Masking with
// ~0xFFF is WRONG: it keeps the high flag bits — notably NX (bit 63), set on
// every non-executable user page (stacks, heap, data) — so the "physical
// address" would carry 0x8000_0000_0000_0000 and any HHDM dereference of it
// faults.  Always isolate the frame with this mask.
private enum ulong PTE_ADDR_MASK = 0x000F_FFFF_FFFF_F000UL;
// Page-Size bit: set on a PDPT/PD entry that maps a 1 GiB / 2 MiB page rather
// than pointing at the next table level.
private enum ulong PTE_PS = 1UL << 7;

// Walk PML4 entries 0..255 (user space) and deep-copy every mapped page
// from srcPml4Phys into dstPml4Phys.  Called during fork.
void walkAndCopyUserPages(ulong srcPml4, ulong dstPml4) {
    auto src4 = cast(ulong*)(srcPml4 + hhdm_offset);
    auto dst4 = cast(ulong*)(dstPml4 + hhdm_offset);

    for (int a = 0; a < 256; a++) {
        if (!(src4[a] & PTE_PRESENT)) continue;

        ulong spdptPhys = src4[a] & PTE_ADDR_MASK;
        auto  spdpt     = cast(ulong*)(spdptPhys + hhdm_offset);

        if (!(dst4[a] & PTE_PRESENT)) {
            ulong np = alloc_phys_page();
            if (np == 0) return;
            dst4[a] = np | PTE_PRESENT | PTE_RW | PTE_USER;
        }
        auto dpdpt = cast(ulong*)((dst4[a] & PTE_ADDR_MASK) + hhdm_offset);

        for (int b = 0; b < 512; b++) {
            if (!(spdpt[b] & PTE_PRESENT)) continue;
            // 1 GiB huge page would need large-page copy; the kernel never maps
            // user space this way, so skip defensively rather than mis-walk it.
            if (spdpt[b] & PTE_PS) { klog("[fork] skip 1G page\n"); continue; }

            ulong spdPhys = spdpt[b] & PTE_ADDR_MASK;
            auto  spd     = cast(ulong*)(spdPhys + hhdm_offset);

            if (!(dpdpt[b] & PTE_PRESENT)) {
                ulong np = alloc_phys_page();
                if (np == 0) return;
                dpdpt[b] = np | PTE_PRESENT | PTE_RW | PTE_USER;
            }
            auto dpd = cast(ulong*)((dpdpt[b] & PTE_ADDR_MASK) + hhdm_offset);

            for (int c = 0; c < 512; c++) {
                if (!(spd[c] & PTE_PRESENT)) continue;
                if (spd[c] & PTE_PS) { klog("[fork] skip 2M page\n"); continue; }

                ulong sptPhys = spd[c] & PTE_ADDR_MASK;
                auto  spt     = cast(ulong*)(sptPhys + hhdm_offset);

                if (!(dpd[c] & PTE_PRESENT)) {
                    ulong np = alloc_phys_page();
                    if (np == 0) return;
                    dpd[c] = np | PTE_PRESENT | PTE_RW | PTE_USER;
                }
                auto dpt = cast(ulong*)((dpd[c] & PTE_ADDR_MASK) + hhdm_offset);

                for (int d = 0; d < 512; d++) {
                    if (!(spt[d] & PTE_PRESENT)) continue;

                    ulong srcPage = spt[d] & PTE_ADDR_MASK;
                    // Preserve every non-frame bit (perms + NX + PAT/etc.).
                    ulong flags   = spt[d] & ~PTE_ADDR_MASK;

                    ulong newPage = alloc_phys_page();
                    if (newPage == 0) return;
                    copy_phys_page(srcPage, newPage);
                    dpt[d] = newPage | flags;
                }
            }
        }
    }
}

// Handle a page fault at virtAddr for task taskId.
// isWrite: bit 1 of the error code is set.
// Returns true if handled, false for a fatal fault.
bool handlePageFault(int taskId, ulong virtAddr, bool isWrite) {
    auto task   = &g_tasks[taskId];
    auto region = findRegion(*task, virtAddr);

    if (region is null) {
        klog("[pf] no region tid="); klog_hex(taskId);
        klog(" va="); klog_hex(virtAddr); klog("\n");
        return false;
    }

    ulong page = virtAddr & ~0xFFFUL;

    final switch (region.type) {

        case RegionType.None:
            return false;

        case RegionType.Mapped:
            // Already eagerly mapped; re-map in case PTE was lost
            ulong offset  = page - region.start;
            ulong phys    = region.physBase + offset;
            ulong flags   = PTE_PRESENT | PTE_USER;
            if (region.perms == RegionPerms.ReadWrite) flags |= PTE_RW;
            map_page_hhdm(phys, page, flags, &alloc_phys_page);
            return true;

        case RegionType.CopyOnWrite:
            if (isWrite) {
                // Allocate new page, copy from source, map writeable
                ulong offset  = page - region.start;
                ulong srcPhys = region.physBase + offset;
                ulong newPhys = alloc_phys_page();
                if (newPhys == 0) return false;
                copy_phys_page(srcPhys, newPhys);
                ulong flags = PTE_PRESENT | PTE_USER;
                if (region.perms == RegionPerms.ReadWrite) flags |= PTE_RW;
                map_page_hhdm(newPhys, page, flags, &alloc_phys_page);
            } else {
                // Read on unmapped COW page — map read-only to source
                ulong offset  = page - region.start;
                ulong srcPhys = region.physBase + offset;
                map_page_hhdm(srcPhys, page, PTE_PRESENT | PTE_USER, &alloc_phys_page);
            }
            return true;

        case RegionType.AllocateOnDemand:
            // Demand-zero: alloc_phys_page already zeroes the page
            ulong newPhys = alloc_phys_page();
            if (newPhys == 0) return false;
            ulong flags = PTE_PRESENT | PTE_USER;
            if (region.perms == RegionPerms.ReadWrite) flags |= PTE_RW;
            map_page_hhdm(newPhys, page, flags, &alloc_phys_page);
            return true;
    }
}
