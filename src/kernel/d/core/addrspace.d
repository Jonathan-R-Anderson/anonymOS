module core.addrspace;

import core.task;
import core.io;
import core.globals;
import memory.mm;
import arch.x86_64.arch;

extern (C) @nogc nothrow:

extern (C) ulong x64ReadCR2() @nogc nothrow;
extern (C) ulong x64ReadCR3() @nogc nothrow;
extern (C) void  x64WriteCR3(ulong) @nogc nothrow;
extern (C) void  x64Invlpg(ulong) @nogc nothrow;
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
// Software/AVL PTE bit (CPU ignores bits 9..11): marks a 4K page that fork()
// shared copy-on-write.  A write fault on such a page makes a private copy (or,
// if it is the last reference, just restores write permission in place).
private enum ulong PTE_COW = 1UL << 9;

// DIAGNOSTIC (Hyprland heap-corruption hunt): counts how often fork's !privatePage
// branch shares an ALREADY-CoW pool frame — the rank-1 suspect's precondition, where
// a new holder is added with no matching physPageRefInc.  If this stays 0 across a
// Hyprland boot, candidate 1 cannot be the corruptor.
__gshared ulong g_cowShareNoRefN = 0;

// Walk the 4-level table rooted at pml4Phys (through the HHDM) and return a
// pointer to the leaf PTE backing `va`, or null if `va` is not mapped by a 4K
// page (absent at any level, or a 2 MiB/1 GiB large page).
private ulong* leafPTEPtr(ulong pml4Phys, ulong va) {
    auto p4 = cast(ulong*)(pml4Phys + hhdm_offset);
    ulong e4 = p4[(va >> 39) & 0x1FF];
    if (!(e4 & PTE_PRESENT)) return null;
    auto p3 = cast(ulong*)((e4 & PTE_ADDR_MASK) + hhdm_offset);
    ulong e3 = p3[(va >> 30) & 0x1FF];
    if (!(e3 & PTE_PRESENT) || (e3 & PTE_PS)) return null;
    auto p2 = cast(ulong*)((e3 & PTE_ADDR_MASK) + hhdm_offset);
    ulong e2 = p2[(va >> 21) & 0x1FF];
    if (!(e2 & PTE_PRESENT) || (e2 & PTE_PS)) return null;
    auto p1 = cast(ulong*)((e2 & PTE_ADDR_MASK) + hhdm_offset);
    return &p1[(va >> 12) & 0x1FF];
}

// Is the page containing `va` present in task `taskId`'s address space?  Used by the
// fatal-page-fault path so it can safely peek at the user stack (e.g. to log the return
// address) WITHOUT itself faulting the kernel — a stack overflow leaves rsp unmapped, and
// dereferencing it from kernel context would otherwise escalate to a fatal KERNEL FAULT.
public bool userPageMapped(int taskId, ulong va) {
    if (taskId < 0 || taskId >= MAX_TASKS) return false;
    auto pte = leafPTEPtr(g_tasks[taskId].pml4Phys, va & ~0xFFFUL);
    return pte !is null && (*pte & PTE_PRESENT) != 0;
}

// L3b: translate a userspace virtual address in task `taskId` to its physical address — the LKL PCI
// backend's .map_page uses this as the no-IOMMU DMA IOVA so a device can DMA into LKL's buffers.
// Returns 0 if `va` is not backed by a present 4K page.
public ulong userVirtToPhys(int taskId, ulong va) {
    if (taskId < 0 || taskId >= MAX_TASKS) return 0;
    auto pte = leafPTEPtr(g_tasks[taskId].pml4Phys, va & ~0xFFFUL);
    if (pte is null || !(*pte & PTE_PRESENT)) return 0;
    return (*pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// Same, but for the CURRENTLY-active address space (the calling task during a syscall) — no task id
// needed.  Used by the L3b LKL PCI bridge syscall to translate a caller's DMA buffer to a phys IOVA.
public ulong activeVirtToPhys(ulong va) {
    const ulong pml4 = x64ReadCR3() & PTE_ADDR_MASK;
    auto pte = leafPTEPtr(pml4, va & ~0xFFFUL);
    if (pte is null || !(*pte & PTE_PRESENT)) return 0;
    return (*pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// Walk PML4 entries 0..255 (user space) and deep-copy every mapped page
// from srcPml4Phys into dstPml4Phys.  Called during fork.
void walkAndCopyUserPages(ulong srcPml4, ulong dstPml4, Task* dstTask = null) {
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

                    ulong va = (cast(ulong)a << 39) |
                               (cast(ulong)b << 30) |
                               (cast(ulong)c << 21) |
                               (cast(ulong)d << 12);
                    AddrRegion* region = (dstTask !is null) ? findRegion(*dstTask, va) : null;

                    // Only exclusively-owned private RAM (anonymous / private
                    // file maps, allocated from the bump pool) may be shared
                    // copy-on-write.  Device pages (g_fb / DRM) and shared memfd
                    // maps must remain genuinely shared after fork, so the child
                    // points at the same frame with identical flags — no CoW,
                    // no refcount (free_phys_page already refuses such pages).
                    bool poolPage    = (srcPage >= 0x100000 && srcPage < g_next_phys_alloc);
                    bool privatePage = poolPage && (region !is null) && region.owned;

                    if (!privatePage) {
                        dpt[d] = spt[d];
                        // DIAGNOSTIC: an already-CoW pool frame reaching the !private
                        // branch gains the child as a holder WITHOUT a physPageRefInc
                        // → undercount → premature free (rank-1 suspect).  Log if it fires.
                        if (poolPage && (spt[d] & PTE_COW) && g_cowShareNoRefN < 32) {
                            ++g_cowShareNoRefN;
                            klog("[fork] COW pool frame shared w/o refInc srcPage=");
                            klog_hex(srcPage); klog(" va="); klog_hex(va);
                            klog(" owned="); klog_hex(region ? (region.owned ? 1 : 0) : 9);
                            klog("\n");
                        }
                        continue;
                    }

                    // Copy-on-write: demote BOTH parent and child to read-only +
                    // CoW over the same physical frame.  The first write by
                    // either side faults into handlePageFault, which makes a
                    // private copy (or reclaims write permission in place if it
                    // is by then the last reference).  This is what lets a large
                    // process fork without duplicating its whole address space.
                    ulong cowFlags = (flags & ~PTE_RW) | PTE_COW;
                    spt[d] = srcPage | cowFlags; // parent now CoW (TLB flushed in forkTask)
                    dpt[d] = srcPage | cowFlags; // child shares the frame
                    physPageRefInc(srcPage);
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
    ulong page  = virtAddr & ~0xFFFUL;

    // Copy-on-write (fork): a write to a frame that fork() shared read-only is
    // resolved here, before any region-type handling — the PTE's CoW bit is
    // authoritative even if region bookkeeping has since changed.  If we are the
    // last reference we just restore write permission in place (no copy/alloc).
    if (isWrite) {
        ulong* pte = leafPTEPtr(task.pml4Phys, page);
        if (pte !is null && (*pte & PTE_PRESENT) && (*pte & PTE_COW)) {
            ulong oldPhys = *pte & PTE_ADDR_MASK;
            ulong keep    = (*pte & ~PTE_ADDR_MASK & ~PTE_COW) | PTE_RW;
            if (physPageRefGet(oldPhys) > 1) {
                ulong nw = alloc_phys_page();
                if (nw == 0) return false;
                copy_phys_page(oldPhys, nw);
                physPageRefDec(oldPhys);
                *pte = nw | keep;
                physPageSetOwner(nw, region ? region.objId : 0, region ? region.vmoObjId : 0);
            } else {
                physPageRefDec(oldPhys); // normalize the count to 0 (exclusive)
                *pte = oldPhys | keep;
            }
            x64Invlpg(page); // drop just this page's stale read-only TLB entry
            return true;
        }
    }

    if (region is null) {
        klog("[pf] no region tid="); klog_hex(taskId);
        klog(" va="); klog_hex(virtAddr); klog("\n");
        return false;
    }

    objEnsureRegion(region);

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
            physPageSetOwner(phys, region.objId, region.vmoObjId);
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
                physPageSetOwner(newPhys, region.objId, region.vmoObjId);
            } else {
                // Read on unmapped COW page — map read-only to source
                ulong offset  = page - region.start;
                ulong srcPhys = region.physBase + offset;
                map_page_hhdm(srcPhys, page, PTE_PRESENT | PTE_USER, &alloc_phys_page);
                physPageSetOwner(srcPhys, region.objId, region.vmoObjId);
            }
            return true;

        case RegionType.AllocateOnDemand:
            // Demand-zero: alloc_phys_page already zeroes the page
            ulong newPhys = alloc_phys_page();
            if (newPhys == 0) return false;
            ulong flags = PTE_PRESENT | PTE_USER;
            if (region.perms == RegionPerms.ReadWrite) flags |= PTE_RW;
            map_page_hhdm(newPhys, page, flags, &alloc_phys_page);
            physPageSetOwner(newPhys, region.objId, region.vmoObjId);
            return true;
    }
}
