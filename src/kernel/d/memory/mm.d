module memory.mm;

import arch.x86_64.limine;
import core.globals;
import core.io;
import core.untyped : untypedRetype, untypedRelease;
import ldc.llvmasm;
import arch.x86_64.arch;

@nogc nothrow:

extern (C):

__gshared limine_memmap_response* mmap_resp;

// Single shared bump pointer for ALL physical allocations.
// Having separate counters for alloc_phys_page vs alloc_phys_pages caused
// them to hand out overlapping physical pages, corrupting page tables.
__gshared ulong g_next_phys_alloc = 0x100000;

// Physical page free list — lets munmap and task teardown actually reclaim
// single 4K pages (the bump pointer never rewinds, so without this every page
// ever mapped leaks and a long-running compositor OOMs).  Sized to cover all of
// a 512 MB guest (131072 pages); frees beyond that are dropped (a harmless leak).
enum size_t FREE_LIST_CAP = 1 << 17;          // 131072 entries * 8B = 1 MB
__gshared ulong[FREE_LIST_CAP] g_free_pages;
__gshared size_t g_free_count = 0;
__gshared ulong  g_free_calls = 0;            // diag counters
__gshared ulong  g_reuse_hits = 0;

// Phase 3 object-memory audit: physical pages can be attributed to the
// MemRegion currently mapping them and/or to a shared VMO backing object.
// Direct-indexed for the 512 MiB guest size this kernel targets today; pages
// outside the table are simply left unattributed.
enum size_t PAGE_AUDIT_CAP = FREE_LIST_CAP;
__gshared uint[PAGE_AUDIT_CAP] g_physPageMemObj;
__gshared uint[PAGE_AUDIT_CAP] g_physPageVmoObj;
__gshared uint[PAGE_AUDIT_CAP] g_physPageUntypedObj;
__gshared ulong g_pageOwnerSetCalls = 0;
__gshared ulong g_pageOwnerClearCalls = 0;
__gshared ulong g_untypedChargeCalls = 0;
__gshared ulong g_untypedChargeDenied = 0;

// IMMUTABLE_ROOTLESS §1.4: once enabled, public physical allocation is no longer
// ambient.  The scheduler/dispatch path selects the current task's Untyped object;
// every page allocation retypes pages from that object and records the page owner
// so free_phys_page() can return quota symmetrically.
__gshared bool g_untypedAllocGateEnabled = false;
__gshared uint g_activeUntypedObjId = 0;

private size_t pageAuditIndex(ulong phys) {
    return cast(size_t)((phys & ~0xFFFUL) >> 12);
}

void physPageSetOwner(ulong phys, uint memObjId, uint vmoObjId = 0) {
    size_t idx = pageAuditIndex(phys);
    if (idx >= PAGE_AUDIT_CAP) return;
    g_physPageMemObj[idx] = memObjId;
    g_physPageVmoObj[idx] = vmoObjId;
    ++g_pageOwnerSetCalls;
}

void physPagesSetOwner(ulong phys, size_t n, uint memObjId, uint vmoObjId = 0) {
    for (size_t i = 0; i < n; ++i)
        physPageSetOwner(phys + i * 4096, memObjId, vmoObjId);
}

void physPageSetUntypedOwner(ulong phys, uint untypedObjId) {
    size_t idx = pageAuditIndex(phys);
    if (idx >= PAGE_AUDIT_CAP) return;
    g_physPageUntypedObj[idx] = untypedObjId;
}

void physPagesSetUntypedOwner(ulong phys, size_t n, uint untypedObjId) {
    for (size_t i = 0; i < n; ++i)
        physPageSetUntypedOwner(phys + i * 4096, untypedObjId);
}

void physClearUntypedOwner(uint untypedObjId) {
    if (untypedObjId == 0) return;
    foreach (ref owner; g_physPageUntypedObj)
        if (owner == untypedObjId) owner = 0;
}

private void physPageReleaseUntyped(ulong phys) {
    size_t idx = pageAuditIndex(phys);
    if (idx >= PAGE_AUDIT_CAP) return;
    uint untypedObjId = g_physPageUntypedObj[idx];
    if (untypedObjId != 0) {
        untypedRelease(untypedObjId, 1);
        g_physPageUntypedObj[idx] = 0;
    }
}

void physPageClearOwner(ulong phys) {
    size_t idx = pageAuditIndex(phys);
    if (idx >= PAGE_AUDIT_CAP) return;
    g_physPageMemObj[idx] = 0;
    g_physPageVmoObj[idx] = 0;
    ++g_pageOwnerClearCalls;
}

void physPageClearMemOwner(ulong phys) {
    size_t idx = pageAuditIndex(phys);
    if (idx >= PAGE_AUDIT_CAP) return;
    g_physPageMemObj[idx] = 0;
    ++g_pageOwnerClearCalls;
}

// Return a single 4K page to the free list for reuse.  GUARDED: only accepts
// pages from the bump pool (>=1 MB and below the high-water mark), so a stray
// device / framebuffer physical address can never be handed back out as RAM.
// Callers must only free pages they exclusively own (anonymous / private file
// maps); never device (g_fb) or shared (memfd) pages — see the `owned` flag.
void free_phys_page(ulong addr) {
    addr &= ~0xFFFUL;
    if (addr < 0x100000) return;             // low memory / null
    if (addr >= g_next_phys_alloc) return;   // never came from the pool
    if (g_free_count >= FREE_LIST_CAP) return; // list full — drop (leak)
    physPageReleaseUntyped(addr);
    physPageClearOwner(addr);
    g_free_pages[g_free_count++] = addr;
    ++g_free_calls;
}

void free_phys_pages(ulong addr, size_t n) {
    foreach (i; 0 .. n) free_phys_page(addr + i * 4096);
}


void init_mm(limine_memmap_response* r) {
    klog("init_mm: starting\n");
    mmap_resp = r;

    if (hhdm_offset != 0) {
        import ldc.llvmasm;
        ulong cr3 = __asm!ulong("mov %cr3, $0", "=r");
        klog("init_mm: CR3="); klog_hex(cr3); klog("\n");

        ulong* pml4 = cast(ulong*)(cr3 + hhdm_offset);
        // Recursive mapping at 510 (0x1FE)
        pml4[510] = cr3 | 3; // Present, RW
        klog("init_mm: Recursive mapping set at index 510\n");
    } else {
        klog("init_mm: Warning: HHDM offset is 0, cannot set recursive mapping!\n");
    }

    klog("init_mm: done\n");
}

void physSetActiveUntyped(uint untypedObjId) {
    g_activeUntypedObjId = untypedObjId;
}

uint physActiveUntyped() {
    return g_activeUntypedObjId;
}

void physEnableUntypedGate(bool enabled = true) {
    g_untypedAllocGateEnabled = enabled;
}

bool physUntypedGateEnabled() {
    return g_untypedAllocGateEnabled;
}

private bool physChargeUntyped(size_t pages, out uint chargedObj) {
    chargedObj = 0;
    if (!g_untypedAllocGateEnabled) return true;
    if (pages == 0) return false;
    uint objId = g_activeUntypedObjId;
    if (objId == 0 || !untypedRetype(objId, cast(ulong)pages)) {
        ++g_untypedChargeDenied;
        return false;
    }
    chargedObj = objId;
    ++g_untypedChargeCalls;
    return true;
}

private void physUnchargeUntyped(uint chargedObj, size_t pages) {
    if (chargedObj == 0 || pages == 0) return;
    untypedRelease(chargedObj, cast(ulong)pages);
}

void archMapKernel(ulong new_cr3) {
    ulong old_cr3 = read_cr3();

    ulong* old_pml4 = cast(ulong*)(old_cr3 + hhdm_offset);
    ulong* new_pml4 = cast(ulong*)(new_cr3 + hhdm_offset);

    klog("archMapKernel: copying kernel mappings\n");

    // Copy entire upper half (kernel + HHDM + everything else)
    for (int i = 256; i < 512; i++) {
        if (i == 510) continue; // skip recursive slot
        new_pml4[i] = old_pml4[i];
    }

    // 🔥 CRITICAL: explicitly ensure HHDM exists (usually slot 256)
    if (new_pml4[256] == 0) {
        klog("archMapKernel: WARNING HHDM missing, forcing copy\n");
        new_pml4[256] = old_pml4[256];
    }

    // 🔥 CRITICAL: explicitly ensure kernel high-half exists (usually slot 511)
    if (new_pml4[511] == 0) {
        klog("archMapKernel: WARNING kernel mapping missing, forcing copy\n");
        new_pml4[511] = old_pml4[511];
    }

    // Set recursive mapping (this page table maps itself)
    new_pml4[510] = new_cr3 | 3; // Present | RW

    // Debug output to confirm mappings
    klog("archMapKernel: PML4[256] = "); klog_hex(new_pml4[256]); klog("\n");
    klog("archMapKernel: PML4[511] = "); klog_hex(new_pml4[511]); klog("\n");
    klog("archMapKernel: done\n");
}

ulong alloc_phys_page() {
    uint chargedObj = 0;
    if (!physChargeUntyped(1, chargedObj)) {
        klog("OOM in alloc_phys_page: untyped denied\n");
        return 0;
    }

    // Reuse a freed page first (zeroed, like the bump path) so churned single-page
    // allocations (per-frame readback buffers, etc.) don't grow the high-water mark.
    if (g_free_count > 0) {
        ulong ret = g_free_pages[--g_free_count];
        ++g_reuse_hits;
        physPageClearOwner(ret);
        physPageSetUntypedOwner(ret, chargedObj);
        if (hhdm_offset != 0) {
            ulong* ptr = cast(ulong*)(ret + hhdm_offset);
            for (size_t k = 0; k < 512; k++) ptr[k] = 0;
        }
        return ret;
    }

    for (size_t i = 0; i < mmap_resp.entry_count; i++) {
        limine_memmap_entry* entry = mmap_resp.entries[i];

        if (entry.type == LIMINE_MEMMAP_USABLE) {
             // Align start to 4K
             ulong start = (entry.base + 0xFFF) & ~0xFFF;
             ulong end   = entry.base + entry.length;

             // If g_next_phys_alloc is below this region, jump to it
             if (g_next_phys_alloc < start) g_next_phys_alloc = start;

             // Check if fits
             if (g_next_phys_alloc + 4096 <= end) {
                 ulong ret = g_next_phys_alloc;
                 g_next_phys_alloc += 4096;
                 physPageClearOwner(ret);
                 physPageSetUntypedOwner(ret, chargedObj);

                 // Zero the page avoiding SSE optimization
                 if (hhdm_offset != 0) {
                     ulong* ptr = cast(ulong*)(ret + hhdm_offset);
                     for(size_t k=0; k < 512; k++) {
                         ptr[k] = 0;
                     }
                 }
                 return ret;
             }
        }
    }
    klog("OOM in alloc_phys_page!\n");
    physUnchargeUntyped(chargedObj, 1);
    return 0;
}

ulong alloc_phys_pages(size_t n) {
    if (n == 0) return 0;

    uint chargedObj = 0;
    if (!physChargeUntyped(n, chargedObj)) {
        klog("OOM in alloc_phys_pages: untyped denied\n");
        return 0;
    }

    ulong needed_size = n * 4096;

    for (size_t i = 0; i < mmap_resp.entry_count; i++) {
        limine_memmap_entry* entry = mmap_resp.entries[i];

        if (entry.type == LIMINE_MEMMAP_USABLE) {
             // Align start to 4K
             ulong start = (entry.base + 0xFFF) & ~0xFFF;
             ulong end   = entry.base + entry.length;

             // If g_next_phys_alloc is below this region, jump to it
             if (g_next_phys_alloc < start) g_next_phys_alloc = start;

             // Check if fits
             if (g_next_phys_alloc + needed_size <= end) {
                 ulong ret = g_next_phys_alloc;
                 g_next_phys_alloc += needed_size;
                 physPagesSetOwner(ret, n, 0, 0);
                 physPagesSetUntypedOwner(ret, n, chargedObj);

                 // Zero the pages
                 if (hhdm_offset != 0) {
                     ulong* ptr = cast(ulong*)(ret + hhdm_offset);
                     for(size_t k=0; k < (needed_size / 8); k++) {
                         ptr[k] = 0;
                     }
                 }
                 return ret;
             }
        }
    }
    klog("OOM in alloc_phys_pages!\n");
    physUnchargeUntyped(chargedObj, n);
    return 0;
}
