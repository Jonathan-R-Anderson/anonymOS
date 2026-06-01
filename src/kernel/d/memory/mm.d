module memory.mm;

import arch.x86_64.limine;
import core.globals;
import core.io;
import ldc.llvmasm;
import arch.x86_64.arch;

@nogc nothrow:

extern (C):

__gshared limine_memmap_response* mmap_resp;

// Single shared bump pointer for ALL physical allocations.
// Having separate counters for alloc_phys_page vs alloc_phys_pages caused
// them to hand out overlapping physical pages, corrupting page tables.
__gshared ulong g_next_phys_alloc = 0x100000;


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
    return 0;
}

ulong alloc_phys_pages(size_t n) {
    if (n == 0) return 0;

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
    return 0;
}
