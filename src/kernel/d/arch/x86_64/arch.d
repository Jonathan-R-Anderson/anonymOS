module arch.x86_64.arch;

import arch.x86_64.limine;
import core.io;
import core.globals;

extern (C):

@nogc nothrow:

struct PageTable {
    ulong[512] entries;
}

enum ARCH_PAGE_SIZE = 4096;
enum ARCH_PAGE_SHIFT = 12;

// Page Table Flags
enum PTE_PRESENT = 1 << 0;
enum PTE_RW      = 1 << 1;
enum PTE_USER    = 1 << 2;
enum PTE_WT      = 1 << 3;
enum PTE_CD      = 1 << 4;
enum PTE_ACCESSED= 1 << 5;
enum PTE_DIRTY   = 1 << 6;
enum PTE_PAT     = 1 << 7; 
enum PTE_GLOBAL  = 1 << 8;
enum PTE_NX      = 1UL << 63;

// Helper to access physical memory via HHDM
PageTable* phys_to_virt_pt(ulong phys_addr) {
    if (phys_addr == 0) return null;
    return cast(PageTable*)(phys_addr + hhdm_offset);
}

import ldc.llvmasm;

extern (C) ulong x64ReadCR3();
extern (C) void x64WriteCR3(ulong);
extern (C) ulong x64ReadCR0();
extern (C) void x64WriteCR0(ulong);
extern (C) ulong x64ReadCR4();
extern (C) void x64WriteCR4(ulong);

void enable_sse() {
    ulong cr0 = x64ReadCR0();
    cr0 &= ~(1UL << 2); // EM = 0
    cr0 |= (1UL << 1);  // MP = 1
    x64WriteCR0(cr0);

    ulong cr4 = x64ReadCR4();
    cr4 |= (1UL << 9);  // OSFXSR = 1
    cr4 |= (1UL << 10); // OSXMMEXCPT = 1
    x64WriteCR4(cr4);
}

ulong read_cr3() {
    return x64ReadCR3();
}
 
// Write CR3
void write_cr3(ulong val) {
    x64WriteCR3(val);
}

// Invalidate Page
void invlpg(ulong addr) {
    __asm("invlpg ($0)", "r", addr);
}

// Map Page implementation (basic)
// Requires a physical allocator callback to allocate new tables!
alias PhysAllocFn = ulong function() @nogc nothrow;

void map_page_hhdm(ulong phys_target, ulong virt_addr, ulong flags, PhysAllocFn allocator) {
    ulong pml4_idx = (virt_addr >> 39) & 0x1FF;
    ulong pdpt_idx = (virt_addr >> 30) & 0x1FF;
    ulong pd_idx   = (virt_addr >> 21) & 0x1FF;
    ulong pt_idx   = (virt_addr >> 12) & 0x1FF;

    ulong cr3 = read_cr3();
    PageTable* pml4 = phys_to_virt_pt(cr3 & ~0xFFF);

    if (!(pml4.entries[pml4_idx] & PTE_PRESENT)) {
        ulong new_table_phys = allocator();
        if (new_table_phys == 0) return; // OOM
        // Zero the new table
        PageTable* new_table_virt = phys_to_virt_pt(new_table_phys);
        for(size_t i=0; i<512; i++) new_table_virt.entries[i] = 0;
        
        pml4.entries[pml4_idx] = new_table_phys | PTE_PRESENT | PTE_RW | PTE_USER;
    }

    PageTable* pdpt = phys_to_virt_pt(pml4.entries[pml4_idx] & ~0xFFF);
    if (!(pdpt.entries[pdpt_idx] & PTE_PRESENT)) {
        ulong new_table_phys = allocator();
        if (new_table_phys == 0) return; // OOM
        PageTable* new_table_virt = phys_to_virt_pt(new_table_phys);
        for(size_t i=0; i<512; i++) new_table_virt.entries[i] = 0;
        
        pdpt.entries[pdpt_idx] = new_table_phys | PTE_PRESENT | PTE_RW | PTE_USER;
    }

    PageTable* pd = phys_to_virt_pt(pdpt.entries[pdpt_idx] & ~0xFFF);
    if (!(pd.entries[pd_idx] & PTE_PRESENT)) {
        ulong new_table_phys = allocator();
        if (new_table_phys == 0) return; // OOM
        PageTable* new_table_virt = phys_to_virt_pt(new_table_phys);
        for(size_t i=0; i<512; i++) new_table_virt.entries[i] = 0;

        pd.entries[pd_idx] = new_table_phys | PTE_PRESENT | PTE_RW | PTE_USER;
    }

    PageTable* pt = phys_to_virt_pt(pd.entries[pd_idx] & ~0xFFF);
    pt.entries[pt_idx] = phys_target | flags;
    
    invlpg(virt_addr);
}

// Protect Page implementation
// Updates flags for an existing mapping without allocating new pages
int protect_page_hhdm(ulong virt_addr, ulong flags_set, ulong flags_clear) {
    ulong pml4_idx = (virt_addr >> 39) & 0x1FF;
    ulong pdpt_idx = (virt_addr >> 30) & 0x1FF;
    ulong pd_idx   = (virt_addr >> 21) & 0x1FF;
    ulong pt_idx   = (virt_addr >> 12) & 0x1FF;

    ulong cr3 = read_cr3();
    PageTable* pml4 = phys_to_virt_pt(cr3 & ~0xFFF);

    if (!(pml4.entries[pml4_idx] & PTE_PRESENT)) return 0; // Not mapped

    PageTable* pdpt = phys_to_virt_pt(pml4.entries[pml4_idx] & ~0xFFF);
    if (!(pdpt.entries[pdpt_idx] & PTE_PRESENT)) return 0; // Not mapped

    PageTable* pd = phys_to_virt_pt(pdpt.entries[pdpt_idx] & ~0xFFF);
    if (!(pd.entries[pd_idx] & PTE_PRESENT)) return 0; // Not mapped

    PageTable* pt = phys_to_virt_pt(pd.entries[pd_idx] & ~0xFFF);
    if (!(pt.entries[pt_idx] & PTE_PRESENT)) return 0; // Not mapped

    // Update flags
    pt.entries[pt_idx] |= flags_set;
    pt.entries[pt_idx] &= ~flags_clear;
    
    invlpg(virt_addr);
    return 1; // Success
}

// Unmap Page implementation
void unmap_page_hhdm(ulong virt_addr) {
    ulong pml4_idx = (virt_addr >> 39) & 0x1FF;
    ulong pdpt_idx = (virt_addr >> 30) & 0x1FF;
    ulong pd_idx   = (virt_addr >> 21) & 0x1FF;
    ulong pt_idx   = (virt_addr >> 12) & 0x1FF;

    ulong cr3 = read_cr3();
    PageTable* pml4 = phys_to_virt_pt(cr3 & ~0xFFF);

    if (!(pml4.entries[pml4_idx] & PTE_PRESENT)) return;

    PageTable* pdpt = phys_to_virt_pt(pml4.entries[pml4_idx] & ~0xFFF);
    if (!(pdpt.entries[pdpt_idx] & PTE_PRESENT)) return;

    PageTable* pd = phys_to_virt_pt(pdpt.entries[pdpt_idx] & ~0xFFF);
    if (!(pd.entries[pd_idx] & PTE_PRESENT)) return;

    PageTable* pt = phys_to_virt_pt(pd.entries[pd_idx] & ~0xFFF);
    if (!(pt.entries[pt_idx] & PTE_PRESENT)) return;

    // Clear present bit
    pt.entries[pt_idx] &= ~PTE_PRESENT;
    
    // We should probably verify if we can free the physical frame here?
    // But since we use a bump allocator for physical memory without a free list, for now we just leak it.
    // TODO: Free physical frame.

    invlpg(virt_addr);
}
