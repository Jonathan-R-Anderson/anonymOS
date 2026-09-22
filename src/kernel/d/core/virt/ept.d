// EPT (Extended Page Tables) builder — guest-physical -> host-physical.
//
// 4-level walk (PML4 -> PDPT -> PD -> PT), 4 KiB pages, on-demand table
// allocation.  All tables are host-physical pages obtained through the
// injected allocator, so this module is fully testable on the host with a
// fake allocator; the kernel wires in alloc_phys_page/free_phys_page and
// phys_to_virt (see core.virt.vm).
//
// EPT PTE format (Intel SDM vol 3C §29.3.2):
//   bit 0: readable, bit 1: writable, bit 2: executable
//   bits 5:3: EPT memory type (6 = write-back)
//   bit 6: ignore PAT, bits 7: reserved 0
//   bits 11:8: ignored / accessed(dirty only for large pages at PT level we
//     still leave 0 — the CPU sets them)
//   bits (phys-1):12: page frame number
//
// Validation is fail-closed: misaligned addresses, zero pages, address
// overflow, and unknown protection bits are all rejected; a failed map
// leaves the EPT unchanged for the failed page (callers unwind the
// pages they already mapped via eptUnmap).
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.ept;

extern (C) @nogc nothrow:

// Allocator interface (injected for host-side testing).
alias EptAllocFn = ulong function();            // zeroed page phys, 0 = fail
alias EptFreeFn  = void function(ulong phys);
alias EptMapFn   = void* function(ulong phys);  // phys -> writable kernel virt

struct Ept {
    ulong pml4Phys;   // 0 = no tables allocated yet
    EptAllocFn allocFn;
    EptFreeFn  freeFn;
    EptMapFn   mapFn;
    uint tables;      // live table count (leak check: 0 after eptFree)
}

enum uint EPT_R = 1;
enum uint EPT_W = 2;
enum uint EPT_X = 4;
enum uint EPT_PROT_MASK = EPT_R | EPT_W | EPT_X;

enum ulong EPT_MT_WB = 6; // write-back memory type

public void eptInit(Ept* e) {
    e.pml4Phys = 0;
    e.allocFn = null;
    e.freeFn = null;
    e.mapFn = null;
    e.tables = 0;
}

// Kernel wiring: real allocators.  Must be called before first eptMap.
public void eptWireKernel(Ept* e, EptAllocFn a, EptFreeFn f, EptMapFn m) {
    e.allocFn = a;
    e.freeFn = f;
    e.mapFn = m;
}

private ulong* eptTable(Ept* e, ulong phys) {
    return cast(ulong*)e.mapFn(phys);
}

private ulong eptNewTable(Ept* e) {
    ulong p = e.allocFn();
    if (p == 0) return 0;
    auto t = eptTable(e, p);
    foreach (i; 0 .. 512) t[i] = 0;
    ++e.tables;
    return p;
}

// Walk to the PT entry for `gpa`, allocating intermediate tables.
// Returns null on allocation failure.  `level` is for the free walk.
private ulong* eptWalk(Ept* e, ulong gpa, bool create) {
    if (e.pml4Phys == 0) {
        if (!create) return null;
        e.pml4Phys = eptNewTable(e);
        if (e.pml4Phys == 0) return null;
    }
    ulong tabPhys = e.pml4Phys;
    // Levels 4,3,2: PML4, PDPT, PD.  Shifts 39, 30, 21.
    for (int level = 0; level < 3; ++level) {
        int shift = (level == 0) ? 39 : (level == 1) ? 30 : 21;
        auto tab = eptTable(e, tabPhys);
        uint idx = cast(uint)((gpa >> shift) & 0x1FF);
        ulong ent = tab[idx];
        if ((ent & 0x7) == 0) {
            if (!create) return null;
            ulong nt = eptNewTable(e);
            if (nt == 0) return null;
            // Non-leaf: R|W|X only.  Bits 5:3 (EPT memory type) are RESERVED
            // and must be zero on entries that reference another EPT table
            // (SDM Vol 3C Table 28-3); only leaf entries carry a memory type.
            // Setting them here would be an EPT misconfiguration on VM entry.
            tab[idx] = nt | 0x7;
            ent = tab[idx];
        }
        tabPhys = ent & 0x000FFFFFFFFFF000UL;
        if (tabPhys == 0) return null;
    }
    auto pt = eptTable(e, tabPhys);
    return &pt[(gpa >> 12) & 0x1FF];
}

// Map one guest-physical page.  prot is a subset of EPT_R|W|X.
public bool eptMap(Ept* e, ulong gpa, ulong hpa, uint prot) {
    if (e is null || e.allocFn is null || e.mapFn is null) return false;
    if ((gpa & 0xFFF) != 0 || (hpa & 0xFFF) != 0) return false;
    if ((prot & ~EPT_PROT_MASK) != 0 || (prot & 0x7) == 0) return false;
    // Canonical 48-bit guest-physical bound (phase 1: no 5-level EPT).
    if ((gpa >> 48) != 0 || (hpa >> 48) != 0) return false;
    ulong* pte = eptWalk(e, gpa, true);
    if (pte is null) return false;
    if ((*pte & 0x7) != 0) return false; // already mapped: caller bug, refuse
    *pte = (hpa & 0x000FFFFFFFFFF000UL) | (prot & 0x7) | (EPT_MT_WB << 3);
    return true;
}

// Remove one mapping.  Returns the host-phys that was mapped (0 if none).
public ulong eptUnmap(Ept* e, ulong gpa) {
    if (e is null || e.pml4Phys == 0 || e.mapFn is null) return 0;
    if ((gpa & 0xFFF) != 0) return 0;
    ulong* pte = eptWalk(e, gpa, false);
    if (pte is null) return 0;
    ulong old = *pte;
    *pte = 0;
    return old & 0x000FFFFFFFFFF000UL;
}

// Look up the host-phys mapped at gpa (0 if unmapped).
public ulong eptLookup(Ept* e, ulong gpa) {
    if (e is null || e.pml4Phys == 0 || e.mapFn is null) return 0;
    if ((gpa & 0xFFF) != 0) return 0;
    ulong* pte = eptWalk(e, gpa, false);
    if (pte is null) return 0;
    ulong v = *pte;
    return ((v & 0x7) != 0) ? (v & 0x000FFFFFFFFFF000UL) : 0;
}

// Free all tables.  After this, tables == 0 and pml4Phys == 0.
public void eptFree(Ept* e) {
    if (e is null || e.freeFn is null || e.mapFn is null) return;
    if (e.pml4Phys == 0) { e.tables = 0; return; }
    // Depth-first free over the 4 levels.  Only follow entries with any
    // of R/W/X set (unmapped entries are zero).
    ulong[4] stackPhys;
    uint[4] stackIdx;
    int depth = 0;
    stackPhys[0] = e.pml4Phys;
    stackIdx[0] = 0;
    while (depth >= 0) {
        if (depth == 3) {
            // PT level: free the table itself, pop.
            e.freeFn(stackPhys[3]);
            --e.tables;
            --depth;
            continue;
        }
        auto tab = eptTable(e, stackPhys[depth]);
        // Find next present child.
        uint i = stackIdx[depth];
        while (i < 512 && (tab[i] & 0x7) == 0) ++i;
        if (i == 512) {
            // No more children: free this table, pop.
            e.freeFn(stackPhys[depth]);
            --e.tables;
            --depth;
            continue;
        }
        stackIdx[depth] = i + 1;
        ++depth;
        stackPhys[depth] = tab[i] & 0x000FFFFFFFFFF000UL;
        stackIdx[depth] = 0;
    }
    e.pml4Phys = 0;
    e.tables = 0;
}
