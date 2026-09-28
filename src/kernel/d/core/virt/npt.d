// NPT (Nested Page Tables) builder — guest-physical -> host-physical.
//
// AMD's nested paging is conceptually EPT's twin: the VMCB's N_CR3 points
// at a 4-level table that translates guest-physical addresses to
// host-physical addresses.  Unlike EPT it uses ORDINARY x86-64 paging
// encodings (AMD APM Vol 2 §5.4, "Nested Paging"):
//
//   bit 0:    present
//   bit 1:    read/write (1 = writable)
//   bit 2:    user/supervisor (1 = accessible at any CPL — set, because
//             EPT has no U/S distinction and the SLAT abstraction must
//             behave the same on both vendors)
//   bits 4:3: PWT/PCD (0 = write-back, via PAT entry 0)
//   bit 63:   no-execute (1 = not executable)
//
// 4-level walk (PML4 -> PDPT -> PD -> PT), 4 KiB pages, on-demand table
// allocation.  All tables are host-physical pages obtained through the
// injected allocator, so this module is fully testable on the host with a
// fake allocator; the kernel wires in alloc_phys_page/free_phys_page and
// phys_to_virt (see core.virt.slat).
//
// Validation is fail-closed exactly like core.virt.ept: misaligned
// addresses, zero pages, address overflow, and unknown protection bits are
// all rejected; a failed map leaves the NPT unchanged for the failed page
// (callers unwind the pages they already mapped via nptUnmap).
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.npt;

extern (C) @nogc nothrow:

// Allocator interface (injected for host-side testing).
alias NptAllocFn = ulong function();            // zeroed page phys, 0 = fail
alias NptFreeFn  = void function(ulong phys);
alias NptMapFn   = void* function(ulong phys);  // phys -> writable kernel virt

struct Npt {
    ulong pml4Phys;   // 0 = no tables allocated yet
    NptAllocFn allocFn;
    NptFreeFn  freeFn;
    NptMapFn   mapFn;
    uint tables;      // live table count (leak check: 0 after nptFree)
}

// Generic protection bits (see core.virt.slat); translated to NPT
// encodings below.  Values deliberately match the EPT_R/W/X numbering so
// the SLAT layer passes them through untouched.
enum uint NPT_R = 1;
enum uint NPT_W = 2;
enum uint NPT_X = 4;
enum uint NPT_PROT_MASK = NPT_R | NPT_W | NPT_X;

// NPT PTE flag bits (AMD APM Vol 2, nested-paging entry format).
enum ulong NPT_PTE_P  = 1UL << 0;  // present
enum ulong NPT_PTE_RW = 1UL << 1;  // writable
enum ulong NPT_PTE_US = 1UL << 2;  // user-accessible (set: EPT-equivalent)
enum ulong NPT_PTE_NX = 1UL << 63; // not executable

enum ulong NPT_PFN_MASK = 0x000FFFFFFFFFF000UL;

public void nptInit(Npt* n) {
    n.pml4Phys = 0;
    n.allocFn = null;
    n.freeFn = null;
    n.mapFn = null;
    n.tables = 0;
}

// Kernel wiring: real allocators.  Must be called before first nptMap.
public void nptWireKernel(Npt* n, NptAllocFn a, NptFreeFn f, NptMapFn m) {
    n.allocFn = a;
    n.freeFn = f;
    n.mapFn = m;
}

private ulong* nptTable(Npt* n, ulong phys) {
    return cast(ulong*)n.mapFn(phys);
}

private ulong nptNewTable(Npt* n) {
    ulong p = n.allocFn();
    if (p == 0) return 0;
    auto t = nptTable(n, p);
    foreach (i; 0 .. 512) t[i] = 0;
    ++n.tables;
    return p;
}

// Walk to the PT entry for `gpa`, allocating intermediate tables.
// Returns null on allocation failure.
private ulong* nptWalk(Npt* n, ulong gpa, bool create) {
    if (n.pml4Phys == 0) {
        if (!create) return null;
        n.pml4Phys = nptNewTable(n);
        if (n.pml4Phys == 0) return null;
    }
    ulong tabPhys = n.pml4Phys;
    // Levels 4,3,2: PML4, PDPT, PD.  Shifts 39, 30, 21.
    for (int level = 0; level < 3; ++level) {
        int shift = (level == 0) ? 39 : (level == 1) ? 30 : 21;
        auto tab = nptTable(n, tabPhys);
        uint idx = cast(uint)((gpa >> shift) & 0x1FF);
        ulong ent = tab[idx];
        if ((ent & NPT_PTE_P) == 0) {
            if (!create) return null;
            ulong nt = nptNewTable(n);
            if (nt == 0) return null;
            // Non-leaf: P|RW|US.  NX is RESERVED on non-leaf entries
            // (AMD APM Vol 2 §5.4.2 — NX is only defined on the leaf);
            // setting it here would be a nested-paging misconfiguration.
            tab[idx] = nt | NPT_PTE_P | NPT_PTE_RW | NPT_PTE_US;
            ent = tab[idx];
        }
        tabPhys = ent & NPT_PFN_MASK;
        if (tabPhys == 0) return null;
    }
    auto pt = nptTable(n, tabPhys);
    return &pt[(gpa >> 12) & 0x1FF];
}

// Map one guest-physical page.  prot is a subset of NPT_R|W|X.
public bool nptMap(Npt* n, ulong gpa, ulong hpa, uint prot) {
    if (n is null || n.allocFn is null || n.mapFn is null) return false;
    if ((gpa & 0xFFF) != 0 || (hpa & 0xFFF) != 0) return false;
    if ((prot & ~NPT_PROT_MASK) != 0 || (prot & 0x7) == 0) return false;
    // Canonical 48-bit guest-physical bound (no 5-level NPT in this tier).
    if ((gpa >> 48) != 0 || (hpa >> 48) != 0) return false;
    ulong* pte = nptWalk(n, gpa, true);
    if (pte is null) return false;
    if ((*pte & NPT_PTE_P) != 0) return false; // already mapped: caller bug, refuse
    ulong ent = (hpa & NPT_PFN_MASK) | NPT_PTE_P | NPT_PTE_US;
    if ((prot & NPT_W) != 0) ent |= NPT_PTE_RW;
    if ((prot & NPT_X) == 0) ent |= NPT_PTE_NX;
    *pte = ent;
    return true;
}

// Remove one mapping.  Returns the host-phys that was mapped (0 if none).
public ulong nptUnmap(Npt* n, ulong gpa) {
    if (n is null || n.pml4Phys == 0 || n.mapFn is null) return 0;
    if ((gpa & 0xFFF) != 0) return 0;
    ulong* pte = nptWalk(n, gpa, false);
    if (pte is null) return 0;
    ulong old = *pte;
    *pte = 0;
    return old & NPT_PFN_MASK;
}

// Look up the host-phys mapped at gpa (0 if unmapped).
public ulong nptLookup(Npt* n, ulong gpa) {
    if (n is null || n.pml4Phys == 0 || n.mapFn is null) return 0;
    if ((gpa & 0xFFF) != 0) return 0;
    ulong* pte = nptWalk(n, gpa, false);
    if (pte is null) return 0;
    ulong v = *pte;
    return ((v & NPT_PTE_P) != 0) ? (v & NPT_PFN_MASK) : 0;
}

// Look up the raw leaf PTE (0 if unmapped).  Test hook: lets the host
// harness assert the exact NPT encodings (RW/US/NX) without hardware.
public ulong nptLookupRaw(Npt* n, ulong gpa) {
    if (n is null || n.pml4Phys == 0 || n.mapFn is null) return 0;
    if ((gpa & 0xFFF) != 0) return 0;
    ulong* pte = nptWalk(n, gpa, false);
    if (pte is null) return 0;
    return *pte;
}

// Free all tables.  After this, tables == 0 and pml4Phys == 0.
public void nptFree(Npt* n) {
    if (n is null || n.freeFn is null || n.mapFn is null) return;
    if (n.pml4Phys == 0) { n.tables = 0; return; }
    // Depth-first free over the 4 levels.  Only follow present entries.
    ulong[4] stackPhys;
    uint[4] stackIdx;
    int depth = 0;
    stackPhys[0] = n.pml4Phys;
    stackIdx[0] = 0;
    while (depth >= 0) {
        if (depth == 3) {
            // PT level: free the table itself, pop.
            n.freeFn(stackPhys[3]);
            --n.tables;
            --depth;
            continue;
        }
        auto tab = nptTable(n, stackPhys[depth]);
        // Find next present child.
        uint i = stackIdx[depth];
        while (i < 512 && (tab[i] & NPT_PTE_P) == 0) ++i;
        if (i == 512) {
            // No more children: free this table, pop.
            n.freeFn(stackPhys[depth]);
            --n.tables;
            --depth;
            continue;
        }
        stackIdx[depth] = i + 1;
        ++depth;
        stackPhys[depth] = tab[i] & NPT_PFN_MASK;
        stackIdx[depth] = 0;
    }
    n.pml4Phys = 0;
    n.tables = 0;
}
