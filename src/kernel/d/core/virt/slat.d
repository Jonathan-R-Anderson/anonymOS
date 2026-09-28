// SLAT — second-level address translation abstraction.
//
// The native Vm object must not permanently embed an Intel-specific EPT:
// on AMD hardware the same guest-physical -> host-physical translation is
// provided by NPT (nested paging).  This module is the vendor-neutral
// layer over both:
//
//   Intel VM ──▶ Slat(Ept) ──▶ EPT  ──▶ EPTP
//   AMD VM   ──▶ Slat(Npt) ──▶ NPT  ──▶ N_CR3
//
// The VM's pinned-page bookkeeping, ceilings, and security model stay
// common (see core.virt.vm); only the table encodings differ, and those
// live in core.virt.ept / core.virt.npt.  Protection bits are generic
// (R/W/X); each backend translates them to its own PTE format.
//
// Constraints: -betterC, @nogc nothrow.
module core.virt.slat;

import core.virt.ept;
import core.virt.npt;

extern (C) @nogc nothrow:

enum SlatKind : ubyte {
    None = 0,
    Ept  = 1, // Intel Extended Page Tables
    Npt  = 2, // AMD nested paging
}

// Generic protection bits.  Values match EPT_R/W/X numbering so the
// existing vm.d call sites pass through untouched.
enum uint SLAT_R = 1;
enum uint SLAT_W = 2;
enum uint SLAT_X = 4;
enum uint SLAT_PROT_MASK = SLAT_R | SLAT_W | SLAT_X;

// Allocator interface (injected for host-side testing; the kernel passes
// alloc_phys_page / free_phys_page / phys_to_virt).
alias SlatAllocFn = ulong function();
alias SlatFreeFn  = void function(ulong phys);
alias SlatMapFn   = void* function(ulong phys);

struct Slat {
    SlatKind kind;
    Ept ept; // valid when kind == Ept
    Npt npt; // valid when kind == Npt
}

public void slatInit(Slat* s, SlatKind kind) {
    s.kind = kind;
    eptInit(&s.ept);
    nptInit(&s.npt);
}

// Kernel wiring: real allocators for whichever backend is active.  Must be
// called before first slatMap.
public void slatWireKernel(Slat* s, SlatAllocFn a, SlatFreeFn f, SlatMapFn m) {
    if (s is null) return;
    eptWireKernel(&s.ept, cast(EptAllocFn)a, cast(EptFreeFn)f, cast(EptMapFn)m);
    nptWireKernel(&s.npt, cast(NptAllocFn)a, cast(NptFreeFn)f, cast(NptMapFn)m);
}

// Map one guest-physical page.  prot is a subset of SLAT_R|W|X.
public bool slatMap(Slat* s, ulong gpa, ulong hpa, uint prot) {
    if (s is null) return false;
    if (s.kind == SlatKind.Ept)
        return eptMap(&s.ept, gpa, hpa, prot);
    if (s.kind == SlatKind.Npt)
        return nptMap(&s.npt, gpa, hpa, prot);
    return false; // None / unknown: fail closed
}

// Remove one mapping.  Returns the host-phys that was mapped (0 if none).
public ulong slatUnmap(Slat* s, ulong gpa) {
    if (s is null) return 0;
    if (s.kind == SlatKind.Ept)
        return eptUnmap(&s.ept, gpa);
    if (s.kind == SlatKind.Npt)
        return nptUnmap(&s.npt, gpa);
    return 0;
}

// Look up the host-phys mapped at gpa (0 if unmapped).
public ulong slatLookup(Slat* s, ulong gpa) {
    if (s is null) return 0;
    if (s.kind == SlatKind.Ept)
        return eptLookup(&s.ept, gpa);
    if (s.kind == SlatKind.Npt)
        return nptLookup(&s.npt, gpa);
    return 0;
}

// Root table physical address for the backend (EPTP base / N_CR3).
// 0 = no tables built yet.
public ulong slatRootPhys(Slat* s) {
    if (s is null) return 0;
    if (s.kind == SlatKind.Ept)
        return s.ept.pml4Phys;
    if (s.kind == SlatKind.Npt)
        return s.npt.pml4Phys;
    return 0;
}

// Number of page-table pages currently allocated (root + intermediates).
public uint slatTableCount(Slat* s) {
    if (s is null) return 0;
    if (s.kind == SlatKind.Ept)
        return s.ept.tables;
    if (s.kind == SlatKind.Npt)
        return s.npt.tables;
    return 0;
}

// Free all tables.  After this the live-table count is 0.
public void slatFree(Slat* s) {
    if (s is null) return;
    if (s.kind == SlatKind.Ept)
        eptFree(&s.ept);
    else if (s.kind == SlatKind.Npt)
        nptFree(&s.npt);
}

// Live table count (leak check: 0 after slatFree).
public uint slatTables(Slat* s) {
    if (s is null) return 0;
    if (s.kind == SlatKind.Ept)
        return s.ept.tables;
    if (s.kind == SlatKind.Npt)
        return s.npt.tables;
    return 0;
}
