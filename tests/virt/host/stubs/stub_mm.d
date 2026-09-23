// HOST STUB for memory.mm — used only by tests/virt/host.
//
// malloc-backed 4 KiB pages: alloc_phys_page returns a real host pointer
// (as ulong "phys"; phys_to_virt is the identity in the exports stub, so
// the virt modules can touch the pages directly).  physPageRefInc/Dec keep
// a tiny advisory refcount table — nothing in the virt path reads the
// counts, but pin/unpin balance is at least tracked.
module memory.mm;

import core.stdc.stdlib : aligned_alloc, free;

extern (C) @nogc nothrow:

private void stubZero(void* p, size_t n) {
    auto b = cast(ubyte*)p;
    foreach (i; 0 .. n) b[i] = 0;
}

public ulong alloc_phys_page() {
    void* p = aligned_alloc(4096, 4096);
    if (p is null) return 0;
    stubZero(p, 4096);
    return cast(ulong)p;
}

public void free_phys_page(ulong addr) {
    if (addr == 0) return;
    stubRefDrop(addr);
    free(cast(void*)addr);
}

// Contiguous multi-page alloc (host stub: one malloc, n*4KiB, 4KiB-aligned).
public ulong alloc_phys_pages(size_t n) {
    if (n == 0) return 0;
    void* p = aligned_alloc(4096, n * 4096);
    if (p is null) return 0;
    stubZero(p, n * 4096);
    return cast(ulong)p;
}

public void free_phys_pages(ulong addr, size_t n) {
    if (addr == 0) return;
    stubRefDrop(addr);
    free(cast(void*)addr);
}

// --- advisory pin counts ----------------------------------------------------
struct StubPinEntry {
    ulong phys;
    ulong refs;
}

enum uint STUB_PIN_MAX = 128;
__gshared StubPinEntry[STUB_PIN_MAX] stub_pins;

private StubPinEntry* stubPinFind(ulong phys) {
    foreach (ref e; stub_pins)
        if (e.phys == phys) return &e;
    return null;
}

public void physPageRefInc(ulong phys) {
    if (phys == 0) return;
    auto e = stubPinFind(phys);
    if (e !is null) { ++e.refs; return; }
    foreach (ref s; stub_pins) {
        if (s.phys == 0) { s.phys = phys; s.refs = 1; return; }
    }
    // Table full: fake it (documented stub limitation; counts are advisory).
}

public bool physPageRefDec(ulong phys) {
    if (phys == 0) return false;
    auto e = stubPinFind(phys);
    if (e is null) return false;
    if (e.refs > 0) --e.refs;
    if (e.refs == 0) e.phys = 0;
    return true;
}

private void stubRefDrop(ulong phys) {
    auto e = stubPinFind(phys);
    if (e !is null) { e.phys = 0; e.refs = 0; }
}
