// HOST STUB for core.addrspace — used only by tests/virt/host.
//
// A fake userspace mapping table with per-page RW bits, which is what the
// userspace-guard tests need:
//
//   stubMapUser(p, n)          — mark pages covering [p, p+n) mapped+WRITABLE
//   stubMapUserReadOnly(p, n)  — mark pages covering [p, p+n) mapped, READ-ONLY
//   userPageMapped(tid, va)    — mapped?
//   userPageWritable(tid, va)  — mapped && writable?
//   handlePageFault(tid, va, isWrite)
//                              — demand-zero: an unmapped page is filled as
//                                writable (like a real fault would); a write
//                                fault on a genuinely read-only page FAILS
//                                (no silent CoW upgrade — that is exactly what
//                                the read-only guard test asserts).
//   userVirtToPhys(tid, va)    — returns ONE shared scratch page's "phys"
//                                for every userspace page.  The virt memslot
//                                path only needs a stable, page-aligned phys
//                                to pin and EPT-map; distinctness is not
//                                required by anything under test.
//
// Table: 2^16-slot open addressing on page address; on overflow an arbitrary
// slot is evicted (documented stub limitation — entries are re-faulted on
// demand, so this degrades gracefully).
//
// Constraints: -betterC, @nogc nothrow.
module core.addrspace;

import core.task : MAX_TASKS;
import core.stdc.stdlib : aligned_alloc;

extern (C) @nogc nothrow:

struct StubPageEntry {
    bool  used;
    bool  writable;
    ulong page; // page-aligned userspace VA
}

enum uint STUB_PAGE_SLOTS = 65536;
enum uint STUB_PAGE_MASK  = STUB_PAGE_SLOTS - 1;

__gshared StubPageEntry[STUB_PAGE_SLOTS] stub_pages;
__gshared uint stub_evictSalt = 0;
__gshared ulong stub_scratchPhys = 0; // shared backing for userVirtToPhys

private uint stubPageHash(ulong page) {
    ulong h = (page >> 12) ^ (page >> 29);
    h ^= h >> 17;
    return cast(uint)h;
}

private StubPageEntry* stubPageFind(ulong page) {
    uint idx = stubPageHash(page) & STUB_PAGE_MASK;
    for (uint n = 0; n < STUB_PAGE_SLOTS; ++n) {
        auto e = &stub_pages[idx];
        if (!e.used) return null;
        if (e.page == page) return e;
        idx = (idx + 1) & STUB_PAGE_MASK;
    }
    return null;
}

private StubPageEntry* stubPageGet(ulong page) {
    uint idx = stubPageHash(page) & STUB_PAGE_MASK;
    for (uint n = 0; n < STUB_PAGE_SLOTS; ++n) {
        auto e = &stub_pages[idx];
        if (!e.used) {
            e.used = true;
            e.page = page;
            e.writable = false;
            return e;
        }
        if (e.page == page) return e;
        idx = (idx + 1) & STUB_PAGE_MASK;
    }
    // Table full: evict a pseudo-random slot (documented fake).
    uint v = stubPageHash(page) ^ (++stub_evictSalt * 0x9E3779B1u);
    auto e = &stub_pages[v & STUB_PAGE_MASK];
    e.used = true;
    e.page = page;
    e.writable = false;
    return e;
}

private bool stubTidOk(int tid) {
    return tid >= 0 && tid < MAX_TASKS;
}

private void stubMarkRange(ulong p, size_t n, bool writable) {
    if (n == 0) return;
    ulong start = p & ~0xFFFUL;
    ulong end = p + n;
    if (end < p) end = ~0UL; // saturate on wrap; pages past the low half
    for (ulong pg = start; pg < end; ) {
        auto e = stubPageGet(pg);
        e.writable = writable;
        if (pg + 0x1000 < pg) break;
        pg += 0x1000;
    }
}

// --- HostTest helpers (imported by core.virt.selftest under version=HostTest)
public void stubMapUser(ulong p, size_t n) {
    stubMarkRange(p, n, true);
}

public void stubMapUserReadOnly(ulong p, size_t n) {
    stubMarkRange(p, n, false);
}

// --- kernel ABI surface -------------------------------------------------------
public bool userPageMapped(int taskId, ulong va) {
    if (!stubTidOk(taskId)) return false;
    auto e = stubPageFind(va & ~0xFFFUL);
    return e !is null;
}

public bool userPageWritable(int taskId, ulong va) {
    if (!stubTidOk(taskId)) return false;
    auto e = stubPageFind(va & ~0xFFFUL);
    return e !is null && e.writable;
}

public bool handlePageFault(int taskId, ulong virtAddr, bool isWrite) {
    if (!stubTidOk(taskId)) return false;
    if (virtAddr < 0x1000) return false; // null page: never faultable
    ulong page = virtAddr & ~0xFFFUL;
    auto e = stubPageFind(page);
    if (e !is null) {
        // Already resolved: a write fault on a read-only mapping genuinely
        // fails (the CoW break would have produced a writable page by now).
        if (isWrite && !e.writable) return false;
        return true;
    }
    // Demand-zero: unmapped pages resolve writable, like the real path.
    auto n = stubPageGet(page);
    n.writable = true;
    return true;
}

public ulong userVirtToPhys(int taskId, ulong va) {
    if (!stubTidOk(taskId)) return 0;
    ulong page = va & ~0xFFFUL;
    if (stubPageFind(page) is null) {
        auto n = stubPageGet(page);
        n.writable = true;
    }
    if (stub_scratchPhys == 0) {
        void* p = aligned_alloc(4096, 4096);
        if (p is null) return 0;
        auto b = cast(ubyte*)p;
        foreach (i; 0 .. 4096) b[i] = 0;
        stub_scratchPhys = cast(ulong)p;
    }
    return stub_scratchPhys;
}
