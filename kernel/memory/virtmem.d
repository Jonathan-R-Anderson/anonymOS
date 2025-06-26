module kernel.memory.virtmem;

import kernel.lib.stdc.stdlib : malloc, realloc, free;
import kernel.types : memset;
import kernel.logger : log_message, log_hex;

struct Segment {
    void* base;
    size_t len;
    bool readonly;
}

struct ProcMem {
    void* buf;        // brk-style heap
    size_t len;
    Segment[8] segs;
    size_t segCount;
}

__gshared ProcMem[16] procTable;

extern(C) void virtmem_init()
{
    foreach(ref p; procTable)
    {
        p.buf = null;
        p.len = 0;
        p.segCount = 0;
    }
    log_message("virtmem_init\n");
}

extern(C) void* virtmem_alloc(size_t pid, size_t size)
{
    if(pid >= procTable.length) return null;
    auto pm = &procTable[pid];
    size_t oldlen = pm.len;
    size_t newlen = pm.len + size;
    if(pm.buf is null)
        pm.buf = malloc(newlen);
    else
        pm.buf = realloc(pm.buf, newlen);
    pm.len = newlen;
    log_message("virtmem_alloc pid="); log_hex(pid); log_message(" size="); log_hex(size); log_message("\n");
    return cast(void*)((cast(ubyte*)pm.buf) + oldlen);
}

extern(C) void* virtmem_resize(size_t pid, size_t newlen)
{
    if(pid >= procTable.length) return null;
    auto pm = &procTable[pid];
    if(pm.buf is null)
        pm.buf = malloc(newlen);
    else
        pm.buf = realloc(pm.buf, newlen);
    pm.len = newlen;
    return pm.buf;
}

extern(C) size_t virtmem_size(size_t pid)
{
    if(pid >= procTable.length) return 0;
    return procTable[pid].len;
}

extern(C) void virtmem_free(size_t pid)
{
    if(pid >= procTable.length) return;
    if(procTable[pid].buf !is null)
    {
        free(procTable[pid].buf);
        procTable[pid].buf = null;
        procTable[pid].len = 0;
    }
    log_message("virtmem_free pid="); log_hex(pid); log_message("\n");
}

extern(C) int brk(size_t pid, size_t addr)
{
    if(pid >= procTable.length) return -1;
    auto pm = &procTable[pid];
    if(addr == 0)
        return 0;
    auto nb = virtmem_resize(pid, addr);
    return nb is null ? -1 : 0;
}

extern(C) size_t seg_attach(size_t pid, void* addr, size_t length, bool readonly)
{
    if(pid >= procTable.length) return size_t.max;
    auto pm = &procTable[pid];
    if(pm.segCount >= pm.segs.length) return size_t.max;
    void* base;
    if(addr is null)
        base = malloc(length);
    else
        base = addr; // unmanaged when addr provided
    if(base is null) return size_t.max;
    pm.segs[pm.segCount] = Segment(base, length, readonly);
    size_t id = pm.segCount;
    pm.segCount++;
    return id;
}

extern(C) int seg_detach(size_t pid, size_t seg)
{
    if(pid >= procTable.length) return -1;
    auto pm = &procTable[pid];
    if(seg >= pm.segCount) return -1;
    if(pm.segs[seg].base !is null && pm.segs[seg].base != pm.buf)
        free(pm.segs[seg].base);
    for(size_t i = seg; i + 1 < pm.segCount; i++)
        pm.segs[i] = pm.segs[i+1];
    pm.segCount--;
    return 0;
}

extern(C) int seg_brk(size_t pid, size_t seg, size_t length)
{
    if(pid >= procTable.length) return -1;
    auto pm = &procTable[pid];
    if(seg >= pm.segCount) return -1;
    auto s = &pm.segs[seg];
    if(s.readonly) return -1;
    auto nb = realloc(s.base, length);
    if(nb is null) return -1;
    s.base = nb;
    s.len = length;
    return 0;
}

extern(C) int seg_free(size_t pid, size_t seg, void* addr, size_t length)
{
    if(pid >= procTable.length) return -1;
    auto pm = &procTable[pid];
    if(seg >= pm.segCount) return -1;
    auto s = &pm.segs[seg];
    if(addr is null || addr == s.base)
    {
        free(s.base);
        s.base = null;
        s.len = 0;
        return 0;
    }
    // partial free just memset to zero
    memset(addr, 0, length);
    return 0;
}

extern(C) int seg_flush(size_t pid, size_t seg, void* addr, size_t length)
{
    // nothing to do in this simple implementation
    return 0;
}
