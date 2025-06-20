module kernel.memory.virtmem;

import core.stdc.stdlib : malloc, realloc, free;
import kernel.logger : log_message, log_hex;

struct ProcMem {
    void* buf;
    size_t len;
}

__gshared ProcMem[16] procTable;

extern(C) void virtmem_init()
{
    foreach(ref p; procTable)
    {
        p.buf = null;
        p.len = 0;
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
