module kernel.thread;

pragma(LDC_no_moduleinfo);

import kernel.lib.stdc.stdlib : malloc, free;

struct ThreadContext {
    ulong rsp;
    ulong rbp;
    ulong rbx;
    ulong r12;
    ulong r13;
    ulong r14;
    ulong r15;
}

extern(C) void switch_thread(ThreadContext* old, ThreadContext* next);
extern(C) void restore_first(ThreadContext* next);

alias ThreadEntry = extern(C) void function();

struct Thread {
    ThreadContext ctx;
    ThreadEntry entry;
    ubyte* stack;
    bool active;
}

enum MAX_THREADS = 16;
__gshared Thread[MAX_THREADS] g_threads;
__gshared size_t g_thread_count = 0;
__gshared size_t current_thread = size_t.max;

extern(C) void thread_init()
{
    g_thread_count = 0;
    current_thread = size_t.max;
}

extern(C) size_t thread_create(ThreadEntry fn)
{
    import kernel.logger : log_message, log_hex;
    if(g_thread_count >= MAX_THREADS)
        return size_t.max;
    auto id = g_thread_count++;
    auto t = &g_threads[id];
    size_t stack_size = 4096 * 4;
    t.stack = cast(ubyte*)malloc(stack_size);
    auto sp = t.stack + stack_size;
    sp -= 8;
    *(cast(ulong*)sp) = cast(ulong)&thread_exit;
    sp -= 8;
    *(cast(ulong*)sp) = cast(ulong)fn;
    t.ctx.rsp = cast(ulong)sp;
    t.ctx.rbp = cast(ulong)sp;
    t.ctx.rbx = 0;
    t.ctx.r12 = 0;
    t.ctx.r13 = 0;
    t.ctx.r14 = 0;
    t.ctx.r15 = 0;
    t.entry = fn;
    t.active = true;
    log_message("Thread created id=");
    log_hex(id);
    log_message("\n");
    return id;
}

extern(C) void thread_start()
{
    if(g_thread_count == 0)
        return;
    current_thread = 0;
    restore_first(&g_threads[0].ctx);
}

extern(C) void thread_yield()
{
    if(g_thread_count < 2)
        return;
    size_t old = current_thread;
    size_t next = old;
    for(size_t i = 0; i < g_thread_count; ++i)
    {
        next = (next + 1) % g_thread_count;
        if(g_threads[next].active)
            break;
    }
    if(next == old)
        return; // no other active thread
    current_thread = next;
    switch_thread(&g_threads[old].ctx, &g_threads[next].ctx);
}

extern(C) void thread_exit()
{
    g_threads[current_thread].active = false;
    size_t old = current_thread;
    size_t next = old;
    for(size_t i = 0; i < g_thread_count; ++i)
    {
        next = (next + 1) % g_thread_count;
        if(g_threads[next].active)
            break;
    }
    if(g_threads[next].active)
    {
        current_thread = next;
        switch_thread(&g_threads[old].ctx, &g_threads[next].ctx);
    }
    while(true) asm { "hlt"; }
}

extern(C) bool threads_active()
{
    foreach(t; g_threads[0 .. g_thread_count])
    {
        if(t.active)
            return true;
    }
    return false;
}

