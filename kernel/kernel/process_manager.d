module kernel.process_manager;

pragma(LDC_no_moduleinfo);

import kernel.logger : log_message, log_hex;
import kernel.object_namespace : Object;
import kernel.lib.stdc.stdlib : malloc, free;

public:

struct Process {
    size_t pid;
    extern(C) void function() entry;
    const(char)* name;
    bool started;
    bool exited;
    int exit_status;
    size_t parent;
    extern(C) void function(const(char)*) note_handler;
    ulong alarm_tick;
    ubyte* user_stack;
    size_t stack_size;
}

alias EntryFunc = extern(C) void function();

enum MAX_PROCESSES = 16;
enum DEFAULT_STACK_SIZE = 256 * 1024; // 256KB user stack - reduced from 1MB to fit within kernel heap

__gshared Process[MAX_PROCESSES] g_processes;
__gshared size_t g_process_count = 0;
__gshared size_t current_pid = size_t.max;

extern(C) void scheduler_init()
{
    g_process_count = 0;
    current_pid = size_t.max;
    foreach(ref p; g_processes)
    {
        p.pid = size_t.max;
        p.entry = null;
        p.name = null;
        p.started = false;
        p.exited = false;
        p.exit_status = 0;
        p.parent = size_t.max;
        p.note_handler = null;
        p.alarm_tick = 0;
        p.user_stack = null;
        p.stack_size = 0;
    }
    log_message("scheduler_init\n");
}

extern(C) size_t process_create_with_parent(EntryFunc entry, size_t parent, const(char)* name)
{
    if(g_process_count >= g_processes.length)
        return size_t.max;
    size_t pid = g_process_count;

    if(parent >= g_process_count)
        parent = size_t.max;
    
    size_t stack_size = DEFAULT_STACK_SIZE;
    ubyte* user_stack = cast(ubyte*)malloc(stack_size);
    if(user_stack is null) {
        log_message("FAILED to allocate user stack for process - DMD needs memory!\n");
        return size_t.max;
    }
    
    g_processes[pid].pid = pid;
    g_processes[pid].entry = entry;
    g_processes[pid].name = name;
    g_processes[pid].started = false;
    g_processes[pid].exited = false;
    g_processes[pid].exit_status = 0;
    g_processes[pid].parent = parent;
    g_processes[pid].note_handler = null;
    g_processes[pid].alarm_tick = 0;
    g_processes[pid].user_stack = user_stack;
    g_processes[pid].stack_size = stack_size;
    
    g_process_count++;
    log_message("*** STACK ALLOCATED for process ");
    log_hex(pid);
    log_message(" size=");
    log_hex(stack_size);
    log_message(" addr=");
    log_hex(cast(ulong)user_stack);
    log_message(" ***\n");
    return pid;
}

extern(C) size_t process_create(EntryFunc entry, const(char)* name)
{
    return process_create_with_parent(entry, size_t.max, name);
}

/// Invoke `fn` with the stack allocated for the given process.
/// Saves and restores the current stack pointer around the call.
private extern(C) void call_on_process_stack(EntryFunc fn, const(char)* fnName, ubyte* stack, size_t stackSize)
{
    log_message("call_on_process_stack: fn=");
    log_hex(cast(ulong)fn);
    log_message(" stack=");
    log_hex(cast(ulong)stack);
    log_message(" stackSize=");
    log_hex(stackSize);
    log_message("\n");
    
    if(fn is null) {
        log_message("call_on_process_stack: ERROR - null function pointer\n");
        return;
    }
    
    if(stack is null) {
        log_message("call_on_process_stack: ERROR - null stack pointer\n");
        return;
    }
    
    if(stackSize < 1024) {
        log_message("call_on_process_stack: ERROR - stack too small\n");
        return;
    }
    
    ulong oldRsp;
    // Save current stack pointer
    asm { "mov %%rsp, %0" : "=r"(oldRsp); };
    log_message("call_on_process_stack: saved RSP=");
    log_hex(oldRsp);
    log_message("\n");
    
    // Switch to the top of the provided stack
    // Reserve a small red zone for the return address
    // and align the pointer down to 16 bytes as per SysV ABI
    auto newRsp = cast(ulong)(stack + stackSize);
    newRsp &= ~cast(ulong)0xF;
    newRsp -= 16;
    
    log_message("Calling function: ");
    log_message(fnName);
    log_message("\n");
    
    log_message("call_on_process_stack: new RSP=");
    log_hex(newRsp);
    log_message("\n");
    
    // Validate new stack pointer is within bounds
    if(newRsp < cast(ulong)stack || newRsp >= cast(ulong)(stack + stackSize)) {
        log_message("call_on_process_stack: ERROR - calculated RSP out of bounds\n");
        return;
    }
    
    asm { "mov %0, %%rsp" : : "r"(newRsp); };
    fn();
    // Restore original stack pointer
    asm { "mov %0, %%rsp" : : "r"(oldRsp); };
    
    log_message("call_on_process_stack: restored RSP, returning\n");
}

extern(C) void scheduler_run()
{
    auto caller_pid = current_pid;
    foreach(ref p; g_processes[0 .. g_process_count])
    {
        if(p.entry !is null && !p.started && !p.exited)
        {
            p.started = true;
            log_message("*** RUNNING process ");
            log_hex(p.pid);
            log_message(" with ALLOCATED STACK at ");
            log_hex(cast(ulong)p.user_stack);
            log_message(" entry=");
            log_hex(cast(ulong)p.entry);
            log_message(" ***\n");
            current_pid = p.pid;

            const(char)* n = (p.name is null) ? "unknown" : p.name;
            call_on_process_stack(p.entry, n, p.user_stack, p.stack_size);

            current_pid = caller_pid;
        }
    }
    current_pid = caller_pid;
}

extern(C) void process_exit(size_t pid, int status)
{
    if(pid >= g_process_count)
        return;
    
    if(g_processes[pid].user_stack !is null) {
        log_message("*** FREEING stack for process ");
        log_hex(pid);
        log_message(" ***\n");
        free(g_processes[pid].user_stack);
        g_processes[pid].user_stack = null;
    }
    
    g_processes[pid].entry = null;
    g_processes[pid].name = null;
    g_processes[pid].started = false;
    g_processes[pid].exited = true;
    g_processes[pid].exit_status = status;
    g_processes[pid].stack_size = 0;
}

extern(C) size_t process_wait(size_t parent)
{
    foreach(ref p; g_processes[0 .. g_process_count])
    {
        if(p.parent == parent && p.exited)
        {
            size_t pid = p.pid;
            
            if(p.user_stack !is null) {
                free(p.user_stack);
                p.user_stack = null;
            }
            
            p.entry = null;
            p.name = null;
            p.started = false;
            p.exited = false;
            p.stack_size = 0;
            return pid;
        }
    }
    return size_t.max;
}

extern(C) size_t get_current_pid()
{
    return current_pid;
}

extern(C) long obj_pm_create_process(Object* obj, void** args, size_t nargs)
{
    if(nargs < 1 || args[0] is null)
        return -1;
    auto entry = cast(EntryFunc)args[0];
    return cast(long)process_create(entry, null);
}

extern(C) long obj_pm_run(Object* obj, void** args, size_t nargs)
{
    scheduler_run();
    return 0;
}

