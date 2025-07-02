module kernel.process_manager;

pragma(LDC_no_moduleinfo);

import kernel.logger : log_message, log_hex;
import kernel.object_namespace : Object;
import kernel.lib.stdc.stdlib : malloc, free;

public:

struct Process {
    size_t pid;
    extern(C) void function() entry;
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

extern(C) size_t process_create_with_parent(EntryFunc entry, size_t parent)
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

extern(C) size_t process_create(EntryFunc entry)
{
    return process_create_with_parent(entry, size_t.max);
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

            p.entry();

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
    return cast(long)process_create(entry);
}

extern(C) long obj_pm_run(Object* obj, void** args, size_t nargs)
{
    scheduler_run();
    return 0;
}

