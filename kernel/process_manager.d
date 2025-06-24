module kernel.process_manager;

pragma(LDC_no_moduleinfo);

import kernel.logger : log_message, log_hex;

public:

struct Process {
    size_t pid;
    extern(C) void function() entry;
    bool started;
}

enum MAX_PROCESSES = 16;

__gshared Process[MAX_PROCESSES] g_processes;
__gshared size_t g_process_count = 0;

extern(C) void scheduler_init()
{
    g_process_count = 0;
    foreach(ref p; g_processes)
    {
        p.pid = size_t.max;
        p.entry = null;
        p.started = false;
    }
    log_message("scheduler_init\n");
}

extern(C) size_t process_create(extern(C) void function() entry)
{
    if(g_process_count >= g_processes.length)
        return size_t.max;
    size_t pid = g_process_count;
    g_processes[pid].pid = pid;
    g_processes[pid].entry = entry;
    g_processes[pid].started = false;
    g_process_count++;
    log_message("process_create pid=");
    log_hex(pid);
    log_message("\n");
    return pid;
}

extern(C) void scheduler_run()
{
    foreach(ref p; g_processes[0 .. g_process_count])
    {
        if(p.entry !is null && !p.started)
        {
            p.started = true;
            log_message("running process ");
            log_hex(p.pid);
            log_message("\n");
            p.entry();
        }
    }
}

extern(C) void process_exit(size_t pid)
{
    if(pid >= g_process_count)
        return;
    g_processes[pid].entry = null;
    g_processes[pid].started = false;
}

