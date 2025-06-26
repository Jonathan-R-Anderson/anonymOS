module kernel.process_manager;

pragma(LDC_no_moduleinfo);

import kernel.logger : log_message, log_hex;

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
}

alias EntryFunc = extern(C) void function();

enum MAX_PROCESSES = 16;

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
    }
    log_message("scheduler_init\n");
}

extern(C) size_t process_create_with_parent(EntryFunc entry, size_t parent)
{
    if(g_process_count >= g_processes.length)
        return size_t.max;
    size_t pid = g_process_count;
    g_processes[pid].pid = pid;
    g_processes[pid].entry = entry;
    g_processes[pid].started = false;
    g_processes[pid].exited = false;
    g_processes[pid].exit_status = 0;
    g_processes[pid].parent = parent;
    g_processes[pid].note_handler = null;
    g_processes[pid].alarm_tick = 0;
    g_process_count++;
    log_message("process_create pid=");
    log_hex(pid);
    log_message("\n");
    return pid;
}

extern(C) size_t process_create(EntryFunc entry)
{
    return process_create_with_parent(entry, size_t.max);
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
            current_pid = p.pid;
            p.entry();
            current_pid = size_t.max;
        }
    }
}

extern(C) void process_exit(size_t pid, int status)
{
    if(pid >= g_process_count)
        return;
    g_processes[pid].entry = null;
    g_processes[pid].started = false;
    g_processes[pid].exited = true;
    g_processes[pid].exit_status = status;
}

extern(C) size_t process_wait(size_t parent)
{
    foreach(ref p; g_processes[0 .. g_process_count])
    {
        if(p.parent == parent && p.exited)
        {
            size_t pid = p.pid;
            p.entry = null;
            p.started = false;
            p.exited = false;
            return pid;
        }
    }
    return size_t.max;
}

extern(C) size_t get_current_pid()
{
    return current_pid;
}

