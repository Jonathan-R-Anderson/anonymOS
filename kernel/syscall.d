module kernel.syscall;

pragma(LDC_no_moduleinfo);

import kernel.terminal : terminal_putchar, terminal_writestring;
import kernel.fs : fs_create_user, fs_open_file;
import kernel.types; // for ulong

public:

enum SyscallID : ulong {
    WriteString = 0,
    CreateUser  = 1,
    Open        = 2,
}

alias SyscallHandler = extern(C) long function(ulong, ulong, ulong, ulong, ulong, ulong);

__gshared SyscallHandler[16] g_syscalls;

extern(C) long sys_write_string(ulong strPtr, ulong len, ulong, ulong, ulong, ulong)
{
    auto s = cast(const(char)*)strPtr;
    for(size_t i = 0; i < len; i++) {
        terminal_putchar(s[i]);
    }
    return cast(long)len;
}

extern(C) long sys_create_user(ulong namePtr, ulong, ulong, ulong, ulong, ulong)
{
    auto name = cast(const(char)*)namePtr;
    fs_create_user(name);
    return 0;
}

extern(C) long sys_open(ulong pathPtr, ulong mode, ulong, ulong, ulong, ulong)
{
    auto path = cast(const(char)*)pathPtr;
    int fd = fs_open_file(path, cast(int)mode);
    return fd;
}

extern(C) long do_syscall(ulong id, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6)
{
    if(id < g_syscalls.length && g_syscalls[id] !is null)
        return g_syscalls[id](a1, a2, a3, a4, a5, a6);
    return -1;
}

extern(C) void syscall_init()
{
    foreach(i; 0 .. g_syscalls.length)
        g_syscalls[i] = null;
    g_syscalls[cast(size_t)SyscallID.WriteString] = &sys_write_string;
    g_syscalls[cast(size_t)SyscallID.CreateUser]  = &sys_create_user;
    g_syscalls[cast(size_t)SyscallID.Open]        = &sys_open;
}
