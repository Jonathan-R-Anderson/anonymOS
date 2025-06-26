module kernel.syscall;

pragma(LDC_no_moduleinfo);

import kernel.terminal : terminal_putchar, terminal_writestring;
import kernel.fs : fs_create_user, fs_open_file, fs_close_file,
                    fs_create_file_desc, fs_pread_file, fs_pwrite_file,
                    fs_seek_file;
import kernel.types; // for ulong

public:

enum SyscallID : ulong {
    WriteString = 0,
    CreateUser  = 1,
    Open        = 2,
    Create      = 3,
    PRead       = 4,
    PWrite      = 5,
    Seek        = 6,
    Close       = 7,
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

extern(C) long sys_create(ulong pathPtr, ulong mode, ulong perm, ulong, ulong, ulong)
{
    auto path = cast(const(char)*)pathPtr;
    int fd = fs_create_file_desc(path, cast(int)mode, cast(int)perm);
    return fd;
}

extern(C) long sys_pread(ulong fd, ulong buf, ulong count, ulong offset, ulong, ulong)
{
    return fs_pread_file(cast(int)fd, cast(void*)buf, cast(size_t)count, cast(size_t)offset);
}

extern(C) long sys_pwrite(ulong fd, ulong buf, ulong count, ulong offset, ulong, ulong)
{
    return fs_pwrite_file(cast(int)fd, cast(const(void)*)buf, cast(size_t)count, cast(size_t)offset);
}

extern(C) long sys_seek(ulong fd, ulong offset, ulong whence, ulong, ulong, ulong)
{
    return fs_seek_file(cast(int)fd, cast(long)offset, cast(int)whence);
}

extern(C) long sys_close(ulong fd, ulong, ulong, ulong, ulong, ulong)
{
    return fs_close_file(cast(int)fd);
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
    g_syscalls[cast(size_t)SyscallID.Create]      = &sys_create;
    g_syscalls[cast(size_t)SyscallID.PRead]       = &sys_pread;
    g_syscalls[cast(size_t)SyscallID.PWrite]      = &sys_pwrite;
    g_syscalls[cast(size_t)SyscallID.Seek]        = &sys_seek;
    g_syscalls[cast(size_t)SyscallID.Close]       = &sys_close;
}
