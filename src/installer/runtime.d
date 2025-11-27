module runtime;

extern(C) void _start()
{
    import main : run;
    run();
    sys_exit(0);
}

extern(C) void sys_exit(int code)
{
    asm {
        mov RAX, 60; // SYS_EXIT
        mov RDI, code;
        syscall;
    }
}

extern(C) long sys_write(int fd, const void* buf, size_t count)
{
    long ret;
    asm {
        mov RAX, 1; // SYS_WRITE
        mov RDI, fd;
        mov RSI, buf;
        mov RDX, count;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

extern(C) long sys_block_read(ulong lba, ulong count, void* buf)
{
    long ret;
    asm {
        mov RAX, 1002; // SYS_BLOCK_READ
        mov RDI, lba;
        mov RSI, count;
        mov RDX, buf;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

extern(C) long sys_block_write(ulong lba, ulong count, void* buf)
{
    long ret;
    asm {
        mov RAX, 1003; // SYS_BLOCK_WRITE
        mov RDI, lba;
        mov RSI, count;
        mov RDX, buf;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

void print(string s)
{
    sys_write(1, s.ptr, s.length);
}

extern(C) void* memset(void* ptr, int value, size_t num)
{
    ubyte* p = cast(ubyte*)ptr;
    for (size_t i = 0; i < num; i++)
    {
        p[i] = cast(ubyte)value;
    }
    return ptr;
}

extern(C) void __assert(const char* msg, const char* file, int line)
{
    print("Assertion failed: ");
    // print(msg); // msg is C string, need conversion or loop
    sys_exit(1);
}
