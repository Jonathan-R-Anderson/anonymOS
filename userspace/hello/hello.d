module hello;
pragma(LDC_no_moduleinfo);

extern(C) long syscall(long id, long a1, long a2, long a3, long a4, long a5, long a6);

extern(C) long _syscall_trap(long id, long a1, long a2, long a3, long a4, long a5, long a6)
{
    asm {
        mov RAX, id;
        mov RDI, a1;
        mov RSI, a2;
        mov RDX, a3;
        mov R10, a4;
        mov R8,  a5;
        mov R9,  a6;
        int 0x80;
    }
    // Return in RAX automatically
}

extern(C) void _start()
{
    import core.stdc.string : strlen;
    const(char)* msg = "hello from userspace\n".ptr;
    auto len = strlen(msg);
    _syscall_trap(0, cast(long)msg, len, 0, 0, 0, 0); // write
    _syscall_trap(21, 0,0,0,0,0,0); // exit
    while(true) {}
} 