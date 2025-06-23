module kernel.logger;

version(unittest)
{
    import std.stdio : putchar;
    void terminal_putchar(char c)
    {
        putchar(c);
    }
}
else
{
    import kernel.terminal : terminal_putchar;
}

__gshared char[8192] logBuffer;
__gshared size_t logIndex;

extern(C) void logger_init()
{
    logIndex = 0;
    for(size_t i = 0; i < logBuffer.length; ++i)
        logBuffer[i] = 0;
}

private void log_putc(char c)
{
    if(logIndex < logBuffer.length - 1)
        logBuffer[logIndex++] = c;
    terminal_putchar(c);
}

extern(C) void log_message(const(char)* s)
{
    if (s is null)
    {
        log_putc('['); log_putc('N'); log_putc('U'); log_putc('L'); log_putc('L'); log_putc(']');
        return;
    }

    size_t i = 0;
    while (s[i] != '\0')
    {
        log_putc(s[i]);
        ++i;
    }
}

extern(C) void log_test()
{
    log_message("Hello from logger!\n");
    log_message("Address of logBuffer: ");
    //log_hex(cast(ulong)logBuffer.ptr);
    //log_message("\nlogIndex = ");
    //log_hex(logIndex);
    log_message("\n");
}

extern(C) void log_hex(ulong val)
{
    immutable(char[16]) hex = "0123456789ABCDEF";
    // Write characters directly to avoid temporary buffers
    log_putc('0');
    log_putc('x');
    foreach (i; 0 .. 16)
    {
        auto shift = 60 - i * 4;
        log_putc(hex[(val >> shift) & 0xF]);
    }
}

extern(C) const(char)* logger_get_buffer()
{
    return logBuffer.ptr;
}

extern(C) size_t logger_get_index()
{
    return logIndex;
}

extern(C) void log_register_state(const(char)* stage)
{
    log_message(stage);
    log_message("\n");
    ulong rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;
    asm { "mov %%rax, %0" : "=r"(rax); }
    asm { "mov %%rbx, %0" : "=r"(rbx); }
    asm { "mov %%rcx, %0" : "=r"(rcx); }
    asm { "mov %%rdx, %0" : "=r"(rdx); }
    asm { "mov %%rsi, %0" : "=r"(rsi); }
    asm { "mov %%rdi, %0" : "=r"(rdi); }
    asm { "mov %%rbp, %0" : "=r"(rbp); }
    asm { "mov %%rsp, %0" : "=r"(rsp); }
    asm { "mov %%r8, %0" : "=r"(r8); }
    asm { "mov %%r9, %0" : "=r"(r9); }
    asm { "mov %%r10, %0" : "=r"(r10); }
    asm { "mov %%r11, %0" : "=r"(r11); }
    asm { "mov %%r12, %0" : "=r"(r12); }
    asm { "mov %%r13, %0" : "=r"(r13); }
    asm { "mov %%r14, %0" : "=r"(r14); }
    asm { "mov %%r15, %0" : "=r"(r15); }

    log_message(" RAX="); log_hex(rax);
    log_message(" RBX="); log_hex(rbx);
    log_message(" RCX="); log_hex(rcx);
    log_message(" RDX="); log_hex(rdx);
    log_message("\n RSI="); log_hex(rsi);
    log_message(" RDI="); log_hex(rdi);
    log_message(" RBP="); log_hex(rbp);
    log_message(" RSP="); log_hex(rsp);
    log_message("\n R8="); log_hex(r8);
    log_message(" R9="); log_hex(r9);
    log_message(" R10="); log_hex(r10);
    log_message(" R11="); log_hex(r11);
    log_message("\n R12="); log_hex(r12);
    log_message(" R13="); log_hex(r13);
    log_message(" R14="); log_hex(r14);
    log_message(" R15="); log_hex(r15);
    log_message("\n");
}
extern(C) void log_mem_dump(const(void)* start, size_t len)
{
    auto p = cast(const ubyte*)start;
    for(size_t i = 0; i < len; ++i)
    {
        if((i & 15) == 0)
        {
            log_hex(cast(ulong)(p + i));
            log_message(": ");
        }
        ubyte b = p[i];
        char[3] hexbuf;
        const(char)* hex = "0123456789ABCDEF";
        hexbuf[0] = hex[b >> 4];
        hexbuf[1] = hex[b & 0xF];
        hexbuf[2] = '\0';
        log_message(hexbuf.ptr);
        if((i & 15) == 15 || i == len - 1)
            log_message("\n");
        else
            log_message(" ");
    }
}
