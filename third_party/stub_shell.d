pragma(LDC_no_moduleinfo);

extern(C) long _syscall_trap(long id, long a1, long a2, long a3, long a4, long a5, long a6);

// System call IDs – keep in sync with kernel.syscall.SyscallID
enum SysWriteString = 0;
enum SysExit        = 21;
enum SysReadChar    = 44;

/// Write a string via the WriteString syscall (pointer + length).
private void _puts(const(char)* p, size_t len)
{
    _syscall_trap(SysWriteString, cast(long)p, len, 0, 0, 0, 0);
}

void puts(const(char)* s)
{
    size_t len = 0;
    for(; s[len]; ++len) {}
    _puts(s, len);
}

/// Write D string literal
void puts(string s)
{
    _puts(s.ptr, s.length);
}

/// Blocking read of a single character from keyboard/serial.
char getchar()
{
    long r = _syscall_trap(SysReadChar, 0,0,0,0,0,0);
    return cast(char)r;
}

/// Simple comparison of null-terminated C strings (returns 0 if equal)
int strcmp(const(char)* a, const(char)* b)
{
    size_t i = 0;
    while(a[i] || b[i]) {
        if(a[i] != b[i]) return 1;
        ++i;
    }
    return 0;
}

/// Entry point expected by the linker (see build_sh_bin.sh)
extern(C) void main()
{
    immutable prompt = "$ ";
    char[256] buf; // current input line
    size_t idx = 0;

    puts("Welcome to stub-shell! Type 'exit' to leave.\n");

    for(;;) {
        puts(prompt);
        idx = 0;
        for(;;) {
            char c = getchar();
            // Echo back to user
            _syscall_trap(SysWriteString, cast(long)&c, 1, 0,0,0,0);

            if(c == '\n') {
                buf[idx] = 0; // null-terminate
                break;
            } else if(c == '\b') {
                if(idx > 0) idx--; // rudimentary backspace handling (cursor not moved)
            } else {
                if(idx < buf.length - 1) {
                    buf[idx++] = c;
                }
            }
        }

        // Process command in buf
        if(idx == 0) {
            continue; // empty line
        }

        // Check for built-in commands
        if(strcmp(buf.ptr, "exit") == 0) {
            puts("Goodbye!\n");
            _syscall_trap(SysExit, 0,0,0,0,0,0);
            // Should not return, but guard anyway
            break;
        } else if(strcmp(buf.ptr, "hello") == 0) {
            puts("Hello from shell!\n");
        } else {
            puts("Unknown command: ");
            _puts(buf.ptr, idx);
            puts("\n");
        }
    }
}

// Assembly implementation of syscall trap wrapper (inline for simplicity)
extern(C) long _syscall_trap(long id, long a1, long a2, long a3, long a4, long a5, long a6)
{
    asm {
        // System V AMD64 calling convention already places args in RDI, RSI, RDX, RCX, R8, R9
        // For the kernel we need: RAX=id, RDI=a1, RSI=a2, RDX=a3, R10=a4, R8=a5, R9=a6
        mov RAX, id;
        mov RDI, a1;
        mov RSI, a2;
        mov RDX, a3;
        mov R10, a4;
        mov R8,  a5;
        mov R9,  a6;
        int 0x80;
        // Return value already in RAX
    }
}
