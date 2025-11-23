module minimal_os.kernel.posixutils.context;

version (X86_64)
{
    // Export the jump buffer type so other modules can selectively import it.
    // Without an explicit `public` the definition ended up module-private on
    // some compilers, which caused imports such as
    // `import minimal_os.kernel.posixutils.context : jmp_buf;` to fail.  Marking it as
    // `public` ensures the scheduler structures in `minimal_os.posix` can use
    // the type regardless of the target architecture.
    public align(16) struct jmp_buf
    {
        size_t[8] regs;
    }

    private enum size_t JMP_RBX = 0 * size_t.sizeof;
    private enum size_t JMP_RBP = 1 * size_t.sizeof;
    private enum size_t JMP_R12 = 2 * size_t.sizeof;
    private enum size_t JMP_R13 = 3 * size_t.sizeof;
    private enum size_t JMP_R14 = 4 * size_t.sizeof;
    private enum size_t JMP_R15 = 5 * size_t.sizeof;
    private enum size_t JMP_RSP = 6 * size_t.sizeof;
    private enum size_t JMP_RIP = 7 * size_t.sizeof;

    extern(C) @nogc nothrow int setjmp(ref jmp_buf env)
    {
        int result;
        auto envPtr = &env;
        asm @nogc nothrow
        {
            mov RDX, envPtr;
            mov [RDX + JMP_RBX], RBX;
            mov [RDX + JMP_RBP], RBP;
            mov [RDX + JMP_R12], R12;
            mov [RDX + JMP_R13], R13;
            mov [RDX + JMP_R14], R14;
            mov [RDX + JMP_R15], R15;
            mov [RDX + JMP_RSP], RSP;
            lea RAX, Lresume;
            mov [RDX + JMP_RIP], RAX;
            xor EAX, EAX;
            mov result, EAX;
            jmp Lend;
        Lresume:
            mov result, EAX;
        Lend:;
        };
        return result;
    }

    extern(C) @nogc nothrow void longjmp(ref jmp_buf env, int value)
    {
        auto envPtr = &env;
        int retval = value ? value : 1;
        asm @nogc nothrow
        {
            mov RDX, envPtr;
            mov RBX, [RDX + JMP_RBX];
            mov RBP, [RDX + JMP_RBP];
            mov R12, [RDX + JMP_R12];
            mov R13, [RDX + JMP_R13];
            mov R14, [RDX + JMP_R14];
            mov R15, [RDX + JMP_R15];
            mov RSP, [RDX + JMP_RSP];
            mov RAX, retval;
            mov R11, [RDX + JMP_RIP];
            jmp R11;
        };
    }
}
else static if (__traits(compiles, { import core.stdc.setjmp : jmp_buf; }))
{
    public import core.stdc.setjmp : jmp_buf;

    extern(C) @nogc nothrow int setjmp(ref jmp_buf env);
    extern(C) @nogc nothrow void longjmp(ref jmp_buf env, int value);
}
else
{
    static assert(0, "jmp_buf implementation only provided for this architecture");
}
