module anonymos.libc_shadow_stack;

// Exposed to compiler-inserted shadow-stack instrumentation.
extern(C) __gshared ulong __shadow_stack_base = 0;
extern(C) __gshared ulong __shadow_stack_top  = 0;
extern(C) __gshared ulong __shadow_stack_ptr  = 0;

extern(C) @nogc nothrow void __shadow_stack_set(ulong base, ulong top, ulong ptr)
{
    __shadow_stack_base = base;
    __shadow_stack_top = top;
    __shadow_stack_ptr = ptr;
}
