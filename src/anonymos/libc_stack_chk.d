module anonymos.libc_stack_chk;

import anonymos.syscalls.posix : sys_kill, sys_getpid, SIG, printLine;
import anonymos.libc_shadow_stack;

extern(C) __gshared ulong __stack_chk_guard = 0;

extern(C) @nogc nothrow void __stack_chk_fail()
{
    printLine("[stack] canary mismatch detected; terminating.");
    auto pid = sys_getpid();
    // Send SIGABRT to self; kernel will reap.
    cast(void) sys_kill(pid, SIG.ABRT);
    // Poison shadow stack so instrumentation won't try to reuse it.
    __shadow_stack_base = __shadow_stack_top = __shadow_stack_ptr = 0;
    for (;;)
    {
        asm @nogc nothrow { hlt; }
    }
}
