.section .text
.global syscall_stub_asm
.type syscall_stub_asm, @function
syscall_stub_asm:
    # Preserve callee-saved registers we will clobber (none for now)
    push %rbp
    mov %rsp, %rbp

    # Arrange syscall arguments for do_syscall(id,a1..a6)
    mov %rax, %rdi      # RDI = id
    # RDI (user) already in RDI becomes a1? Wait original a1 is in RDI – already ok
    # RSI = a2, RDX = a3
    mov %r10, %rcx      # RCX = a4 (user passed via R10 per SYSV int convention)
    # R8  = a5, R9 = a6 already set

    call do_syscall
    # Return value in RAX

    leave
    iretq

.size syscall_stub_asm, .-syscall_stub_asm
.section .note.GNU-stack,"",@progbits 