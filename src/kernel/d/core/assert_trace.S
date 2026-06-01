.section .rodata
.balign 1
.Lassert_msg:
    .asciz "ASSERTION FAILED @ "
.Lnewline:
    .asciz "\n"

.text
.global c_assert
.type c_assert, @function
c_assert:
    test %edi, %edi
    jne .Lassert_ok

    mov (%rsp), %rax
    push %rax

    lea .Lassert_msg(%rip), %rdi
    call klog

    pop %rdi
    call klog_hex

    lea .Lnewline(%rip), %rdi
    call klog

.Lassert_halt:
    hlt
    jmp .Lassert_halt

.Lassert_ok:
    ret
