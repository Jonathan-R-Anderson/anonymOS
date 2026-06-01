// Macro for stubs without error codes
.macro ISR_NOERR index
.global isr\index
isr\index:
    push $0        // Dummy error code
    push $\index    // Vector number
    jmp common_stub
.endm

// Macro for stubs with error codes
.macro ISR_ERR index
.global isr\index
isr\index:
    // Error code is already on stack
    push $\index    // Vector number
    jmp common_stub
.endm

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

.global early_fault_asm
early_fault_asm:
    push $0
    push $0
    jmp common_stub

// Scratch area for saving rax/rdx without touching the stack in common_stub.
// Interrupts are already disabled at exception entry so there is no
// re-entrancy hazard between the save and restore.
.section .data
.align 8
early_stub_rax_save: .quad 0
early_stub_rdx_save: .quad 0
.section .text

common_stub:
    // sentinel 0x40 '@': early IDT common_stub entered.
    // Proves the early IDT is still loaded (real IDT routes to serviceISR).
    // Use memory-save instead of stack push to preserve the exact stack
    // layout that early_fault_handler_d argument extraction relies on.
    movq %rax, early_stub_rax_save(%rip)
    movq %rdx, early_stub_rdx_save(%rip)
.L_early_serial_wait:
    movl $0x3FD, %edx
    inb %dx, %al
    testb $0x20, %al
    jz .L_early_serial_wait
    movb $0x40, %al
    movl $0x3F8, %edx
    outb %al, %dx
    movq early_stub_rax_save(%rip), %rax
    movq early_stub_rdx_save(%rip), %rdx

    // Stack: Vector, ErrorCode, RIP, CS, RFLAGS
    // Save regs
    push %rax
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11

    // Arguments for D: void early_fault_handler_d(ulong err_code, ulong rip, ulong vector)
    // err_code is at 80(%rsp) -> 9*8=72 + 8
    // rip is at 88(%rsp)
    // vector is at 72(%rsp)

    mov 80(%rsp), %rdi // err_code
    mov 88(%rsp), %rsi // rip
    mov 72(%rsp), %rdx // vector

    call early_fault_handler_d
    
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rax
    
    add $16, %rsp // pop vector and err_code
    iretq
